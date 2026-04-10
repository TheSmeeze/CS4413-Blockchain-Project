# CS4413 Blockchain Project
A prototype blockchain system investigating privacy-preserving techniques including mixers and ring signatures. Built as part of CS4413 - focuses on anonymous transactions, cryptographic identity, and tamper-evident ledger design.

---

## Features

### User Management
- Create users with password authentication (PBKDF2 + SHA-256 + random salt)
- Automatic SECP256K1 key pair generation on user creation - public key `Q = d * G` [3][6]
  - Security is based on the Elliptic Curve Discrete Logarithm Problem (ECDLP): given `Q = k*G`, recovering `k` is computationally infeasible [3][4]
  - 256-bit ECC key offers equivalent security to a 3072-bit RSA key [3][6]
  - Private key stored locally in `keys/<username>.pem`
  - Public key stored in `users.json`
- Deposit and withdraw funds (both require authentication, both signed with ECDSA)
- Activate / deactivate accounts via Status Check
- Check balance (requires authentication, account must be active)
- View public key (requires authentication)

### Transaction Types

#### 1. Direct Transaction
- Standard peer-to-peer transfer
- Signed with sender's private key using ECDSA + SHA-256
- Signature verified immediately on creation
- `sig_type: "ECDSA"` recorded in the ledger
- Sender identity is visible on the ledger

#### 2. Ring Signature Transaction (Anonymous)
- Sender signs as one of N users - real signer is mathematically hidden
- System automatically selects 2 decoy users from active users to form the ring
- Signer inserted at a random position so position does not reveal identity
- Ledger records `sender = "RING_ANONYMOUS"` - real sender never stored
- Uses LSAG-style ring signatures with proper EC point commitments [3][4]:
  - Commitment: `r[i]*G + c[i]*PK[i]` (elliptic curve point addition) [3][4]
  - Challenge chain: `c[i+1] = H(msg || commit.x || commit.y)` [3][4]
  - Real signer closes the ring: `r = (w - c*sk) mod order` [3][4]
- Double-spend detection via private `key_images.json`:
  - Key image: `I = sk * H(PK || tx_id) mod order` - unique per transaction [2][4]
  - Only the real signer's key image is stored (decoys are never recorded)
  - Prevents replay of the same transaction; does not block future transactions
- Ring size: 3 members (1 real signer + 2 decoys)
- `sig_type: "Ring"` recorded in the ledger

#### 3. Mixer + Ring Signature (Anonymous)
- Users submit transfer requests to a shared pool (`mix_pool.json`)
- Pool requires a minimum of 3 participants and a time deadline
- Funds locked on join: deducted from sender, credited to `MIXER_POOL`
- On settlement:
  - Outputs shuffled randomly before payout — breaks input/output ordering
  - Each payout is ring-signed using all pool participants as the ring
  - Each payout uses a different signer to avoid key image reuse
  - Ledger records `sender = "MIXER_POOL"` - original sender never stored
- Fixed denomination per pool neutralizes amount-based correlation attacks (Heuristic 5) [5]
- Pools with fewer than 3 participants when deadline expires are refunded automatically
- Pool size is capped at the number of active users - can't create impossible pools
- Provides two layers of privacy: mixer breaks the transaction graph, ring signature hides which pool member authorized each payout

### Verification
- Verify any transaction by its transaction ID (menu option 8)
- **ECDSA**: recomputes signature against sender's stored public key
- **Ring**: recomputes the full EC commitment chain and checks it closes
- **Deposits**: verified against the receiver's public key (receiver signed the deposit)
- Mixer settlements carry ring signatures from pool participants

---

## Cryptographic Mechanisms

| Mechanism | Purpose |
|---|---|
| SHA-256 | Transaction ID chaining `SHA-256(prev_hash \|\| sender \|\| receiver \|\| amount \|\| timestamp)` [6][7] - first transaction uses a genesis hash of 64 zeroes, password hashing, ring challenge hashing |
| SECP256K1 ECC | Key pair generation on curve `y² = x³ + 7 (mod p)` [3] - same curve as Bitcoin |
| ECDSA | Digital signatures on direct transactions, deposits, and withdrawals [3][6] |
| PBKDF2 + random salt | Password hashing - resistant to brute-force and rainbow table attacks [6] |
| LSAG Ring Signatures | Anonymous signing using EC point commitments - hides real signer among decoys [3][4] |
| EC Point Arithmetic | Pure-Python SECP256K1 scalar multiplication and point addition - no external EC library needed |
| Key Image | Per-transaction double-spend detection - unique to (signer, tx_id), stored privately [2][4] |
| CoinJoin Mixer | Shuffled pool settlements break the sender-receiver transaction graph link [5][7] |

### Ring Signature — How the Math Works

Each ring member `i` contributes a challenge-response pair `(c[i], r[i])` [3][4]:

```
Commitment  =  r[i]*G  +  c[i]*PK[i]          (EC point) [3][4]
c[i+1]      =  H(message_hash || commit.x || commit.y)    [3][4]
```

For decoys, `r[i]` is random. For the real signer, `r = (w - c*sk) mod order` [3][4] using a secret nonce `w`, which ensures `r*G + c*PK = w*G` - the ring closes without revealing the signer's position.

Verification recomputes the full chain and checks every `c[i+1]` matches the stored value.

---

## Known Limitation
The implementation is vulnerable to **amount correlation attacks** [5] - an observer with read access to the ledger can cross-reference balance changes with transaction amounts to potentially identify the real signer within a ring. Production systems (e.g. Monero) mitigate this with RingCT using Pedersen Commitments, which is beyond the scope of this prototype.

---

## Storage
All data is persisted locally in JSON files:

| File | Contents |
|---|---|
| `users.json` | User accounts, balances, public keys, password hashes |
| `transaction.json` | Full transaction ledger |
| `mix_pool.json` | Pending and active mixer pools |
| `key_images.json` | Used ring transaction key images (double-spend detection, private) |
| `keys/<username>.pem` | Private keys (one file per user) |

None of the above are committed to version control (see `.gitignore`).

---

## Requirements
```
pip install cryptography pycryptodomex
```

## Run
```
python bc.py
```
On startup the system automatically initializes all data files, regenerates any missing key pairs, prompts for passwords for any accounts that do not have one set, and checks whether any mixer pools have expired and need to be settled or refunded.

---

## Menu Options
```
1. Create User
2. Deposit
3. Withdraw
4. Create Transaction       (Direct  /  Mixer + Ring Sig  /  Standalone Ring Sig)
5. Status Check
6. Check Balance
7. View Public Key
8. Verify Transaction
9. Exit
```

---

## References

[1] Eli Ben-Sasson, Alessandro Chiesa, Christina Garman, Matthew Green, Ian Miers, Eran Tromer, and Madars Virza. 2014. Zerocash: Decentralized Anonymous Payments from Bitcoin. In *Proceedings of the 2014 IEEE Symposium on Security and Privacy (SP '14)*. IEEE Computer Society, USA, 459–474. https://doi.org/10.1109/SP.2014.36

[2] J. Duan, L. Gu, and S. Zheng. 2020. ARCT: An efficient aggregating ring confidential transaction protocol in blockchain. *IEEE Access* 8 (2020), 198118–198130. https://doi.org/10.1109/access.2020.3034333

[3] Xiaofeng Li, Yongle Mei, Juntao Gong, Fagen Xiang, and Zhaofeng Sun. 2023. Secure ring signature scheme for privacy-preserving blockchain. *Entropy* 25, 9 (September 2023), 1334. https://doi.org/10.3390/e25091334

[4] Bender, A., Katz, J. and Morselli, R. 2006. Ring signatures: Stronger definitions, and constructions without random oracles. In *Proceedings of the Theory of Cryptography Conference (TCC 2006)*. Springer. https://link.springer.com/chapter/10.1007/11681878_4

[5] Zhipeng Wang, Stefanos Chaliasos, Kaihua Qin, Liyi Zhou, Lifeng Gao, Pascal Berrang, Benjamin Livshits, and Arthur Gervais. 2023. On how zero-knowledge proof blockchain mixers improve, and worsen user privacy. In *Proceedings of the ACM Web Conference 2023 (WWW '23)*. ACM, New York, NY, USA, 2022–2032. https://doi.org/10.1145/3543507.3583217

[6] Yu, Y., et al. 2018. Blockchain-based solutions to security and privacy issues in the Internet of Things. *IEEE Access*. https://ieeexplore.ieee.org/document/8600751/

[7] Jingqiao Zhang, Zheng Gao, and Wei Wang. 2019. A survey on privacy protection in blockchain system. *Journal of Network and Computer Applications* 126 (January 2019), 45–58. https://doi.org/10.1016/j.jnca.2018.10.020
