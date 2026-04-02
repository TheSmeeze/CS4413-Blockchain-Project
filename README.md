# CS4413 Blockchain Project
A prototype blockchain system investigating privacy-preserving techniques including mixers and ring signatures. Built as part of CS4413 — focuses on anonymous transactions, cryptographic identity, and tamper-evident ledger design.

---

## Features

### User Management
- Create users with password authentication (PBKDF2 + SHA-256 + random salt)
- Automatic SECP256K1 key pair generation on user creation
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
- Sender signs as one of N users — real signer is mathematically hidden
- System automatically selects 2 decoy users from active users to form the ring
- Signer inserted at a random position so position does not reveal identity
- Ledger records `sender = "RING_ANONYMOUS"` — real sender never stored
- Uses LSAG-style ring signatures with proper EC point commitments:
  - Commitment: `r[i]*G + c[i]*PK[i]` (elliptic curve point addition)
  - Challenge chain: `c[i+1] = H(msg || commit.x || commit.y)`
  - Real signer closes the ring: `r = (w - c*sk) mod order`
- Double-spend detection via private `key_images.json`:
  - Key image: `I = sk * H(PK || tx_id) mod order` — unique per transaction
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
  - Ledger records `sender = "MIXER_POOL"` — original sender never stored
- Pools with fewer than 3 participants when deadline expires are refunded automatically
- Pool size is capped at the number of active users — can't create impossible pools
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
| SHA-256 | Transaction ID chaining, password hashing, ring challenge hashing |
| SECP256K1 ECC | Key pair generation — same curve as Bitcoin |
| ECDSA | Digital signatures on direct transactions, deposits, and withdrawals |
| PBKDF2 + random salt | Password hashing — resistant to brute-force and rainbow table attacks |
| LSAG Ring Signatures | Anonymous signing using EC point commitments — hides real signer among decoys |
| EC Point Arithmetic | Pure-Python SECP256K1 scalar multiplication and point addition — no external EC library needed |
| Key Image | Per-transaction double-spend detection — unique to (signer, tx_id), stored privately |
| CoinJoin Mixer | Shuffled pool settlements break the sender-receiver transaction graph link |

### Ring Signature — How the Math Works

Each ring member `i` contributes a challenge-response pair `(c[i], r[i])`:

```
Commitment  =  r[i]*G  +  c[i]*PK[i]          (EC point)
c[i+1]      =  H(message_hash || commit.x || commit.y)
```

For decoys, `r[i]` is random. For the real signer, `r = (w - c*sk) mod order` using a secret nonce `w`, which ensures `r*G + c*PK = w*G` — the ring closes without revealing the signer's position.

Verification recomputes the full chain and checks every `c[i+1]` matches the stored value.

---

## Known Limitation
The implementation is vulnerable to **amount correlation attacks** — an observer with read access to the ledger can cross-reference balance changes with transaction amounts to potentially identify the real signer within a ring. Production systems (e.g. Monero) mitigate this with RingCT using Pedersen Commitments, which is beyond the scope of this prototype.

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
