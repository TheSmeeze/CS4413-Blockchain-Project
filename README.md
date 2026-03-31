# CS4413 Blockchain Project
A prototype blockchain system investigating privacy-preserving techniques including mixers and ring signatures. Built as part of CS4413 — focuses on anonymous transactions, cryptographic identity, and tamper-evident ledger design.

---

## Features

### User Management
- Create users with password authentication (PBKDF2 + SHA-256 + random salt)
- Automatic SECP256K1 key pair generation on user creation
  - Private key stored locally in `keys/<username>.pem`
  - Public key stored in `users.json`
- Deposit and withdraw funds
- Activate / deactivate accounts
- Check balance (requires authentication, account must be active)
- View public key

### Transaction Types

#### 1. Direct Transaction
- Standard peer-to-peer transfer
- Signed with sender's private key using ECDSA + SHA-256
- Signature stored in the transaction record and verified on creation
- Sender identity is visible on the ledger

#### 2. Ring Transaction (Anonymous)
- Sender signs as one of N users — real signer is mathematically hidden
- System automatically selects 2 decoy users from active users to form the ring
- Signer inserted at a random position in the ring
- Ledger records `sender = "RING_ANONYMOUS"` — real sender never stored
- Key image stored for double-spend detection: same signer always produces same key image
- Ring size: 3 members (1 real signer + 2 decoys)

#### 3. Mixer (CoinJoin-Style)
- Users submit anonymous transfer requests to a shared pool (`mix_pool.json`)
- Pool requires a minimum of 3 participants and has a time deadline
- Funds locked on join: deducted from sender, credited to `MIXER_POOL`
- On settlement: outputs shuffled randomly, each transfer recorded as `sender = "MIXER_POOL"`
- Breaks the sender-receiver link — observer cannot tell who paid whom
- Pools expire automatically and refund participants if minimum not reached

### Verification
- Verify any transaction by supplying its transaction ID
- Supports ECDSA verification (direct transactions)
- Supports ring signature verification (ring transactions)
- Mixer settlements have no individual signature by design

---

## Cryptographic Mechanisms

| Mechanism | Purpose |
|---|---|
| SHA-256 | Transaction ID generation, password hashing, ring challenge chaining |
| SECP256K1 ECC | Key pair generation (same curve as Bitcoin) |
| ECDSA | Digital signatures on direct transactions |
| PBKDF2 + salt | Password hashing — resistant to brute force |
| LSAG Ring Signatures | Anonymous signing — hides real signer among decoys |
| Key Image | Double-spend detection for ring transactions |
| CoinJoin Mixer | Breaks sender-receiver transaction graph link |

---

## Known Limitation
The implementation is vulnerable to **amount correlation attacks** — an observer with read access to the ledger can cross-reference balance changes with transaction amounts to identify the real signer within a ring. Production systems (e.g. Monero) mitigate this with RingCT using Pedersen Commitments, which is beyond the scope of this prototype.

---

## Storage
All data is persisted locally in JSON files:

| File | Contents |
|---|---|
| `users.json` | User accounts, balances, public keys, password hashes |
| `transaction.json` | Full transaction ledger |
| `mix_pool.json` | Pending and active mixer pools |
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
1.  Create User
2.  Deposit
3.  Withdraw
4.  Create Transaction       (Direct or, Mixer + Ring Sig. or, Standalone Ring Sig.)
5.  Status Check
6.  Check Balance
7.  View Public Key
8.  Verify Transaction
9. Exit
```
