import hashlib
import json, os, random, getpass
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Util.number import bytes_to_long

#files
USERS = "users.json"
BLOCKCHAIN = "transaction.json"
KEYS_DIR = "keys"
MIX_POOL_FILE = "mix_pool.json"
KEY_IMAGES_FILE = "key_images.json"  # private store — never committed to git

SYSTEM_ACCOUNTS = {"MIXER_POOL", "DEPOSIT", "WITHDRAWAL", "MIXER"}

# minimum participants for mixer
MIN_MIX_PARTICIPANTS = 3

# Key Pair Functions
def generateKeyPair(username):
    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256K1())
    priv_path = os.path.join(KEYS_DIR, f"{username}.pem")
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return pub_pem

def loadPrivateKey(username):
    priv_path = os.path.join(KEYS_DIR, f"{username}.pem")
    if not os.path.exists(priv_path):
        return None
    with open(priv_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)                  # End Key Pair Functions

# Signing Functions
def signTransaction(username, tx_data):
    private_key = loadPrivateKey(username)
    if private_key is None:
        print(f"No private key found for '{username}'.")
        return None
    message = json.dumps(tx_data, sort_keys=True).encode()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()

def verifySignature(username, tx_data, signature_hex):
    userlist = loadFile(USERS)
    pub_pem = None
    for user in userlist:
        if user["username"] == username:
            pub_pem = user.get("public_key")
            break
    if pub_pem is None:
        print(f"No public key found for '{username}'.")
        return False
    public_key = serialization.load_pem_public_key(pub_pem.encode())
    message = json.dumps(tx_data, sort_keys=True).encode()
    try:
        public_key.verify(bytes.fromhex(signature_hex), message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False                                                                        # End Signing Functions

# Password Functions
def hashPassword(password, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return salt, hashed

def authenticateUser(username):
    password = getpass.getpass(f"Enter password for '{username}': ")
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == username:
            salt = user.get("salt")
            stored_hash = user.get("password_hash")
            if not salt or not stored_hash:
                print("No password set for this user.")
                return False
            _, computed = hashPassword(password, salt)
            if computed == stored_hash:
                return True
            print("Incorrect password.")
            return False
    return False                                                                           # End Password Functions



# verifies existence of a user
def verifyUser(username):
    user_list = loadFile(USERS)
    for user in user_list:
        if user["username"] == username:
            return True
    return False

def loadFile(filename):
    if not os.path.exists(filename):
        with open(filename,"w") as file:
            json.dump([],file)
        return []
    with open(filename, "r") as file:
        try:
            return json.load(file)
        except json.JSONDecodeError:
            return []

def saveFile(filename, filedata):
    with open (filename,"w") as file:
        json.dump(filedata, file, indent = 4)


# SHA-256 chain: each transaction hashes its own data + previous transaction's hash
GENESIS_HASH = "0" * 64

def getPrevHash():
    transList = loadFile(BLOCKCHAIN)
    if not transList:
        return GENESIS_HASH
    return transList[-1].get("transaction_id", GENESIS_HASH)

def generateTransactionID(prev_hash, sender, reciever, amount):
    timestamp = datetime.now().isoformat()
    raw = prev_hash + sender + reciever + str(amount) + timestamp
    return hashlib.sha256(raw.encode()).hexdigest()

def computeKeyImage(username, tx_id):
    """Compute a per-transaction key image: I = sk * H(PK || tx_id) mod order.
    Unique per transaction — same user can sign multiple different transactions.
    A double-spend only occurs if someone submits the exact same tx_id twice."""
    sk, _ = pem_to_ecc_keypair(username)
    pt = _get_pub_xy(username)
    if pt is None:
        return None
    px, py = pt
    order = get_curve_order()
    key_image = (hash_to_scalar(px.to_bytes(32, 'big') + py.to_bytes(32, 'big') + tx_id.encode()) * sk) % order
    return hex(key_image)

def isDoubleSpend(key_image_hex):
    """Check if a key image has already been used — stored privately in key_images.json."""
    images = loadFile(KEY_IMAGES_FILE)
    return key_image_hex in images

def logTransaction(sender, reciever, amt, sign_as=None, ring_sign=None, auto_sign=False):
    prev_hash = getPrevHash()
    txn_id = generateTransactionID(prev_hash, sender, reciever, amt)
    tx = {
        "transaction_id": txn_id,
        "prev_transaction_id": prev_hash,
        "sender": sender,
        "amount": amt,
        "reciever": reciever,
        "timestamp": datetime.now().isoformat()
    }
    if sign_as:
        sig = signTransaction(sign_as, tx)
        if sig:
            tx["signature"] = sig
            tx["sig_type"] = "ECDSA"
    elif ring_sign:
        usernames, singer = ring_sign
        signer_idx = usernames.index(singer)
        ring_sig = signRingTransaction(usernames, tx, signer_idx, singer, auto_sign=auto_sign)
        if ring_sig:
            tx["signature"] = ring_sig
            tx["sig_type"] = "Ring"
    transList = loadFile(BLOCKCHAIN)
    transList.append(tx)
    saveFile(BLOCKCHAIN, transList)
    return txn_id


# create user
def createUser():
    name = input("Enter username: ")
    if verifyUser(name) == True:
        print("User already exists")
        return

    password = getpass.getpass("Set password: ")
    confirm  = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        return
    salt, hashed = hashPassword(password)

    pub_pem = generateKeyPair(name)
    new_user = {
        "username": name,
        "balance": 0,
        "active": True,
        "creation-Timestamp": datetime.now().isoformat(),
        "public_key": pub_pem,
        "salt": salt,
        "password_hash": hashed
    }
    userlist = loadFile(USERS)
    userlist.append(new_user)
    saveFile(USERS, userlist)
    print(f"User '{name}' created with balance $0. Key pair generated.")
    print(f"Private key saved to: {os.path.join(KEYS_DIR, name + '.pem')}")
    deposit_now = input("Would you like to make an initial deposit? (y/n): ").strip()
    if deposit_now == "y":
        deposit(name, skip_auth=True)


def deposit(username=None, skip_auth=False):
    if username is None:
        username = input("Enter username: ").strip()
    if not verifyUser(username):
        print("\nUser does not exist.")
        return
    userlist = loadFile(USERS)

    target_user = None
    for u in userlist:
        if u["username"] == username:
            target_user = u
            break

    if target_user["active"] != True:
        print("User is inactive")
        return

    if not skip_auth and not authenticateUser(username):
        return

    try:
        amt = float(input("Enter deposit amount($): "))
    except ValueError:
        print("Invalid amount.")
        return
    if amt <= 0:
        print("Deposit amount must be greater than 0.")
        return

    target_user["balance"] = float(target_user["balance"]) + amt
    saveFile(USERS, userlist)
    logTransaction("DEPOSIT", username, amt, sign_as=username)
    print(f"Deposited ${amt:.2f}.")
    print(f"Updated balance of {target_user['username']}: ${target_user['balance']:.2f}")


def withdraw():
    username = input("Enter username: ").strip()
    if not verifyUser(username):
        print("\nUser does not exist.")
        return

    userlist = loadFile(USERS)

    target_user = None
    for u in userlist:
        if u["username"] == username:
            target_user = u
            break

    if target_user["active"] != True:
        print("User is inactive.")
        return

    if not authenticateUser(username):
        return

    try:
        amt = float(input("Enter withdrawal amount($): "))
    except ValueError:
        print("Invalid amount.")
        return
    if amt <= 0:
        print("Withdrawal amount must be greater than 0.")
        return

    if float(target_user["balance"]) < amt:
        print("Insufficient funds")
        return

    target_user["balance"] = float(target_user["balance"]) - amt
    saveFile(USERS, userlist)
    logTransaction(username, "WITHDRAWAL", amt, sign_as=username)
    print(f"Withdrew ${amt:.2f}.")
    print(f"Updated balance of {target_user['username']}: ${target_user['balance']:.2f}")


# Mixer helper

def ensureMixerPool():
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == "MIXER_POOL":
            return
    userlist.append({
        "username": "MIXER_POOL",
        "balance": 0,
        "active": True,
        "creation-Timestamp": datetime.now().isoformat()
    })
    saveFile(USERS, userlist)

def _settleMix(pool):
    """Settle a mix pool: shuffle outputs then ring-sign each payout using pool participants as the ring."""
    participants = pool["participants"]
    payouts = [{"destination": p["destination"], "amount": p["amount"]} for p in participants]
    random.shuffle(payouts)

    # all pool senders form the ring — any one of them could be the signer
    ring_members = [p["sender"] for p in participants]

    userlist = loadFile(USERS)
    for payout in payouts:
        for u in userlist:
            if u["username"] == "MIXER_POOL":
                u["balance"] = float(u["balance"]) - payout["amount"]
            elif u["username"] == payout["destination"]:
                u["balance"] = float(u["balance"]) + payout["amount"]
    saveFile(USERS, userlist)

    # each payout uses a different signer so no key image is reused (no double-spend false positive)
    shuffled_signers = ring_members[:]
    random.shuffle(shuffled_signers)
    for payout, signer in zip(payouts, shuffled_signers):
        logTransaction("MIXER_POOL", payout["destination"], payout["amount"],
                       ring_sign=(ring_members, signer), auto_sign=True)

    print(f"Mix complete. {len(participants)} transactions anonymised with ring signatures.")

def _refundMix(pool):
    """Refund all locked funds back to senders (pool expired with too few participants)."""
    userlist = loadFile(USERS)
    for p in pool["participants"]:
        for u in userlist:
            if u["username"] == p["sender"]:
                u["balance"] = float(u["balance"]) + p["amount"]
            elif u["username"] == "MIXER_POOL":
                u["balance"] = float(u["balance"]) - p["amount"]
    saveFile(USERS, userlist)
    # log each refund so there is an audit trail of returned funds
    for p in pool["participants"]:
        logTransaction("MIXER_POOL", p["sender"], p["amount"])
    print(f"Pool '{pool['pool_id']}' expired with only {len(pool['participants'])}/{MIN_MIX_PARTICIPANTS} participants. Funds refunded.")

def checkExpiredPools():
    pools = loadFile(MIX_POOL_FILE)
    now = datetime.now()
    updated = False
    remaining = []
    for pool in pools:
        if pool.get("status", "open") != "open":
            continue
        deadline = datetime.fromisoformat(pool["deadline"])
        if now >= deadline:
            updated = True
            if len(pool["participants"]) >= MIN_MIX_PARTICIPANTS:
                print(f"\nPool '{pool['pool_id']}' expired — processing {len(pool['participants'])} participants...")
                _settleMix(pool)
            else:
                _refundMix(pool)
        else:
            remaining.append(pool)
    if updated:
        saveFile(MIX_POOL_FILE, remaining)

def createMixPool():
    ensureMixerPool()
    userlist = loadFile(USERS)
    active_real = [u for u in userlist if u.get("active") and u["username"] not in SYSTEM_ACCOUNTS]
    if len(active_real) < MIN_MIX_PARTICIPANTS:
        print(f"Not enough active users. Need at least {MIN_MIX_PARTICIPANTS}.")
        return

    max_pool = len(active_real)
    try:
        pool_size = int(input(f"Pool size (min {MIN_MIX_PARTICIPANTS}, max {max_pool}): ").strip())
    except ValueError:
        print("Invalid number.")
        return
    if pool_size < MIN_MIX_PARTICIPANTS:
        print(f"Pool size must be at least {MIN_MIX_PARTICIPANTS}.")
        return
    # pool cannot exceed the number of active users - can't have more slots than participants
    if pool_size > max_pool:
        print(f"Pool size cannot exceed the number of active users ({max_pool}).")
        return

    try:
        minutes = int(input("Time limit in minutes: ").strip())
    except ValueError:
        print("Invalid number.")
        return
    if minutes <= 0:
        print("Time limit must be greater than 0.")
        return

    deadline = (datetime.now() + timedelta(minutes=minutes)).isoformat()
    pool_id = hashlib.sha256((deadline + str(pool_size)).encode()).hexdigest()[:8]

    pool = {
        "pool_id": pool_id,
        "pool_size": pool_size,
        "deadline": deadline,
        "participants": [],
        "status": "open"
    }
    pools = loadFile(MIX_POOL_FILE)
    pools.append(pool)
    saveFile(MIX_POOL_FILE, pools)
    print(f"Pool '{pool_id}' created. Size: {pool_size}, closes at: {deadline}")

    join_now = input("Would you like to join this pool now? (y/n): ").strip().lower()
    if join_now == "y":
        joinMixPool(pool_id)

def joinMixPool(pool_id=None):
    ensureMixerPool()
    pools = loadFile(MIX_POOL_FILE)
    open_pools = [p for p in pools if p["status"] == "open"]
    if not open_pools:
        print("No open mix pools.")
        return

    if pool_id is None:
        print("\n--- Open Mix Pools ---")
        now = datetime.now()
        for i, p in enumerate(open_pools, 1):
            deadline = datetime.fromisoformat(p["deadline"])
            mins_left = max(0, int((deadline - now).total_seconds() // 60))
            print(f"{i}. Pool '{p['pool_id']}' | {len(p['participants'])}/{p['pool_size']} joined | {mins_left} min remaining")
        try:
            idx = int(input(f"Select pool (1-{len(open_pools)}): ").strip()) - 1
        except ValueError:
            print("Invalid selection.")
            return
        if idx < 0 or idx >= len(open_pools):
            print("Invalid selection.")
            return
        pool_id = open_pools[idx]["pool_id"]

    # reload to get fresh state
    pools = loadFile(MIX_POOL_FILE)
    pool = next((p for p in pools if p["pool_id"] == pool_id), None)
    if not pool or pool["status"] != "open":
        print("Pool not found or no longer open.")
        return

    # check deadline hasn't passed
    if datetime.now() >= datetime.fromisoformat(pool["deadline"]):
        print("This pool has expired.")
        checkExpiredPools()
        return

    userlist = loadFile(USERS)
    sender = input("Your username: ").strip()
    if not verifyUser(sender) or sender in SYSTEM_ACCOUNTS:
        print("Invalid user.")
        return
    sender_data = next((u for u in userlist if u["username"] == sender), None)
    if not sender_data or not sender_data.get("active"):
        print("User is inactive.")
        return
    if any(p["sender"] == sender for p in pool["participants"]):
        print("You are already in this pool.")
        return
    if not authenticateUser(sender):
        return

    destination = input("Destination username: ").strip()
    if not verifyUser(destination) or destination in SYSTEM_ACCOUNTS:
        print("Invalid destination.")
        return
    # block sending to an inactive user - they opted out of all activity
    dest_data = next((u for u in userlist if u["username"] == destination), None)
    if not dest_data or not dest_data.get("active"):
        print("Destination user is inactive. Transaction cancelled.")
        return

    try:
        amt = float(input("Amount($): "))
    except ValueError:
        print("Invalid amount.")
        return
    if amt <= 0:
        print("Amount must be greater than 0.")
        return
    if float(sender_data["balance"]) < amt:
        print("Insufficient funds.")
        return

    # lock funds: deduct from sender, credit MIXER_POOL, log Phase 1 tx
    userlist = loadFile(USERS)
    for u in userlist:
        if u["username"] == sender:
            u["balance"] = float(u["balance"]) - amt
        elif u["username"] == "MIXER_POOL":
            u["balance"] = float(u["balance"]) + amt
    saveFile(USERS, userlist)
    logTransaction(sender, "MIXER_POOL", amt, sign_as=sender)

    pool["participants"].append({"sender": sender, "destination": destination, "amount": amt})
    saveFile(MIX_POOL_FILE, pools)
    print(f"Joined pool '{pool_id}'. Participants: {len(pool['participants'])}/{pool['pool_size']}.")

    # prompt to add another participant if pool isn't full yet
    if len(pool["participants"]) < pool["pool_size"]:
        add_another = input("Would you like to add another participant to this pool now? (y/n): ").strip().lower()
        if add_another == "y":
            joinMixPool(pool_id)
        else:
            print(f"Pool '{pool_id}' is open. Others can join later via 'Create Transaction → Mixer → Join existing pool'.")

    if len(pool["participants"]) >= pool["pool_size"]:
        print("Pool is full. Processing mix now...")
        _settleMix(pool)
        pools = loadFile(MIX_POOL_FILE)
        for p in pools:
            if p["pool_id"] == pool_id:
                p["status"] = "complete"
                break
        # remove completed pools
        saveFile(MIX_POOL_FILE, [p for p in pools if p["status"] == "open"])

def runMixer():
    print("\n  1. Create new mix pool")
    print("  2. Join existing pool")
    choice = input("  Select: ").strip()
    if choice == "1":
        createMixPool()
    elif choice == "2":
        joinMixPool()
    else:
        print("Invalid option.")


# creates transaction item
def createTransaction():
    print("\n  1. Normal Transaction")
    print("  2. Mixer + Ring Signature (anonymous)")
    print("  3. Ring Signature only (anonymous)")
    tx_type = input("  Select type: ").strip()

    if tx_type == "2":
        runMixer()
        return

    if tx_type == "3":
        createRingTransaction()
        return

    if tx_type != "1":
        print("Invalid option.")
        return

    sender = input("Enter sender username: ").strip()
    if not verifyUser(sender):
        print("\nUser does not exist.")
        return

    userlist = loadFile(USERS)

    # check if sender active before moving forward
    for user in userlist:
        if user["username"] == sender:
            if user["active"] != True:
                print("User is inactive.\n")
                print("Transaction cancelled.\n")
                return

    if not authenticateUser(sender):
        return

    reciever = input("Enter reciever username: ").strip()
    if not verifyUser(reciever):
        print("\nUser does not exist.")
        return

    # check if reciever active before moving forward
    for user in userlist:
        if user["username"] == reciever:
            if user["active"] != True:
                print("User is inactive\n")
                print("Transaction cancelled.\n")
                return

    try:
        amt = float(input("Enter an amt($): "))
    except ValueError:
        print("Invalid amount.")
        return
    if amt <= 0:
        print("Amount must be greater than 0.")
        return
    confirm = input(f"Are you sure that you would like to send: ${amt} to: {reciever}?(y/n): ")
    if confirm.lower() == "y":
        sender_balance = None
        for user in userlist:
            if user["username"] == sender:
                sender_balance = float(user["balance"])
                break
        if sender_balance < amt:
            print("Insufficient funds")
            return
        for user in userlist:
            if user["username"] == sender:
                user["balance"] = sender_balance - amt
            elif user["username"] == reciever:
                user["balance"] = float(user["balance"]) + amt
        saveFile(USERS, userlist)
        prev_hash = getPrevHash()
        txn_id = generateTransactionID(prev_hash, sender, reciever, amt)
        tx_data = {
            "transaction_id": txn_id,
            "prev_transaction_id": prev_hash,
            "sender": sender,
            "amount": amt,
            "reciever": reciever,
            "timestamp": datetime.now().isoformat()
        }
        signature = signTransaction(sender, tx_data)
        if signature is None:
            print("Transaction cancelled: could not sign.")
            return
        tx_data["signature"] = signature
        tx_data["sig_type"] = "ECDSA"
        tx_data_without_sig = {k: v for k, v in tx_data.items() if k not in ["signature", "sig_type"]}
        if verifySignature(sender, tx_data_without_sig, signature):
            print("Signature verified.")
        else:
            print("Warning: signature verification failed.")
        transList = loadFile(BLOCKCHAIN)
        transList.append(tx_data)
        saveFile(BLOCKCHAIN, transList)
        print(f"Transaction complete: ${amt:.2f} sent from {sender} to {reciever}.")
    else:
        print("Transaction cancelled.\n")


# status func check status of user, and has the ability to update status
def user_status():
    username = input("Enter username to check status: ").strip()
    userlist = loadFile(USERS)

    for user in userlist:
        if user["username"] == username:
            if user["active"]:
                print(f"User: {username} status is Active.")
                decision = input("Would you like to Deactivate the user?(y/n): ").strip()
                if decision == "y":
                    if not authenticateUser(username):
                        return
                    user["active"] = False
                    saveFile(USERS, userlist)
                    print(f"User: {username} is now Inactive.")
            else:
                print(f"User: {username} status is Inactive.")
                decision = input("Would you like to Activate the user?(y/n): ").strip()
                if decision == "y":
                    if not authenticateUser(username):
                        return
                    user["active"] = True
                    saveFile(USERS, userlist)
                    print(f"User: {username} is now Active.")
            return

    print("User does not exist.")

def checkBalance():
    username = input("Enter username: ").strip()
    if not verifyUser(username):
        print("User does not exist.")
        return
    # block inactive users - must reactivate first via Status Check
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == username:
            if not user.get("active"):
                print("Account is inactive. Please activate your account first (Status Check).")
                return
    # require password - only the account owner should see their balance
    if not authenticateUser(username):
        return
    for user in userlist:
        if user["username"] == username:
            print(f"Balance of {username}: ${float(user['balance']):.2f}")
            return

def verifyTransaction():
    txn_id = input("Enter transaction ID to verify: ").strip()
    transList = loadFile(BLOCKCHAIN)
    for tx in transList:
        if tx.get("transaction_id") == txn_id:
            sender = tx.get("sender")
            signature = tx.get("signature")
            sig_type = tx.get("sig_type", "ecdsa")
            if not signature:
                print("This transaction has no signature (deposit/withdrawal/mixed).")
                return
            tx_data = {k: v for k, v in tx.items() if k not in ["signature", "sig_type"]}
            
            if sig_type == "Ring":
                if isinstance(signature, dict) and verifyRingSignature(signature.get("ring_members", []),tx_data, signature):
                    ring_size = len(signature.get("ring_members", []))
                    print(f"Ring signature valid. Transaction was authorized by one of {ring_size} possible users (anonymous).")
                else:
                    print("Ring signature INVALID. Transaction may have been tampered with.")                                                                         
            
            else:
                # for DEPOSIT the receiver signed it, for all others the sender signed it
                signer = tx.get("reciever") if sender == "DEPOSIT" else sender
                if verifySignature(signer, tx_data, signature):
                    print("Signature valid. Transaction was authorized by sender.")
                else:
                    print("Signature INVALID. Transaction may have been tampered with.")
            return
    print("Transaction not found.")

def viewPublicKey():
    username = input("Enter username: ").strip()
    if not verifyUser(username):
        print("User does not exist.")
        return
    if not authenticateUser(username):
        return
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == username:
            pub = user.get("public_key", None)
            if pub:
                print(f"\nPublic key for '{username}':\n{pub}")
            else:
                print("No public key found for this user.")
            return

def generateMissingKeys():
    userlist = loadFile(USERS)
    updated = False
    for user in userlist:
        if not user.get("public_key") and user["username"] not in SYSTEM_ACCOUNTS:
            pub_pem = generateKeyPair(user["username"])
            user["public_key"] = pub_pem
            updated = True
    if updated:
        saveFile(USERS, userlist)

def setMissingPasswords():
    userlist = loadFile(USERS)
    updated = False
    for user in userlist:
        if user["username"] in SYSTEM_ACCOUNTS:
            continue
        if not user.get("password_hash"):
            print(f"\nNo password set for '{user['username']}'. Please set one now.")
            while True:
                password = getpass.getpass("  Set password: ")
                confirm  = getpass.getpass("  Confirm password: ")
                if password == confirm:
                    break
                print("  Passwords do not match, try again.")
            salt, hashed = hashPassword(password)
            user["salt"] = salt
            user["password_hash"] = hashed
            updated = True
    if updated:
        saveFile(USERS, userlist)

#ECC helper functions for ring signatures

# SECP256K1 curve parameters
_SECP256K1_P     = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_Gx    = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_Gy    = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def get_curve_order():
    return _SECP256K1_ORDER

def _point_add(P, Q, p=_SECP256K1_P):
    """Add two EC points on SECP256K1."""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if y1 != y2: return None  # point at infinity
        # point doubling
        lam = (3 * x1 * x1) * pow(2 * y1, p - 2, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return x3, y3

def _point_mul(k, P, p=_SECP256K1_P):
    """Scalar multiplication k*P using double-and-add."""
    k = k % _SECP256K1_ORDER
    R = None
    while k:
        if k & 1:
            R = _point_add(R, P, p)
        P = _point_add(P, P, p)
        k >>= 1
    return R

def pem_to_ecc_keypair(username):
    """Load PEM private key → (secret_key_int, public_point_tuple)"""
    private_key = loadPrivateKey(username)
    private_value = private_key.private_numbers().private_value
    x = private_key.private_numbers().public_numbers.x
    y = private_key.private_numbers().public_numbers.y
    return private_value, (x, y)

#ring sig helpers

def hash_to_scalar(data, order=None):
    """Convert hash → scalar in valid range"""
    if order is None:
        order = get_curve_order()
    h = hashlib.sha256(data).digest()
    scalar = bytes_to_long(h) % order
    return max(1, scalar)  # Non-zero



# Ring Signature Functions
# LSAG (Linkable Spontaneous Anonymous Group) scheme.
# Signs a message as "one of N users" without revealing which one.
# A key image ties each signer to their signatures for double-spend detection.


def _get_pub_xy(username):
    """Load a user's public key as (x, y) integers from users.json."""
    userlist = loadFile(USERS)
    for u in userlist:
        if u["username"] == username:
            pub_pem = u.get("public_key")
            if not pub_pem:
                return None
            pub = serialization.load_pem_public_key(pub_pem.encode())
            nums = pub.public_numbers()
            return nums.x, nums.y
    return None

def signRingTransaction(ring_usernames, tx_data, signer_index, signer_username, auto_sign=False):
    """
    Ring signature (LSAG)
    - Real signer uses private key to close the ring.
    - Decoys use random responses.
    - auto_sign=True skips password prompt (used by mixer settlement).

    Returns a dict with: challenges, responses, ring_members, message_hash
    """
    # auto_sign means no interactive auth needed (mixer calls this without a user present)
    if not auto_sign and not authenticateUser(signer_username):
        return None

    order = get_curve_order()
    n = len(ring_usernames)
    signer_idx = signer_index

    # load real signer's private key scalar
    sk, _ = pem_to_ecc_keypair(signer_username)

    # message hash - what we're committing to
    message = json.dumps(tx_data, sort_keys=True).encode()
    message_hash = hashlib.sha256(message).digest()

    # random commitment scalar for the real signer
    w = random.randint(1, order - 1)

    # random responses for all positions (signer's will be overwritten to close the ring)
    challenges = [None] * n
    responses = [None] * n

    # load all ring members' public key coordinates — needed for challenge computation
    pub_points = []
    for username in ring_usernames:
        pt = _get_pub_xy(username)
        if pt is None:
            print(f"Could not load public key for ring member '{username}'.")
            return None
        pub_points.append(pt)

    G = (_SECP256K1_Gx, _SECP256K1_Gy)

    def _commitment(r, c, PK):
        """Compute r*G + c*PK — the EC commitment point."""
        return _point_add(_point_mul(r, G), _point_mul(c, PK))

    def _challenge(commit_pt):
        """Hash the commitment point into a scalar challenge."""
        cx, cy = commit_pt
        return hash_to_scalar(message_hash + cx.to_bytes(32, 'big') + cy.to_bytes(32, 'big'), order)

    # Phase 1: signer's commitment using random scalar w → c[signer+1]
    commit_w = _point_mul(w, G)
    next_c = _challenge(commit_w)

    # Phase 2: propagate challenges forward from signer+1 around the ring
    # Each decoy: pick random r[i], compute commitment r[i]*G + c[i]*PK[i], hash to get c[i+1]
    for step in range(1, n):
        i = (signer_idx + step) % n
        responses[i] = random.randint(1, order - 1)
        challenges[i] = next_c
        commit = _commitment(responses[i], challenges[i], pub_points[i])
        next_c = _challenge(commit)

    # Phase 3: close the ring — signer's challenge is the one that wraps back
    challenges[signer_idx] = next_c
    # signer's response: r = w - c*sk  (so r*G + c*PK = w*G)
    responses[signer_idx] = (w - challenges[signer_idx] * sk) % order

    return {
        "challenges": [hex(c) for c in challenges],
        "responses": [hex(r) for r in responses],
        "ring_members": ring_usernames,
        "message_hash": message_hash.hex()
    }

def verifyRingSignature(ring_usernames, tx_data, ring_sig):
    """
    Verify ring signature using EC commitments: r[i]*G + c[i]*PK[i]
    Each commitment hashes to the next challenge — the ring must close perfectly.
    """
    order = get_curve_order()
    G = (_SECP256K1_Gx, _SECP256K1_Gy)
    message = json.dumps(tx_data, sort_keys=True).encode()
    message_hash = hashlib.sha256(message).digest()

    if ring_sig.get("message_hash") != message_hash.hex():
        return False

    challenges = [int(c, 16) for c in ring_sig["challenges"]]
    responses  = [int(r, 16) for r in ring_sig["responses"]]
    n = len(ring_usernames)

    # load all public keys
    pub_points = []
    for username in ring_usernames:
        pt = _get_pub_xy(username)
        if pt is None:
            return False
        pub_points.append(pt)

    # recompute each commitment and check challenge chain closes
    # c[i+1] = H(msg || (r[i]*G + c[i]*PK[i]))  — must match stored c[i+1]
    for i in range(n):
        commit = _point_add(_point_mul(responses[i], G), _point_mul(challenges[i], pub_points[i]))
        if commit is None:
            return False
        cx, cy = commit
        recomputed = hash_to_scalar(message_hash + cx.to_bytes(32, 'big') + cy.to_bytes(32, 'big'), order)
        expected_next = challenges[(i + 1) % n]
        if recomputed != expected_next:
            return False

    return True

# Ring Transaction Menu Function

def createRingTransaction():
    """
    Anonymous transaction using a ring signature.
    Sender signs as 'one of N' users — receiver and amount are public,
    but the actual signer is hidden within the ring.
    """
    userlist = loadFile(USERS)
    # only active non-system users can form a ring
    eligible = [u for u in userlist if u.get("active") and u["username"] not in SYSTEM_ACCOUNTS]

    if len(eligible) < 3:
        print("Need at least 3 active users in the system for a ring transaction.")
        return

    signer = input("Enter your username: ").strip()
    if not verifyUser(signer) or signer in SYSTEM_ACCOUNTS:
        print("Invalid user.")
        return

    signer_data = next((u for u in userlist if u["username"] == signer), None)
    if not signer_data or not signer_data.get("active"):
        print("User is inactive.")
        return

    receiver = input("Enter receiver username: ").strip()
    if not verifyUser(receiver) or receiver in SYSTEM_ACCOUNTS:
        print("Invalid receiver.")
        return

    receiver_data = next((u for u in userlist if u["username"] == receiver), None)
    if not receiver_data or not receiver_data.get("active"):
        print("Receiver is inactive.")
        return

    try:
        amt = float(input("Enter amount($): "))
    except ValueError:
        print("Invalid amount.")
        return
    if amt <= 0:
        print("Amount must be greater than 0.")
        return
    if float(signer_data["balance"]) < amt:
        print("Insufficient funds.")
        return

    # pick 2 random decoys from eligible users (excluding signer)
    decoys = [u["username"] for u in eligible if u["username"] != signer]
    if len(decoys) < 2:
        print("Not enough other users to form a ring (need at least 2 decoys).")
        return
    ring_members = random.sample(decoys, 2)
    # insert signer at a random position so position doesn't reveal identity
    insert_pos = random.randint(0, len(ring_members))
    ring_members.insert(insert_pos, signer)

    print(f"\nRing members (shuffled): {ring_members}")
    print("(Your position in the ring is hidden)")

    # deduct sender, credit receiver
    for u in userlist:
        if u["username"] == signer:
            u["balance"] = float(u["balance"]) - amt
        elif u["username"] == receiver:
            u["balance"] = float(u["balance"]) + amt
    saveFile(USERS, userlist)

    # build tx payload (no signature field yet - sign over this)
    prev_hash = getPrevHash()
    txn_id = generateTransactionID(prev_hash, "RING_ANONYMOUS", receiver, amt)
    tx_data = {
        "transaction_id": txn_id,
        "prev_transaction_id": prev_hash,
        "sender": "RING_ANONYMOUS",
        "amount": amt,
        "reciever": receiver,
        "timestamp": datetime.now().isoformat()
    }

    # check for double-spend before signing — key image is unique per (signer, tx_id)
    key_image = computeKeyImage(signer, txn_id)
    if key_image is None:
        print("Could not compute key image.")
        return
    if isDoubleSpend(key_image):
        print("Double-spend detected. This key image has already been used. Transaction rejected.")
        return

    # sign the transaction as one of the ring members (auto_sign=False → will prompt password)
    signer_idx = ring_members.index(signer)
    ring_sig = signRingTransaction(ring_members, tx_data, signer_idx, signer, auto_sign=False)
    if ring_sig is None:
        print("Ring signing failed.")
        return

    tx_data["signature"] = ring_sig
    tx_data["sig_type"] = "Ring"

    transList = loadFile(BLOCKCHAIN)
    transList.append(tx_data)
    saveFile(BLOCKCHAIN, transList)

    # record key image privately — only real signer tracked, decoys are not
    images = loadFile(KEY_IMAGES_FILE)
    images.append(key_image)
    saveFile(KEY_IMAGES_FILE, images)

    print(f"Ring transaction complete: ${amt:.2f} sent anonymously to {receiver}.")

def main():
    loadFile(USERS)
    loadFile(BLOCKCHAIN)
    loadFile(MIX_POOL_FILE)
    loadFile(KEY_IMAGES_FILE)
    generateMissingKeys()
    setMissingPasswords()
    checkExpiredPools()

    while True:
        print("\n--- Blockchain Menu ---")
        print("1. Create User")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Create Transaction")
        print("5. Status Check")
        print("6. Check Balance")
        print("7. View Public Key")
        print("8. Verify Transaction")
        print("9. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            createUser()
        elif choice == "2":
            deposit()
        elif choice == "3":
            withdraw()
        elif choice == "4":
            createTransaction()
        elif choice == "5":
            user_status()
        elif choice == "6":
            checkBalance()
        elif choice == "7":
            viewPublicKey()
        elif choice == "8":
            verifyTransaction()
        elif choice == "9":
            print("Goodbye!")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
