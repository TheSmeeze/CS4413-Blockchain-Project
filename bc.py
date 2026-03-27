import hashlib
import json, os, random, getpass
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.PublicKey import ECC
from Cryptodome.Hash import SHA256
from Cryptodome.Util.number import bytes_to_long, long_to_bytes

#files
USERS = "users.json"
BLOCKCHAIN = "transaction.json"
KEYS_DIR = "keys"
MIX_POOL_FILE = "mix_pool.json"

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
    with open(USERS, "r"):
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
    logTransaction("DEPOSIT", username, amt)
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
    """Settle a mix pool: Phase 1 logged already at join time. Phase 2: shuffle → MIXER_POOL → destinations."""
    participants = pool["participants"]
    payouts = [{"destination": p["destination"], "amount": p["amount"]} for p in participants]
    random.shuffle(payouts)

    userlist = loadFile(USERS)
    for payout in payouts:
        for u in userlist:
            if u["username"] == "MIXER_POOL":
                u["balance"] = float(u["balance"]) - payout["amount"]
            elif u["username"] == payout["destination"]:
                u["balance"] = float(u["balance"]) + payout["amount"]
    saveFile(USERS, userlist)

    for payout in payouts:
        # mixer settles anonymously - no individual signature, sender is MIXER_POOL
        logTransaction("MIXER_POOL", payout["destination"], payout["amount"])

    print(f"Mix complete. {len(participants)} transactions settled anonymously.")

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

    from datetime import timedelta
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

    # auto-settle if pool is full
    if len(pool["participants"]) >= pool["pool_size"]:
        pass
    else:
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
    print("  2. Mixer (anonymous)")
    tx_type = input("  Select type: ").strip()

    if tx_type == "2":
        runMixer()
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
        tx_data_without_sig = {k: v for k, v in tx_data.items() if k != "signature"}
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
            #tx_data = {k: v for k, v in tx.items() if k != "signature"}
            tx_data = {k: v for k, v in tx.items() if k not in ["signature", "sig_type"]}
            
            if sig_type == "Ring":
                if isinstance(signature, dict) and verifyRingSignature(signature.get("ring_members", []),tx_data, signature):
                    ring_size = len(signature.get("ring_members", []))
                    print(f"Ring signature valid. Transaction was authorized by one of {ring_size} possible users (anonymous).")
                else:
                    print("Ring signature INVALID. Transaction may have been tampered with.")                                                                         
            
            else:                                                                             
                if verifySignature(sender, tx_data, signature):                                                                       
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

def get_curve_order():
    """SECP256K1 curve order (Bitcoin standard)"""
    return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def pem_to_ecc_keypair(username):
    """Load PEM private key → (secret_key_int, public_point_tuple)"""
    private_key = loadPrivateKey(username)  # Existing function
    private_value = private_key.private_numbers().private_value
    x = private_key.private_numbers().public_numbers.x
    y = private_key.private_numbers().public_numbers.y
    return private_value, (x, y)

#converts ECC point to bytes for hashing/signing
def ecc_to_bytes(ecc_point):
    return ecc_point.export_key(format='SEC1')

#converts bytes back to ECC point for verification
def bytes_to_ecc(bytes_data, curve='NIST256p'):
    key = ECC.construct(curve=curve, x=0, y=0)  # dummy point to get curve
    return ECC.construct(curve=curve, point_x=int.from_bytes(bytes_data[:32], 'big'))

#performs scaler multiplication on ECC point (for ring signature math)
def ecc_scalar_mult(scalar, point):
    return point * scalar

def get_public_keys_from_ring(usernames):
    """Get list of public key points for all users in ring."""
    userlist = loadFile(USERS)
    pub_points = []
    
    for username in usernames:
        user_data = next((u for u in userlist if u["username"] == username), None)
        if not user_data:
            return None
        
        pub_pem = user_data.get("public_key")
        if not pub_pem:
            return None
        
        try:
            pub_key = serialization.load_pem_public_key(pub_pem.encode())
            x = pub_key.public_numbers().x
            y = pub_key.public_numbers().y
            pub_points.append((x, y))
        except Exception:
            return None
    
    return pub_points

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

def _pub_point(username):
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

def _hash_point(x, y):
    """Hash an EC point (x,y) to a scalar — used to chain ring challenges."""
    data = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
    return bytes_to_long(hashlib.sha256(data).digest())

def signRingTransaction(signer_username, ring_usernames, tx_data):
    """
    Ring signature (LSAG)
    - Real signer uses private key to close the ring.
    - Decoys use random responses.
    - Chain always starts at index 0 so verify can replay it the same way.

    Returns a dict with: c0, responses, ring_members, key_image
    """
    order = get_curve_order()
    n = len(ring_usernames)
    signer_idx = ring_usernames.index(signer_username)

    # load real signer's private key scalar
    sk, _ = pem_to_ecc_keypair(signer_username)

    # message hash - what we're committing to
    message = json.dumps(tx_data, sort_keys=True).encode()
    msg_hash = hashlib.sha256(message).digest()

    # key image: I = sk * H(PK) - deterministic per signer, used for double-spend detection
    px, py = _pub_point(signer_username)
    key_image_scalar = (_hash_point(px, py) * sk) % order

    # random commitment scalar for the real signer
    alpha = random.randint(1, order - 1)

    # random responses for all positions (signer's will be overwritten to close the ring)
    responses = [random.randint(1, order - 1) for _ in range(n)]

    # Step 1: compute challenge at signer_idx from alpha
    # c[signer_idx] = H(msg || alpha)
    seed_data = msg_hash + alpha.to_bytes(32, 'big')
    c_signer = bytes_to_long(hashlib.sha256(seed_data).digest()) % order

    # Step 2: propagate challenges forward from signer_idx+1 to signer_idx (wrapping)
    challenges = [0] * n
    challenges[signer_idx] = c_signer

    for step in range(1, n):
        i     = (signer_idx + step) % n
        prev  = (signer_idx + step - 1) % n
        px_prev, py_prev = _pub_point(ring_usernames[prev])
        chain_data = (msg_hash
                      + responses[prev].to_bytes(32, 'big')
                      + challenges[prev].to_bytes(32, 'big')
                      + px_prev.to_bytes(32, 'big')
                      + py_prev.to_bytes(32, 'big'))
        challenges[i] = bytes_to_long(hashlib.sha256(chain_data).digest()) % order

    # Step 3: close the ring - solve for signer's response
    # The chain will arrive back at signer_idx with challenges[signer_idx].
    # We need: verify starting from c0 and chaining through to reproduce c[signer_idx].
    # So set: s_signer = alpha - c_signer * sk  (mod order)
    responses[signer_idx] = (alpha - c_signer * sk) % order

    # c0 is challenges[0] — verification always starts here
    return {
        "c0": hex(challenges[0]),
        "responses": [hex(r) for r in responses],
        "ring_members": ring_usernames,
        "key_image": hex(key_image_scalar)
    }

def verifyRingSignature(ring_usernames, tx_data, ring_sig):
    """
    Replay the ring chain from c0 through all N members.
    Valid if the chain produces the same c0 at the end.
    """
    order = get_curve_order()
    message = json.dumps(tx_data, sort_keys=True).encode()
    msg_hash = hashlib.sha256(message).digest()

    responses = [int(r, 16) for r in ring_sig["responses"]]
    c0 = int(ring_sig["c0"], 16)
    n = len(ring_usernames)

    c = c0
    for i in range(n):
        px_i, py_i = _pub_point(ring_usernames[i])
        if px_i is None:
            return False
        chain_data = (msg_hash
                      + responses[i].to_bytes(32, 'big')
                      + c.to_bytes(32, 'big')
                      + px_i.to_bytes(32, 'big')
                      + py_i.to_bytes(32, 'big'))
        c = bytes_to_long(hashlib.sha256(chain_data).digest()) % order

    # ring closes if we arrive back at c0
    return c == c0

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

    if not authenticateUser(signer):
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

    # sign the transaction as one of the ring members
    ring_sig = signRingTransaction(signer, ring_members, tx_data)
    if ring_sig is None:
        print("Ring signing failed.")
        return

    tx_data["signature"] = ring_sig
    tx_data["sig_type"] = "Ring"

    transList = loadFile(BLOCKCHAIN)
    transList.append(tx_data)
    saveFile(BLOCKCHAIN, transList)
    print(f"Ring transaction complete: ${amt:.2f} sent anonymously to {receiver}.")

# End Ring Signature Functions

def main():
    loadFile(USERS)
    loadFile(BLOCKCHAIN)
    loadFile(MIX_POOL_FILE)
    generateMissingKeys()
    setMissingPasswords()
    checkExpiredPools()

    while True:
        print("\n--- Blockchain Menu ---")
        print("1. Create User")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Create Transaction")
        print("5. Ring Transaction (anonymous)")
        print("6. Status Check")
        print("7. Check Balance")
        print("8. View Public Key")
        print("9. Verify Transaction")
        print("10. Exit")
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
            createRingTransaction()
        elif choice == "6":
            user_status()
        elif choice == "7":
            checkBalance()
        elif choice == "8":
            viewPublicKey()
        elif choice == "9":
            verifyTransaction()
        elif choice == "10":
            print("Goodbye!")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
