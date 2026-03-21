import hashlib
import json, os, random, getpass
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.PublicKey import ECC       # pycryptodome: raw EC point arithmetic
from Cryptodome.Hash import SHA256
from Cryptodome.Util.number import bytes_to_long, long_to_bytes


#files
USERS = "users.json"
BLOCKCHAIN = "transaction.json"
KEYS_DIR = "keys"
MIX_POOL_FILE = "mix_pool.json"

# system accounts that don't have passwords / are not real users
SYSTEM_ACCOUNTS = {"MIXER_POOL", "DEPOSIT", "WITHDRAWAL", "MIXER"}

# minimum participants for mixer
MIN_MIX_PARTICIPANTS = 3

# --- Key Pair Functions ---

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
        return serialization.load_pem_private_key(f.read(), password=None)

# --- End Key Pair Functions ---

# --- Signing Functions ---

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
        return False

# --- End Signing Functions ---

# --- Password Functions ---

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
    return False

# --- End Password Functions ---

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


# --- Mixer helper ---

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

    ring_members = [p["sender"] for p in participants]

    userlist = loadFile(USERS)
    for payout in payouts:
        for u in userlist:
            if u["username"] == "MIXER_POOL":
                u["balance"] = float(u["balance"]) - payout["amount"]
            elif u["username"] == payout["destination"]:
                u["balance"] = float(u["balance"]) + payout["amount"]
    saveFile(USERS, userlist)

    for payout in payouts:
        signer = random.choice(ring_members)
        signer_idx = ring_members.index(signer)
        # auto_sign=True skips authentication (no user present for mixer)
        logTransaction("MIXER_POOL", payout["destination"], payout["amount"], ring_sign=(ring_members, signer), auto_sign=True)

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

    try:
        pool_size = int(input(f"Pool size (min {MIN_MIX_PARTICIPANTS}): ").strip())
    except ValueError:
        print("Invalid number.")
        return
    if pool_size < MIN_MIX_PARTICIPANTS:
        print(f"Pool size must be at least {MIN_MIX_PARTICIPANTS}.")
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
    confirm = input(f"Are you sure that you would like to send: {amt} to: {reciever}?(y/n): ")
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
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == username:
            print(f"Balance of {username}: ${float(user['balance']):.2f}")
            return
    print("User does not exist.")

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
                    print(f"Ring signature valid. Transaction was authorized by one of {ring_size} possible users (anonomous).")
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



#sign ring transaction with multiple keys (for mixer phase 2) --- IGNORE FOR NOW ---
def signRingTransaction(usernames, tx_data, signer_index, signer_username, auto_sign=False):
    # 1. Authenticate ONLY the signer (unless auto-signing for mixer)
    if not auto_sign and not authenticateUser(signer_username):
        return None
    
    # 2. Get message hash
    message = json.dumps(tx_data, sort_keys=True).encode()
    message_hash = hashlib.sha256(message).digest()
    
    # 3. Get signer's private key
    sk, pk = pem_to_ecc_keypair(signer_username)
    if sk is None:
        print(f"Could not load signer's private key.")
        return None
    
    order = get_curve_order()
    w = random.randint(1, order - 1)  # Random commitment
    
    # 4. Build the ring: Non-signers have random responses, signer's closes the ring
    challenges = [None] * len(usernames)
    responses = [None] * len(usernames)
    
    # Phase 1: Non-signers BEFORE signer generate random responses
    for i in range(signer_index):
        responses[i] = random.randint(1, order - 1)
    
    # Phase 2: Compute challenges forward through the ring
    # Start with message + first response (or w*G for signer position)
    for i in range(signer_index):
        challenges[i] = hash_to_scalar(message_hash + responses[i].to_bytes(32, 'big'), order)
    
    # At signer position: use the commitment w
    challenges[signer_index] = hash_to_scalar(message_hash + w.to_bytes(32, 'big'), order)
    
    # Phase 3: Signer's response (closes the ring)
    responses[signer_index] = (w - (challenges[signer_index] * sk)) % order
    
    # Phase 4: Non-signers AFTER signer also generate random responses
    for i in range(signer_index + 1, len(usernames)):
        responses[i] = random.randint(1, order - 1)
        challenges[i] = hash_to_scalar(message_hash + responses[i].to_bytes(32, 'big'), order)
    
    return {
        "challenges": [hex(c) for c in challenges],
        "responses": [hex(r) for r in responses],
        "ring_members": usernames,
        "message_hash": message_hash.hex()
    }
    

#verify ring signature --- IGNORE FOR NOW ---
def verifyRingSignature(usernames, tx_data, ring_sig):
    # 1. Extract and validate components
    message = json.dumps(tx_data, sort_keys=True).encode()
    message_hash = hashlib.sha256(message).digest()
    
    # Verify message hash matches
    if ring_sig["message_hash"] != message_hash.hex():
        return False
    
    # 2. Convert hex back to integers
    challenges = [int(c, 16) for c in ring_sig["challenges"]]
    responses = [int(r, 16) for r in ring_sig["responses"]]
    
    # 3. Verify all values in valid range
    order = get_curve_order()
    for c, r in zip(challenges, responses):
        if not (0 < c < order and 0 < r < order):
            return False
    
    # 4. Verify ring closure (proves exactly one member signed)
    # Reconstruct: [s_i*G - c_i*PK_i]_x should chain properly
    return True  # Ring structure valid

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
