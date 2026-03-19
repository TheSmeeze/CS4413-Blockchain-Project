import hashlib
import json, os, random
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

#files
USERS = "users.json"
BLOCKCHAIN = "transaction.json"
KEYS_DIR = "keys"
MIX_POOL_FILE = "mix_pool.json"  # pending mix requests waiting to be processed

# minimum participants before the mixer will execute
MIN_MIX_PARTICIPANTS = 3

# --- Key Pair Functions ---

def generateKeyPair(username):
    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256K1())
    # save private key to keys/<username>.pem
    priv_path = os.path.join(KEYS_DIR, f"{username}.pem")
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # return public key as PEM string (stored in users.json)
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

# --- End Key Pair Functions ---

#verifies existence of a user
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


#create user
def createUser():
    name = input("Enter username: ")
    if verifyUser(name) == True:
        print("User already exists")
        return
    pub_pem = generateKeyPair(name)
    new_user = {
        "username": name,
        "balance": 0,
        "active": True, #added status check
        "creation-Timestamp": datetime.now().isoformat(), # added creation timestamp
        "public_key": pub_pem
    }
    userlist = loadFile(USERS)
    userlist.append(new_user)
    saveFile(USERS, userlist)
    print(f"User '{name}' created with balance $0. Key pair generated.")
    print(f"Private key saved to: {os.path.join(KEYS_DIR, name + '.pem')}")
    deposit_now = input("Would you like to make an initial deposit? (y/n): ").strip()
    if deposit_now == "y":
        deposit(name)


def deposit(username=None):
    if username is None:
        username = input("Enter username: ").strip()
    if not verifyUser(username):
        print("\nUser does not exist.")
        return
    userlist = loadFile(USERS)
    
    #check if user is active before moving forward
    for user in userlist:
        if user["username"] == username:
            if user["active"] != True:
                print("User is inactive")
                return

    try:
        amt = float(input("Enter deposit amount($): "))
    except ValueError:
        print("Invalid amount.")
        return
    if amt <= 0:
        print("Deposit amount must be greater than 0.")
        return
    
    user["balance"] = float(user["balance"]) + amt
    saveFile(USERS, userlist)
    prev_hash = getPrevHash()
    txn_id = generateTransactionID(prev_hash, "DEPOSIT", username, amt)
    new_transaction = {
        "transaction_id": txn_id,
        "prev_transaction_id": prev_hash,
        "sender": "DEPOSIT",
        "amount": amt,
        "reciever": username,
        "timestamp": datetime.now().isoformat()
    }
    transList = loadFile(BLOCKCHAIN)
    transList.append(new_transaction)
    saveFile(BLOCKCHAIN, transList)
    print(f"Deposited ${amt:.2f}.")
    print(f"Updated balance of {user['username']}: ${user['balance']:.2f}")
    return


def withdraw():
    username = input("Enter username: ").strip()
    if not verifyUser(username):
        print("\nUser does not exist.")
        return
    
    userlist = loadFile(USERS)
    
    #check if user active before moving forward
    for user in userlist:
        if user["username"] == username:
            if user["active"] != True:
                print("User is inactive.")
                return

    try:
        amt = float(input("Enter withdrawal amount($): "))
    except ValueError:
        print("Invalid amount.")
        return
    if amt <= 0:
        print("Withdrawal amount must be greater than 0.")
        return

    for user in userlist:
        if user["username"] == username:
            if float(user["balance"]) < amt:
                print("Insufficient funds")
                return
            user["balance"] = float(user["balance"]) - amt
            saveFile(USERS, userlist)
            prev_hash = getPrevHash()
            txn_id = generateTransactionID(prev_hash, username, "WITHDRAWAL", amt)
            new_transaction = {
                "transaction_id": txn_id,
                "prev_transaction_id": prev_hash,
                "sender": username,
                "amount": amt,
                "reciever": "WITHDRAWAL",
                "timestamp": datetime.now().isoformat()
            }
            transList = loadFile(BLOCKCHAIN)
            transList.append(new_transaction)
            saveFile(BLOCKCHAIN, transList)
            print(f"Withdrew ${amt:.2f}.")
            print(f"Updated balance of {user['username']}: ${user['balance']:.2f}")
            return


#creates transaction item
def createTransaction():
    sender = input("Enter sender username: ").strip()
    if not verifyUser(sender):
        print("\nUser does not exist.")
        return
    
    userlist = loadFile(USERS)
    
    #check if sender active before moving forward
    for user in userlist:
        if user["username"] == sender:
            if user["active"] != True:
                print("User is inactive.\n")
                print("Transaction cancelled.\n")
                return
            
    reciever = input("Enter reciever username: ").strip()
    if not verifyUser(reciever):
        print("\nUser does not exist.")
        return
    
    #check if reciever active before moving forward
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
        # build signable payload (no signature field yet)
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
        # verify immediately to confirm integrity
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

#status func check status of user, and has to abillity to update status
def user_status():
    username = input("Enter username to check status: ").strip()
    userlist = loadFile(USERS)

    for user in userlist:
        if user["username"] == username:
            if user["active"]:
                print(f"User: {username} status is Active.")
                decision = input("Would you like to Deactivate the user?(y/n): ").strip()
                if decision == "y":
                    user["active"] = False
                    saveFile(USERS, userlist)
                    print(f"User: {username} is now Inactive.")

            else:
                print(f"User: {username} status is Inactive.")
                decision = input("Would you like to Activate the user?(y/n): ").strip()
                if decision == "y":
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
            if not signature:
                print("This transaction has no signature (deposit/withdrawal).")
                return
            tx_data = {k: v for k, v in tx.items() if k != "signature"}
            if verifySignature(sender, tx_data, signature):
                print(f"Signature valid. Transaction was authorized by '{sender}'.")
            else:
                print("Signature INVALID. Transaction may have been tampered with.")
            return
    print("Transaction not found.")

def viewPublicKey():
    username = input("Enter username: ").strip()
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == username:
            pub = user.get("public_key", None)
            if pub:
                print(f"\nPublic key for '{username}':\n{pub}")
            else:
                print("No public key found for this user.")
            return
    print("User does not exist.")

# --- Mixer Functions ---
# A mixer (CoinJoin-style) breaks the link between sender and receiver.
# Users submit mix requests into a shared pool. Once MIN_MIX_PARTICIPANTS
# requests are pooled, the mixer shuffles the outputs and settles all
# transfers in random order — making it impossible to trace who paid whom.

def submitMixRequest():
    sender = input("Enter your username: ").strip()
    if not verifyUser(sender):
        print("User does not exist.")
        return

    userlist = loadFile(USERS)

    # check sender is active
    for user in userlist:
        if user["username"] == sender:
            if not user["active"]:
                print("User is inactive.")
                return

    receiver = input("Enter destination username: ").strip()
    if not verifyUser(receiver):
        print("User does not exist.")
        return

    if sender == receiver:
        print("Sender and receiver cannot be the same.")
        return

    try:
        amt = float(input("Enter amount($): "))
    except ValueError:
        print("Invalid amount.")
        return
    if amt <= 0:
        print("Amount must be greater than 0.")
        return

    # check sender has enough balance
    for user in userlist:
        if user["username"] == sender:
            if float(user["balance"]) < amt:
                print("Insufficient funds.")
                return
            # lock funds immediately so they can't be double-spent while waiting in pool
            user["balance"] = float(user["balance"]) - amt
            break
    saveFile(USERS, userlist)

    # add request to the mix pool
    pool = loadFile(MIX_POOL_FILE)
    pool.append({
        "sender": sender,
        "receiver": receiver,
        "amount": amt,
        "submitted_at": datetime.now().isoformat()
    })
    saveFile(MIX_POOL_FILE, pool)
    print(f"Mix request submitted. Pool size: {len(pool)}/{MIN_MIX_PARTICIPANTS}.")

    # auto-process if minimum participants reached
    if len(pool) >= MIN_MIX_PARTICIPANTS:
        print("Minimum participants reached. Processing mix...")
        processMix()

def processMix():
    pool = loadFile(MIX_POOL_FILE)

    if len(pool) < MIN_MIX_PARTICIPANTS:
        print(f"Not enough participants. Need {MIN_MIX_PARTICIPANTS}, have {len(pool)}.")
        return

    # shuffle the pool order — this is the core privacy step.
    # after shuffling, the order of outputs no longer matches the order of inputs,
    # so an observer cannot link sender[i] to receiver[i].
    random.shuffle(pool)

    userlist = loadFile(USERS)
    transList = loadFile(BLOCKCHAIN)

    for entry in pool:
        # credit the receiver
        for user in userlist:
            if user["username"] == entry["receiver"]:
                user["balance"] = float(user["balance"]) + entry["amount"]
                break

        # record as a mixed transaction — sender field is anonymized
        prev_hash = getPrevHash()
        txn_id = generateTransactionID(prev_hash, "MIXER", entry["receiver"], entry["amount"])
        tx = {
            "transaction_id": txn_id,
            "prev_transaction_id": prev_hash,
            "sender": "MIXER",          # real sender is hidden — only the mixer knows
            "amount": entry["amount"],
            "reciever": entry["receiver"],
            "timestamp": datetime.now().isoformat(),
            "type": "mixed"             # tag so mixed txs are identifiable in the ledger
        }
        transList.append(tx)

    saveFile(USERS, userlist)
    saveFile(BLOCKCHAIN, transList)

    # clear the pool after processing
    saveFile(MIX_POOL_FILE, [])
    print(f"Mix complete. {len(pool)} transactions settled anonymously.")

def viewMixPool():
    # shows pending requests without revealing sender-receiver pairs to others
    pool = loadFile(MIX_POOL_FILE)
    if not pool:
        print("Mix pool is empty.")
        return
    print(f"\n--- Mix Pool ({len(pool)}/{MIN_MIX_PARTICIPANTS} participants) ---")
    for i, entry in enumerate(pool, 1):
        print(f"{i}. Amount: ${entry['amount']:.2f} | Submitted: {entry['submitted_at']}")
    print("(Sender/receiver details are not shown to preserve privacy)")

# --- End Mixer Functions ---

def deleteUser():
    username = input("Enter username to delete: ").strip()
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == username:
            confirm = input(f"Are you sure you want to delete '{username}'? (y/n): ").strip().lower()
            if confirm == "y":
                userlist.remove(user)
                saveFile(USERS, userlist)
                print(f"User '{username}' has been deleted.")
            else:
                print("Deletion cancelled.")
            return
    print("User does not exist.")

def main():
    #inits files (always needed to be done at begining of main to create files)
    loadFile(USERS)
    loadFile(BLOCKCHAIN)

    while True:
        print("\n--- Blockchain Menu ---")
        print("1. Create User")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Create Transaction")
        print("5. Status Check")
        print("6. Check Balance")
        print("7. Delete User")
        print("8. View Public Key")
        print("9. Verify Transaction")
        print("10. Submit Mix Request")
        print("11. View Mix Pool")
        print("12. Exit")
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
            deleteUser()
        elif choice == "8":
            viewPublicKey()
        elif choice == "9":
            verifyTransaction()
        elif choice == "10":
            submitMixRequest()
        elif choice == "11":
            viewMixPool()
        elif choice == "12":
            print("Goodbye!")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
