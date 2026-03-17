import hashlib
import json, os
from datetime import datetime
#files
USERS = "users.json"
BLOCKCHAIN = "transaction.json"

#verifys existence of a user
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
    new_user = {
        "username": name,
        "balance": 0,
        "active": True, #added status check
        "creation-Timestamp": datetime.now().isoformat() # added creation timestamp
    }
    userlist = loadFile(USERS)
    userlist.append(new_user)
    saveFile(USERS, userlist)
    print(f"User '{name}' created with balance $0.")
    deposit_now = input("Would you like to make an initial deposit? (y/n): ").strip()
    if deposit_now == "y":
        deposit(name)


def deposit():
    username = input("Enter username: ").strip()
    if not verifyUser(username):
        print("\nUser does not exist")
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
        print("Invalid amount")
        return
    if amt <= 0:
        print("Deposit amount must be greater than 0")
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
        print("\nUser does not exist")
        return
    
    userlist = loadFile(USERS)
    
    #check if user active before moving forward
    for user in userlist:
        if user["username"] == username:
            if user["active"] != True:
                print("User is inactive")
                return

    try:
        amt = float(input("Enter withdrawal amount($): "))
    except ValueError:
        print("Invalid amount")
        return
    if amt <= 0:
        print("Withdrawal amount must be greater than 0")
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
        print("\nUser does not exist")
        return
    
    userlist = loadFile(USERS)
    
    #check if sender active before moving forward
    for user in userlist:
        if user["username"] == sender:
            if user["active"] != True:
                print("User is inactive\n")
                print("Transaction cancelled.\n")
                return
            
    reciever = input("Enter reciever username: ").strip()
    if not verifyUser(reciever):
        print("\nUser does not exist")
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
        print("Invalid amount")
        return
    if amt <= 0:
        print("Amount must be greater than 0")
        return
    confirm = input(f"Are you sure that you would like to send: {amt} to: {reciever}?(y/n)")
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
        new_transaction = {
            "transaction_id": txn_id,
            "prev_transaction_id": prev_hash,
            "sender": sender,
            "amount": amt,
            "reciever": reciever,
            "timestamp": datetime.now().isoformat()
        }
        transList = loadFile(BLOCKCHAIN)
        transList.append(new_transaction)
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
                print(f"User: {username} status is Active")
                decision = input("Would you like to Deactivate the user?(y/n)").strip()
                if decision == "y":
                    user["active"] = False
                    saveFile(USERS, userlist)
                    print(f"User: {username} is now Inactive")

            else:
                print(f"User: {username} status is Inactive")
                decision = input("Would you like to Activate the user?(y/n)").strip()
                if decision == "y":
                    user["active"] = True
                    saveFile(USERS, userlist)
                    print(f"User: {username} is now Active")
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
        print("8. Exit")
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
            print("Goodbye!")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
