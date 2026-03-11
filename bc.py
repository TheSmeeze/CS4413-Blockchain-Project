# barebones transaction system
# followinbg the g4g explanation of transaction system
# improvements to be added after barebones function

#adam's version / work
import json, os

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


#create user
def createUser():
    name = input("Enter username: ")
    if verifyUser(name) == True:
        print("User already exists")
        return
    new_user = {
        "username": name,
        "balance": 0
    }
    userlist = loadFile(USERS)
    userlist.append(new_user)
    saveFile(USERS, userlist)
    print(f"User '{name}' created with balance $0.")
    deposit_now = input("Would you like to make an initial deposit? (y/n): ").strip().lower()
    if deposit_now == "y":
        deposit(name)


# turzabasak's version / work
def deposit(username=None):
    if username is None:
        username = input("Enter username: ")
    if not verifyUser(username):
        print("User does not exist")
        return
    try:
        amt = float(input("Enter deposit amount($): "))
    except ValueError:
        print("Invalid amount")
        return
    if amt <= 0:
        print("Deposit amount must be greater than 0")
        return
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == username:
            user["balance"] = float(user["balance"]) + amt
            saveFile(USERS, userlist)
            print(f"Deposited ${amt:.2f}. New balance: ${user['balance']:.2f}")
            return


def withdraw(username=None):
    if username is None:
        username = input("Enter username: ")
    if not verifyUser(username):
        print("User does not exist")
        return
    try:
        amt = float(input("Enter withdrawal amount($): "))
    except ValueError:
        print("Invalid amount")
        return
    if amt <= 0:
        print("Withdrawal amount must be greater than 0")
        return
    userlist = loadFile(USERS)
    for user in userlist:
        if user["username"] == username:
            if float(user["balance"]) < amt:
                print("Insufficient funds")
                return
            user["balance"] = float(user["balance"]) - amt
            saveFile(USERS, userlist)
            new_transaction = {
                "sender": username,
                "amount": amt,
                "reciever": "WITHDRAWAL"
            }
            transList = loadFile(BLOCKCHAIN)
            transList.append(new_transaction)
            saveFile(BLOCKCHAIN, transList)
            print(f"Withdrew ${amt:.2f}. New balance: ${user['balance']:.2f}")
            return


#creates transaction item
def createTransaction():
    sender = input("Enter sender username: ")
    if not verifyUser(sender):
        print("User does not exist")
        return
    reciever = input("Enter reciever username: ")
    if not verifyUser(reciever):
        print("User does not exist")
        return
    try:
        amt = float(input("Enter an amt($): "))
    except ValueError:
        print("Invalid amount")
        return
    if amt <= 0:
        print("Amount must be greater than 0")
        return
    userlist = loadFile(USERS)
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
    new_transaction = {
        "sender": sender,
        "amount": amt,
        "reciever": reciever
    }
    transList = loadFile(BLOCKCHAIN)
    transList.append(new_transaction)
    saveFile(BLOCKCHAIN, transList)
    print(f"Transaction complete: ${amt:.2f} sent from {sender} to {reciever}.")

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
        print("5. Exit")
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
            print("Goodbye!")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()
