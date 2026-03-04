# barebones transaction system
# followinbg the g4g explanation of transaction system
# improvements to be added after barebones function

#adam's version / work
import json, os

#files
USERS = "users.json"
BLOCKCHAIN = "bc.json"

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
    user_file = loadFile(USERS)
    if verifyUser(name) == True:
        print("User already exists")
        return
    amt = input("Enter a starting amt: ")
    new_user = {
        "username": name,
        "balance": amt
    }
    userlist = loadFile(USERS)
    userlist.append(new_user)
    saveFile(USERS, userlist)


#creates transaction item -- for testing 
#DOES NOT VERIFY SENDER HAS ENOUGH, 
#DOES NOT REMOVE AMT FROM SENDER BALANCE, DOES NOT ENSURE "AMT" > 0, OR CHECKS AMT IS A NUMBER
def createTransaction():
    sender = input("Enter sender username: ")
    if verifyUser(sender) == False:
        print("User does not exist")
        return
    reciever = input("Enter reciever username: ")
    if verifyUser(reciever) == False:
        print("User does not exist")
        return
    chain_file = loadFile(BLOCKCHAIN)
    #entered as a string (for now)
    amt = input("Enter an amt($): ")
    new_transaction = {
        "sender": sender,
        "amount": amt,
        "reciever": reciever
    }
    transList = loadFile(BLOCKCHAIN)
    transList.append(new_transaction)
    saveFile(BLOCKCHAIN, transList)

def main():
    #inits files (always needed to be done at begining of main to create files)
    loadFile(USERS)
    loadFile(BLOCKCHAIN)
    
    #testing users 
    # seems to fully work 
    # (made 2 distinct users, and caught a new user trying an already used username) - adam)
    #createUser()
    #createUser()
    #createUser()

   # createTransaction()
   # createTransaction()
    

if __name__ == "__main__":
    main()