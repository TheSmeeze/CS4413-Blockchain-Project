# CS4413-Blockchain-Project
In this project we are studying blockchain technology and will develop a prototype for privacy-preserved transactions using mixer networks and efficient ring signatures.

Offers standard transaction system requirements, user creation, deposits, withdrawls, balence checks, etc.

Currently offers registered users to engage in 2 logged transaction types:
  1.  Direct Transaction - uses ECDSA signatures and lacks anoninomity
  2.  Private Transaction - uses ring signatures and mixers to anonomize sender to        reciever link however it relys on at least 3 users being active and trying to       complete similar transactions within the same timeframe.

Transactions can be verified in both transaction types by supplying the transactionID of the desired transaction. 

Terminal based UI is used for navigating and interacting with the prototype efficently on low spec systems.
