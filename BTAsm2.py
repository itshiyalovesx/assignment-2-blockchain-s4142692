# --- Standard Library Imports ---
import hashlib  # To create secure one-way hashes (e.g., SHA-256 for block and transaction hashes)
import json     # For serializing Python dictionaries into a JSON string format(essential for consistent hashing)
import time     # Provides time-related functions
import os       # For file and directory management (e.g., creating a directory for the blockchain data)
import glob     # Finds all the file pathnames matching a specified pattern, used here to load all saved block files
import pickle   # A module for serializing and deserializing Python objects (To save and load entire block objects to and from files)
from datetime import datetime  
from uuid import uuid4       # Generates a random, universally unique identifier (UUID) for transactions, ensuring each one has a unique ID.

# --- Third-Party Cryptographic Library ---
import ecdsa #for the security of digital signatures in transactions
#(Ensures that only the rightful owner of a private key can authorize a transaction)

# --- Cryptographic Utilities ---

class Wallet: #Manages public/private key pairs for users
    
    def __init__(self):
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        self.address = self.public_key.to_string().hex()

    def sign_transaction(self, transaction_data):  #Signs a transaction with the wallet's private key
        return self.private_key.sign(transaction_data.encode()).hex()

    def verify_signature(self, public_key, signature, transaction_data):#Verifies a transaction's signature using the sender's public key

        try:
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
            return vk.verify(bytes.fromhex(signature), transaction_data.encode())
        except ecdsa.BadSignatureError:
            return False

# --- Transaction and UTXO Management ---

class Transaction: #Represents a transaction in the blockchain, uses existing UTXOs as inputs to fund the transfer

    def __init__(self, sender_address, recipient_address, amount, input_utxos=None):
        # Generates a unique identifier for the transaction using a UUID
        self.id = str(uuid4())
        # The address of the sender. This must match the address in the input UTXOs
        self.sender_address = sender_address
        # The address of the recipient
        self.recipient_address = recipient_address
        # The amount of cryptocurrency to transfer
        self.amount = amount
        # A list of UTXOs (Unspent Transaction Outputs) being consumed to fund this transaction
        self.input_utxos = input_utxos or [] 
        # The cryptographic signature of the transaction, created by the sender's private key
        self.signature = None
        # Timestamp the transaction with the current date and time
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def __repr__(self): #Returns a concise, human-readable representation of the transaction
        return f"Transaction(ID: {self.id}, From: {self.sender_address[:8]}..., To: {self.recipient_address[:8]}..., Amount: {self.amount})"

    def to_dict(self): #Converts the transaction object to a dictionary for JSON serialization, important for for creating a consistent hash of the transaction data
        return {
            'tx_id': self.id,
            'sender_address': self.sender_address,
            'recipient_address': self.recipient_address,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'inputs': self.input_utxos,
            'outputs': [],  
            'signature': self.signature
        }

    def get_hash(self): #Generates a SHA-256 hash of the transaction data

        transaction_data_str = json.dumps(self.to_dict(), sort_keys=True) #Ensures the data is always in the same order to  produce a consistent hash
        # The data is encoded to bytes before being hashed, as required by the `hashlib` library
        return hashlib.sha256(transaction_data_str.encode()).hexdigest()

class UTXO: #Represents an unspent transaction output A UTXO is a record of value that an address can spend
            #It's the fundamental unit of value in this blockchain model
    
    def __init__(self, tx_id, output_index, amount, recipient_address):
        self.tx_id = tx_id                # The ID of the transaction that created this UTXO
        self.output_index = output_index  # The index (position) of this output within its parent transaction
        self.amount = amount              # The amount of value stored in this UTXO
        self.recipient_address = recipient_address # The public address that is the owner of this UTXO

    def to_dict(self): #Converts the UTXO object to a dictionary for serialization
        return {
            "tx_id": self.tx_id,
            "output_index": self.output_index,
            "amount": self.amount,
            "recipient_address": self.recipient_address
        }

    def __repr__(self):  #Returns a concise, human-readable representation of the UTXO
        return f"UTXO(tx_id: {self.tx_id[:8]}..., amount: {self.amount})"


# --- Block and Blockchain ---

class Block: # A single block in the blockchain

    def __init__(self, index, previous_hash, transactions, nonce=0):
        self.index = index
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        # Calculates the initial hash when the block is created
        self.hash = self.calculate_hash()

    def calculate_hash(self): #Calculates block hash using dictionary representation
        # Creates a dictionary of the block's data.
        block_dict = {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions], # Serializes each transaction within the block
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }
        # Converts the dictionary to a sorted JSON string for consistent hashing
        block_string = json.dumps(block_dict, sort_keys=True)
        # Computes the SHA-256 hash.
        return hashlib.sha256(block_string.encode()).hexdigest()

    def __repr__(self):
        # Human-readable representation of the block
        return f"Block(Index: {self.index}, Hash: {self.hash[:8]}..., Prev Hash: {self.previous_hash[:8]}..., Transactions: {len(self.transactions)})"

class Blockchain: #The main blockchain class
    
    def __init__(self):
        
        self.pending_transactions = []   # A list to hold transactions waiting to be mined
        self.utxo_set = {}    # A dictionary to store all unspent transaction outputs
        self.difficulty = 4 # The number of leading zeros required for a valid block hash
        self.chain = []   # The list of blocks that make up the blockchain
        self.block_data_dir = "blockchain_data" # The directory where blocks are saved to disk
        
        # Create data directory if it doesn't exist
        if not os.path.exists(self.block_data_dir):
            os.makedirs(self.block_data_dir)

        # Load any existing blocks from storage.
        self.load_chain()

        # Create the first block (the genesis block) if the chain is empty
        if not self.chain:
            self.create_genesis_block()

    def create_genesis_block(self): #Creates the first block in the chain
        # The genesis block has an index of 0, a previous hash of "0", and no transactions
        genesis_block = Block(0, "0", [])
        self.chain.append(genesis_block)
        self.save_block(genesis_block)
        print("✅ Genesis Block created.")

    def save_block(self, block): #Persists a block to a file
        # Creates a file path using the block's index
        filepath = os.path.join(self.block_data_dir, f"block_{block.index}.pickle")
        # Uses the pickle library to serialize the block object and save it to the file
        with open(filepath, "wb") as f:
            pickle.dump(block, f)

    def load_chain(self): #Loads the blockchain from persistent storage
        # Finds all files that match the pattern "block_*.pickle"
        # It's sorted to ensure the blocks are loaded in the correct order
        block_files = sorted(glob.glob(os.path.join(self.block_data_dir, "block_*.pickle")), 
                             key=lambda x: int(os.path.basename(x).split('_')[1].split('.')[0]))
        self.chain = []
        if block_files:
            for filepath in block_files:
                # Loads the pickled block object from each file
                with open(filepath, "rb") as f:
                    block = pickle.load(f)
                    self.chain.append(block)
            print(f"Loaded {len(self.chain)} blocks from storage.")

    def get_last_block(self): #Returns the last block in the chain
        return self.chain[-1]

    def add_transaction(self, transaction):  #Adds a new transaction to the pool of pending transactions

        if not self.validate_transaction(transaction):   # First, validate the transaction before adding it
            print("❌ Invalid transaction. Rejected.")
            return False
        self.pending_transactions.append(transaction)
        print(f"➕ Transaction added to mempool: {transaction.id}")
        return True

    def mine_block(self, miner_address): #Mines a new block using the Proof-of-Work algorithm
        print("⛏️ Starting mining process...")

        # Creates a special coinbase transaction to reward the miner
        coinbase_tx = Transaction(sender_address="blockchain_reward", recipient_address=miner_address, amount=100.0)
        
        # The block will contain the coinbase transaction plus all pending transactions
        block_transactions = [coinbase_tx] + self.pending_transactions
        
        last_block = self.get_last_block()
        new_block = Block(
            index=last_block.index + 1,
            previous_hash=last_block.hash,
            transactions=block_transactions,
        )

        # Proof-of-Work: Iterates the nonce until the block's hash meets the difficulty target
        while new_block.hash[:self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.hash = new_block.calculate_hash()

        # Updates the UTXO set based on the transactions in the newly mined block
        for tx in block_transactions:
            # For non-coinbase transactions, remove the spent UTXOs from the set
            if tx.sender_address != "blockchain_reward":
                for utxo_in in tx.input_utxos:
                    self.utxo_set.pop((utxo_in['tx_id'], utxo_in['output_index']), None)
            
            # Creates a new UTXO for the transaction's recipient and add it to the set
            utxo_out = UTXO(tx.id, 0, tx.amount, tx.recipient_address)
            self.utxo_set[(utxo_out.tx_id, utxo_out.output_index)] = utxo_out

        # Clears the pending transactions because they are now in a block
        self.pending_transactions = []
        self.chain.append(new_block)
        self.save_block(new_block)
        print(f"✅ Block #{new_block.index} mined successfully with nonce: {new_block.nonce}")
        return new_block

    def validate_chain(self): #Validates the integrity of the entire blockchain
        # Iterates through the blocks, starting from the second block (index 1)
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # Checks if the block's hash is correct by recalculating it
            if current_block.hash != current_block.calculate_hash():
                print(f"❌ Block {current_block.index} hash is invalid!")
                return False

            # Check if the current block's previous hash points to the hash of the actual previous block
            if current_block.previous_hash != previous_block.hash:
                print(f"❌ Block {current_block.index} previous hash link is broken!")
                return False
        
        print("✅ Blockchain integrity check passed.")
        return True

    def validate_transaction(self, transaction): #Validates a transaction, including double-spend prevention
        wallet_manager = Wallet()

        if transaction.sender_address != "blockchain_reward" and not wallet_manager.verify_signature( # Checks for signature validity
            transaction.sender_address, transaction.signature, json.dumps(transaction.to_dict(), sort_keys=True)
        ):
            print("❌ Transaction signature is invalid.")
            return False

        # Double-Spend Prevention using UTXO model
        total_input_amount = 0
        consumed_utxos = set()
        for utxo_in_dict in transaction.input_utxos:
            utxo_key = (utxo_in_dict['tx_id'], utxo_in_dict['output_index'])
            
            # Checks if the UTXO exists in the global set
            if utxo_key not in self.utxo_set:
                print("❌ Double-spend attempt detected or UTXO not found.")
                return False

            # Checks if this specific UTXO is already being spent in this same transaction
            if utxo_key in consumed_utxos:
                print("❌ Transaction attempts to spend the same UTXO multiple times.")
                return False
            
            consumed_utxos.add(utxo_key)
            total_input_amount += self.utxo_set[utxo_key].amount
        
        # Ensures the sender has enough funds (the sum of input UTXOs) for the transaction
        if total_input_amount < transaction.amount:
            print("❌ Insufficient funds in UTXOs to cover transaction amount.")
            return False
        
        return True
    
    def get_balance(self, address): #Calculates the balance for a given address based on the UTXO set
        balance = 0
        for utxo_key, utxo in self.utxo_set.items(): # Iterates through all UTXOs in the global set
            if utxo.recipient_address == address: # If the UTXO belongs to the specified address, add its amount to the balance
                balance += utxo.amount
        return balance

# --- Main CLI ---

def main():
    blockchain = Blockchain()
    wallets = {}

    while True:
        print("\n--- Blockchain CLI ---")
        print("1. Create New Wallet")
        print("2. Add Transaction")
        print("3. Mine Block")
        print("4. View Blockchain")
        print("5. View Pending Transactions")
        print("6. Check Balance")
        print("7. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            wallet_name = input("Enter wallet name: ")
            wallets[wallet_name] = Wallet()
            print(f"🎉 New wallet '{wallet_name}' created. Address: {wallets[wallet_name].address}")
        
        elif choice == '2':
            if len(wallets) < 2:
                print("❌ You need at least two wallets to create a transaction.")
                continue

            sender_name = input("Enter sender's wallet name: ")
            recipient_name = input("Enter recipient's wallet name: ")
            amount = float(input("Enter amount: "))

            if sender_name not in wallets or recipient_name not in wallets:
                print("❌ Invalid wallet name.")
                continue

            sender_wallet = wallets[sender_name]
            recipient_wallet = wallets[recipient_name]

            # Find UTXOs for the sender
            sender_utxos = [utxo.to_dict() for utxo in blockchain.utxo_set.values() if utxo.recipient_address == sender_wallet.address]
            total_available = sum(utxo['amount'] for utxo in sender_utxos)

            if total_available < amount:
                print("❌ Insufficient funds. Available:", total_available)
                continue

            # Create the transaction
            tx = Transaction(sender_wallet.address, recipient_wallet.address, amount, input_utxos=sender_utxos)
            
            # Sign the transaction
            tx.signature = sender_wallet.sign_transaction(json.dumps(tx.to_dict(), sort_keys=True))
            
            blockchain.add_transaction(tx)

        elif choice == '3':
            miner_name = input("Enter miner's wallet name: ")
            if miner_name not in wallets:
                print("❌ Invalid wallet name.")
                continue
            
            blockchain.mine_block(wallets[miner_name].address)
        
        elif choice == '4':
            print("\n--- Blockchain Contents ---")
            for block in blockchain.chain:
                print(f"Block #{block.index}")
                print(f"  Timestamp: {block.timestamp}")
                print(f"  Hash: {block.hash}")
                print(f"  Previous Hash: {block.previous_hash}")
                print(f"  Nonce: {block.nonce}")
                print("  Transactions:")
                for tx in block.transactions:
                    print(f"    - {tx}")
            print("-" * 20)
        
        elif choice == '5':
            print("\n--- Pending Transactions ---")
            if not blockchain.pending_transactions:
                print("No pending transactions.")
            for tx in blockchain.pending_transactions:
                print(f"  - {tx}")
            print("-" * 20)

        elif choice == '6':
            address_or_name = input("Enter wallet name or address: ")
            if address_or_name in wallets:
                address_to_check = wallets[address_or_name].address
            else:
                address_to_check = address_or_name
            
            balance = blockchain.get_balance(address_to_check)
            print(f"💰 Balance for {address_to_check[:8]}... is: {balance}")

        elif choice == '7':
            print("Exiting.")
            break

if __name__ == "__main__":
    main()