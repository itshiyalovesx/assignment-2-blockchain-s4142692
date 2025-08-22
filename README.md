#  Blockchain Technology Assignment 2 - Crypto Data- s4142692  #
## Source Codes: From Google AI Gemini, and made few alterations to it ##


This python code implements the core concepts of a blockchain, while featuring cryptographic wallets, a Proof-of-Work (PoW) mining algorithm, and a robust double-spending prevention mechanism using the Unspent Transaction Output (UTXO) model.

It runs as a Command-Line Interface (CLI), allowing users to simulate blockchain operations locally, including creating wallets, sending transactions, and mining new blocks.

✨ Features ✨

Cryptographic Wallets: Securely generates public/private key pairs using the ecdsa library

Transactions & Signatures: Transactions are cryptographically signed by the sender's private key to ensure authenticity

UTXO Model: A secure way to track unspent outputs, which are used as inputs for new transactions, effectively preventing double-spending

Proof-of-Work (PoW): Miners compete to solve a computational puzzle to add new blocks to the chain, ensuring network security

Chain Integrity: Blocks are linked by their hash and the hash of the previous block, creating a tamper-proof chain

Data Persistence: The blockchain is saved to and loaded from disk using the pickle module, so the state is maintained between sessions

Simple CLI: An interactive command-line interface, which makes it easy to experiment with the blockchain's functionality

📦 Prerequisites
This project requires Python 3.6 or higher & the only external dependency is the ecdsa library

🚀 Installation & Setup

Clone the repository:
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

Install dependencies:
pip install ecdsa

💻 Usage

Run the script directly from your terminal:
python blockchain_cli.py

You will be presented with an interactive menu to perform various actions:
"

--- Blockchain CLI ---
1. Create New Wallet
2. Add Transaction
3. Mine Block
4. View Blockchain
5. View Pending Transactions
6. Check Balance
7. Exit
Enter your choice:
"

🧑‍💻 Code Structure

Wallet: Manages the creation of public/private key pairs and handles transaction signing and verification.

Transaction: Defines the structure of a transaction ( inputs, outputs, and cryptographic signatures).

UTXO: Represents an unspent transaction output, a core component for fund management and double-spend prevention.

Block: The fundamental building block of the blockchain, containing a list of transactions, a timestamp, and a hash.

Blockchain: The main class that orchestrates the entire system. It manages the chain, handles transactions, and implements the mining process.
