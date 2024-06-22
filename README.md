# Secure Banking System

This Secure Banking System is a C-based application designed to simulate the operations of a banking system, featuring secure communication between bank servers and ATM clients. It supports user registration, login, and basic banking transactions, ensuring data integrity and confidentiality through encrypted communications.

## Features

- User registration and authentication.
- Secure communication using symmetric encryption and message authentication codes (MAC).
- Support for multiple ATM clients connecting to a single bank server.
- Basic banking transactions: deposits, withdrawals, and balance inquiries (to be implemented).

## Getting Started

### Prerequisites

- IDE compatible with C
- Network access between the server and clients (if running on separate machines).

### Installation

1. Clone the repository:
https://github.com/abdueee/817-project.git

2. Navigate to the project directory:
cd secure-banking-system

### Running the Application

1. Start the bank server:
-cp out/production/secure-banking-system BankServer

2. In separate terminal windows, start each ATM client:
-cp out/production/secure-banking-system ATMClient


## Usage

After starting the bank server and ATM clients:

1. Follow the prompts in the ATM client application to register or log in.
2. Once logged in, follow the on-screen instructions to perform banking transactions.

## Contributing

Contributions to the Secure Banking System project are welcome. Please follow these steps:

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -am 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a pull request.
