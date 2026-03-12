# Secure IIoT Communication Framework

A **Secure Industrial Internet of Things (IIoT) Communication Framework** that demonstrates secure sensor data transmission from industrial devices to the cloud with **cryptographic protection, blockchain-based verification, and attack detection**.

The system simulates an industrial monitoring environment where sensor data from an **ESP32 device** is securely transmitted to AWS cloud services and displayed on a real-time dashboard while detecting and blocking malicious activities.

**Live Dashboard:**  
https://main.d3n61mig0ws1i3.amplifyapp.com/

---

## Project Overview

This project demonstrates how industrial sensor data can be **securely transmitted, validated, stored, and monitored** using cloud computing and cybersecurity techniques.

The framework includes:

- Secure IoT device communication
- Cloud-based data processing
- Cryptographic security validation
- Attack detection and logging
- Blockchain-based verification
- Real-time monitoring dashboard

The system simulates a **secure industrial monitoring infrastructure**.

---

## Hardware Components

The demonstration setup uses an **ESP32 microcontroller** connected with the following sensors:

### BMP280 Sensor
Measures:
- Temperature
- Atmospheric pressure

### MQ-2 Gas Sensor
Detects:
- Smoke
- LPG
- Combustible gases

These sensors simulate **industrial environmental monitoring conditions**.

---

## System Architecture

Data Flow:

ESP32 → AWS IoT Core → AWS Lambda → DynamoDB → API Gateway → Web Dashboard

---

## Working Process

### ESP32 Device
- Collects data from BMP280 and MQ-2 sensors
- Encrypts data using **AES encryption**
- Generates **SHA-based digital signature**
- Sends secured data to **AWS IoT Core**

### AWS IoT Core
- Receives encrypted IoT device data
- Routes messages to AWS Lambda for processing

### AWS Lambda
- Verifies the digital signature
- Processes sensor data
- Stores validated data in **DynamoDB**

### DynamoDB
Stores:
- Sensor data
- Security logs
- Attack detection records

### API Gateway
Provides secure API endpoints for retrieving sensor data and security logs.

### Web Dashboard
The dashboard hosted through GitHub and AWS Amplify displays:

- Real-time sensor readings
- Attack detection alerts
- Security logs
- System monitoring information

---

## Security Features

### AES Encryption
Sensor data transmitted from the ESP32 is encrypted using **AES encryption** to protect confidentiality.

### SHA Digital Signature
A **SHA-based digital signature** ensures data integrity and verifies that the data has not been tampered with.

### Consortium Blockchain
A lightweight **consortium blockchain mechanism** is used to verify trusted communication events and maintain integrity across the system.

### Attack Detection System
The framework can detect malicious activities such as:

- Unauthorized API access
- Data tampering
- Suspicious network requests
- Replay attacks

### Automatic IP Blocking
When a malicious activity is detected:

- The event is logged
- The attacker IP address is blocked
- The attack details are stored in **DynamoDB SecurityLog table**

---

## Security Logs

All detected attacks are recorded in **DynamoDB SecurityLog** including:

- Attack type
- Source IP address
- Timestamp
- Detection status
- Action taken

These logs are displayed on the dashboard.

---

## Attack Simulation

For educational purposes, custom **attack scripts** were developed to simulate cybersecurity threats such as:

- Data tampering
- Unauthorized API requests
- Malicious payload injection

These simulations demonstrate how the system **detects, logs, and blocks attacks in real time**.

---

## AWS Services Used

- AWS IoT Core
- AWS Lambda
- AWS DynamoDB
- AWS API Gateway
- AWS IAM
- AWS Amplify

---

## Technologies Used

### Hardware
- ESP32
- BMP280 Sensor
- MQ-2 Gas Sensor

### Cloud Services
- AWS IoT Core
- AWS Lambda
- DynamoDB
- API Gateway
- AWS Amplify

### Security Technologies
- AES Encryption
- SHA Hashing
- Digital Signatures
- Consortium Blockchain

### Frontend
- HTML
- CSS
- JavaScript

---

## Educational Purpose

This project was developed for **educational and research purposes** to demonstrate:

- Secure IIoT communication
- Industrial sensor monitoring
- Cloud-based IoT architecture
- Cyber attack detection and prevention

All attack simulations were performed in a **controlled environment for educational use only**.

---

## Author

Developed as part of a **Cyber Security and Industrial IoT research demonstration project**.

---

## License

This project is intended for **educational and research purposes**.
