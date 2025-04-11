# FIDO2 Frequent Devices Authentication System

A modern client-server application for FIDO2 device authentication, allowing users to register and authenticate trusted devices securely using two different authentication methods: WebCrypto and WebAuthn.

## Project Structure

The project consists of two main components:

### 1. Backend Server (`/backend`)

A Node.js Express server that provides dual authentication APIs:
- Challenge generation for both WebCrypto and WebAuthn
- Device registration with support for both authentication types
- Signature verification with type-specific validation
- Persistent storage of device credentials in JSON files

### 2. Frontend Client (`/frontend`)

A modular browser-based client application that:
- Implements a common interface for authentication clients
- Provides two concrete implementations:
  - **WebCrypto Client**: Uses the Web Cryptography API for key generation and challenge signing
  - **WebAuthn Client**: Uses the WebAuthn standard for passwordless authentication with biometrics or security keys
- Generates unique device IDs
- Creates and securely stores cryptographic keys
- Signs challenges with the appropriate method
- Offers a user-friendly interface for the authentication flow

## Features

### Core Features
- **Dual Authentication Methods**: Choose between WebCrypto (software-based) or WebAuthn (hardware-backed)
- **Device ID Generation**: Create unique identifiers for devices
- **Key Pair Generation**: Generate cryptographic key pairs for secure authentication
- **Challenge-Response Authentication**: Secure authentication using cryptographic signatures
- **Secure Key Storage**: Encrypted storage of private keys in the browser (WebCrypto) or secure element (WebAuthn)

### Security Features
- **Type-specific Authentication**: Server validates signatures based on the authentication type
- **Persistent Credential Storage**: Server maintains a database of registered devices
- **Counter Verification**: WebAuthn implementation supports signature counter verification (configurable)
- **Encrypted Private Keys**: WebCrypto implementation encrypts private keys before storage

### User Experience
- **Modern UI**: Clean interface with real-time status updates
- **Authentication Type Selection**: Easily switch between WebCrypto and WebAuthn
- **Detailed Logging**: View the authentication process in real-time

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)
- Modern browser with WebCrypto and WebAuthn support

### Installation

1. Clone the repository
2. Install dependencies for each component:

```bash
# Install backend dependencies
cd backend
npm install

# Install web-server dependencies
cd ../web-server
npm install
```

### Running with Docker

The easiest way to run the application is using Docker:

```bash
# Build and start the containers
docker-compose up
```

Or run individual services:

```bash
# Run backend server
docker run -p 3000:3000 fido2-backend

# Run web server
docker run -p 8080:8080 fido2-web-server
```

### Running Manually

1. Start the backend server:
```bash
cd backend
npm start
```

2. In a separate terminal, start the web server:
```bash
cd web-server
npm start
```

3. Access the application at http://localhost:8080

## API Endpoints

### Backend Server (http://localhost:3000)

- `GET /api/challenge?deviceId=<deviceId>` - Generate a new challenge
- `POST /api/register` - Register a device with its public key
- `POST /api/verify` - Verify a challenge signature

## Security Considerations

- This is a demonstration project and should be enhanced with additional security measures for production use
- In a production environment, device keys and challenges should be stored in a secure database
- Additional authentication factors should be considered for high-security applications

## License

This project is licensed under the MIT License - see the LICENSE file for details.
