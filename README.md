# FIDO2 Frequent Devices Authentication System

A modern client-server application for FIDO2 device authentication, allowing users to register and authenticate trusted devices securely.

## Project Structure

The project consists of three main components:

### 1. Backend Server (`/backend`)

A Node.js Express server that provides the FIDO2 authentication API:
- Challenge generation
- Device registration
- Signature verification

### 2. Frontend Client (`/frontend`)

A browser-based client application that:
- Generates device IDs
- Creates and stores cryptographic keys
- Signs challenges
- Provides a user interface for the authentication flow

### 3. Web Server (`/web-server`)

A simple Express server that:
- Serves the static frontend files
- Proxies API requests to the backend server

## Features

- **Device ID Generation**: Create unique identifiers for devices
- **Key Pair Generation**: Generate cryptographic key pairs for secure authentication
- **Challenge-Response Authentication**: Secure authentication using cryptographic signatures
- **Secure Key Storage**: Encrypted storage of private keys in the browser

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)

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
