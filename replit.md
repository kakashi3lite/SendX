# One-View Secrets

## Overview

One-View Secrets is a zero-knowledge secret sharing application built with FastAPI and client-side encryption. The application allows users to securely share sensitive information through one-time links that automatically destroy the secret after viewing. All encryption and decryption happens in the user's browser using the WebCrypto API, ensuring the server never has access to plaintext data. The system implements true zero-knowledge architecture where encryption keys are embedded in URL fragments and never transmitted to the server.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes (August 20, 2025)

Enhanced UX following comprehensive design principles:
- Improved microcopy with calm, factual tone ("One view only", "Create one-view link")
- Enhanced security warnings emphasizing URL fragment protection
- Better toast notifications for user feedback
- Character counter with visual warnings at 90% capacity
- Streamlined TTL options (10 minutes, 1 hour, 1 day, 7 days)
- Improved error handling with specific user-friendly messages
- Enhanced security headers following OWASP guidelines

## System Architecture

### Frontend Architecture
- **Client-side Encryption**: Uses WebCrypto API with AES-GCM 256-bit encryption
- **Zero-knowledge Design**: All encryption/decryption happens in the browser before any server communication
- **URL Fragment Key Storage**: Encryption keys are stored in URL hash fragments (#) which browsers never send to servers
- **Progressive Web App**: Responsive design with Bootstrap 5 for cross-device compatibility
- **Security-first UI**: Implements CSP headers and HTTPS-only design patterns

### Backend Architecture  
- **FastAPI Framework**: Modern Python web framework with automatic API documentation
- **Rate Limiting**: SlowAPI middleware for DDoS protection and abuse prevention
- **Security Middleware**: Custom middleware for security headers (HSTS, CSP, Referrer-Policy)
- **Stateless Design**: Server only stores encrypted ciphertext, never plaintext or keys
- **RESTful API**: Clean endpoint design for secret creation and retrieval

### Data Storage Strategy
- **Encrypted-only Storage**: Server stores only AES-GCM encrypted ciphertext
- **One-time Retrieval**: Atomic get-and-delete operations to ensure true one-time access
- **No Key Storage**: Encryption keys never touch server storage or logs
- **Minimal Data Retention**: Secrets are immediately destroyed after viewing

### Security Architecture
- **Defense in Depth**: Multiple security layers including rate limiting, CSP, and HSTS
- **Timing Attack Prevention**: Constant-time comparisons using HMAC or secrets.compare_digest
- **CSRF Protection**: Stateless design eliminates traditional CSRF vulnerabilities  
- **XSS Mitigation**: Strict Content Security Policy with nonce-based script execution

### Authentication & Authorization
- **No Traditional Auth**: Stateless design with cryptographic proof of access via URL fragments
- **Bearer Token Pattern**: HTTP Bearer security for API endpoints
- **IP-based Rate Limiting**: Per-IP restrictions to prevent brute force attacks
- **Cryptographic Access Control**: Access granted through possession of encryption key

## External Dependencies

### Core Framework Dependencies
- **FastAPI**: ASGI web framework for Python APIs
- **Jinja2Templates**: Server-side templating for HTML rendering
- **Starlette**: ASGI framework components (middleware, responses)

### Security & Rate Limiting
- **SlowAPI**: Rate limiting middleware with Redis backend support
- **python-secrets**: Cryptographically strong random number generation
- **hmac/hashlib**: HMAC-based authentication and secure hashing

### Frontend Libraries
- **Bootstrap 5**: CSS framework via CDN (cdn.jsdelivr.net)
- **WebCrypto API**: Browser-native cryptography (no external crypto libraries)

### Development & Deployment
- **Uvicorn**: ASGI server for FastAPI applications
- **Static File Serving**: FastAPI's built-in static file middleware

### Optional Integrations
- **Redis**: Recommended for atomic GETDEL operations and distributed rate limiting
- **QR Code Generation**: Python qrcode library for shareable link QR codes
- **Database**: Designed to work with any key-value store (current implementation uses in-memory storage)

The architecture prioritizes security and privacy through client-side encryption, ensuring that even if the server is compromised, user secrets remain protected. The zero-knowledge design means the application cannot be compelled to reveal user data since it never has access to it in the first place.