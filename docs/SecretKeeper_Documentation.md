# SecretKeeper Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Getting Started](#getting-started)
3. [Architecture Documentation](#architecture-documentation)
4. [API Documentation](#api-documentation)
5. [Deployment Guide](#deployment-guide)
6. [Security Considerations](#security-considerations)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)
8. [User Guide](#user-guide)

---

## Project Overview

### What is SecretKeeper?

SecretKeeper (also known as One-View Secrets) is a secure, zero-knowledge secret sharing platform that enables users to share sensitive information via one-time access links. The application is designed with security as its core principle, implementing end-to-end encryption and a "view once, then destroy" paradigm.

### Key Features

- **Zero-Knowledge Architecture**: All encryption/decryption happens client-side, ensuring the server never sees your unencrypted data.
- **One-Time Access**: Secrets can only be viewed once before being permanently deleted.
- **Configurable Expiration**: Set time-to-live (TTL) ranging from 10 minutes to 7 days.
- **No Account Required**: Share secrets without creating accounts or saving user data.
- **QR Code Generation**: Easy sharing via automatically generated QR codes.
- **Advanced Security Features**: Protection against various attacks, including AI-based threats.
- **Mobile-Friendly Interface**: Responsive design works across devices.

### Value Proposition

SecretKeeper provides a secure solution for sharing sensitive information like:
- Passwords and credentials
- Private keys and tokens
- Personal information
- Confidential business data
- Temporary access codes

Unlike email or messaging apps, SecretKeeper ensures that:
1. Data is encrypted end-to-end
2. Information exists only for a limited time
3. Content is accessible exactly once
4. No traces remain after viewing

### Technology Stack

#### Backend
- **FastAPI**: High-performance Python web framework
- **Starlette**: ASGI framework for middleware components
- **Pydantic**: Data validation and settings management
- **SlowAPI**: Rate limiting to prevent abuse
- **Uvicorn**: ASGI server for production deployment

#### Frontend
- **Modern JavaScript**: ES6+ with WebCrypto API for client-side encryption
- **Bootstrap 5**: Responsive UI framework
- **CSS3**: Custom styling and animations

#### Storage
- **Pluggable Storage Backend**: Modular design supporting different storage options
  - In-memory storage (development)
  - Key-Value stores (production)
  - Future support for Redis (atomic operations)

### Security Model

SecretKeeper implements a true zero-knowledge architecture:

1. **Client-Side Encryption**: All encryption and decryption happens in the user's browser using the Web Cryptography API.
2. **URL Fragment-Based Key Management**: Encryption keys are stored in URL fragments (after the # symbol), which browsers never send to servers.
3. **One-Time Access Pattern**: Once a secret is viewed, it's permanently deleted from storage.
4. **Automatic Expiration**: All secrets have a mandatory time-to-live, after which they're automatically purged.
5. **AI Security Protection**: Advanced protection against AI-based threats, including prompt injection attacks.

---

## Getting Started

### System Requirements

#### Server Requirements
- Python 3.11 or higher
- 1GB RAM minimum (2GB+ recommended for production)
- 1 CPU core minimum (2+ recommended for production)
- 1GB disk space

#### Supported Client Environments
- **Desktop Browsers**: Chrome 80+, Firefox 75+, Safari 13.1+, Edge 80+
- **Mobile Browsers**: iOS Safari 13.4+, Android Chrome 80+

### Installation

#### Using Python Package
```bash
# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# Install from PyPI
pip install secretkeeper

# Run the application
secretkeeper run
```

#### From Source Code
```bash
# Clone the repository
git clone https://github.com/yourorganization/secretkeeper.git
cd secretkeeper

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python -m uvicorn secretkeeper.main:app --host 0.0.0.0 --port 8000
```

#### Using Docker
```bash
# Pull the image
docker pull yourorganization/secretkeeper:latest

# Run the container
docker run -d -p 8000:8000 --name secretkeeper yourorganization/secretkeeper:latest
```

### Configuration

SecretKeeper uses environment variables for configuration:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `STORAGE_BACKEND` | Storage backend ("memory", "kv", or "redis") | `memory` | No |
| `HMAC_KEY` | Key for generating secret IDs | Random (on startup) | No |
| `MAX_CONTENT_SIZE` | Maximum request body size in bytes | `200000` | No |
| `REDIS_URL` | Redis connection URL (if using Redis backend) | None | Only for Redis backend |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` | No |
| `ALLOWED_HOSTS` | Comma-separated list of allowed hosts | `*` | No |
| `CORS_ORIGINS` | Comma-separated list of allowed origins for CORS | `*` | No |

Create a `.env` file in the project root with your configuration:

```
STORAGE_BACKEND=redis
REDIS_URL=redis://localhost:6379/0
HMAC_KEY=your-secret-key-here
ALLOWED_HOSTS=secretkeeper.example.com
CORS_ORIGINS=https://example.com
```

### Quick Start Guide

1. **Install and run the application** following the instructions above
2. **Access the web interface** at `http://localhost:8000` (or your configured domain)
3. **Create your first secret**:
   - Enter your secret text
   - Select an expiration time
   - Click "Create one-view link"
4. **Share the generated link** with the recipient
5. **Recipient views the secret** by opening the link and clicking "Reveal Secret"
6. Once viewed, the secret is **permanently deleted**

---

## Architecture Documentation

### Component Overview

SecretKeeper consists of four primary components:

1. **Web Server (FastAPI)**: Handles HTTP requests, serves static files, and manages API endpoints
2. **Storage Backend**: Manages the persistence and retrieval of encrypted secrets
3. **Frontend Client**: Provides the user interface and handles client-side encryption/decryption
4. **Security Layer**: Implements various security measures across the application

![SecretKeeper Architecture Diagram](docs/images/architecture.png)

### Component Interactions

#### Secret Creation Flow
1. User enters secret text and selects TTL in browser
2. Browser generates random encryption key using WebCrypto API
3. Browser encrypts secret with AES-GCM
4. Encrypted data (never the plaintext) is sent to server via POST /api/create
5. Server generates unique ID and stores encrypted data with expiration
6. Server returns success response with secret ID
7. Browser constructs URL with secret ID and encryption key in fragment

#### Secret Retrieval Flow
1. Recipient opens URL containing secret ID and encryption key
2. Browser extracts secret ID from URL and key from fragment
3. Browser requests encrypted data from server via GET /api/secret/{id}
4. Server retrieves, marks as accessed, and deletes the secret
5. Server returns encrypted data to browser
6. Browser decrypts data using the key from URL fragment
7. Decrypted content is displayed to user

### Data Flow Diagram

```
┌─────────────┐     Encrypted     ┌──────────────┐
│             │───Secret+TTL─────▶│              │
│   Browser   │                   │   FastAPI    │
│  (Creator)  │◀──Secret ID───────│    Server    │
│             │                   │              │
└─────────────┘                   └──────────────┘
                                        │ │
                                        │ │
┌─────────────┐     Encrypted     ┌─────┘ └─────┐
│             │◀───Secret─────────│              │
│   Browser   │                   │   Storage    │
│ (Recipient) │───Secret ID─────▶│   Backend    │
│             │                   │              │
└─────────────┘                   └──────────────┘
```

### Security Architecture

SecretKeeper implements multiple security layers:

1. **Transport Security**:
   - HTTPS/TLS for all communications
   - Strict Transport Security (HSTS) headers
   - Content Security Policy (CSP)

2. **Zero-Knowledge Encryption**:
   - AES-GCM 256-bit encryption
   - Client-side key generation and encryption
   - URL fragment-based key transport

3. **Access Control**:
   - One-time access enforcement
   - Time-based automatic expiration
   - Rate limiting to prevent abuse

4. **AI Security Protection**:
   - Middleware detection of prompt injection attempts
   - Client-side validation of potentially harmful content
   - AI-specific security headers

### Storage Options

SecretKeeper supports multiple storage backends:

1. **Memory Storage**:
   - In-process memory storage
   - Suitable for development/testing
   - Not persistent across restarts
   - Simple but not scalable

2. **Key-Value Storage**:
   - Persistent storage using key-value databases
   - Suitable for production deployments
   - Configurable via `STORAGE_BACKEND` environment variable
   - Current implementation is a placeholder for specific KV solutions

3. **Redis Storage** (recommended for production):
   - Atomic operations for true one-time access
   - Built-in TTL support
   - High performance and reliability
   - Clustering support for scalability

---

## API Documentation

### API Endpoints

SecretKeeper exposes the following API endpoints:

#### Secret Management

##### `POST /api/create`
Creates a new secret with an expiration time.

**Request Body**:
```json
{
  "ciphertext": "string",  // Base64-encoded encrypted data
  "ttl": 24.0              // Time-to-live in hours (0.1 to 168)
}
```

**Response**:
```json
{
  "success": true,
  "secret_id": "string",
  "expires_in_hours": 24.0
}
```

**Rate Limit**: 10 requests per minute per IP

##### `GET /api/secret/{secret_id}`
Retrieves and invalidates a secret. This is a one-time operation.

**Path Parameters**:
- `secret_id`: The unique identifier for the secret

**Response**:
```json
{
  "success": true,
  "ciphertext": "string"  // Base64-encoded encrypted data
}
```

**Rate Limit**: 20 requests per minute per IP

##### `GET /api/qr/{secret_id}`
Generates a QR code image for the given secret URL.

**Path Parameters**:
- `secret_id`: The unique identifier for the secret

**Response**: PNG image

**Rate Limit**: 5 requests per minute per IP

#### System Information

##### `GET /api/health`
Health check endpoint for monitoring systems.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-08-20T12:00:00Z"
}
```

### Authentication

SecretKeeper's API does not require authentication, as the security model is based on the secrecy of the URLs and the one-time access pattern.

### Rate Limiting

Rate limiting is implemented to prevent abuse:

| Endpoint | Rate Limit |
|----------|------------|
| `/` (index page) | 30 requests per minute per IP |
| `/view` (view page) | 30 requests per minute per IP |
| `/api/create` | 10 requests per minute per IP |
| `/api/secret/{id}` | 20 requests per minute per IP |
| `/api/qr/{id}` | 5 requests per minute per IP |

When rate limits are exceeded, the API returns a 429 (Too Many Requests) status code with a message indicating when the client can retry.

### Error Handling

API errors follow a consistent format:

```json
{
  "error": "Error Type",
  "message": "Human-readable error message"
}
```

Common error codes:

| Status Code | Error Type | Description |
|-------------|------------|-------------|
| 400 | Bad Request | Invalid input parameters |
| 404 | Not Found | Secret not found, expired, or already accessed |
| 413 | Payload Too Large | Request body exceeds size limits |
| 429 | Rate Limit Exceeded | Too many requests in a given time |
| 500 | Internal Server Error | Unexpected server error |

---

## Deployment Guide

### Development Environment Setup

1. **Prerequisites**:
   - Python 3.11+
   - Git
   - Docker (optional)
   - Redis (optional)

2. **Setup Steps**:
   ```bash
   # Clone the repository
   git clone https://github.com/yourorganization/secretkeeper.git
   cd secretkeeper
   
   # Create a virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install development dependencies
   pip install -r requirements-dev.txt
   
   # Install pre-commit hooks
   pre-commit install
   
   # Run in development mode
   uvicorn secretkeeper.main:app --reload
   ```

3. **Development Configuration**:
   Create a `.env.development` file:
   ```
   STORAGE_BACKEND=memory
   LOG_LEVEL=DEBUG
   ```

### Testing

1. **Running Tests**:
   ```bash
   # Run all tests
   pytest
   
   # Run with coverage
   pytest --cov=secretkeeper
   
   # Generate coverage report
   pytest --cov=secretkeeper --cov-report=html
   ```

2. **Test Types**:
   - **Unit Tests**: Test individual components in isolation
   - **Integration Tests**: Test component interactions
   - **End-to-End Tests**: Test full workflows
   - **Security Tests**: Verify security properties

3. **Manual Testing Checklist**:
   - Create and view secrets with different TTLs
   - Verify one-time access behavior
   - Test rate limiting functionality
   - Validate encryption/decryption workflows
   - Check mobile compatibility

### Production Deployment

#### Option 1: Docker Deployment

1. **Build the Docker Image**:
   ```bash
   docker build -t secretkeeper:latest .
   ```

2. **Run with Docker Compose**:
   Create a `docker-compose.yml`:
   ```yaml
   version: '3'
   services:
     web:
       image: secretkeeper:latest
       ports:
         - "8000:8000"
       environment:
         - STORAGE_BACKEND=redis
         - REDIS_URL=redis://redis:6379/0
         - ALLOWED_HOSTS=secretkeeper.example.com
         - CORS_ORIGINS=https://example.com
       depends_on:
         - redis
     redis:
       image: redis:alpine
       volumes:
         - redis_data:/data
   volumes:
     redis_data:
   ```

3. **Start the Services**:
   ```bash
   docker-compose up -d
   ```

#### Option 2: Traditional Deployment

1. **Set Up a Production Environment**:
   ```bash
   # Create a dedicated user
   sudo useradd -m secretkeeper
   sudo su - secretkeeper
   
   # Clone the repository
   git clone https://github.com/yourorganization/secretkeeper.git
   cd secretkeeper
   
   # Create a virtual environment
   python -m venv venv
   source venv/bin/activate
   
   # Install production dependencies
   pip install -r requirements.txt
   ```

2. **Configure the Application**:
   Create a `.env.production` file:
   ```
   STORAGE_BACKEND=redis
   REDIS_URL=redis://localhost:6379/0
   HMAC_KEY=your-very-secure-random-key
   ALLOWED_HOSTS=secretkeeper.example.com
   CORS_ORIGINS=https://example.com
   ```

3. **Set Up a Process Manager (Systemd)**:
   Create `/etc/systemd/system/secretkeeper.service`:
   ```
   [Unit]
   Description=SecretKeeper Service
   After=network.target
   
   [Service]
   User=secretkeeper
   Group=secretkeeper
   WorkingDirectory=/home/secretkeeper/secretkeeper
   Environment="PATH=/home/secretkeeper/secretkeeper/venv/bin"
   EnvironmentFile=/home/secretkeeper/secretkeeper/.env.production
   ExecStart=/home/secretkeeper/secretkeeper/venv/bin/uvicorn secretkeeper.main:app --host 0.0.0.0 --port 8000
   Restart=on-failure
   
   [Install]
   WantedBy=multi-user.target
   ```

4. **Enable and Start the Service**:
   ```bash
   sudo systemctl enable secretkeeper
   sudo systemctl start secretkeeper
   ```

#### Option 3: Cloud Deployment

1. **AWS Elastic Beanstalk**:
   - Create a `Procfile`:
     ```
     web: uvicorn secretkeeper.main:app --host 0.0.0.0 --port $PORT
     ```
   - Deploy using the EB CLI:
     ```bash
     eb init -p python-3.11 secretkeeper
     eb create production-environment
     ```

2. **Heroku**:
   - Create a `Procfile`:
     ```
     web: uvicorn secretkeeper.main:app --host 0.0.0.0 --port $PORT
     ```
   - Deploy using the Heroku CLI:
     ```bash
     heroku create secretkeeper
     git push heroku main
     ```

3. **Azure App Service**:
   - Create a `startup.txt`:
     ```
     gunicorn secretkeeper.main:app -k uvicorn.workers.UvicornWorker
     ```
   - Deploy using Azure CLI:
     ```bash
     az webapp up --name secretkeeper --resource-group myResourceGroup --runtime "PYTHON|3.11"
     ```

### Load Balancing and Scaling

For high-availability deployments:

1. **Horizontal Scaling**:
   - Deploy multiple application instances
   - Use a load balancer (NGINX, AWS ELB, etc.)
   - Ensure Redis is configured for clustering or sentinel

2. **Scaling Considerations**:
   - Redis should be scaled separately from the application
   - Use a CDN for static assets
   - Monitor resource usage and scale accordingly

3. **Sample NGINX Configuration**:
   ```nginx
   upstream secretkeeper {
       server 127.0.0.1:8001;
       server 127.0.0.1:8002;
       server 127.0.0.1:8003;
   }
   
   server {
       listen 80;
       server_name secretkeeper.example.com;
       
       location / {
           return 301 https://$host$request_uri;
       }
   }
   
   server {
       listen 443 ssl;
       server_name secretkeeper.example.com;
       
       ssl_certificate /etc/letsencrypt/live/secretkeeper.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/secretkeeper.example.com/privkey.pem;
       
       location / {
           proxy_pass http://secretkeeper;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

---

## Security Considerations

### Zero-Knowledge Encryption

SecretKeeper implements true zero-knowledge encryption:

1. **Encryption Algorithm**: AES-GCM with 256-bit keys
2. **Key Generation**: Cryptographically secure random keys generated client-side
3. **Key Transport**: Encryption keys are stored in URL fragments (after #), which browsers never send to servers
4. **Cipher Implementation**: WebCrypto API (browser native) for cryptographic operations

#### Technical Details

- **Key Generation**: `crypto.subtle.generateKey()`
- **Encryption**: `crypto.subtle.encrypt()` with AES-GCM
- **IV**: 12 bytes, randomly generated for each secret
- **Ciphertext Format**: Base64-encoded concatenation of IV + ciphertext

### One-Time Access Implementation

SecretKeeper ensures secrets can only be viewed once:

1. **Tombstone Pattern**: When a secret is accessed, it's marked as consumed
2. **Immediate Deletion**: After retrieval, the secret is removed from storage
3. **Race Condition Protection**: 
   - Memory backend uses atomic operations
   - Redis backend uses GETDEL for true atomicity (when available)
   - KV backend uses tombstone pattern with deletion

### AI Security Features

SecretKeeper includes advanced protection against AI-based threats:

1. **Prompt Injection Detection**:
   - Server-side middleware scans for prompt injection patterns
   - Client-side validation of inputs before submission
   - Detection of evasion techniques (base64 encoding, special characters)

2. **AI Security Headers**:
   - `X-LLM-Protection`: Instructs LLMs to block injection attempts
   - `LLM-Processing-Policy`: Prevents processing by AI systems
   - `LLM-Context-Policy`: Blocks use in AI training/context

3. **Content Sanitization**:
   - Validation of all user inputs
   - Blocking of patterns that might manipulate AI systems
   - Protection against data extraction via AI

### Security Headers

SecretKeeper implements comprehensive security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Enforce HTTPS |
| `Content-Security-Policy` | Various directives | Control resource loading |
| `Referrer-Policy` | `no-referrer` | Prevent leaking URL in referrer |
| `Cache-Control` | `no-store, no-cache, must-revalidate, private` | Prevent caching |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Permissions-Policy` | Various restrictions | Limit browser features |
| `X-LLM-Protection` | `1; mode=block` | Prevent AI manipulation |

### OWASP Compliance

SecretKeeper addresses the OWASP Top 10 vulnerabilities:

1. **Injection**: Input validation, parameterized queries
2. **Broken Authentication**: Not applicable (no auth system)
3. **Sensitive Data Exposure**: Zero-knowledge encryption
4. **XML External Entities**: Not using XML
5. **Broken Access Control**: One-time access enforcement
6. **Security Misconfiguration**: Secure default settings
7. **Cross-Site Scripting**: CSP, input validation
8. **Insecure Deserialization**: Type validation with Pydantic
9. **Using Components with Known Vulnerabilities**: Regular dependency updates
10. **Insufficient Logging & Monitoring**: Structured logging, monitoring endpoints

### Security Recommendations for Deployment

1. **Use TLS/SSL**: Always deploy behind HTTPS
2. **Secure Redis**: If using Redis:
   - Enable authentication
   - Disable dangerous commands
   - Use encryption in transit
3. **Regular Updates**: Keep dependencies up to date
4. **Firewalls**: Restrict access to production servers
5. **Monitoring**: Set up alerts for suspicious activities

---

## Monitoring and Maintenance

### Logging Configuration

SecretKeeper uses Python's standard logging module with structured JSON logs:

1. **Log Levels**:
   - `DEBUG`: Detailed debugging information
   - `INFO`: Confirmation of normal operation
   - `WARNING`: Indication of potential issues
   - `ERROR`: Error conditions that should be investigated
   - `CRITICAL`: Critical failures requiring immediate attention

2. **Configure Logging**:
   Set the `LOG_LEVEL` environment variable to control verbosity.

3. **Log Format**:
   Logs are output in JSON format with the following fields:
   - `timestamp`: ISO 8601 timestamp
   - `level`: Log level
   - `message`: Log message
   - `module`: Source module
   - Additional context fields as appropriate

### Monitoring Recommendations

1. **Health Checks**:
   - Use the `/api/health` endpoint for basic health monitoring
   - Configure uptime monitoring (Pingdom, UptimeRobot, etc.)

2. **Metrics to Track**:
   - Request rate and latency
   - Error rate and types
   - Storage usage and operations
   - Rate limit hits
   - Secret creation and access counts

3. **Monitoring Tools**:
   - **Prometheus**: For metrics collection
   - **Grafana**: For visualization
   - **ELK Stack**: For log analysis
   - **Sentry**: For error tracking

4. **Sample Prometheus Configuration**:
   ```yaml
   scrape_configs:
     - job_name: 'secretkeeper'
       metrics_path: '/metrics'
       static_configs:
         - targets: ['secretkeeper:8000']
   ```

### Backup Strategies

1. **Redis Backup**:
   - Enable Redis persistence (RDB and/or AOF)
   - Schedule regular RDB snapshots
   - Replicate to secondary instances

2. **Configuration Backup**:
   - Store configuration in version control
   - Document environment variables
   - Use infrastructure as code for deployments

3. **Backup Schedule**:
   - Hourly: Redis RDB snapshots
   - Daily: Full backup of Redis data
   - Weekly: Full system backup including configuration

### Maintenance Tasks

1. **Regular Updates**:
   - Update dependencies monthly
   - Apply security patches immediately
   - Test updates in staging before production

2. **Performance Tuning**:
   - Monitor Redis memory usage
   - Adjust rate limits based on usage patterns
   - Optimize database queries if using SQL backends

3. **Storage Cleanup**:
   - Redis automatically removes expired keys
   - For KV stores, implement a periodic cleanup job
   - Monitor storage growth and implement purging if needed

### Troubleshooting Common Issues

1. **Application Won't Start**:
   - Check environment variables are set correctly
   - Verify Python version (3.11+)
   - Check for port conflicts
   - Review logs for initialization errors

2. **Rate Limiting Too Aggressive**:
   - Adjust rate limits in configuration
   - Check if you're behind a proxy and configure X-Forwarded-For correctly

3. **Secrets Not Being Stored**:
   - Verify storage backend is running and accessible
   - Check storage backend configuration
   - Review logs for storage-related errors

4. **High Memory Usage**:
   - Switch from memory to Redis storage
   - Monitor Redis memory usage and increase if needed
   - Check for memory leaks with profiling tools

5. **Slow Response Times**:
   - Check server resources (CPU, memory)
   - Verify Redis performance
   - Consider scaling horizontally
   - Use a CDN for static assets

---

## User Guide

### Creating and Sharing Secrets

#### Creating a Secret

1. **Access the application** through your web browser at your deployed URL
2. **Enter your secret text** in the main textarea
   - The secret can be any text: passwords, private keys, personal information, etc.
   - Maximum length is 50,000 characters
3. **Select an expiration time** from the dropdown menu:
   - 10 minutes
   - 1 hour (default)
   - 24 hours (1 day)
   - 7 days (maximum)
4. **Click "Create one-view link"**
5. **Wait for encryption** to complete (happens in your browser)
6. **Copy the generated link** when it appears

#### Sharing the Secret

1. **Copy the entire link** including the part after the # symbol
   - The part after # contains the encryption key and never reaches our servers
   - Without this part, the secret cannot be decrypted
2. **Share the link** with your intended recipient via your preferred method:
   - Messaging app
   - Email
   - QR code (click "Show QR Code" button)
3. **Warn the recipient** that the link will only work once
4. **Optional**: Set a different communication channel for the # part for extra security

#### Viewing a Secret

1. **Open the received link** in your web browser
2. **Click "Reveal Secret"** to decrypt and view the content
3. **Copy the secret** if needed using the "Copy to Clipboard" button
4. **Note**: Once you close the page, the secret is gone forever
5. **Important**: The link becomes invalid after viewing, even if you saved it

### Understanding the UI

#### Home Page Elements

- **Secret Input**: Large textarea for entering your secret
- **Expiration Selector**: Dropdown to select the time-to-live
- **Create Button**: Initiates the encryption and storage process
- **Loading Indicator**: Shows when encryption or API calls are in progress
- **Success View**: Shows the generated link after successful creation
- **QR Code**: Optional visual representation of the link for easy sharing

#### View Page Elements

- **Ready to Reveal**: Initial state before the secret is decrypted
- **Reveal Button**: Triggers the one-time retrieval and decryption
- **Secret Display**: Shows the decrypted secret
- **Copy Button**: Copies the revealed secret to clipboard
- **Error States**: Various error messages for different failure scenarios

### Best Practices for End Users

1. **Use Secure Channels** to share the generated link
2. **Consider Splitting the Link** for highly sensitive information:
   - Send the base URL through one channel (e.g., email)
   - Send the part after # through another channel (e.g., SMS)
3. **Set Appropriate Expiration Times**:
   - Use shorter times (10 minutes) for highly sensitive information
   - Use longer times only when necessary for coordination
4. **Don't Send Links to Multiple People**:
   - Links can only be viewed once
   - Create separate secrets for each recipient
5. **Clear Your Browser History** after creating sensitive secrets
6. **Use Incognito/Private Browsing** for extra security
7. **Avoid Public Computers** when creating or viewing secrets

### Frequently Asked Questions

#### General Questions

**Q: Is my data encrypted?**  
A: Yes, all secrets are encrypted in your browser before being sent to the server. The server never sees the unencrypted content.

**Q: How secure is this service?**  
A: SecretKeeper uses modern encryption standards (AES-GCM 256-bit) and a zero-knowledge architecture. The encryption key never leaves your browser, making it highly secure.

**Q: Do I need an account to use SecretKeeper?**  
A: No, SecretKeeper is designed to be used without accounts to minimize data collection.

**Q: Is there a size limit for secrets?**  
A: Yes, secrets are limited to 50,000 characters to prevent abuse.

**Q: How long are secrets stored?**  
A: You choose the storage duration when creating a secret, from 10 minutes up to 7 days maximum.

#### Technical Questions

**Q: What if I accidentally close the page after creating a secret?**  
A: The secret will still be stored on the server until its expiration time or until someone views it.

**Q: Can I revoke a secret after creating it?**  
A: No, once created, a secret can only be deleted by viewing it or waiting for it to expire.

**Q: What browsers are supported?**  
A: All modern browsers (Chrome, Firefox, Safari, Edge) released in the last 3 years are supported.

**Q: Does SecretKeeper work on mobile devices?**  
A: Yes, SecretKeeper is fully responsive and works on mobile browsers.

**Q: Can secrets be recovered if lost?**  
A: No, secrets are designed to be unrecoverable once viewed or expired.

#### Security Questions

**Q: Can the SecretKeeper team read my secrets?**  
A: No, all encryption happens in your browser. We only store the encrypted data without the encryption key.

**Q: Are my secrets protected from AI systems?**  
A: Yes, SecretKeeper implements AI security headers and protection mechanisms to prevent content from being processed by AI systems.

**Q: Is my IP address logged when I create or view a secret?**  
A: IP addresses are temporarily stored for rate limiting purposes only and are not associated with secret content.

**Q: What happens if someone tries to view a secret multiple times?**  
A: After the first view, the secret is permanently deleted. Subsequent attempts will show an error message.

**Q: How can I verify the service is working properly?**  
A: Create a test secret with non-sensitive information and view it to verify the end-to-end workflow.

---

© 2025 YourCompany, Inc. All rights reserved.
