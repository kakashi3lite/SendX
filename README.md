# SendX

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100.0-green)](https://fastapi.tiangolo.com/)

SendX is a zero-knowledge, one-time secret sharing platform built with security as the primary focus. Share sensitive information securely with automatic expiration and client-side encryption.

## 🔐 Key Features

- **Zero-Knowledge Architecture**: Server never sees plaintext content
- **Client-Side Encryption**: AES-GCM 256-bit encryption in your browser
- **One-Time Access**: Secrets are automatically deleted after viewing
- **Automatic Expiration**: Set custom time-to-live for secrets
- **QR Code Sharing**: Generate QR codes for easy secret sharing
- **AI Security Protection**: Advanced protection against AI-based attacks
- **No Account Required**: Completely anonymous usage

## 📋 Table of Contents

- [Demo](#-demo)
- [Quick Start](#-quick-start)
- [How It Works](#-how-it-works)
- [Security](#-security)
- [Documentation](#-documentation)
- [Development](#-development)
- [License](#-license)

## 🌐 Demo

Try SendX at [https://sendx.example.com](https://sendx.example.com)

## 📦 Download Ready-Made ZIP

Developers can download and try SendX directly from these links:

- [SendX Latest Release (ZIP)](https://github.com/kakashi3lite/SendX/releases/latest/download/sendx-release.zip)
- [SendX AI Shield Demo (ZIP)](https://github.com/kakashi3lite/SendX/releases/latest/download/sendx-ai-shield-demo.zip)
- [Developer Documentation (PDF)](https://github.com/kakashi3lite/SendX/releases/latest/download/sendx-documentation.pdf)

## 🚀 Quick Start

### Using Docker

```bash
# Run with in-memory storage (data will be lost on container restart)
docker run -d -p 8000:8000 --name secretkeeper yourcompany/secretkeeper:latest

# Run with Redis storage
docker run -d -p 8000:8000 --name secretkeeper \
  -e STORAGE_TYPE=redis \
  -e REDIS_URL=redis://redis-host:6379/0 \
  yourcompany/secretkeeper:latest
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/yourcompany/secretkeeper.git
cd secretkeeper

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn main:app --host 0.0.0.0 --port 8000
```

Then open [http://localhost:8000](http://localhost:8000) in your browser.

## 🔍 How It Works

1. **Create a Secret**:
   - Enter your secret text in the browser
   - Choose how long the secret should be available
   - Your browser encrypts the text with a randomly generated key
   - The encrypted data is sent to the server (the server never sees the plaintext)
   - The encryption key stays in your browser and is added to the URL as a fragment (#)

2. **Share the Secret**:
   - Copy the generated URL and share it with the recipient
   - The URL contains both the secret ID and the encryption key
   - The encryption key in the URL fragment (#) is never sent to the server

3. **View a Secret**:
   - The recipient opens the URL
   - Their browser retrieves the encrypted data from the server
   - The secret is automatically deleted from the server
   - The browser decrypts the data using the key from the URL fragment
   - After viewing, the secret is gone forever

## 🔒 Security

SecretKeeper employs multiple layers of security:

- **Zero-Knowledge Encryption**: The server only stores encrypted data and never has access to encryption keys
- **One-Time Access**: Secrets are permanently deleted after being viewed once
- **Automatic Expiration**: All secrets automatically expire after their time-to-live
- **No Logs**: No IP addresses or user data are logged
- **HTTPS Only**: All communications are encrypted in transit
- **Content Security Policy**: Strict CSP to prevent XSS and other attacks
- **Rate Limiting**: Protection against brute-force and DoS attacks
- **AI Security Middleware**: Protection against prompt injection and AI-based attacks

For a detailed security assessment, see our [Security Documentation](docs/Security_Assessment.md).

## 📚 Documentation

- [Installation Guide](docs/Installation_Guide.md)
- [API Reference](docs/API_Reference.md)
- [Security Assessment](docs/Security_Assessment.md)
- [User Guide](docs/User_Guide.md)

## 💻 Development

### Prerequisites

- Python 3.8+
- Node.js 14+ (for frontend development)

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/yourcompany/secretkeeper.git
cd secretkeeper

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run with auto-reload for development
uvicorn main:app --reload
```

### Running Tests

```bash
pytest
```

### Code Style

This project uses:

- Black for Python code formatting
- ESLint for JavaScript linting
- Prettier for JavaScript formatting

```bash
# Format Python code
black .

# Lint JavaScript
cd static && npm run lint
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgements

SecretKeeper was inspired by:

- [PrivateBin](https://privatebin.info/)
- [OneTimeSecret](https://onetimesecret.com/)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ❓ FAQ

**Q: Is SecretKeeper suitable for sharing sensitive information like passwords?**  
A: Yes, SecretKeeper is designed specifically for securely sharing sensitive information. However, for the highest security, always use end-to-end encrypted messaging when possible and set short expiration times.

**Q: Can the administrator of the server see my secrets?**  
A: No. SecretKeeper uses client-side encryption, so the server only ever sees encrypted data. Without the encryption key (which stays in the URL fragment and is never sent to the server), the data cannot be decrypted.

**Q: What happens if someone intercepts the URL?**  
A: If someone intercepts the complete URL, they could access the secret. Always share the URL via a secure channel and consider using additional authentication methods for highly sensitive information.

**Q: How long can I store a secret?**  
A: By default, secrets expire after 24 hours, but you can set a custom expiration time from 10 minutes up to 7 days.

## 📧 Contact

For questions or support, please contact:

- Email: [support@kakashi3lite.com](mailto:support@kakashi3lite.com)
- GitHub Issues: [https://github.com/kakashi3lite/SendX/issues](https://github.com/kakashi3lite/SendX/issues)
