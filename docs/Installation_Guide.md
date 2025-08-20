# SecretKeeper Installation Guide

This guide provides step-by-step instructions for installing and configuring SecretKeeper in various environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Methods](#installation-methods)
   - [Docker Installation](#docker-installation)
   - [Manual Installation](#manual-installation)
   - [Cloud Deployment](#cloud-deployment)
3. [Configuration](#configuration)
4. [Storage Options](#storage-options)
5. [Security Considerations](#security-considerations)
6. [Advanced Configuration](#advanced-configuration)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

Before installing SecretKeeper, ensure your environment meets the following requirements:

### System Requirements

- **CPU**: 1+ cores (2+ recommended for production)
- **RAM**: 512MB minimum (1GB+ recommended for production)
- **Disk**: 1GB available space (10GB+ recommended for production)
- **Network**: Internet connectivity for dependency installation

### Software Requirements

- **Python**: 3.8 or newer
- **Operating System**: Linux, macOS, or Windows
- **Additional Software**:
  - For Redis backend: Redis 5.0+
  - For Docker installation: Docker 19.03+

## Installation Methods

### Docker Installation

Docker provides the simplest way to deploy SecretKeeper with minimal configuration.

#### Using Pre-built Image

```bash
# Pull the SecretKeeper image
docker pull yourcompany/secretkeeper:latest

# Run with in-memory storage (data will be lost on container restart)
docker run -d -p 8000:8000 --name secretkeeper yourcompany/secretkeeper:latest

# Run with Redis storage
docker run -d -p 8000:8000 --name secretkeeper \
  -e STORAGE_TYPE=redis \
  -e REDIS_URL=redis://redis-host:6379/0 \
  yourcompany/secretkeeper:latest
```

#### Using Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3'

services:
  secretkeeper:
    image: yourcompany/secretkeeper:latest
    container_name: secretkeeper
    ports:
      - "8000:8000"
    environment:
      - STORAGE_TYPE=redis
      - REDIS_URL=redis://redis:6379/0
      - SECRET_TTL_DEFAULT=24
      - SECRET_TTL_MAX=168
      - MAX_SECRET_SIZE=100000
    restart: unless-stopped
    depends_on:
      - redis

  redis:
    image: redis:alpine
    container_name: secretkeeper-redis
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

Then run:

```bash
docker-compose up -d
```

### Manual Installation

For environments where Docker is not available or when more control is needed.

#### Step 1: Clone the Repository

```bash
# Clone the repository
git clone https://github.com/yourcompany/secretkeeper.git
cd secretkeeper

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

#### Step 2: Install Dependencies

```bash
pip install -r requirements.txt

# For Redis storage backend
pip install redis
```

#### Step 3: Configure the Application

Create a `.env` file in the project root:

```env
STORAGE_TYPE=memory
SECRET_TTL_DEFAULT=24
SECRET_TTL_MAX=168
MAX_SECRET_SIZE=100000
# For Redis storage:
# STORAGE_TYPE=redis
# REDIS_URL=redis://localhost:6379/0
```

#### Step 4: Run the Application

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

For production deployment, consider using Gunicorn with Uvicorn workers:

```bash
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

### Cloud Deployment

#### AWS Elastic Beanstalk

1. Install the EB CLI:
   ```bash
   pip install awsebcli
   ```

2. Initialize EB application:
   ```bash
   eb init -p python-3.8 secretkeeper
   ```

3. Create an `Procfile` in the project root:
   ```
   web: gunicorn main:app -k uvicorn.workers.UvicornWorker
   ```

4. Create a `requirements.txt` file with all dependencies.

5. Create a `.ebextensions/01_secretkeeper.config` file:
   ```yaml
   option_settings:
     aws:elasticbeanstalk:container:python:
       WSGIPath: main:app
     aws:elasticbeanstalk:application:environment:
       STORAGE_TYPE: redis
       REDIS_URL: redis://your-redis-endpoint.amazonaws.com:6379/0
       SECRET_TTL_DEFAULT: 24
       SECRET_TTL_MAX: 168
       MAX_SECRET_SIZE: 100000
   ```

6. Deploy:
   ```bash
   eb create secretkeeper-env
   ```

#### Google Cloud Run

1. Create a `Dockerfile`:
   ```dockerfile
   FROM python:3.9-slim

   WORKDIR /app
   COPY . .
   RUN pip install --no-cache-dir -r requirements.txt

   CMD exec gunicorn --bind :$PORT --workers 1 --worker-class uvicorn.workers.UvicornWorker --threads 8 main:app
   ```

2. Build and deploy:
   ```bash
   gcloud builds submit --tag gcr.io/your-project-id/secretkeeper
   
   gcloud run deploy secretkeeper \
     --image gcr.io/your-project-id/secretkeeper \
     --platform managed \
     --region us-central1 \
     --set-env-vars "STORAGE_TYPE=redis,REDIS_URL=redis://your-redis-host:6379/0"
   ```

#### Heroku

1. Create a `Procfile`:
   ```
   web: gunicorn main:app -k uvicorn.workers.UvicornWorker
   ```

2. Create a `runtime.txt`:
   ```
   python-3.9.7
   ```

3. Deploy:
   ```bash
   heroku create secretkeeper
   heroku config:set STORAGE_TYPE=redis
   heroku config:set REDIS_URL=redis://your-redis-url
   git push heroku main
   ```

## Configuration

SecretKeeper can be configured using environment variables:

| Environment Variable | Description | Default Value |
|---------------------|-------------|---------------|
| `STORAGE_TYPE` | Storage backend type (memory, redis, kv) | memory |
| `REDIS_URL` | Redis connection URL for redis storage | redis://localhost:6379/0 |
| `SECRET_TTL_DEFAULT` | Default secret expiration time in hours | 24 |
| `SECRET_TTL_MAX` | Maximum allowed secret expiration time in hours | 168 |
| `MAX_SECRET_SIZE` | Maximum size of secret in bytes | 100000 |
| `RATE_LIMIT_CREATE` | Rate limit for create endpoint (requests/minute) | 10 |
| `RATE_LIMIT_VIEW` | Rate limit for view endpoint (requests/minute) | 20 |
| `RATE_LIMIT_QR` | Rate limit for QR endpoint (requests/minute) | 5 |
| `ENABLE_QR` | Enable/disable QR code generation | true |
| `ENABLE_AI_SECURITY` | Enable/disable AI security middleware | true |

## Storage Options

SecretKeeper supports multiple storage backends:

### Memory Storage

```env
STORAGE_TYPE=memory
```

- Simple in-memory storage
- Data is lost when the application restarts
- Suitable for development or testing
- No additional configuration required

### Redis Storage

```env
STORAGE_TYPE=redis
REDIS_URL=redis://localhost:6379/0
```

- Persistent storage using Redis
- Data survives application restarts
- Supports clustering for high availability
- Recommended for production use

#### Redis Configuration Options

| Environment Variable | Description | Default Value |
|---------------------|-------------|---------------|
| `REDIS_URL` | Redis connection string | redis://localhost:6379/0 |
| `REDIS_SSL` | Enable SSL for Redis connection | false |
| `REDIS_PASSWORD` | Password for Redis authentication | None |

### KV Storage

```env
STORAGE_TYPE=kv
KV_URL=your-kv-url
```

- Generic key-value store interface
- Implementation depends on the specific KV store
- Requires custom implementation in `storage.py`

## Security Considerations

### HTTPS Configuration

Always deploy SecretKeeper with HTTPS in production environments:

#### NGINX Configuration Example

```nginx
server {
    listen 80;
    server_name your-secretkeeper-domain.com;
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name your-secretkeeper-domain.com;
    
    # SSL configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    # Modern SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security headers are already added by the application
    
    # Proxy to SecretKeeper
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Recommended Security Practices

1. **Use HTTPS Only**: Configure proper TLS for all traffic.
2. **Keep Dependencies Updated**: Regularly update all dependencies.
3. **Run as Non-root User**: If using Docker, ensure the application runs as a non-root user.
4. **Use Redis Authentication**: Always set a strong password for Redis.
5. **Enable AI Security Middleware**: Keep the AI security middleware enabled.
6. **Set Appropriate Rate Limits**: Adjust rate limits based on your expected traffic.

## Advanced Configuration

### Running Behind a Proxy

When running SecretKeeper behind a reverse proxy, ensure the proxy forwards the appropriate headers:

- `X-Forwarded-For`: Client's real IP address
- `X-Forwarded-Proto`: Original protocol (http/https)
- `X-Forwarded-Host`: Original host requested by the client

### Scaling Horizontally

For high-traffic deployments, consider these scaling strategies:

1. **Multiple Application Instances**: Deploy multiple SecretKeeper instances behind a load balancer.
2. **Redis Cluster**: Use Redis Cluster for distributed storage.
3. **Stateless Design**: The application is designed to be stateless, allowing for easy horizontal scaling.

Example Docker Compose setup for scaling:

```yaml
version: '3'

services:
  secretkeeper:
    image: yourcompany/secretkeeper:latest
    environment:
      - STORAGE_TYPE=redis
      - REDIS_URL=redis://redis:6379/0
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
    networks:
      - secretkeeper-network

  redis:
    image: redis:alpine
    volumes:
      - redis-data:/data
    networks:
      - secretkeeper-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - secretkeeper
    networks:
      - secretkeeper-network

networks:
  secretkeeper-network:

volumes:
  redis-data:
```

### Customizing Templates

To customize the HTML templates, create a `templates` directory with your modified templates:

1. Create `templates/index.html` and `templates/view.html` based on the originals
2. Modify the CSS in `static/style.css`
3. Restart the application

## Troubleshooting

### Common Issues

#### Application Won't Start

**Symptoms**: The application fails to start, with errors like "Address already in use" or Python exceptions.

**Solutions**:

- Check if another process is using port 8000: `lsof -i :8000` (Linux/macOS) or `netstat -ano | findstr :8000` (Windows)
- Verify Python version: `python --version`
- Check for dependency conflicts: `pip check`

#### Redis Connection Issues

**Symptoms**: Errors like "Connection refused" or "Authentication required" when using Redis storage.

**Solutions**:

- Verify Redis is running: `redis-cli ping`
- Check connection string format
- Verify network connectivity to Redis
- Ensure authentication credentials are correct

#### Rate Limiting Problems

**Symptoms**: Users receiving 429 Too Many Requests errors.

**Solutions**:

- Adjust rate limits in environment variables
- Implement a caching proxy
- Check if users are behind shared IPs (corporate networks)

### Logging

By default, SecretKeeper logs to standard output. To capture logs:

```bash
# Redirect logs to file
uvicorn main:app --host 0.0.0.0 --port 8000 > secretkeeper.log 2>&1

# Or with Docker
docker logs secretkeeper > secretkeeper.log
```

### Getting Support

If you encounter issues not covered in this guide:

1. Check the [GitHub repository](https://github.com/yourcompany/secretkeeper) for known issues
2. Open a new issue with detailed information about your problem
3. Contact support at [support@yourcompany.com](mailto:support@yourcompany.com)

## Updating SecretKeeper

To update to a newer version:

### Docker Update

```bash
# Pull the latest image
docker pull yourcompany/secretkeeper:latest

# Restart the container
docker stop secretkeeper
docker rm secretkeeper
docker run -d -p 8000:8000 --name secretkeeper \
  -e STORAGE_TYPE=redis \
  -e REDIS_URL=redis://redis-host:6379/0 \
  yourcompany/secretkeeper:latest

# Or with Docker Compose
docker-compose pull
docker-compose up -d
```

### Manual Update

```bash
cd secretkeeper
git pull origin main

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Update dependencies
pip install -r requirements.txt

# Restart the application
# (depends on your deployment method)
```

## Conclusion

You have successfully installed SecretKeeper. For more information about using the application, refer to the user guide and API documentation.

---

*This installation guide was last updated on August 20, 2023. For the latest instructions, please refer to the official documentation.*
