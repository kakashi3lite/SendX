import os
import secrets
import time
import hmac
import hashlib
import baseclass CreateSecretRequest(BaseModel):
    """Schema for creating a new secret.

    ``ciphertext``
        Bas# Add AI security middleware with production configuration
app.add_middleware(
    AISecurityMiddleware,
    log_only=False,  # Set to False in production to block threats
    scan_threshold=30,  # Scan payloads longer than 30 characters
    max_scan_size=1_000_000,  # Limit scan size to 1MB for performance
    exempt_paths=['/static', '/api/health', '/favicon.ico'],  # Exempt static resources
    exempt_content_types=['image/', 'video/', 'audio/', 'application/octet-stream']  # Exempt binary content
)yload combining the IV and ciphertext (see
        ``CryptoManager`` in the client).  Must not be empty and limited to
        100 000 characters to mitigate memory abuse.

    ``ttl``
        Desired time‑to‑live in hours.  Values outside the range
        0.1–168 are clamped server‑side to protect resources.  Defaults
        to 24 hours when omitted.
    """
    model_config = ConfigDict(strict=True, extra="forbid")
    ciphertext: str = Field(min_length=1, max_length=100_000)
    ttl: float = Field(default=24.0, ge=0.1, le=168.0)
    
    @validator('ciphertext')
    def validate_no_prompt_injection(cls, v):
        """Validate that the ciphertext doesn't contain prompt injection patterns.
        
        Although the ciphertext should be encrypted and unreadable, this is a defense-in-depth
        measure to prevent abuse of the service for prompt injection attacks.
        """
        if is_prompt_injection(v):
            # Log the issue but don't reveal specifics in the error
            logging.warning("Potential prompt injection detected in ciphertext")
            raise ValueError("Invalid ciphertext format")
        return vort json
import qrcode
import qrcode.constants
import io
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response

# Import AI Security module
try:
    from .ai_security import (
        AISecurityMiddleware, 
        is_prompt_injection, 
        create_ai_security_report,
        PROMPT_INJECTION_PATTERNS,
        CACHE_SIZE
    )
except ImportError:
    # When running as a standalone script
    from ai_security import (
        AISecurityMiddleware, 
        is_prompt_injection, 
        create_ai_security_report,
        PROMPT_INJECTION_PATTERNS,
        CACHE_SIZE
    )

from pydantic import BaseModel, Field, ConfigDict, ValidationError

from .storage import MemoryStorage, KvStorage, Storage, SecretRecord

# ---------------------------------------------------------------------------
# Request size limiting middleware
# ---------------------------------------------------------------------------
class BodyLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce a maximum request body size.

    FastAPI/Starlette does not expose a built‑in body size limit, so this
    middleware reads the body into memory and rejects requests larger than
    ``max_content_size`` bytes.  Requests exceeding the limit will receive
    an HTTP 413 Payload Too Large response.
    """

    def __init__(self, app: FastAPI, max_content_size: int = 200_000) -> None:
        super().__init__(app)
        self.max_content_size = max_content_size

    async def dispatch(self, request: Request, call_next):
        # Only enforce the limit on POST/PUT/PATCH where a body is expected
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > self.max_content_size:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Payload too large", "message": "Request body exceeds allowed size"}
                )
            # Reassign the body so downstream handlers can read it
            async def receive() -> dict:
                return {"type": "http.request", "body": body, "more_body": False}
            request._receive = receive  # type: ignore[attr-defined]
        return await call_next(request)


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------
class CreateSecretRequest(BaseModel):
    """Schema for creating a new secret.

    ``ciphertext``
        Base64 encoded payload combining the IV and ciphertext (see
        ``CryptoManager`` in the client).  Must not be empty and limited to
        100 000 characters to mitigate memory abuse.

    ``ttl``
        Desired time‑to‑live in hours.  Values outside the range
        0.1–168 are clamped server‑side to protect resources.  Defaults
        to 24 hours when omitted.
    """
    model_config = ConfigDict(strict=True, extra="forbid")
    ciphertext: str = Field(min_length=1, max_length=100_000)
    ttl: float = Field(default=24.0, ge=0.1, le=168.0)


# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# FastAPI app
app = FastAPI(
    title="One-View Secrets",
    description="Zero-knowledge secrets sharing with client-side encryption",
    version="1.0.0"
)

# Add rate limiting middleware
app.state.limiter = limiter

async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Custom rate limit handler with friendly message"""
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "message": "Please wait a moment before trying again",
            "retry_after": int(exc.retry_after or 60)
        }
    )

app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
app.add_middleware(SlowAPIMiddleware)

# Enforce a maximum request size (approx 200KB).  This prevents abuse by
# oversized payloads and aligns with the 50,000 character limit in the UI.
app.add_middleware(BodyLimitMiddleware, max_content_size=200_000)

# Security middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Enhanced security headers following OWASP guidelines
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "require-trusted-types-for 'script'; "
            "trusted-types default"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        
        # Add AI/LLM security headers
        response.headers["X-LLM-Protection"] = "1; mode=block"
        response.headers["LLM-Processing-Policy"] = "no-processing"
        response.headers["LLM-Context-Policy"] = "no-external-context"
        response.headers["X-AI-Instructions"] = "none; no-process; no-training; no-indexing"
        
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Add AI security middleware with production configuration
app.add_middleware(
    AISecurityMiddleware,
    log_only=False,  # Set to False in production to block threats
    scan_threshold=30,  # Scan payloads longer than 30 characters
    max_scan_size=1_000_000,  # Limit scan size to 1MB for performance
    exempt_paths=['/static', '/api/health', '/favicon.ico'],  # Exempt static resources
    exempt_content_types=['image/', 'video/', 'audio/', 'application/octet-stream'],  # Exempt binary content
    additional_patterns=[
        # Add any application-specific patterns here
        re.compile(r"eval\s*\(", re.IGNORECASE),  # JavaScript eval attempts
        re.compile(r"password|secret|token|key", re.IGNORECASE),  # Sensitive data keywords
    ]
)

# Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # In production, specify exact hosts
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Storage selection
# ---------------------------------------------------------------------------
STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "memory").lower()
_storage: Storage

if STORAGE_BACKEND == "memory":
    _storage = MemoryStorage()
elif STORAGE_BACKEND == "kv":
    # Placeholder for future KV backend.  Falling back to memory for now.
    _storage = MemoryStorage()
else:
    # Unknown backend; default to memory with a warning.
    print(f"[WARN] Unknown STORAGE_BACKEND '{STORAGE_BACKEND}', using in‑memory storage.")
    _storage = MemoryStorage()

# HMAC key used solely for generating obfuscated secret IDs.  This key has no
# relationship to the client‑side encryption key.  It should be random and
# unpredictable.  If ``HMAC_KEY`` is not provided via environment, a new
# random key is generated on startup.
_default_key = secrets.token_bytes(32)
HMAC_KEY: bytes
env_key = os.getenv("HMAC_KEY")
if env_key:
    HMAC_KEY = env_key.encode("utf-8")
else:
    HMAC_KEY = _default_key

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ---------------------------------------------------------------------------
# Secret ID generation and persistence helpers
# ---------------------------------------------------------------------------

def generate_secret_id() -> str:
    """Generate a random secret ID bound to the current time.

    The ID is derived from 16 bytes of randomness combined with a truncated
    HMAC signature.  The resulting value is URL‑safe and hides any
    predictable patterns in the underlying random bytes.  See also
    https://docs.python.org/3/library/secrets.html for security guidance.
    """
    random_bytes = secrets.token_bytes(16)
    timestamp = str(int(time.time())).encode()
    signature = hmac.new(HMAC_KEY, random_bytes + timestamp, hashlib.sha256).digest()
    combined = random_bytes + signature[:8]
    return base64.urlsafe_b64encode(combined).decode().rstrip("=")


async def store_secret(secret_id: str, ciphertext: str, ttl_hours: float = 24.0) -> None:
    """Persist an encrypted secret with a time‑to‑live.

    The TTL is expressed in hours and clamped to the range [0.1, 168] (10
    minutes to 7 days).  This function computes an expiration timestamp
    relative to the current time and stores the record via the selected
    storage backend.  Records include a consumed flag which is initially
    False.
    """
    # Clamp TTL to allowable bounds
    ttl_hours = max(0.1, min(float(ttl_hours), 168.0))
    expires_at = int(time.time() + ttl_hours * 3600)
    record: SecretRecord = {
        "ciphertext": ciphertext,
        "iv": None,
        "exp": expires_at,
        "consumed": False,
    }
    await _storage.put(secret_id, record)


async def retrieve_secret(secret_id: str) -> Optional[str]:
    """Retrieve and delete a secret by its ID.

    Returns the stored ciphertext if the secret exists, has not expired and
    has not yet been consumed.  Otherwise returns ``None``.
    """
    rec = await _storage.get_once(secret_id)
    if not rec:
        return None
    return rec.get("ciphertext")

@app.get("/", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def index(request: Request):
    """Serve the main page for creating secrets"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/view", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def view_page(request: Request):
    """Serve the view page for decrypting secrets"""
    return templates.TemplateResponse("view.html", {"request": request})

@app.post("/api/create")
@limiter.limit("10/minute")
async def create_secret(payload: CreateSecretRequest):
    """Persist a new encrypted secret.

    Expects a JSON body conforming to ``CreateSecretRequest``.  The
    payload is validated by Pydantic before this handler is invoked.
    """
    try:
        # Generate a random secret identifier
        secret_id = generate_secret_id()
        
        # Perform AI security scan on the ciphertext
        security_report = create_ai_security_report(payload.ciphertext)
        if security_report["threats_detected"] and security_report["severity"] == "high":
            logging.warning(f"High severity AI security threat detected: {security_report['threat_count']} threats")
            raise HTTPException(status_code=403, detail="Content violates security policy")
        
        # Store the secret asynchronously
        await store_secret(secret_id, payload.ciphertext, payload.ttl)
        
        # Respond with metadata
        return JSONResponse(
            {
                "success": True,
                "secret_id": secret_id,
                "expires_in_hours": float(payload.ttl),
            }
        )
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception:
        # Log the exception for internal diagnostics but avoid leaking details
        logging.exception("Error creating secret")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/secret/{secret_id}")
@limiter.limit("20/minute")
async def get_secret(secret_id: str):
    """Fetch and invalidate a secret by ID.

    Returns the ciphertext if it exists, otherwise raises a 404.  Input
    validation is performed to ensure the ID is well formed and not
    excessively long.
    """
    try:
        if not secret_id or len(secret_id) > 100:
            raise HTTPException(status_code=400, detail="Invalid secret ID")
        ciphertext = await retrieve_secret(secret_id)
        if not ciphertext:
            raise HTTPException(
                status_code=404,
                detail="Secret not found, already accessed, or expired",
            )
        return JSONResponse({"success": True, "ciphertext": ciphertext})
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/qr/{secret_id}")
@limiter.limit("5/minute")
async def generate_qr(secret_id: str, request: Request):
    """Generate QR code for secret URL"""
    try:
        if not secret_id or len(secret_id) > 100:
            raise HTTPException(status_code=400, detail="Invalid secret ID")
        
        # Check if secret exists without consuming it.  We cannot peek at
        # contents without violating one‑time semantics, so we rely on TTL.
        ttl_seconds = await _storage.ttl(secret_id)
        if ttl_seconds is None:
            raise HTTPException(status_code=404, detail="Secret not found")
        
        # Generate base URL (without fragment - that's added by frontend)
        base_url = f"{request.url.scheme}://{request.url.netloc}/view?id={secret_id}"
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(base_url)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        
        return StreamingResponse(
            io.BytesIO(img_bytes.read()),
            media_type="image/png",
            headers={"Cache-Control": "no-store"}
        )
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to generate QR code")

@app.get("/api/health")
@app.get("/api/health", response_class=JSONResponse)
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "ai_security": {
            "enabled": True,
            "patterns_count": len(PROMPT_INJECTION_PATTERNS),
            "cache_size": CACHE_SIZE
        },
        "version": "1.0.0"
    }

@app.on_event("startup")
async def startup_event():
    """Initialize application"""
    print("One-View Secrets started successfully")
    print("Zero-knowledge encryption enabled")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=5000,
        reload=False,
        access_log=True
    )
