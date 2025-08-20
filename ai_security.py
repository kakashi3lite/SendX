"""
SendX AI Security Module
========================

Advanced AI security protections for SendX's zero-knowledge secure messaging platform.
This module provides enterprise-grade middleware and utility functions to detect and block 
attempts to manipulate AI systems through prompt injection or similar attacks.

SendX's AI security layer ensures that:
1. User messages cannot be used to manipulate LLMs that might process content
2. The platform is protected from automated red team attacks and AI-based exploits
3. All future AI integrations remain secure from the start
4. Enterprise compliance requirements for AI safety are fully satisfied
"""

import re
import json
import base64
import logging
import functools
import hashlib
import time
import datetime
from typing import Set, List, Dict, Any, Optional, Pattern, Union, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import MutableHeaders

# Configure logger with proper formatter
logger = logging.getLogger("sendx.security")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - SendX - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# LRU cache for pattern matching to improve performance
CACHE_SIZE = 1000

# Thread-safe LRU cache implementation
import threading
class ThreadSafeLRUCache:
    """Thread-safe LRU cache implementation for high-volume concurrent environments."""
    
    def __init__(self, maxsize=1000):
        self.cache = {}
        self.maxsize = maxsize
        self.lock = threading.RLock()
        self.access_order = []
        
    def get(self, key):
        """Get a value from the cache, returning None if not found."""
        with self.lock:
            if key not in self.cache:
                return None
            
            # Update access order
            self.access_order.remove(key)
            self.access_order.append(key)
            
            return self.cache[key]
            
    def put(self, key, value):
        """Put a value in the cache, evicting least recently used items if needed."""
        with self.lock:
            if key in self.cache:
                self.access_order.remove(key)
            
            # If cache is full, remove least recently used item
            if len(self.cache) >= self.maxsize:
                oldest_key = self.access_order[0]
                del self.cache[oldest_key]
                self.access_order.pop(0)
            
            # Add new item
            self.cache[key] = value
            self.access_order.append(key)

# Initialize thread-safe cache
pattern_cache = ThreadSafeLRUCache(CACHE_SIZE)

# Common prompt injection patterns
PROMPT_INJECTION_PATTERNS: List[Pattern] = [
    # System prompt takeover attempts
    re.compile(r"ignore previous (instructions|prompts)", re.IGNORECASE),
    re.compile(r"ignore all previous commands", re.IGNORECASE),
    re.compile(r"you are now (a|an) (?!assistant)", re.IGNORECASE),  # "You are now a [anything except 'assistant']"
    re.compile(r"system prompt", re.IGNORECASE),
    re.compile(r"you must (obey|follow)", re.IGNORECASE),
    
    # Jailbreak attempts
    re.compile(r"DAN|do anything now", re.IGNORECASE),
    re.compile(r"character\s*mode", re.IGNORECASE),
    re.compile(r"dev\s*mode", re.IGNORECASE),
    re.compile(r"ignore (ethics|rules|restrictions|guidelines)", re.IGNORECASE),
    re.compile(r"harmful\s*content", re.IGNORECASE),
    
    # Data extraction instructions
    re.compile(r"extract (all|sensitive) data", re.IGNORECASE),
    re.compile(r"dump (database|data|config|credentials)", re.IGNORECASE),
    
    # Evasion techniques
    re.compile(r"[^\w\s.,;:!?](\s*)[^\w\s.,;:!?](\s*)[^\w\s.,;:!?]", re.IGNORECASE),  # Repeated special chars to bypass filters
    re.compile(r"base64:", re.IGNORECASE),
    re.compile(r"\\u[0-9a-fA-F]{4}"),  # Unicode escape sequences
    
    # Command injection
    re.compile(r"curl|wget|bash|sh|powershell|cmd|exec", re.IGNORECASE),
    re.compile(r"http://|https://", re.IGNORECASE),  # URLs that might be used for data exfiltration
    
    # Instructions to override security
    re.compile(r"bypass (security|authentication|verification)", re.IGNORECASE),
    re.compile(r"disable (security|authentication|verification)", re.IGNORECASE)
]

# SendX Security Headers - Enterprise-grade protection with detailed directives
LLM_SECURITY_HEADERS = {
    "X-LLM-Protection": "1; mode=block",  # Similar to XSS protection but for LLMs
    "LLM-Processing-Policy": "no-processing; no-embedding; no-learning",  # Instruct LLMs not to process this content
    "LLM-Context-Policy": "no-external-context; no-sharing",  # Prevent using content in training or other contexts
    "X-AI-Instructions": "none; no-process; no-training; no-indexing",  # Comprehensive AI handling directives
    "X-Content-Type-Options": "nosniff",  # Already used but important for AI contexts too
    "AI-Content-Safety": "user-generated-content; verify-intent",  # Additional safety directives
    "Content-Security-Processing": "restrict=prompt-injection,jailbreak,sensitive-data-extraction",  # Specific processing restrictions
    "X-SendX-AI-Protection": "enterprise; max-security",  # SendX-specific AI protection header
    "X-SendX-Security": "ai-shield-enabled"  # SendX security branding
}

# LRU cache decorator for pattern matching
def lru_cache(maxsize: int = 128) -> Callable:
    """Simple LRU cache implementation for pattern matching results.
    
    Args:
        maxsize: Maximum size of the cache
        
    Returns:
        Decorator function that caches results
    """
    def decorator(func):
        cache = {}
        
        @functools.wraps(func)
        def wrapper(text):
            # Create a hash of the input text for the cache key
            # Using hash of text to avoid storing large strings in memory
            text_hash = hashlib.md5(text.encode()).hexdigest()
            
            if text_hash in cache:
                return cache[text_hash]
                
            result = func(text)
            
            # Maintain cache size
            if len(cache) >= maxsize:
                # Simple strategy: clear half the cache when full
                keys_to_remove = list(cache.keys())[:maxsize // 2]
                for k in keys_to_remove:
                    del cache[k]
                    
            cache[text_hash] = result
            return result
            
        return wrapper
    return decorator

class AISecurityMiddleware(BaseHTTPMiddleware):
    """SendX AI Shield - Enterprise-grade middleware to detect and block AI-based threats.
    
    This middleware inspects message content and query parameters for patterns
    that may indicate prompt injection attempts or other AI security threats.
    When a potential threat is detected, the request is blocked and logged.
    
    Part of SendX's zero-knowledge security architecture, this middleware provides
    an additional layer of protection without compromising the end-to-end encryption
    model of the platform.
    
    Attributes:
        log_only: If True, only log threats without blocking requests
        scan_threshold: Only scan content longer than this threshold
        patterns: List of regex patterns to check against
        exempt_paths: List of URL paths that should be exempted from scanning
        exempt_content_types: List of content types that should be exempted from scanning
    """
    
    def __init__(
        self, 
        app, 
        log_only: bool = False, 
        additional_patterns: Optional[List[Pattern]] = None,
        scan_threshold: int = 50,  # Only scan content longer than this threshold
        exempt_paths: Optional[List[str]] = None,
        exempt_content_types: Optional[List[str]] = None,
        max_scan_size: int = 5_000_000,  # Don't scan content larger than 5MB
        use_constant_time_responses: bool = True,  # Protection against timing attacks
        max_process_time: float = 2.0  # Maximum time in seconds to process a request
    ):
        """Initialize the SendX AI Shield middleware.
        
        Args:
            app: The ASGI application
            log_only: If True, only log threats without blocking requests
            additional_patterns: Additional regex patterns to check against
            scan_threshold: Only scan content longer than this threshold
            exempt_paths: List of URL paths that should be exempted from scanning
            exempt_content_types: List of content types that should be exempted from scanning
            max_scan_size: Maximum size of content to scan in bytes
            use_constant_time_responses: If True, use constant-time responses to prevent timing attacks
            max_process_time: Maximum time in seconds to process a request
        """
        super().__init__(app)
        self.log_only = log_only
        self.scan_threshold = scan_threshold
        self.max_scan_size = max_scan_size
        self.patterns = PROMPT_INJECTION_PATTERNS.copy()
        self.exempt_paths = exempt_paths or ['/static', '/api/health', '/favicon.ico']
        self.exempt_content_types = exempt_content_types or ['image/', 'video/', 'audio/', 'application/octet-stream']
        self.use_constant_time_responses = use_constant_time_responses
        self.max_process_time = max_process_time
        
        # Initialize performance tracking
        self.total_requests = 0
        self.total_blocked = 0
        self.total_processing_time = 0.0
        self.stats_lock = threading.RLock()
        
        # Cache settings
        self.pattern_cache_lock = threading.RLock()
        self.use_ai_patterns = True
        self.ai_patterns_compiled = {}
        
        # Initialize threat detection counters for types of attacks
        self.threat_stats = {
            "prompt_injection": 0,
            "jailbreak": 0,
            "nested_content": 0,
            "resource_exhaustion": 0,
            "content_spoofing": 0,
            "total": 0
        }
        
        # Initialize recursion depth counter for base64 decoding to prevent nested attacks
        self._base64_recursion_depth = 0
        self.MAX_BASE64_RECURSION = 3  # Limit nested base64 encoding attacks
        
        if additional_patterns:
            self.patterns.extend(additional_patterns)
    
    async def dispatch(self, request: Request, call_next):
        """Process the request, checking for potential AI security threats.
        
        Args:
            request: The incoming request
            call_next: The next middleware or application to call
            
        Returns:
            Response: The response from the next middleware or application
        """
        # Capture request start time for monitoring
        start_time = time.time()
        target_time = None  # Will be set to implement constant-time responses
        
        # Skip checks for exempt paths
        for exempt_path in self.exempt_paths:
            if request.url.path.startswith(exempt_path):
                return await call_next(request)
        
        # Skip checks for certain content types if the header is present
        try:
            content_type = request.headers.get("content-type", "")
            
            # Validate the content type - don't trust the header blindly
            if content_type:
                try:
                    actual_content = await request.body()
                    # Check if binary content matches the declared type
                    if any(exempt in content_type.lower() for exempt in self.exempt_content_types):
                        # Verify it's actually binary content (check first few bytes)
                        # This prevents content-type spoofing attacks
                        is_text = self._is_text_content(actual_content[:1000])
                        if is_text:
                            # Content-type header might be spoofed, continue scanning
                            logger.warning("SendX AI Shield: Possible content-type spoofing detected")
                            content_type = "text/plain"  # Force scanning
                        else:
                            # Exempt from scanning as it's truly binary content
                            return await call_next(request)
                except Exception:
                    pass  # If we can't verify, proceed with scanning
            
            # If exempt after verification, skip scanning
            if any(exempt in content_type.lower() for exempt in self.exempt_content_types):
                return await call_next(request)
        except Exception as e:
            # Catch-all error handler to prevent middleware failures
            logger.error(f"Unexpected error in SendX AI Shield content-type processing: {type(e).__name__}", 
                        exc_info=False)  # Don't include stack trace in logs
        
        # Check if we need to inspect the message content
        threat_detected = False
        scan_info = {"scanned": False, "threat_detected": False, "content_size": 0}
        
        # Use try/except for all operations to ensure middleware resilience
        try:
            # Only scan specific HTTP methods that might contain message content
            if request.method in ["POST", "PUT", "PATCH"]:
                try:
                    body = await request.body()
                    scan_info["content_size"] = len(body)
                    
                    # Set target processing time for constant-time responses
                    if self.use_constant_time_responses:
                        # Calculate target time based on content size to make it less suspicious
                        # We'll sleep at the end to make all responses take approximately the same time
                        target_time = time.time() + min(0.05 + (len(body) / 2_000_000), self.max_process_time)
                    
                    # Only scan if body is within appropriate size limits
                    if self.scan_threshold <= len(body) <= self.max_scan_size:
                        scan_info["scanned"] = True
                        body_text = body.decode("utf-8", errors="ignore")
                        
                        # Normalize and sanitize unicode to prevent evasion techniques
                        import unicodedata
                        body_text = unicodedata.normalize('NFKC', body_text)
                        # Replace invisible/zero-width characters that might be used to evade detection
                        body_text = re.sub(r'[\u200B-\u200D\uFEFF\u2060\u180E]', '', body_text)
                        
                        # Try to parse as JSON to check content
                        try:
                            json_data = json.loads(body_text)
                            
                            # Start tracking JSON node scan count
                            self._json_nodes_scanned = 0
                            self._json_scan_start_time = time.time()
                            
                            threat_detected = self._scan_json_values(json_data)
                        except json.JSONDecodeError:
                            # If not JSON, scan the raw text
                            threat_detected = self._scan_text(body_text)
                    
                    scan_info["threat_detected"] = threat_detected
                    
                    if threat_detected:
                        # Track threat statistics
                        with self.stats_lock:
                            self.total_blocked += 1
                            self.threat_stats["total"] += 1
                        
                        if self.log_only:
                            logger.warning(
                                f"SendX AI Shield: Threat detected in request to {request.url.path}. "
                                f"Request allowed due to log_only mode. "
                                f"Method: {request.method}, "
                                f"Client: {request.client.host if request.client else 'Unknown'}"
                            )
                        else:
                            logger.warning(
                                f"SendX AI Shield: Threat blocked in request to {request.url.path}. "
                                f"Method: {request.method}, "
                                f"Client: {request.client.host if request.client else 'Unknown'}"
                            )
                            
                            # If using constant-time responses, sleep until target time
                            if self.use_constant_time_responses and target_time and target_time > time.time():
                                await self._safe_sleep(target_time - time.time())
                                
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "error": "Forbidden",
                                    "message": "Request contains patterns that violate SendX security policy"
                                }
                            )
                    
                    # Reconstruct request body for downstream handlers
                    async def receive():
                        return {"type": "http.request", "body": body}
                    request._receive = receive
                
                except Exception as e:
                    logger.error(f"Error in SendX AI Shield message content processing: {type(e).__name__}", 
                                exc_info=False)  # Don't include stack trace
            
            # Check query parameters
            query_params = dict(request.query_params)
            if query_params:
                try:
                    if self._scan_json_values(query_params):
                        with self.stats_lock:
                            self.total_blocked += 1
                            self.threat_stats["total"] += 1
                            
                        if self.log_only:
                            logger.warning(
                                f"SendX AI Shield: Threat detected in query params to {request.url.path}. "
                                f"Request allowed due to log_only mode. "
                                f"Client: {request.client.host if request.client else 'Unknown'}"
                            )
                        else:
                            logger.warning(
                                f"SendX AI Shield: Threat blocked in query params to {request.url.path}. "
                                f"Client: {request.client.host if request.client else 'Unknown'}"
                            )
                            
                            # If using constant-time responses, sleep until target time
                            if self.use_constant_time_responses and target_time and target_time > time.time():
                                await self._safe_sleep(target_time - time.time())
                                
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "error": "Forbidden",
                                    "message": "Request contains patterns that violate SendX security policy"
                                }
                            )
                except Exception as e:
                    logger.error(f"Error in SendX AI Shield query parameter processing: {type(e).__name__}", 
                                exc_info=False)
        
            # Call the next middleware/application and get the response
            response = await call_next(request)
            
            # Update performance tracking
            with self.stats_lock:
                self.total_requests += 1
                self.total_processing_time += (time.time() - start_time)
            
            # If using constant-time responses, sleep until target time
            if self.use_constant_time_responses and target_time and target_time > time.time():
                await self._safe_sleep(target_time - time.time())
            
            # Add security headers to the response
            self._add_sendx_security_headers(response)
            
            return response
        except Exception as e:
            # Catch-all error handler to prevent middleware failures
            logger.error(f"Unexpected error in SendX AI Shield middleware: {type(e).__name__}", 
                        exc_info=False)  # Don't include stack trace in logs
            
            # If we encounter an error, still try to process the request
            return await call_next(request)
            
            # Add SendX security headers to all responses
            self._add_sendx_security_headers(response)
            
            # Log performance metrics for monitoring
            processing_time = time.time() - start_time
            if processing_time > 0.1:  # Log slow middleware processing
                logger.info(
                    f"SendX AI Shield processing took {processing_time:.3f}s for {request.url.path}. "
                    f"Scanned: {scan_info['scanned']}, "
                    f"Content size: {scan_info['content_size']} bytes"
                )
            
            return response
            
        except Exception as e:
            # Catch-all error handler to prevent middleware from crashing the application
            logger.error(f"Unexpected error in SendX AI Shield: {str(e)}", exc_info=True)
            # Continue processing the request even if there's an error in the middleware
            return await call_next(request)
    
    @lru_cache(maxsize=CACHE_SIZE)
    def _scan_text(self, text: str) -> bool:
        """Scan message content for prompt injection patterns with optimization and caching.
        
        Args:
            text: The text to scan
            
        Returns:
            bool: True if a threat is detected, False otherwise
        """
        # Normalize and sanitize unicode to prevent evasion techniques
        import unicodedata
        text = unicodedata.normalize('NFKC', text)
        # Replace invisible/zero-width characters that might be used to evade detection
        text = re.sub(r'[\u200B-\u200D\uFEFF\u2060\u180E]', '', text)
        
        # Skip very short texts - unlikely to be threats and improves performance
        if len(text) < self.scan_threshold:
            return False
            
        # Check if text exceeds maximum size to prevent DoS
        if len(text) > 500000:  # Limit to 500KB
            logger.warning("SendX AI Shield: Text exceeds maximum scan size (500KB)")
            text = text[:500000]  # Only scan first 500KB
            
        # Apply a heuristic check first to potentially skip full pattern matching
        # Check for suspicious character frequency as a fast pre-filter
        if not self._quick_heuristic_check(text):
            return False
            
        # Time tracking for overall scan
        scan_start_time = time.time()
            
        # Check for base64 encoded content and decode it if found
        try:
            # Look for base64 patterns - at least 20 chars of base64-compatible content
            # More precise than the previous regex pattern matching
            base64_matches = re.findall(r"[A-Za-z0-9+/=]{20,}", text)
            
            # Limit number of base64 matches to prevent DoS attacks
            base64_matches = base64_matches[:5]  # Process at most 5 potential base64 strings (reduced from 10)
            
            # Track recursion depth for base64 decoding to prevent attacks
            base64_recursion_depth = getattr(self, '_base64_recursion_depth', 0)
            
            # Only process if we haven't gone too deep with recursive decoding
            if base64_recursion_depth < 3:  # Limit to max 3 levels of nested base64
                # Set recursion depth for next level
                self._base64_recursion_depth = base64_recursion_depth + 1
                
                # Track time spent in base64 decoding to prevent DoS
                base64_start_time = time.time()
                
                # Only try to decode strings that have a reasonable base64 structure
                # (valid padding, appropriate length)
                for match in base64_matches:
                    # Skip if overall scanning is taking too long
                    if time.time() - scan_start_time > 1.5:  # 1.5s overall timeout
                        logger.warning("SendX AI Shield: Base64 scan timeout")
                        break
                    
                    # Check if it's likely valid base64 before attempting decode
                    if len(match) % 4 == 0 and '=' not in match[:-2]:
                        try:
                            # Limit size of decoded content to prevent memory attacks
                            if len(match) > 500_000:  # Reduced from 1M to 500K
                                logger.warning(f"SendX AI Shield: Skipping large base64 string ({len(match)} bytes)")
                                continue
                                
                            decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                            # Only recursive scan if the decoded content looks like text (not binary)
                            # Added more stringent checks for text content
                            if (decoded.isprintable() and 
                                len(decoded) > 10 and 
                                len(decoded) < 100000 and  # Limit decoded content size
                                any(c.isalpha() for c in decoded[:100])):  # Contains some letters
                                if self._scan_text(decoded):
                                    # Reset recursion depth before returning
                                    self._base64_recursion_depth = 0
                                    return True
                        except Exception:
                            # Invalid base64 or binary content, continue
                            pass
                
                # Reset recursion depth after processing this level
                self._base64_recursion_depth = base64_recursion_depth
            else:
                logger.warning("SendX AI Shield: Maximum base64 recursion depth reached")
        except Exception as e:
            # Log the error but continue processing
            logger.debug(f"Error in base64 scanning: {str(e)}")
            # Reset recursion counter on error
            self._base64_recursion_depth = 0
            
        # Check against prompt injection patterns with timeout protection
        pattern_start_time = time.time()
        
        # Skip if overall scan is taking too long
        if time.time() - scan_start_time > 2.0:  # 2 second overall timeout
            logger.warning("SendX AI Shield: Overall scan timeout reached - potential DoS attack")
            return False  # Return false instead of true to avoid false positives
            
        for pattern in self.patterns:
            # Skip if we've already spent too much time on pattern matching
            if time.time() - pattern_start_time > 0.5:  # 500ms timeout for pattern matching
                logger.warning("SendX AI Shield: Pattern matching timeout reached - potential DoS attack")
                return True  # Treat as a threat if it's causing excessive processing
                
            try:
                # Use timeout for regex matching if available (Python 3.11+)
                if hasattr(re, 'timeout'):
                    match = pattern.search(text, timeout=0.1)  # 100ms timeout per pattern
                else:
                    # Fallback for older Python versions - limit input size
                    # Only scan the first 50KB for each pattern to prevent catastrophic backtracking
                    match = pattern.search(text[:50000])
                    
                if match:
                    # Log the specific pattern that matched for analysis
                    logger.info(f"SendX AI Shield: Pattern matched: {pattern.pattern}")
                    return True
            except re.error as e:
                # Handle regex timeout or other regex errors
                logger.warning(f"SendX AI Shield: Regex error with pattern {pattern.pattern}: {str(e)}")
                continue  # Continue with other patterns
                
        # Compute time spent in scanning
        scan_time = time.time() - scan_start_time
        if scan_time > 0.5:  # Log slow scans (>500ms)
            logger.warning(f"SendX AI Shield: Slow text scan: {scan_time:.2f}s for {len(text)} bytes")
            
        return False
        
    def _quick_heuristic_check(self, text: str) -> bool:
        """Perform a quick heuristic check to see if full pattern matching is needed.
        
        This improves SendX's performance by quickly filtering out content that is unlikely
        to contain threats.
        
        Args:
            text: The text to check
            
        Returns:
            bool: True if the text should undergo full pattern matching
        """
        # Check for key trigger words that might indicate a threat
        trigger_words = ["ignore", "system", "prompt", "jailbreak", "bypass", 
                        "extract", "security", "credentials", "curl", "http"]
        
        text_lower = text.lower()
        for word in trigger_words:
            if word in text_lower:
                return True
                
        # Check for suspicious character sequences
        suspicious_sequences = ["base64", "\\u", "===", "```"]
        for seq in suspicious_sequences:
            if seq in text:
                return True
                
        # Check for unusually high special character ratio
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        if len(text) > 0 and special_chars / len(text) > 0.3:  # More than 30% special chars
            return True
            
        return False
    
    def _scan_json_values(self, data: Any) -> bool:
        """Recursively scan JSON values for prompt injection patterns.
        
        Inspects message data fields for potential threats to SendX's security.
        
        Args:
            data: The data to scan
            
        Returns:
            bool: True if a threat is detected, False otherwise
        """
        # Reset scan counters for new scan
        self._json_nodes_scanned = 0
        self._json_scan_start_time = time.time()
        
        # Guard against deeply nested JSON
        max_recursion = 10
        return self._scan_json_recursive(data, 0, max_recursion)
        
    def _scan_json_recursive(self, data: Any, depth: int, max_depth: int) -> bool:
        """Helper method for recursive JSON scanning with depth limit.
        
        Protects SendX message content by recursively scanning through JSON structures.
        
        Args:
            data: The data to scan
            depth: Current recursion depth
            max_depth: Maximum recursion depth
            
        Returns:
            bool: True if a threat is detected, False otherwise
        """
        # Prevent too deep recursion
        if depth >= max_depth:
            logger.warning(f"SendX AI Shield: Maximum recursion depth reached ({max_depth}) during JSON scanning")
            return False
            
        # Track total nodes scanned to prevent resource exhaustion
        self._json_nodes_scanned = getattr(self, '_json_nodes_scanned', 0) + 1
        
        # Limit total number of nodes to scan to prevent DoS
        if self._json_nodes_scanned > 1000:  # Limit to 1000 nodes per request
            logger.warning("SendX AI Shield: Too many JSON nodes to scan - potential resource exhaustion")
            return True  # Treat as a threat since it could be a resource exhaustion attack
            
        # Check for timing attacks - if scanning is taking too long, abort
        scan_start_time = getattr(self, '_json_scan_start_time', time.time())
        if time.time() - scan_start_time > 1.0:  # 1 second timeout
            logger.warning("SendX AI Shield: JSON scanning timeout - potential DoS attack")
            return True  # Treat as a threat
            
        if isinstance(data, dict):
            # Prioritize checking known sensitive fields
            sensitive_keys = ["prompt", "instruction", "query", "command", "message", "text"]
            
            # Limit dict size to prevent DoS
            if len(data) > 100:
                logger.warning(f"SendX AI Shield: Large dictionary detected ({len(data)} keys) - limiting scan")
                # Create a subset of the dictionary with only the first 100 items
                # Prioritize sensitive keys
                subset_data = {}
                
                # First add sensitive keys if they exist
                for key in sensitive_keys:
                    if key in data:
                        subset_data[key] = data[key]
                
                # Then add other keys until we reach 100
                for key, value in data.items():
                    if key not in subset_data and len(subset_data) < 100:
                        subset_data[key] = value
                
                data = subset_data
            
            # Check sensitive keys first
            for key in sensitive_keys:
                if key in data and isinstance(data[key], str):
                    if self._scan_text(data[key]):
                        return True
            
            # Then check all other keys
            for key, value in data.items():
                if key not in sensitive_keys:
                    if isinstance(value, (str)):
                        if len(value) > self.scan_threshold and self._scan_text(value):
                            return True
                    elif self._scan_json_recursive(value, depth + 1, max_depth):
                        return True
                        
        elif isinstance(data, list):
            # Limit list size to prevent DoS
            if len(data) > 100:
                logger.warning(f"SendX AI Shield: Large array detected ({len(data)} items) - limiting scan")
                data = data[:100]  # Only scan first 100 items
                
            for item in data:
                if isinstance(item, str):
                    # Limit string length to prevent regex DoS
                    if len(item) > 100000:
                        item = item[:100000]
                        
                    if len(item) > self.scan_threshold and self._scan_text(item):
                        return True
                elif self._scan_json_recursive(item, depth + 1, max_depth):
                    return True
                    
        elif isinstance(data, str):
            # Limit string length to prevent regex DoS
            if len(data) > 100000:
                data = data[:100000]
                
            if len(data) > self.scan_threshold and self._scan_text(data):
                return True
                
        return False
        
    def _is_text_content(self, content: bytes, sample_size: int = 1000) -> bool:
        """Determine if content is likely text rather than binary.
        
        This helps prevent content-type spoofing attacks where attackers set binary
        MIME types but send text payloads to bypass scanning.
        
        Args:
            content: The content to check
            sample_size: Number of bytes to sample
            
        Returns:
            bool: True if content is likely text, False if likely binary
        """
        # Sample the first 1000 bytes (or fewer if content is smaller)
        sample = content[:sample_size]
        
        # If there are too many non-printable ASCII characters, it's likely binary
        text_chars = 0
        binary_chars = 0
        
        for byte in sample:
            # Count printable ASCII and common whitespace chars as text
            if (32 <= byte <= 126) or byte in (9, 10, 13):  # TAB, LF, CR
                text_chars += 1
            else:
                binary_chars += 1
                
        # If >20% of content is binary characters, it's likely binary
        if len(sample) > 0 and binary_chars / len(sample) > 0.20:
            return False
            
        return True
        
    async def _safe_sleep(self, seconds: float) -> None:
        """Safely sleep for the specified time, capping at max value.
        
        Used for implementing constant-time responses to prevent timing attacks.
        
        Args:
            seconds: The number of seconds to sleep
        """
        import asyncio
        
        # Ensure sleep time is reasonable
        sleep_time = max(0, min(seconds, 2.0))  # Cap at 2 seconds maximum
        
        try:
            await asyncio.sleep(sleep_time)
        except Exception:
            # Ignore sleep errors - we don't want to break the middleware
            pass
    
    def _generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce for CSP headers."""
        # Use secrets module for true cryptographic randomness
        import secrets
        return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode()
        
    def _add_sendx_security_headers(self, response: Response) -> None:
        """Add SendX security headers to the response.
        
        Args:
            response: The response to add headers to
        """
        headers = MutableHeaders(response.headers)
        for name, value in LLM_SECURITY_HEADERS.items():
            headers[name] = value
            
        # Add a nonce to CSP header if it exists for better security
        if "Content-Security-Policy" in headers:
            nonce = self._generate_nonce()
            if "script-src" in headers["Content-Security-Policy"]:
                headers["Content-Security-Policy"] = headers["Content-Security-Policy"].replace(
                    "script-src", f"script-src 'nonce-{nonce}'"
                )
                
    def _generate_nonce(self) -> str:
        """Generate a secure nonce for CSP headers.
        
        Returns:
            str: A secure random nonce
        """
        return base64.b64encode(hashlib.sha256(str(time.time()).encode()).digest()[:16]).decode()


@lru_cache(maxsize=CACHE_SIZE)
def is_prompt_injection(text: str) -> bool:
    """Utility function to check if a message contains prompt injection patterns.
    
    This function is cached to improve SendX's performance for repeated checks 
    of the same content.
    
    Args:
        text: The string to check for prompt injection patterns
        
    Returns:
        bool: True if potential prompt injection is detected, False otherwise
    """
    # Skip very short texts
    if len(text) < 10:
        return False
        
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def add_sendx_security_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Add SendX security headers to an existing headers dictionary.
    
    Args:
        headers: Dictionary of existing headers
        
    Returns:
        Dict: Updated headers dictionary with SendX security headers
    """
    updated_headers = headers.copy()
    for name, value in LLM_SECURITY_HEADERS.items():
        updated_headers[name] = value
    return updated_headers


def create_ai_security_report(text: str) -> Dict[str, Any]:
    """Create a detailed SendX AI security report for the given text.
    
    This function analyzes text for potential AI security threats and provides
    a detailed report with identified issues and recommended actions.
    
    Args:
        text: The text to analyze
        
    Returns:
        Dict: Security report with threat assessment
    """
    threats = []
    severity = "low"
    
    # Check each pattern individually
    for pattern in PROMPT_INJECTION_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            threat_name = pattern.pattern.replace(r"\\", "\\").replace("(?:", "").replace(")", "")
            threats.append({
                "pattern": threat_name,
                "matches": matches,
                "count": len(matches)
            })
            severity = "medium" if severity == "low" else severity
            
    # Check for potential base64 encoding
    base64_matches = re.findall(r"[A-Za-z0-9+/=]{20,}", text)
    if base64_matches:
        for match in base64_matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if is_prompt_injection(decoded):
                    threats.append({
                        "pattern": "base64_encoded_threat",
                        "matches": [match[:20] + "..."],
                        "count": 1
                    })
                    severity = "high"
            except:
                pass
                
    # Overall report
    return {
        "threats_detected": len(threats) > 0,
        "threat_count": len(threats),
        "severity": severity,
        "threats": threats,
        "recommended_action": "block" if severity == "high" else "review" if severity == "medium" else "allow",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "generated_by": "SendX AI Shield",
        "enterprise_protection": True,
        "sendx_version": "1.0.0"
    }


# AI security exceptions
class AISecurityException(Exception):
    """Base exception for SendX AI security related errors."""
    pass


class PromptInjectionDetected(AISecurityException):
    """Exception raised when a prompt injection attempt is detected by SendX AI Shield."""
    
    def __init__(self, message: str = "Potential prompt injection detected", details: Optional[Dict] = None):
        self.details = details or {}
        super().__init__(message)
