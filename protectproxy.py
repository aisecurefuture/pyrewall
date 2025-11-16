import os
import ipaddress
import json
import logging
import socket
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse, parse_qsl, urlencode

# Load .env file if it exists (must be before reading environment variables)
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file from current directory
except ImportError:
    # python-dotenv not installed, skip .env loading
    pass

import httpx
from fastapi import FastAPI, Request, Response, HTTPException, Depends, status
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bleach
from datetime import datetime
from logging.handlers import BufferingHandler
import threading
from queue import Queue
import jwt
from jwt import PyJWKClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded


def get_env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_env_list(name: str, default: Optional[list[str]] = None, separator: str = ",") -> list[str]:
    """
    Parse an environment variable as a list of strings.
    
    Supports:
    - Comma-separated: "item1,item2,item3"
    - Space-separated: "item1 item2 item3" (if separator=" ")
    - JSON array: '["item1","item2","item3"]'
    
    Args:
        name: Environment variable name
        default: Default value if not set (default: None)
        separator: Separator for simple string splitting (default: ",")
    
    Returns:
        List of strings, or default if not set
    """
    value = os.getenv(name)
    if value is None:
        return default or []
    
    value = value.strip()
    if not value:
        return default or []
    
    # Try parsing as JSON first (more flexible)
    if value.startswith("[") and value.endswith("]"):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if item]
        except (json.JSONDecodeError, TypeError):
            pass
    
    # Fall back to separator-based splitting
    return [item.strip() for item in value.split(separator) if item.strip()]


TARGET_URL = os.getenv("TARGET_URL")
PROXY_PREFIX = os.getenv("PROXY_PREFIX", "").strip()
TIMEOUT_SECONDS = float(os.getenv("PROXY_TIMEOUT_SECONDS", "60"))
PER_REQUEST_TIMEOUT = float(os.getenv("PROXY_PER_REQUEST_TIMEOUT", "30"))  # Per-request timeout
ALLOW_INSECURE_SSL = get_env_bool("PROXY_ALLOW_INSECURE_SSL", False)

# Azure Entra OAuth2 Configuration
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_AUDIENCE = os.getenv("AZURE_AUDIENCE", AZURE_CLIENT_ID)  # Default to client ID if not set
AZURE_ENABLE_AUTH = get_env_bool("AZURE_ENABLE_AUTH", False)
AZURE_ISSUER = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0" if AZURE_TENANT_ID else None

# Rate limiting configuration
RATE_LIMIT_ENABLED = get_env_bool("RATE_LIMIT_ENABLED", True)
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_PER_HOUR = int(os.getenv("RATE_LIMIT_PER_HOUR", "1000"))

# TLS version enforcement
MIN_TLS_VERSION = os.getenv("MIN_TLS_VERSION", "1.2")  # Minimum TLS version
# Maximum body size to sanitize (default: 1 MiB)
# Larger bodies are passed through without sanitization to avoid performance impact.
# Recommended values:
#   - 524288 (512 KiB): Conservative, for APIs with small payloads
#   - 1048576 (1 MiB): Default, good balance for most APIs
#   - 5242880 (5 MiB): Aggressive, for APIs with large JSON/XML payloads
MAX_BODY_SANITIZE_BYTES = int(os.getenv("PROXY_MAX_BODY_SANITIZE_BYTES", "1048576"))

# httpx connection limits
HTTPX_MAX_CONNECTIONS = int(os.getenv("PROXY_HTTPX_MAX_CONNECTIONS", "100"))
HTTPX_MAX_KEEPALIVE = int(os.getenv("PROXY_HTTPX_MAX_KEEPALIVE", "20"))
HTTPX_KEEPALIVE_EXPIRY = float(os.getenv("PROXY_HTTPX_KEEPALIVE_EXPIRY", "30"))

# Parse and validate TARGET_URL for SSRF protection
ALLOWED_HOSTNAME: Optional[str] = None
ALLOWED_NETLOC: Optional[str] = None
if TARGET_URL:
    try:
        parsed = urlparse(TARGET_URL)
        ALLOWED_HOSTNAME = parsed.hostname
        ALLOWED_NETLOC = parsed.netloc
    except Exception:
        pass

logger = logging.getLogger("reverse_proxy")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(title="Reverse Proxy", version="1.0.0")

# Rate limiting setup with IP validation
def get_client_ip(request: Request) -> str:
    """Get client IP address, validating X-Forwarded-For to prevent spoofing."""
    # Get real IP from request
    client_ip = get_remote_address(request)
    
    # If behind proxy, validate X-Forwarded-For
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        # Take the first IP (original client) but validate it
        xff_ips = [ip.strip() for ip in xff.split(",")]
        if xff_ips:
            first_ip = xff_ips[0]
            try:
                # Validate it's a real IP
                ipaddress.ip_address(first_ip)
                return first_ip
            except ValueError:
                pass
    
    return client_ip

limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# OAuth2 security scheme
security = HTTPBearer(auto_error=False)

# Azure AD JWKS client (lazy initialization)
_jwks_client: Optional[PyJWKClient] = None

def get_jwks_client() -> Optional[PyJWKClient]:
    """Get or create Azure AD JWKS client."""
    global _jwks_client
    if AZURE_TENANT_ID and not _jwks_client:
        try:
            # Validate tenant ID to prevent injection
            if not AZURE_TENANT_ID.replace("-", "").replace("_", "").isalnum():
                logger.error("Invalid Azure tenant ID format")
                return None
            jwks_url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/discovery/v2.0/keys"
            _jwks_client = PyJWKClient(jwks_url)
        except Exception as e:
            logger.error(f"Failed to initialize Azure AD JWKS client: {e}")
            return None
    return _jwks_client


async def verify_azure_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[Dict]:
    """Verify Azure Entra OAuth2 token."""
    if not AZURE_ENABLE_AUTH:
        return None  # Authentication disabled
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    # Limit token size to prevent DoS (JWT tokens are typically < 8KB)
    MAX_TOKEN_SIZE = 16384  # 16KB
    if len(token) > MAX_TOKEN_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token too large",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        jwks_client = get_jwks_client()
        if not jwks_client:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable"
            )
        
        # Get signing key
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Decode and verify token - explicitly restrict to RS256 to prevent algorithm confusion
        decoded_token = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],  # Only allow RS256, prevent algorithm confusion attacks
            audience=AZURE_AUDIENCE,
            issuer=AZURE_ISSUER,
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_signature": True,  # Explicitly require signature verification
            }
        )
        
        return decoded_token
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


# External logging service configuration
DATADOG_API_KEY = os.getenv("DATADOG_API_KEY")
DATADOG_SITE = os.getenv("DATADOG_SITE", "datadoghq.com")
DATADOG_SERVICE = os.getenv("DATADOG_SERVICE", "reverse-proxy")
DATADOG_ENV = os.getenv("DATADOG_ENV", "production")

GOOGLE_CHRONICLE_API_KEY = os.getenv("GOOGLE_CHRONICLE_API_KEY")
GOOGLE_CHRONICLE_REGION = os.getenv("GOOGLE_CHRONICLE_REGION", "us")
GOOGLE_CHRONICLE_CUSTOMER_ID = os.getenv("GOOGLE_CHRONICLE_CUSTOMER_ID")
GOOGLE_CHRONICLE_LOG_TYPE = os.getenv("GOOGLE_CHRONICLE_LOG_TYPE", "REVERSE_PROXY")


class DatadogLogHandler(logging.Handler):
    """Custom logging handler for Datadog Logs API."""
    
    def __init__(self, api_key: str, site: str, service: str, env: str):
        super().__init__()
        self.api_key = api_key
        self.site = site
        self.service = service
        self.env = env
        self.url = f"https://http-intake.logs.{site}/v1/input/{api_key}"
        self.queue = Queue(maxsize=1000)  # Limit queue size to prevent memory exhaustion
        self.client = httpx.Client(timeout=5.0)
        # Start background thread for sending logs
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
    
    def emit(self, record: logging.LogRecord):
        """Send log to Datadog."""
        try:
            log_data = {
                "timestamp": int(record.created * 1000),  # milliseconds
                "level": record.levelname,
                "message": self.format(record),
                "service": self.service,
                "env": self.env,
                "logger.name": record.name,
                "logger.thread_name": record.threadName,
            }
            
            # Add structured data if available
            if hasattr(record, "dd_extra"):
                log_data.update(record.dd_extra)
            
            # Queue for background sending (non-blocking)
            try:
                self.queue.put_nowait(log_data)
            except:
                pass  # Queue full, drop log
        except Exception:
            pass
    
    def _worker(self):
        """Background worker thread to send logs."""
        while True:
            try:
                log_data = self.queue.get(timeout=1.0)
                try:
                    self.client.post(
                        self.url,
                        json=log_data,
                        headers={"Content-Type": "application/json"},
                    )
                except Exception:
                    pass  # Fail silently
                finally:
                    self.queue.task_done()
            except:
                continue


class GoogleChronicleLogHandler(logging.Handler):
    """Custom logging handler for Google Chronicle API."""
    
    def __init__(self, api_key: str, region: str, customer_id: Optional[str] = None, log_type: str = "REVERSE_PROXY"):
        super().__init__()
        self.api_key = api_key
        self.region = region
        self.customer_id = customer_id
        self.log_type = log_type
        self.url = f"https://{region}-ingestion.chronicle.security/v1/udmevents:batchCreate"
        self.queue = Queue(maxsize=1000)  # Limit queue size to prevent memory exhaustion
        self.client = httpx.Client(timeout=5.0)
        # Start background thread for sending logs
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
    
    def emit(self, record: logging.LogRecord):
        """Send log to Google Chronicle."""
        try:
            # Chronicle expects UDM (Unified Data Model) format
            event = {
                "metadata": {
                    "eventTimestamp": datetime.utcnow().isoformat() + "Z",
                    "eventType": self._map_log_level_to_event_type(record.levelname),
                    "productLogId": f"{record.name}-{record.created}",
                    "logType": self.log_type,
                },
                "target": {
                    "hostname": socket.gethostname(),
                },
                "security_result": {
                    "summary": self.format(record),
                    "severity": self._map_log_level_to_severity(record.levelname),
                },
            }
            
            # Add structured data if available
            if hasattr(record, "chronicle_extra"):
                event.update(record.chronicle_extra)
            
            # Add customer ID if provided
            if self.customer_id:
                event["metadata"]["customerId"] = self.customer_id
            
            # Queue for background sending (non-blocking)
            try:
                self.queue.put_nowait(event)
            except:
                pass  # Queue full, drop log
        except Exception:
            pass
    
    def _worker(self):
        """Background worker thread to send logs."""
        while True:
            try:
                event = self.queue.get(timeout=1.0)
                try:
                    self.client.post(
                        self.url,
                        json={"events": [event]},
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {self.api_key}",
                        },
                    )
                except Exception:
                    pass  # Fail silently
                finally:
                    self.queue.task_done()
            except:
                continue
    
    def _map_log_level_to_event_type(self, level: str) -> str:
        """Map log level to Chronicle event type."""
        mapping = {
            "DEBUG": "GENERIC_EVENT",
            "INFO": "GENERIC_EVENT",
            "WARNING": "SECURITY_EVENT",
            "ERROR": "SECURITY_EVENT",
            "CRITICAL": "SECURITY_EVENT",
        }
        return mapping.get(level, "GENERIC_EVENT")
    
    def _map_log_level_to_severity(self, level: str) -> str:
        """Map log level to Chronicle severity."""
        mapping = {
            "DEBUG": "LOW",
            "INFO": "LOW",
            "WARNING": "MEDIUM",
            "ERROR": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        return mapping.get(level, "LOW")


# Configure external logging handlers
if DATADOG_API_KEY:
    datadog_handler = DatadogLogHandler(DATADOG_API_KEY, DATADOG_SITE, DATADOG_SERVICE, DATADOG_ENV)
    datadog_handler.setLevel(logging.INFO)
    logger.addHandler(datadog_handler)
    logger.info("Datadog logging enabled")

if GOOGLE_CHRONICLE_API_KEY:
    chronicle_handler = GoogleChronicleLogHandler(
        GOOGLE_CHRONICLE_API_KEY, 
        GOOGLE_CHRONICLE_REGION, 
        GOOGLE_CHRONICLE_CUSTOMER_ID,
        GOOGLE_CHRONICLE_LOG_TYPE
    )
    chronicle_handler.setLevel(logging.INFO)
    logger.addHandler(chronicle_handler)
    logger.info("Google Chronicle logging enabled")


# Optional: Global max request size enforcement using Content-Length header
MAX_REQUEST_BYTES = int(os.getenv("PROXY_MAX_REQUEST_BYTES", "20971520"))  # 20 MiB default


@app.middleware("http")
async def security_monitoring_middleware(request: Request, call_next):
    """Enhanced security monitoring middleware."""
    start_time = datetime.utcnow()
    client_ip = get_client_ip(request)
    
    # Track request patterns for security monitoring
    request_path = str(request.url.path)
    request_method = request.method
    
    try:
        response = await call_next(request)
        
        # Enhanced monitoring: log suspicious patterns
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Log slow requests (potential DoS)
        if duration > 10:
            logger.warning(
                "Slow request detected",
                extra={
                    "dd_extra": {
                        "event_type": "slow_request",
                        "duration": duration,
                        "path": request_path[:200],
                        "method": request_method,
                        "client_ip": client_ip,
                    }
                }
            )
        
        # Log high status codes
        if response.status_code >= 400:
            logger.info(
                f"Request returned {response.status_code}",
                extra={
                    "dd_extra": {
                        "event_type": "http_error",
                        "status_code": response.status_code,
                        "path": request_path[:200],
                        "method": request_method,
                        "client_ip": client_ip,
                    }
                }
            )
        
        return response
    except Exception as e:
        logger.error(f"Request processing error: {e}", exc_info=True)
        raise


@app.middleware("http")
async def max_request_size_middleware(request: Request, call_next):
    try:
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            declared_size = int(content_length)
            if declared_size > MAX_REQUEST_BYTES:
                logger.warning("Request rejected: content-length exceeds limit (%s > %s)", content_length, MAX_REQUEST_BYTES)
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "Payload Too Large",
                        "message": "Request body exceeds maximum allowed size",
                        "type": "REQUEST_SIZE_LIMIT"
                    },
                )
            # Also check if body is being streamed and exceeds limit
            # Note: FastAPI reads body into memory, so we'll check actual size in _proxy
    except (ValueError, OverflowError):
        # Invalid content-length header
        return JSONResponse(
            status_code=400,
            content={
                "error": "Bad Request",
                "message": "Invalid Content-Length header",
                "type": "INVALID_HEADER"
            },
        )
    except Exception:
        # Fail-open on other errors
        pass

    return await call_next(request)


@app.get("/healthz")
@limiter.limit("10/minute")
async def health(request: Request) -> Response:
    if not TARGET_URL:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "reason": "TARGET_URL not configured"},
        )
    return JSONResponse({"status": "ok"})


def _merge_paths(base: str, *parts: str) -> str:
    base_sanitized = base.rstrip("/")
    path_segments = [p.strip("/") for p in parts if p is not None and p != ""]
    if not path_segments:
        return base_sanitized or "/"
    return f"{base_sanitized}/" + "/".join(path_segments)


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def _filter_request_headers(headers: Iterable[tuple[str, str]]) -> Dict[str, str]:
    filtered: Dict[str, str] = {}
    for key, value in headers:
        lk = key.lower()
        if lk in HOP_BY_HOP_HEADERS or lk == "host" or lk == "content-length":
            continue
        filtered[key] = value
    return filtered


def _filter_response_headers(headers: Iterable[tuple[bytes, bytes]]) -> Dict[str, str]:
    filtered: Dict[str, str] = {}
    for key_b, value_b in headers:
        key = key_b.decode("latin-1")
        value = value_b.decode("latin-1")
        lk = key.lower()
        if lk in HOP_BY_HOP_HEADERS:
            continue
        filtered[key] = value
    return filtered


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def _default_port_for_scheme(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _resolve_ips(hostname: str) -> list[str]:
    """Resolve hostname to IPs with timeout to prevent DoS."""
    try:
        # Set socket timeout to prevent hanging on DNS resolution
        socket.setdefaulttimeout(5.0)  # 5 second timeout
        infos = socket.getaddrinfo(hostname, None)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except (socket.timeout, socket.gaierror, Exception):
        return []
    finally:
        # Reset timeout
        socket.setdefaulttimeout(None)


def _validate_url_ssrf(url: str) -> tuple[bool, Optional[str]]:
    """
    Validate URL for SSRF protection.
    Returns (is_valid, error_message).
    """
    try:
        parsed = urlparse(url)
        
        # Must have a hostname
        if not parsed.hostname:
            return False, "URL must have a hostname"
        
        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            # Block private/internal IPs
            if _is_private_ip(parsed.hostname):
                return False, f"Access to private/internal IP {parsed.hostname} is blocked"
        except ValueError:
            # Not an IP, treat as hostname
            pass
        
        # Validate hostname matches allowed TARGET_URL hostname
        if ALLOWED_HOSTNAME:
            # Normalize hostnames (case-insensitive)
            if parsed.hostname.lower() != ALLOWED_HOSTNAME.lower():
                return False, f"Hostname {parsed.hostname} does not match allowed hostname {ALLOWED_HOSTNAME}"

        # Enforce port matches allowed TARGET_URL port (defaulting by scheme)
        try:
            allowed_parsed = urlparse(TARGET_URL or "")
            allowed_port = allowed_parsed.port or _default_port_for_scheme(allowed_parsed.scheme or "http")
            url_port = parsed.port or _default_port_for_scheme(parsed.scheme or "http")
            if url_port != allowed_port:
                return False, f"Port {url_port} is not allowed"
        except Exception:
            pass
        
        # Block dangerous schemes
        if parsed.scheme not in ("http", "https"):
            return False, f"Scheme {parsed.scheme} is not allowed (only http/https)"
        
        # Additional validation: check for encoded characters that might bypass checks
        # This helps prevent double-encoding attacks
        if "%" in parsed.hostname or "\\" in parsed.hostname:
            return False, "Invalid characters in hostname"
        
        # Decode URL-encoded hostname and re-validate to prevent encoding bypass
        try:
            from urllib.parse import unquote
            decoded_hostname = unquote(parsed.hostname)
            if decoded_hostname != parsed.hostname:
                # Hostname was encoded, validate the decoded version
                try:
                    ip = ipaddress.ip_address(decoded_hostname)
                    if _is_private_ip(decoded_hostname):
                        return False, f"Encoded hostname decodes to private/internal IP {decoded_hostname}"
                except ValueError:
                    # Not an IP, check if decoded hostname matches allowed
                    if ALLOWED_HOSTNAME and decoded_hostname.lower() != ALLOWED_HOSTNAME.lower():
                        return False, f"Encoded hostname does not match allowed hostname"
        except Exception:
            pass
        
        # DNS resolution checks to avoid DNS rebinding to private IPs
        resolved_ips = _resolve_ips(parsed.hostname)
        if not resolved_ips:
            return False, "Unable to resolve upstream hostname"
        for ip in resolved_ips:
            if _is_private_ip(ip):
                return False, f"Resolved IP {ip} is private/internal"

        # Also resolve the allowed hostname and ensure it does not resolve privately
        if ALLOWED_HOSTNAME:
            allowed_ips = _resolve_ips(ALLOWED_HOSTNAME)
            if not allowed_ips:
                return False, "Unable to resolve allowed hostname"
            for ip in allowed_ips:
                if _is_private_ip(ip):
                    return False, f"Allowed hostname resolves to private/internal IP {ip}"

        return True, None
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"


def _sanitize_string(value: str) -> str:
    """Sanitize a string value to mitigate XSS/injection when forwarded upstream."""
    return bleach.clean(value, tags=[], strip=True)


def _sanitize_json(obj: Any) -> Any:
    """Recursively sanitize JSON values (strings only)."""
    if isinstance(obj, dict):
        return {k: _sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_json(i) for i in obj]
    if isinstance(obj, str):
        return _sanitize_string(obj)
    return obj


def _is_json_content_type(content_type: str) -> bool:
    return "application/json" in content_type


def _is_urlencoded_content_type(content_type: str) -> bool:
    return "application/x-www-form-urlencoded" in content_type


def _is_text_content_type(content_type: str) -> bool:
    return content_type.startswith("text/") or "application/xml" in content_type or "application/xhtml+xml" in content_type


def _sanitize_request_body(raw_body: bytes, content_type: str) -> bytes:
    """Sanitize request body based on content type. Skip binary/multipart.

    - JSON: sanitize string values
    - x-www-form-urlencoded: sanitize values and re-encode
    - text/xml/xhtml: sanitize as text
    - multipart/* and others: return as-is to avoid corrupting binary uploads
    - Large bodies over MAX_BODY_SANITIZE_BYTES: return as-is to avoid latency
    """
    if not raw_body:
        return raw_body

    if len(raw_body) > MAX_BODY_SANITIZE_BYTES:
        return raw_body

    ct = (content_type or "").lower()
    if not ct or ct.startswith("multipart/"):
        return raw_body

    try:
        if _is_json_content_type(ct):
            data = json.loads(raw_body.decode("utf-8", errors="strict"))
            sanitized = _sanitize_json(data)
            return json.dumps(sanitized, separators=(",", ":")).encode("utf-8")

        if _is_urlencoded_content_type(ct):
            pairs = parse_qsl(raw_body.decode("utf-8", errors="strict"), keep_blank_values=True)
            sanitized_pairs = [(k, _sanitize_string(v)) for k, v in pairs]
            return urlencode(sanitized_pairs).encode("utf-8")

        if _is_text_content_type(ct):
            text = raw_body.decode("utf-8", errors="strict")
            return _sanitize_string(text).encode("utf-8")

    except Exception:
        # On any parsing error, fall back to original body to avoid breaking requests
        return raw_body

    return raw_body


async def _proxy(request: Request, full_path: str, token: Optional[Dict] = None) -> StreamingResponse:
    if not TARGET_URL:
        return JSONResponse(
            status_code=500,
            content={"error": "TARGET_URL environment variable is required"},
        )

    #
    # OHS Custom protection code here
    # Path sanitization: Check for dangerous patterns before processing
    #
    if full_path:
        # Check for dangerous path patterns
        dangerous_patterns = [
            "../",  # Directory traversal
            "..\\",  # Windows directory traversal
            "\x00",  # Null byte
        ]
        for pattern in dangerous_patterns:
            if pattern in full_path:
                # Enhanced logging with structured data
                log_record = logging.LogRecord(
                    name=logger.name,
                    level=logging.WARNING,
                    pathname="",
                    lineno=0,
                    msg="Path sanitization blocked",
                    args=(),
                    exc_info=None,
                )
                log_record.dd_extra = {
                    "event_type": "path_sanitization_blocked",
                    "pattern": pattern,
                    "path": full_path[:200],
                    "client_ip": request.client.host if request.client else None,
                    "user_agent": request.headers.get("user-agent"),
                }
                log_record.chronicle_extra = {
                    "network": {
                        "http": {
                            "request": {
                                "method": request.method,
                                "url": str(request.url),
                            }
                        }
                    },
                    "about": {
                        "labels": ["PATH_SANITIZATION", "SECURITY_EVENT"],
                    },
                }
                logger.handle(log_record)
                logger.warning("Path sanitization blocked: pattern=%r path=%r", pattern, full_path[:200])
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Bad Request",
                        "message": f"Dangerous pattern detected in path: {repr(pattern)}",
                        "type": "PATH_SANITIZATION"
                    }
                )
        
        # Additional sanitization with bleach for HTML/script injection prevention
        sanitized_path = bleach.clean(full_path, tags=[], strip=True)
        # Only reject if bleach significantly modified the path (indicating injection attempt)
        if len(sanitized_path) < len(full_path) * 0.8:  # Allow minor changes, reject major ones
            # Enhanced logging with structured data
            log_record = logging.LogRecord(
                name=logger.name,
                level=logging.WARNING,
                pathname="",
                lineno=0,
                msg="Path sanitization blocked: sanitized shrinkage threshold exceeded",
                args=(),
                exc_info=None,
            )
            log_record.dd_extra = {
                "event_type": "path_sanitization_blocked",
                "reason": "sanitized_shrinkage_threshold",
                "path": full_path[:200],
                "client_ip": request.client.host if request.client else None,
            }
            log_record.chronicle_extra = {
                "network": {
                    "http": {
                        "request": {
                            "method": request.method,
                            "url": str(request.url),
                        }
                    }
                },
            }
            logger.handle(log_record)
            logger.warning("Path sanitization blocked: sanitized shrinkage threshold exceeded")
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Bad Request",
                    "message": "Invalid characters detected in path",
                    "type": "PATH_SANITIZATION"
                }
            )

    upstream_base = TARGET_URL
    path_to_forward = _merge_paths("", PROXY_PREFIX, full_path)
    upstream_url = _merge_paths(upstream_base, path_to_forward)
    if request.url.query:
        # Sanitize query string to prevent injection
        from urllib.parse import parse_qs
        try:
            query_params = parse_qs(request.url.query, keep_blank_values=True)
            # Sanitize query parameter values
            sanitized_params = {}
            for key, values in query_params.items():
                sanitized_key = _sanitize_string(key) if isinstance(key, str) else key
                sanitized_values = [_sanitize_string(str(v)) if isinstance(v, str) else str(v) for v in values]
                sanitized_params[sanitized_key] = sanitized_values
            upstream_url = f"{upstream_url}?{urlencode(sanitized_params, doseq=True)}"
        except Exception:
            # If parsing fails, reject the request
            return JSONResponse(
                status_code=400,
                content={"error": "Bad Request", "message": "Invalid query string", "type": "QUERY_SANITIZATION"}
            )

    #
    # SSRF Protection: Validate final URL before making request
    #
    is_valid, error_msg = _validate_url_ssrf(upstream_url)
    if not is_valid:
        # Enhanced logging with structured data
        log_record = logging.LogRecord(
            name=logger.name,
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg=f"SSRF blocked: {error_msg}",
            args=(),
            exc_info=None,
        )
        log_record.dd_extra = {
            "event_type": "ssrf_blocked",
            "error": error_msg,
            "blocked_url": upstream_url[:500],  # Truncate to prevent log injection
            "client_ip": request.client.host if request.client else None,
            "user_agent": (request.headers.get("user-agent") or "")[:200],  # Truncate user agent
        }
        log_record.chronicle_extra = {
            "network": {
                "http": {
                    "request": {
                        "method": request.method,
                        "url": str(request.url),
                    }
                }
            },
            "security_result": {
                "action": "BLOCKED",
                "category": "SSRF_ATTEMPT",
            },
        }
        logger.handle(log_record)
        logger.warning("SSRF blocked: %s", error_msg)
        return JSONResponse(
            status_code=403,
            content={
                "error": "Forbidden",
                "message": error_msg or "URL validation failed",
                "type": "SSRF_PROTECTION"
            }
        )

    method = request.method
    # OHS Custom Protection code for sanitizing the body from XSS & Injection attacks
    raw_body: Optional[bytes] = await request.body()
    
    # Validate actual body size (not just Content-Length header) to prevent bypass
    if raw_body and len(raw_body) > MAX_REQUEST_BYTES:
        logger.warning("Request rejected: actual body size exceeds limit (%s > %s)", len(raw_body), MAX_REQUEST_BYTES)
        return JSONResponse(
            status_code=413,
            content={
                "error": "Payload Too Large",
                "message": "Request body exceeds maximum allowed size",
                "type": "REQUEST_SIZE_LIMIT"
            },
        )
    
    content_type_header = request.headers.get("content-type", "")
    body = _sanitize_request_body(raw_body or b"", content_type_header)

    headers = _filter_request_headers(request.headers.raw)

    client_host = request.client.host if request.client else ""
    # Sanitize X-Forwarded-For to prevent header injection
    xff = request.headers.get("x-forwarded-for", "")
    # Validate X-Forwarded-For contains only IP addresses (comma-separated)
    if xff:
        # Remove any newlines, carriage returns, or other control characters
        xff = "".join(c for c in xff if c.isprintable() or c in [",", " "])
        # Validate each IP in the chain
        xff_ips = [ip.strip() for ip in xff.split(",")]
        valid_ips = []
        for ip in xff_ips:
            try:
                # Validate it's a valid IP address
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                # Invalid IP, skip it
                pass
        if valid_ips:
            headers["x-forwarded-for"] = ", ".join(valid_ips + ([client_host] if client_host else []))
        else:
            headers["x-forwarded-for"] = client_host
    else:
        headers["x-forwarded-for"] = client_host
    headers["x-forwarded-proto"] = request.url.scheme
    headers["x-forwarded-host"] = request.headers.get("host", "")
    
    # Per-request timeout (separate from connection timeout)
    timeout = httpx.Timeout(
        connect=TIMEOUT_SECONDS,
        read=PER_REQUEST_TIMEOUT,
        write=PER_REQUEST_TIMEOUT,
        pool=TIMEOUT_SECONDS
    )
    
    # TLS version enforcement (cache SSL context)
    import ssl
    if not hasattr(app.state, '_ssl_context'):
        ssl_context = None
        if not ALLOW_INSECURE_SSL:
            ssl_context = ssl.create_default_context()
            # Enforce minimum TLS version
            if MIN_TLS_VERSION == "1.3":
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
            elif MIN_TLS_VERSION == "1.2":
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            else:
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        app.state._ssl_context = ssl_context
    ssl_context = app.state._ssl_context
    
    limits = httpx.Limits(max_connections=HTTPX_MAX_CONNECTIONS, max_keepalive_connections=HTTPX_MAX_KEEPALIVE, keepalive_expiry=HTTPX_KEEPALIVE_EXPIRY)
    async with httpx.AsyncClient(
        verify=ssl_context if ssl_context else (not ALLOW_INSECURE_SSL),
        timeout=timeout,
        limits=limits
    ) as client:
        upstream_response = await client.request(
            method,
            upstream_url,
            content=body,
            headers=headers,
            cookies=request.cookies,
        )

    response_headers = _filter_response_headers(upstream_response.headers.raw)

    def iter_content() -> Iterable[bytes]:
        yield from upstream_response.iter_bytes()

    return StreamingResponse(
        iter_content(),
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
        background=None,
    )


def _apply_rate_limit(func):
    """Conditionally apply rate limiting."""
    if RATE_LIMIT_ENABLED:
        return limiter.limit(f"{RATE_LIMIT_PER_MINUTE}/minute")(func)
    return func

@app.api_route("/{full_path:path}", methods=[
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
])
@_apply_rate_limit
async def proxy_all(
    request: Request, 
    full_path: str,
    token: Optional[Dict] = Depends(verify_azure_token)
) -> Response:
    return await _proxy(request, full_path, token)


if __name__ == "__main__":
    import aikido_zen
    aikido_zen.protect()

    import uvicorn
    port = int(os.getenv("PORT", "9000"))
    uvicorn.run("protectproxy:app", host="0.0.0.0", port=port, reload=get_env_bool("RELOAD", False))


