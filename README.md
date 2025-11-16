# Reverse Proxy (FastAPI)

A lightweight reverse proxy built with FastAPI and httpx.

## Requirements

- Python 3.10+

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure

Set environment variables:

- `TARGET_URL` (required): Upstream base URL to proxy to (e.g., `https://httpbin.org`).
- `PROXY_PREFIX` (optional): Prefix to add between base and forwarded path.
- `PROXY_TIMEOUT_SECONDS` (optional, default `60`).
- `PROXY_ALLOW_INSECURE_SSL` (optional, default `false`): `true` to skip TLS verification.
- `PROXY_MAX_BODY_SANITIZE_BYTES` (optional, default `1048576`): Maximum request body size to sanitize (1 MiB). Larger bodies are passed through without sanitization. Recommended: `524288` (512 KiB) for small payloads, `1048576` (1 MiB) for most APIs, `5242880` (5 MiB) for large JSON/XML payloads.
- `PROXY_PER_REQUEST_TIMEOUT` (optional, default `30`): Per-request timeout in seconds (separate from connection timeout).
- `MIN_TLS_VERSION` (optional, default `1.2`): Minimum TLS version to enforce (`1.2` or `1.3`).
- `PORT` (optional, default `8000`).
- `RELOAD` (optional, default `false`).

### Azure Entra OAuth2 Authentication

- `AZURE_ENABLE_AUTH` (optional, default `false`): Enable Azure Entra OAuth2 authentication.
- `AZURE_TENANT_ID` (required if auth enabled): Your Azure AD tenant ID.
- `AZURE_CLIENT_ID` (required if auth enabled): Your Azure AD application (client) ID.
- `AZURE_AUDIENCE` (optional): Token audience (defaults to `AZURE_CLIENT_ID`).

### Rate Limiting

- `RATE_LIMIT_ENABLED` (optional, default `true`): Enable rate limiting.
- `RATE_LIMIT_PER_MINUTE` (optional, default `60`): Maximum requests per minute per IP.
- `RATE_LIMIT_PER_HOUR` (optional, default `1000`): Maximum requests per hour per IP (for future use).

### External Logging Services

- **Datadog** (optional):
  - `DATADOG_API_KEY`: Your Datadog API key (required for Datadog logging)
  - `DATADOG_SITE`: Datadog site (default: `datadoghq.com`, use `datadoghq.eu` for EU)
  - `DATADOG_SERVICE`: Service name (default: `reverse-proxy`)
  - `DATADOG_ENV`: Environment name (default: `production`)

- **Google Chronicle** (optional):
  - `GOOGLE_CHRONICLE_API_KEY`: Your Chronicle API key (required for Chronicle logging)
  - `GOOGLE_CHRONICLE_REGION`: Chronicle region (default: `us`, options: `us`, `eu`, `asia`)
  - `GOOGLE_CHRONICLE_CUSTOMER_ID`: Optional customer ID for multi-tenant setups
  - `GOOGLE_CHRONICLE_LOG_TYPE`: Log type identifier (default: `REVERSE_PROXY`). This is required by Chronicle for proper log categorization and processing.

## Run

```bash
export TARGET_URL="https://httpbin.org"
python protectproxy.py
```

Or with uvicorn explicitly:

```bash
uvicorn protectproxy:app --host 0.0.0.0 --port 8000
```

## How it works

- Proxies all HTTP methods and paths: `/{full_path}` → `${TARGET_URL}/{PROXY_PREFIX}/{full_path}`
- Preserves query strings and cookies.
- Forwards headers except hop-by-hop and `Host`/`Content-Length`.
- Adds `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host`.
- Health check at `/healthz`.

## Security Features

- **SSRF Protection**: Validates URLs to prevent requests to private/internal IPs and ensures requests only go to the configured `TARGET_URL` hostname.
- **Path Sanitization**: Blocks directory traversal attacks (`../`, `..\\`) and null bytes.
- **Body Sanitization**: Sanitizes request bodies to prevent XSS and injection attacks:
  - JSON payloads: Recursively sanitizes all string values
  - Form data: Sanitizes form field values
  - Text/XML: Sanitizes text content
  - Multipart/binary: Passed through unchanged (to avoid corrupting file uploads)
  - Large bodies (> `PROXY_MAX_BODY_SANITIZE_BYTES`): Passed through to avoid performance impact

## Logging

The proxy supports structured logging to external services:

- **Standard Logging**: All logs are written to stdout/stderr with structured format
- **Datadog Integration**: Automatically sends logs to Datadog when `DATADOG_API_KEY` is configured
- **Google Chronicle Integration**: Automatically sends security events to Chronicle when `GOOGLE_CHRONICLE_API_KEY` is configured

### Security Event Logging

Security events are automatically logged with structured data:
- **SSRF Attempts**: Logged with blocked URL, client IP, user agent
- **Path Sanitization Blocks**: Logged with pattern detected, path, client IP
- **Request Size Limits**: Logged when requests exceed size limits

All security events include:
- Timestamp
- Event type and severity
- Client IP address
- User agent
- Request details (method, URL)
- Structured metadata for SIEM integration

### Example .env Configuration

```env
# Basic configuration
TARGET_URL=https://api.example.com
PROXY_PREFIX=/api

# Azure Entra OAuth2 Authentication
AZURE_ENABLE_AUTH=true
AZURE_TENANT_ID=your-tenant-id-here
AZURE_CLIENT_ID=your-client-id-here
AZURE_AUDIENCE=your-client-id-here  # Usually same as client ID

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# Security Settings
PROXY_PER_REQUEST_TIMEOUT=30
MIN_TLS_VERSION=1.2

# Logging configuration
DATADOG_API_KEY=your_datadog_api_key_here
DATADOG_SERVICE=reverse-proxy
DATADOG_ENV=production

GOOGLE_CHRONICLE_API_KEY=your_chronicle_api_key_here
GOOGLE_CHRONICLE_REGION=us
GOOGLE_CHRONICLE_LOG_TYPE=REVERSE_PROXY
```

## Azure Entra OAuth2 Setup

To enable Azure Entra authentication:

1. **Register an application in Azure AD:**
   - Go to Azure Portal → Azure Active Directory → App registrations
   - Create a new registration
   - Note the **Application (client) ID** and **Directory (tenant) ID**

2. **Configure API permissions:**
   - Add the required API permissions for your application
   - Grant admin consent if needed

3. **Set environment variables:**
   ```env
   AZURE_ENABLE_AUTH=true
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-client-id
   AZURE_AUDIENCE=your-client-id  # Usually same as client ID
   ```

4. **Client requests must include Bearer token:**
   ```bash
   curl -H "Authorization: Bearer <your-access-token>" \
        http://localhost:8000/api/endpoint
   ```

The proxy validates tokens using Azure AD's public keys (JWKS) and enforces:
- Token expiration
- Audience validation
- Issuer validation
- Signature verification