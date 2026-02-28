# Test Server for Sentinel

This directory contains a vulnerable FastAPI server for testing Sentinel security scanner.

## ⚠️ WARNING

**This API is intentionally vulnerable!** DO NOT deploy this in production or expose it to the internet. It contains:

- SQL Injection vulnerabilities
- Authentication bypass vulnerabilities  
- IDOR (Insecure Direct Object Reference) vulnerabilities

## Running the Server

```bash
# From the sentinel project root
pip install -r requirements.txt

# Start the vulnerable API server
cd test_server
python vulnerable_api.py
```

The server will start on `http://localhost:8000`

## API Documentation

Once the server is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Testing with Sentinel

```bash
# In another terminal
cd /path/to/sentinel
python -m sentinel scan --swagger examples/sample_api.yaml --target http://localhost:8000
```

## Included Vulnerabilities

### 1. SQL Injection
- **Endpoint**: `GET /api/users?search=`
- **Payload**: `' OR '1'='1`
- **Effect**: Returns all users with sensitive data

### 2. Authentication Bypass
- **Endpoint**: `GET /api/users/{id}`
- **Issue**: Accepts invalid or missing auth tokens
- **Effect**: Access protected data without authentication

### 3. IDOR
- **Endpoint**: `GET /api/orders/{id}`
- **Issue**: No ownership validation
- **Effect**: Access any user's orders by changing ID

## Sample Credentials

For testing authentication:
- Admin: `admin` / `admin123`
- User: `user1` / `password`
