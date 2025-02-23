"""
Vulnerable FastAPI server for testing Sentinel.

This API intentionally contains security vulnerabilities for educational
and testing purposes. DO NOT deploy this in production!

Vulnerabilities included:
1. SQL Injection in /api/users endpoint
2. Auth Bypass in /api/users/{id} endpoint
3. IDOR in /api/orders/{id} endpoint
"""

import json
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="Vulnerable Test API",
    description="Intentionally vulnerable API for testing Sentinel",
    version="1.0.0"
)

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock database (in-memory)
fake_db = {
    "users": [
        {"id": 1, "username": "admin", "password": "admin123", "email": "admin@example.com", "role": "admin"},
        {"id": 2, "username": "user1", "password": "password", "email": "user1@example.com", "role": "user"},
        {"id": 3, "username": "user2", "password": "password", "email": "user2@example.com", "role": "user"},
    ],
    "products": [
        {"id": 1, "name": "Laptop", "price": 999.99, "category": "electronics", "stock": 50},
        {"id": 2, "name": "Phone", "price": 699.99, "category": "electronics", "stock": 100},
        {"id": 3, "name": "Book", "price": 19.99, "category": "books", "stock": 200},
    ],
    "orders": [
        {"id": 1, "user_id": 1, "status": "completed", "total": 999.99, "products": [{"product_id": 1, "quantity": 1}]},
        {"id": 2, "user_id": 2, "status": "pending", "total": 699.99, "products": [{"product_id": 2, "quantity": 1}]},
        {"id": 3, "user_id": 3, "status": "completed", "total": 39.98, "products": [{"product_id": 3, "quantity": 2}]},
    ],
    "tokens": {
        "valid_token": {"user_id": 2, "role": "user"},
        "admin_token": {"user_id": 1, "role": "admin"},
    }
}

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    category: Optional[str] = None
    stock: int = 0

class OrderCreate(BaseModel):
    products: list
    shipping_address: Optional[str] = None

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None


# Helper functions
def get_user_by_token(token: str):
    """Get user from token (simplified)."""
    if token in fake_db["tokens"]:
        token_data = fake_db["tokens"][token]
        for user in fake_db["users"]:
            if user["id"] == token_data["user_id"]:
                return user
    return None


# ==================== AUTH ENDPOINTS ====================

@app.post("/api/auth/login")
async def login(request: LoginRequest):
    """
    User login endpoint.
    
    VULNERABILITY: Returns password in response (information disclosure)
    """
    for user in fake_db["users"]:
        if user["username"] == request.username and user["password"] == request.password:
            # Generate token (simplified)
            token = f"token_{user['id']}"
            fake_db["tokens"][token] = {"user_id": user["id"], "role": user["role"]}
            return {
                "token": token,
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"]
                    # VULNERABILITY: Should NOT return password!
                    # "password": user["password"]  # Uncomment for extra vulnerability
                }
            }
    
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/auth/register")
async def register(request: RegisterRequest):
    """User registration endpoint."""
    # Check if username exists
    for user in fake_db["users"]:
        if user["username"] == request.username:
            raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create new user
    new_user = {
        "id": len(fake_db["users"]) + 1,
        "username": request.username,
        "password": request.password,  # VULNERABILITY: Stored in plain text
        "email": request.email,
        "role": "user"
    }
    fake_db["users"].append(new_user)
    
    return {"message": "User created successfully", "user_id": new_user["id"]}


# ==================== USER ENDPOINTS ====================

@app.get("/api/users")
async def get_users(
    authorization: Optional[str] = Header(None),
    page: int = Query(1),
    limit: int = Query(10),
    search: Optional[str] = Query(None)
):
    """
    Get all users endpoint.
    
    VULNERABILITY: Auth bypass - accepts any token format
    VULNERABILITY: SQL injection in search parameter (simulated)
    """
    # VULNERABILITY: Weak auth check - any non-empty auth header is accepted
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    users = fake_db["users"].copy()
    
    # VULNERABILITY: Simulated SQL injection
    if search:
        # In a real app with SQL, this would be:
        # query = f"SELECT * FROM users WHERE username LIKE '%{search}%'"
        # This allows SQL injection
        
        # Simulate SQL injection success
        sql_patterns = ["'", "OR", "--", "1=1", "' OR '1'='1"]
        if any(pattern in search.upper() for pattern in sql_patterns):
            # VULNERABILITY: SQL injection returns all users with passwords
            return {
                "users": users,  # Returns ALL users including passwords
                "sql_query": f"SELECT * FROM users WHERE username LIKE '%{search}%'",  # Exposes query
                "injection_detected": True
            }
        
        # Normal search
        users = [u for u in users if search.lower() in u["username"].lower()]
    
    # Remove passwords from response (security best practice)
    safe_users = [{k: v for k, v in u.items() if k != "password"} for u in users]
    
    return safe_users


@app.get("/api/users/{user_id}")
async def get_user(
    user_id: int,
    authorization: Optional[str] = Header(None)
):
    """
    Get user by ID endpoint.
    
    VULNERABILITY: IDOR - No authorization check, any user can access any other user's data
    VULNERABILITY: Auth bypass - weak token validation
    """
    # VULNERABILITY: Accepts empty or invalid tokens
    if authorization is None:
        # Should return 401, but we're vulnerable
        pass  # VULNERABILITY: Allows access without auth!
    
    for user in fake_db["users"]:
        if user["id"] == user_id:
            return {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"]
            }
    
    raise HTTPException(status_code=404, detail="User not found")


@app.put("/api/users/{user_id}")
async def update_user(
    user_id: int,
    request: UserUpdate,
    authorization: Optional[str] = Header(None)
):
    """
    Update user endpoint.
    
    VULNERABILITY: IDOR - Can update any user's data
    """
    # VULNERABILITY: No proper auth check
    
    for user in fake_db["users"]:
        if user["id"] == user_id:
            if request.username:
                user["username"] = request.username
            if request.email:
                user["email"] = request.email
            return {"message": "User updated", "user": user}
    
    raise HTTPException(status_code=404, detail="User not found")


@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: int,
    authorization: Optional[str] = Header(None)
):
    """
    Delete user endpoint.
    
    VULNERABILITY: IDOR + No auth check
    """
    # VULNERABILITY: No auth check at all!
    
    for i, user in enumerate(fake_db["users"]):
        if user["id"] == user_id:
            deleted = fake_db["users"].pop(i)
            return {"message": f"User {user_id} deleted"}
    
    raise HTTPException(status_code=404, detail="User not found")


# ==================== PRODUCT ENDPOINTS ====================

@app.get("/api/products")
async def get_products(
    category: Optional[str] = Query(None),
    min_price: Optional[float] = Query(None),
    max_price: Optional[float] = Query(None),
    sort: Optional[str] = Query(None),
    order: str = Query("asc")
):
    """Get all products."""
    products = fake_db["products"].copy()
    
    if category:
        products = [p for p in products if p["category"] == category]
    
    if min_price is not None:
        products = [p for p in products if p["price"] >= min_price]
    
    if max_price is not None:
        products = [p for p in products if p["price"] <= max_price]
    
    if sort:
        reverse = order == "desc"
        if sort == "price":
            products.sort(key=lambda x: x["price"], reverse=reverse)
        elif sort == "name":
            products.sort(key=lambda x: x["name"], reverse=reverse)
    
    return products


@app.post("/api/products")
async def create_product(
    request: ProductCreate,
    authorization: Optional[str] = Header(None)
):
    """Create product endpoint."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    new_product = {
        "id": len(fake_db["products"]) + 1,
        "name": request.name,
        "description": request.description,
        "price": request.price,
        "category": request.category,
        "stock": request.stock
    }
    fake_db["products"].append(new_product)
    
    return {"message": "Product created", "product": new_product}


@app.get("/api/products/{product_id}")
async def get_product(product_id: int):
    """Get product by ID."""
    for product in fake_db["products"]:
        if product["id"] == product_id:
            return product
    
    raise HTTPException(status_code=404, detail="Product not found")


# ==================== ORDER ENDPOINTS ====================

@app.get("/api/orders")
async def get_orders(
    authorization: Optional[str] = Header(None),
    status: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None)
):
    """
    Get orders endpoint.
    
    VULNERABILITY: Can view other users' orders via user_id parameter (IDOR)
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    orders = fake_db["orders"].copy()
    
    if status:
        orders = [o for o in orders if o["status"] == status]
    
    # VULNERABILITY: Any user can view any other user's orders
    if user_id:
        orders = [o for o in orders if o["user_id"] == user_id]
    
    return orders


@app.post("/api/orders")
async def create_order(
    request: OrderCreate,
    authorization: Optional[str] = Header(None)
):
    """Create order endpoint."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Calculate total
    total = 0
    for item in request.products:
        for product in fake_db["products"]:
            if product["id"] == item.get("product_id"):
                total += product["price"] * item.get("quantity", 1)
    
    new_order = {
        "id": len(fake_db["orders"]) + 1,
        "user_id": 1,  # Simplified: always assign to user 1
        "status": "pending",
        "total": total,
        "products": request.products,
        "shipping_address": request.shipping_address
    }
    fake_db["orders"].append(new_order)
    
    return {"message": "Order created", "order": new_order}


@app.get("/api/orders/{order_id}")
async def get_order(
    order_id: int,
    authorization: Optional[str] = Header(None)
):
    """
    Get order by ID endpoint.
    
    VULNERABILITY: IDOR - No check if user owns the order
    """
    # VULNERABILITY: Auth check exists but doesn't validate ownership
    if not authorization:
        # Should return 401, but we allow access anyway
        pass  # VULNERABILITY: Auth bypass
    
    for order in fake_db["orders"]:
        if order["id"] == order_id:
            # VULNERABILITY: Returns order without checking ownership
            return order
    
    raise HTTPException(status_code=404, detail="Order not found")


# ==================== SEARCH ENDPOINT ====================

@app.get("/api/search")
async def search_products(
    q: str = Query(...),
    fields: Optional[str] = Query(None)
):
    """
    Search products endpoint.
    
    VULNERABILITY: SQL injection in search query
    """
    results = []
    
    # VULNERABILITY: Simulated SQL injection
    sql_patterns = ["'", "OR", "--", "1=1", "UNION"]
    if any(pattern in q.upper() for pattern in sql_patterns):
        # Simulate SQL injection returning all products with extra data
        return {
            "results": fake_db["products"],
            "query": f"SELECT * FROM products WHERE name LIKE '%{q}%'",  # Exposes query
            "warning": "SQL injection detected in query"
        }
    
    # Normal search
    for product in fake_db["products"]:
        if q.lower() in product["name"].lower():
            results.append(product)
    
    return results


# ==================== HEALTH CHECK ====================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Vulnerable Test API",
        "version": "1.0.0",
        "docs": "/docs",
        "warning": "This API is intentionally vulnerable. DO NOT deploy in production!"
    }


if __name__ == "__main__":
    import uvicorn
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║          VULNERABLE TEST API - FOR TESTING ONLY              ║
    ║                                                               ║
    ║  This API contains intentional security vulnerabilities:      ║
    ║  - SQL Injection                                              ║
    ║  - Authentication Bypass                                      ║
    ║  - IDOR (Insecure Direct Object Reference)                   ║
    ║                                                               ║
    ║  DO NOT DEPLOY IN PRODUCTION!                                ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8000)
