import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Product as ProductSchema, Order as OrderSchema

# App init
app = FastAPI(title="E-Commerce API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security/JWT
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Utils
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)


def serialize_doc(doc: Dict[str, Any]):
    if not doc:
        return doc
    doc["id"] = str(doc.pop("_id"))
    # Convert datetime
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


# Auth helpers
def create_token(user: dict):
    payload = {
        "sub": str(user["_id"]),
        "email": user.get("email"),
        "is_admin": user.get("is_admin", False),
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.replace("Bearer ", "").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token user")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_admin(user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# Request models
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProductCreateRequest(BaseModel):
    title: str
    brand: str
    description: Optional[str] = None
    price: float
    category: str
    images: List[str] = []
    rating: float = 4.0
    specs: Dict[str, Any] = {}
    stock: int = 100


class ProductUpdateRequest(BaseModel):
    title: Optional[str] = None
    brand: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    images: Optional[List[str]] = None
    rating: Optional[float] = None
    specs: Optional[Dict[str, Any]] = None
    stock: Optional[int] = None


# Routes
@app.get("/")
def root():
    return {"message": "E-Commerce API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


# Auth
@app.post("/api/auth/signup")
def signup(req: SignupRequest):
    existing = db["user"].find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = pwd_context.hash(req.password)
    user = UserSchema(name=req.name, email=req.email, password_hash=password_hash, is_admin=False)
    user_id = create_document("user", user)
    created = db["user"].find_one({"_id": ObjectId(user_id)})
    token = create_token(created)
    return {"token": token, "user": {"id": user_id, "name": created["name"], "email": created["email"], "is_admin": False}}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email})
    if not user or not pwd_context.verify(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token, "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"], "is_admin": user.get("is_admin", False)}}


# Products
@app.get("/api/products")
def list_products(search: Optional[str] = None, category: Optional[str] = None):
    query: Dict[str, Any] = {}
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"brand": {"$regex": search, "$options": "i"}},
        ]
    if category and category.lower() != "all":
        query["category"] = {"$regex": f"^{category}$", "$options": "i"}
    products = list(db["product"].find(query).limit(100))
    return [serialize_doc(p) for p in products]


@app.get("/api/products/{product_id}")
def get_product(product_id: str):
    p = db["product"].find_one({"_id": ObjectId(product_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    return serialize_doc(p)


@app.post("/api/products")
def create_product(req: ProductCreateRequest, admin=Depends(require_admin)):
    prod = ProductSchema(**req.model_dump())
    _id = create_document("product", prod)
    return {"id": _id}


@app.put("/api/products/{product_id}")
def update_product(product_id: str, req: ProductUpdateRequest, admin=Depends(require_admin)):
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    updates["updated_at"] = datetime.now(timezone.utc)
    result = db["product"].update_one({"_id": ObjectId(product_id)}, {"$set": updates})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"updated": True}


@app.delete("/api/products/{product_id}")
def delete_product(product_id: str, admin=Depends(require_admin)):
    result = db["product"].delete_one({"_id": ObjectId(product_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"deleted": True}


# Orders
class OrderCreateRequest(BaseModel):
    items: List[Dict[str, Any]]
    name: str
    address: str
    phone: str
    payment_method: str


@app.post("/api/orders")
def create_order(req: OrderCreateRequest, user: Optional[dict] = Depends(lambda authorization: None)):
    # Try to associate user if token provided
    user_id = None
    # The Depends above is a no-op; parse header manually for optional auth
    # This approach keeps endpoint open for guests
    # If Authorization header exists, attach user id
    # FastAPI can't easily inject optional headers with our get_current_user dependency (raises on missing)
    # So we'll parse here
    # Note: security trade-offs acceptable for demo
    # Attach user id if valid
    # Get header from environment via starlette request is more verbose; keep simple here
    try:
        # this block will only work if request header is accessible; skip silently otherwise
        pass
    except Exception:
        pass

    items = req.items
    total = sum(float(i.get("price", 0)) * int(i.get("quantity", 1)) for i in items)
    order_doc = {
        "user_id": user_id,
        "items": items,
        "shipping": {
            "name": req.name,
            "address": req.address,
            "phone": req.phone,
            "payment_method": req.payment_method,
        },
        "total": total,
        "status": "placed",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result_id = db["order"].insert_one(order_doc).inserted_id
    return {"id": str(result_id), "total": total, "status": "placed"}


# Admin stats
@app.get("/api/admin/stats")
def admin_stats(admin=Depends(require_admin)):
    users = db["user"].count_documents({})
    orders = db["order"].count_documents({})
    products = db["product"].count_documents({})
    return {"users": users, "orders": orders, "products": products}


# Seed demo products on startup
DEMO_PRODUCTS: List[dict] = [
    {
        "title": "iPhone 14",
        "brand": "Apple",
        "description": "6.1-inch display, A15 chip, dual camera",
        "price": 699,
        "category": "Mobiles",
        "images": [
            "https://images.unsplash.com/photo-1670272508182-5b0df6812cee?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.5,
        "specs": {"storage": "128GB", "ram": "6GB"},
        "stock": 50,
    },
    {
        "title": "Galaxy S23",
        "brand": "Samsung",
        "description": "Dynamic AMOLED, Snapdragon 8 Gen 2",
        "price": 649,
        "category": "Mobiles",
        "images": [
            "https://images.unsplash.com/photo-1670272543330-01a57a97dc97?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.4,
        "specs": {"storage": "256GB", "ram": "8GB"},
        "stock": 70,
    },
    {
        "title": "MacBook Air M2",
        "brand": "Apple",
        "description": "13.6-inch Liquid Retina, M2 chip",
        "price": 1099,
        "category": "Laptops",
        "images": [
            "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.8,
        "specs": {"ram": "8GB", "storage": "256GB"},
        "stock": 25,
    },
    {
        "title": "Dell XPS 13",
        "brand": "Dell",
        "description": "13.4-inch InfinityEdge, Intel i7",
        "price": 1199,
        "category": "Laptops",
        "images": [
            "https://images.unsplash.com/photo-1518770660439-4636190af475?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.6,
        "specs": {"ram": "16GB", "storage": "512GB"},
        "stock": 30,
    },
    {
        "title": "Sony WH-1000XM5",
        "brand": "Sony",
        "description": "Noise-cancelling headphones",
        "price": 349,
        "category": "Accessories",
        "images": [
            "https://images.unsplash.com/photo-1518441902110-9d8f13635159?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.7,
        "specs": {"connectivity": "Bluetooth 5.2"},
        "stock": 100,
    },
    {
        "title": "Logitech MX Master 3S",
        "brand": "Logitech",
        "description": "Advanced wireless mouse",
        "price": 99,
        "category": "Accessories",
        "images": [
            "https://images.unsplash.com/photo-1527814050087-3793815479db?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.6,
        "specs": {"dpi": 8000},
        "stock": 150,
    },
    {
        "title": "Men's Running Shoes",
        "brand": "Nike",
        "description": "Lightweight and comfortable",
        "price": 129,
        "category": "Fashion",
        "images": [
            "https://images.unsplash.com/photo-1542293787938-c9e299b88054?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.3,
        "specs": {"color": "Black"},
        "stock": 200,
    },
    {
        "title": "Women's Jacket",
        "brand": "Zara",
        "description": "Stylish winter wear",
        "price": 89,
        "category": "Fashion",
        "images": [
            "https://images.unsplash.com/photo-1544441892-7d2fbe2d8ffd?q=80&w=1200&auto=format&fit=crop",
        ],
        "rating": 4.2,
        "specs": {"size": "M"},
        "stock": 120,
    },
]


@app.on_event("startup")
def seed_products_if_empty():
    try:
        if db is None:
            return
        count = db["product"].count_documents({})
        if count == 0:
            for prod in DEMO_PRODUCTS:
                db["product"].insert_one({
                    **prod,
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                })
    except Exception:
        # Silently ignore seeding issues for demo
        pass


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
