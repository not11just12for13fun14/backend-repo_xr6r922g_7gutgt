"""
Database Schemas for the E‑Commerce app

Each Pydantic model maps to a MongoDB collection (lowercased class name).

Collections:
- user
- product
- order
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr


class User(BaseModel):
    """
    Users collection schema
    Collection name: "user"
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    is_admin: bool = Field(False, description="Admin user flag")


class Product(BaseModel):
    """
    Products collection schema
    Collection name: "product"
    """
    title: str = Field(..., description="Product title")
    brand: str = Field(..., description="Product brand")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in USD")
    category: str = Field(..., description="Category: Mobiles, Laptops, Accessories, Fashion")
    images: List[str] = Field(default_factory=list, description="Image URLs")
    rating: float = Field(4.0, ge=0, le=5, description="Average rating")
    specs: Dict[str, Any] = Field(default_factory=dict, description="Key specifications")
    stock: int = Field(100, ge=0, description="Units in stock")


class OrderItem(BaseModel):
    product_id: str
    title: str
    price: float
    quantity: int = Field(1, ge=1)
    image: Optional[str] = None


class ShippingInfo(BaseModel):
    name: str
    address: str
    phone: str
    payment_method: str


class Order(BaseModel):
    """
    Orders collection schema
    Collection name: "order"
    """
    user_id: Optional[str] = None
    items: List[OrderItem]
    shipping: ShippingInfo
    total: float
    status: str = Field("placed", description="placed | shipped | delivered | cancelled")
