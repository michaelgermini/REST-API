# API avec Python et FastAPI

## Introduction

**FastAPI** est un framework web moderne et rapide pour Python, conçu spécifiquement pour les APIs. Il est basé sur les annotations de type Python et génère automatiquement la documentation OpenAPI. FastAPI est particulièrement apprécié pour sa **performance**, sa **facilité d'utilisation** et son **écosystème** riche. Dans ce chapitre, nous allons créer une API REST complète avec FastAPI.

## Configuration du projet

### Initialisation

```bash
# Créer un nouveau projet
mkdir blog-api-python
cd blog-api-python
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install fastapi uvicorn[standard]
pip install sqlalchemy psycopg2-binary
pip install python-jose[cryptography] passlib[bcrypt]
pip install python-multipart email-validator
pip install pydantic[email] alembic
pip install --dev pytest httpx
```

### Structure du projet

```
blog-api-python/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── security.py
│   │   └── database.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   └── post.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   └── post.py
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── users.py
│   │   └── posts.py
│   ├── dependencies/
│   │   ├── __init__.py
│   │   └── auth.py
│   └── utils/
│       ├── __init__.py
│       └── pagination.py
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_users.py
│   └── test_posts.py
├── alembic/
│   ├── versions/
│   ├── env.py
│   └── script.py.mako
├── requirements.txt
├── pyproject.toml
└── README.md
```

### Configuration

```toml
# pyproject.toml
[tool.poetry]
name = "blog-api"
version = "0.1.0"
description = "REST API for a blog platform"
authors = ["Your Name <your.email@example.com>"]

[tool.poetry.dependencies]
python = "^3.9"
fastapi = "^0.100.0"
uvicorn = {extras = ["standard"], version = "^0.23.0"}
sqlalchemy = "^2.0.0"
psycopg2-binary = "^2.9.0"
python-jose = {extras = ["cryptography"], version = "^3.3.0"}
passlib = {extras = ["bcrypt"], version = "^1.7.4"}
python-multipart = "^0.0.6"
email-validator = "^2.0.0"
pydantic = {extras = ["email"], version = "^2.0.0"}
alembic = "^1.12.0"

[tool.poetry.dev-dependencies]
pytest = "^7.4.0"
httpx = "^0.24.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
```

## Application principale

```python
# app/main.py
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time

from app.core.config import settings
from app.core.database import engine, Base
from app.routers import auth, users, posts

# Création des tables
Base.metadata.create_all(bind=engine)

# Application FastAPI
app = FastAPI(
    title="Blog API",
    description="REST API for a blog platform",
    version="1.0.0",
    contact={
        "name": "API Support",
        "url": "https://support.example.com",
        "email": "api@example.com"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# ✅ Middleware de sécurité
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=86400
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# ✅ Middleware de logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    # Logging des requêtes
    print(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.4f}s")

    # Headers de métriques
    response.headers["X-Process-Time"] = str(process_time)
    return response

# ✅ Health check
@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "1.0.0"
    }

# ✅ Root endpoint
@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to Blog API",
        "docs": "/docs",
        "redoc": "/redoc"
    }

# ✅ Routes de l'API
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(posts.router, prefix="/api/posts", tags=["Posts"])

# ✅ Gestion des erreurs globales
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "path": str(request.url)
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
```

## Configuration et sécurité

### Configuration

```python
# app/core/config.py
from pydantic import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    # API
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Blog API"

    # Security
    SECRET_KEY: str = "your-secret-key-here"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/blogdb"

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8080"
    ]

    ALLOWED_HOSTS: List[str] = [
        "localhost",
        "127.0.0.1",
        "api.example.com"
    ]

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    class Config:
        case_sensitive = True
        env_file = ".env"

# Instance globale
settings = Settings()
```

### Sécurité

```python
# app/core/security.py
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.core.config import settings

# Contexte de hachage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ✅ Hachage des mots de passe
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# ✅ Génération des tokens JWT
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})

    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

# ✅ Vérification des tokens
def verify_token(token: str, token_type: str = "access"):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")

        if not user_id:
            return None

        if payload.get("type") != token_type:
            return None

        return user_id
    except JWTError:
        return None

# ✅ Vérification de la force du mot de passe
def validate_password_strength(password: str) -> bool:
    """
    Valide la force du mot de passe selon les critères OWASP
    """
    if len(password) < 8:
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    return has_upper and has_lower and has_digit and has_special
```

## Modèles SQLAlchemy

### Base et configuration

```python
# app/core/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Engine SQLAlchemy
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=settings.DATABASE_URL.startswith("sqlite")  # Logging SQL en dev
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base pour les modèles
Base = declarative_base()

# ✅ Fonction pour récupérer la session DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

### Modèle User

```python
# app/models/user.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.core.security import get_password_hash, verify_password
import enum

class UserRole(str, enum.Enum):
    user = "user"
    author = "author"
    admin = "admin"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.user)
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relations
    posts = relationship("Post", back_populates="author")
    comments = relationship("Comment", back_populates="author")

    def set_password(self, password: str):
        self.password_hash = get_password_hash(password)

    def check_password(self, password: str) -> bool:
        return verify_password(password, self.password_hash)

    def get_full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    def get_permissions(self) -> list:
        permissions = {
            "user": ["read:profile", "write:profile", "read:posts"],
            "author": ["read:profile", "write:profile", "read:posts", "write:posts", "delete:own-posts"],
            "admin": ["*"]
        }
        return permissions.get(self.role, [])
```

### Modèle Post

```python
# app/models/post.py
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum

class PostStatus(str, enum.Enum):
    draft = "draft"
    published = "published"
    archived = "archived"

class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    excerpt = Column(String(300), nullable=True)
    status = Column(Enum(PostStatus), default=PostStatus.draft)
    published_at = Column(DateTime, nullable=True)
    view_count = Column(Integer, default=0)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relations
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")

    def publish(self):
        self.status = PostStatus.published
        self.published_at = func.now()

    def unpublish(self):
        self.status = PostStatus.draft
        self.published_at = None

    def is_published(self) -> bool:
        return self.status == PostStatus.published and self.published_at is not None

    def increment_views(self):
        self.view_count += 1
```

## Schémas Pydantic

### Schémas de base

```python
# app/schemas/__init__.py
from .user import User, UserCreate, UserUpdate, UserInDB, UserResponse
from .post import Post, PostCreate, PostUpdate, PostResponse
from .auth import Token, TokenData, LoginRequest
from .common import PaginationParams, PaginatedResponse

__all__ = [
    # User schemas
    "User", "UserCreate", "UserUpdate", "UserInDB", "UserResponse",
    # Post schemas
    "Post", "PostCreate", "PostUpdate", "PostResponse",
    # Auth schemas
    "Token", "TokenData", "LoginRequest",
    # Common schemas
    "PaginationParams", "PaginatedResponse"
]
```

### Schémas User

```python
# app/schemas/user.py
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from app.models.user import UserRole

# ✅ Schéma de base
class UserBase(BaseModel):
    email: EmailStr
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    role: UserRole = UserRole.user

# ✅ Schéma de création
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    class Config:
        schema_extra = {
            "example": {
                "email": "john.doe@example.com",
                "password": "SecurePass123!",
                "first_name": "John",
                "last_name": "Doe"
            }
        }

# ✅ Schéma de mise à jour
class UserUpdate(BaseModel):
    first_name: Optional[str] = Field(None, min_length=2, max_length=50)
    last_name: Optional[str] = Field(None, min_length=2, max_length=50)
    email: Optional[EmailStr] = None

# ✅ Schéma de réponse
class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# ✅ Schéma interne (avec mot de passe)
class UserInDB(UserBase):
    id: int
    password_hash: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# ✅ Schéma public (sans données sensibles)
class UserPublic(BaseModel):
    id: int
    first_name: str
    last_name: str

    class Config:
        from_attributes = True
```

## Dépendances et authentification

```python
# app/dependencies/auth.py
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User
from app.core.security import verify_token

# ✅ OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# ✅ Dépendance pour récupérer l'utilisateur actuel
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        user_id = verify_token(token, "access")
        if not user_id:
            raise credentials_exception

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise credentials_exception

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive"
            )

        return user
    except JWTError:
        raise credentials_exception

# ✅ Dépendance pour les admins
async def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

# ✅ Dépendance pour les auteurs
async def get_current_author(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["admin", "author"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

# ✅ Dépendance optionnelle (utilisateur ou anonyme)
async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    if not token:
        return None

    try:
        user_id = verify_token(token, "access")
        if not user_id:
            return None

        user = db.query(User).filter(User.id == user_id).first()
        return user
    except JWTError:
        return None
```

## Routes et contrôleurs

### Authentification

```python
# app/routers/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, create_refresh_token
from app.models.user import User
from app.schemas.auth import Token, LoginRequest

router = APIRouter()

# ✅ Inscription
@router.post("/register", response_model=Token)
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    # Vérifier si l'utilisateur existe déjà
    db_user = db.query(User).filter(User.email == user_data.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )

    # Créer l'utilisateur
    db_user = User(
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name
    )
    db_user.set_password(user_data.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Générer les tokens
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(db_user.id)}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"sub": str(db_user.id)})

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

# ✅ Connexion
@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == login_data.email).first()

    if not user or not user.check_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is inactive"
        )

    # Mettre à jour la dernière connexion
    user.last_login_at = datetime.utcnow()
    db.commit()

    # Générer les tokens
    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token = create_refresh_token(data={"sub": str(user.id)})

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

# ✅ Actualisation des tokens
@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    try:
        user_id = verify_token(refresh_data.refresh_token, "refresh")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )

        # Générer de nouveaux tokens
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(data={"sub": str(user.id)})

        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
```

### Utilisateurs

```python
# app/routers/users.py
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.models.user import User
from app.schemas.user import UserResponse, UserUpdate
from app.dependencies.auth import get_current_user, get_current_admin
from app.utils.pagination import paginate

router = APIRouter()

# ✅ Récupérer tous les utilisateurs (admin uniquement)
@router.get("/", response_model=PaginatedResponse[UserResponse])
async def get_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    role: Optional[UserRole] = Query(None),
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    query = db.query(User)

    # Filtres
    if search:
        query = query.filter(
            User.first_name.contains(search) |
            User.last_name.contains(search) |
            User.email.contains(search)
        )

    if role:
        query = query.filter(User.role == role)

    # Pagination
    return paginate(query, page, limit)

# ✅ Récupérer un utilisateur
@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Vérification BOLA
    if user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user

# ✅ Modifier un utilisateur
@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Vérification BOLA
    if user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Vérifier l'unicité de l'email
    if user_update.email and user_update.email != user.email:
        existing_user = db.query(User).filter(User.email == user_update.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already in use"
            )

    # Mise à jour
    update_data = user_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    db.commit()
    db.refresh(user)

    return user
```

## Pagination et utilitaires

```python
# app/utils/pagination.py
from typing import TypeVar, Generic, List
from pydantic import BaseModel
from sqlalchemy.orm import Query
from math import ceil

T = TypeVar('T')

class PaginationParams(BaseModel):
    page: int = 1
    limit: int = 20

class PaginatedResponse(BaseModel, Generic[T]):
    data: List[T]
    pagination: dict
    links: dict

def paginate(query: Query, page: int, limit: int):
    # Calcul de l'offset
    offset = (page - 1) * limit

    # Exécution de la requête
    total = query.count()
    items = query.offset(offset).limit(limit).all()

    # Métadonnées de pagination
    total_pages = ceil(total / limit)

    pagination = {
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1
    }

    links = {
        "self": f"?page={page}&limit={limit}",
        "first": f"?page=1&limit={limit}",
        "last": f"?page={total_pages}&limit={limit}"
    }

    if page < total_pages:
        links["next"] = f"?page={page + 1}&limit={limit}"

    if page > 1:
        links["prev"] = f"?page={page - 1}&limit={limit}"

    return PaginatedResponse(
        data=items,
        pagination=pagination,
        links=links
    )
```

## Tests avec pytest

```python
# tests/test_auth.py
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_register_user():
    response = client.post("/api/auth/register", json={
        "email": "test@example.com",
        "password": "SecurePass123!",
        "first_name": "Test",
        "last_name": "User"
    })

    assert response.status_code == 201
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()

def test_login_user():
    # D'abord créer un utilisateur
    client.post("/api/auth/register", json={
        "email": "login@example.com",
        "password": "SecurePass123!",
        "first_name": "Login",
        "last_name": "Test"
    })

    # Puis se connecter
    response = client.post("/api/auth/login", json={
        "email": "login@example.com",
        "password": "SecurePass123!"
    })

    assert response.status_code == 200
    assert "access_token" in response.json()

def test_invalid_login():
    response = client.post("/api/auth/login", json={
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    })

    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"

def test_access_protected_route():
    # Se connecter
    login_response = client.post("/api/auth/login", json={
        "email": "test@example.com",
        "password": "SecurePass123!"
    })

    token = login_response.json()["access_token"]

    # Accéder à une route protégée
    response = client.get(
        "/api/users/1",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
```

## Documentation automatique

FastAPI génère automatiquement la documentation OpenAPI :

```bash
# Lancer le serveur
uvicorn app.main:app --reload

# Documentation disponible
# http://localhost:8000/docs (Swagger UI)
# http://localhost:8000/redoc (ReDoc)
```

### Documentation personnalisée

```python
# app/routers/posts.py
from fastapi import APIRouter, Depends, HTTPException
from app.dependencies.auth import get_current_user

router = APIRouter()

@router.get("/", response_model=PaginatedResponse[PostResponse])
async def get_posts(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[PostStatus] = Query(None, description="Filter by status"),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Récupérer la liste des articles

    - **page**: Numéro de page (commence à 1)
    - **limit**: Nombre d'articles par page (max 100)
    - **status**: Filtrer par statut (draft, published, archived)
    """
    query = db.query(Post)

    if status:
        query = query.filter(Post.status == status)

    return paginate(query, page, limit)
```

## Déploiement

### Dockerfile

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copie des fichiers de dépendances
COPY requirements.txt .

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

# Exposition du port
EXPOSE 8000

# Commande de démarrage
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:password@db:5432/blogdb
      - SECRET_KEY=your-secret-key
    depends_on:
      - db
    volumes:
      - .:/app
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=blogdb
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## Quiz Python et FastAPI

**Question 1** : Quel est l'avantage principal de FastAPI ?
**Réponse** : Génération automatique de la documentation OpenAPI et validation des données avec Pydantic

**Question 2** : Comment définir une dépendance dans FastAPI ?
**Réponse** : Avec Depends() et une fonction qui retourne la dépendance

**Question 3** : Comment activer l'authentification OAuth2 dans FastAPI ?
**Réponse** : Avec OAuth2PasswordBearer() et Depends()

## En résumé

### Avantages de FastAPI
- 🚀 **Performance** : Un des frameworks les plus rapides
- 📚 **Documentation** automatique (OpenAPI/Swagger)
- ✅ **Validation** des données avec Pydantic
- 🔒 **Sécurité** intégrée
- 🧪 **Tests** faciles avec pytest
- 📦 **Type hints** Python natifs

### Structure recommandée
```
app/
├── core/           # Configuration, sécurité, DB
├── models/         # Modèles SQLAlchemy
├── schemas/        # Schémas Pydantic
├── routers/        # Routes de l'API
├── dependencies/   # Dépendances FastAPI
└── utils/          # Fonctions utilitaires
```

### Bonnes pratiques
- ✅ **Validation** automatique avec Pydantic
- ✅ **Dépendances** pour l'authentification
- ✅ **Documentation** auto-générée
- ✅ **Tests** avec pytest et httpx
- ✅ **Docker** pour le déploiement

### Configuration complète
```python
# FastAPI moderne
✅ ASGI avec uvicorn
✅ SQLAlchemy 2.0
✅ Pydantic v2
✅ JWT avec python-jose
✅ Password hashing avec bcrypt
✅ Pagination automatique
✅ Validation d'entrée
✅ Documentation interactive
✅ Tests automatisés
```

Dans le prochain chapitre, nous verrons comment implémenter une API avec **PHP et Laravel**, un framework mature et robuste !

---

**Prochain chapitre** : [03-API-avec-PHP-Laravel](03-API-avec-PHP-Laravel.md)
