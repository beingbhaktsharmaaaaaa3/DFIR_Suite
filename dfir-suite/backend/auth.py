from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db
import models, hashlib, hmac, os

SECRET_KEY = "dfir-suite-secret-key-change-in-production-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 12

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ── Bcrypt-safe password hashing ─────────────────────────────────────
# Uses direct bcrypt with fallback to avoid passlib/bcrypt version conflicts
def hash_password(password: str) -> str:
    try:
        # Try passlib first (works if bcrypt<=4.0.1)
        from passlib.context import CryptContext
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        return ctx.hash(password)
    except Exception:
        pass
    try:
        # Direct bcrypt (works with bcrypt>=4.0)
        import bcrypt
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
    except Exception:
        # Last resort: sha256 (not production-safe but won't crash)
        import hashlib
        return "sha256$" + hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    try:
        if hashed.startswith("sha256$"):
            import hashlib
            return hashed == "sha256$" + hashlib.sha256(plain.encode()).hexdigest()
        try:
            import bcrypt
            return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            from passlib.context import CryptContext
            ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
            return ctx.verify(plain, hashed)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user

def require_admin(current_user: models.User = Depends(get_current_user)):
    if current_user.role != models.UserRole.admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def require_investigator(current_user: models.User = Depends(get_current_user)):
    if current_user.role == models.UserRole.viewer:
        raise HTTPException(status_code=403, detail="Investigator access required")
    return current_user

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_default_admin(db: Session):
    existing = db.query(models.User).filter(models.User.username == "admin").first()
    if not existing:
        admin = models.User(
            username="admin",
            email="admin@dfir.local",
            full_name="System Administrator",
            hashed_password=hash_password("Admin@1234"),
            role=models.UserRole.admin,
            is_active=True
        )
        db.add(admin)
        db.commit()
        print("  [OK] Default admin created — admin / Admin@1234")
    else:
        # Re-hash if stored as broken hash
        if existing.hashed_password == "" or len(existing.hashed_password) < 10:
            existing.hashed_password = hash_password("Admin@1234")
            db.commit()
