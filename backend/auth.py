import os
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db
from models import User

ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()

if ENVIRONMENT == "production":
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    if not JWT_SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY environment variable MUST be set in production mode.")
else:
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev_fallback_secret_only_for_sih_prototype_32")

if len(JWT_SECRET_KEY.encode("utf-8")) < 32:
    raise ValueError("JWT_SECRET_KEY must be at least 32 bytes long for secure HS256 signatures.")
JWT_ALGORITHM = "HS256"

try:
    JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", "24"))
except ValueError:
    JWT_EXPIRATION_HOURS = 24

# The tokenUrl is a placeholder since we don't use standard form login, but OAuth2PasswordBearer requires it
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/token")

def create_access_token(user_id: int) -> str:
    """Create a signed JWT access token containing the user's ID as the subject."""
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "sub": str(user_id),
        "exp": expire,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> User:
    """FastAPI dependency to extract and validate the user from the JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id_str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user_id = int(user_id_str)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.InvalidTokenError, ValueError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
        
    return user
