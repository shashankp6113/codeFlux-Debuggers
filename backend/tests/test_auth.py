import pytest
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth import create_access_token, get_current_user, JWT_SECRET_KEY, JWT_ALGORITHM
from models import Base, User
from database import get_db

# Setup test database
engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# Setup dummy app to test the dependency
app = FastAPI()
app.dependency_overrides[get_db] = override_get_db

@app.get("/protected")
def protected_route(user: User = Depends(get_current_user)):
    return {"user_id": user.id, "email": user.email}

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    db = TestingSessionLocal()
    user = User(email="test@example.com", name="Test User")
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()

def test_successful_authentication():
    token = create_access_token(user_id=1)
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"user_id": 1, "email": "test@example.com"}

def test_missing_token():
    response = client.get("/protected")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

def test_malformed_token():
    response = client.get("/protected", headers={"Authorization": "Bearer not.a.real.jwt"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

def test_forged_signature():
    # Create token with a different secret
    expire = datetime.now(timezone.utc) + timedelta(hours=1)
    payload = {"sub": "1", "exp": expire}
    forged_token = jwt.encode(payload, "wrong_secret_key_that_is_at_least_32_bytes_long", algorithm=JWT_ALGORITHM)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {forged_token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

def test_expired_token():
    expire = datetime.now(timezone.utc) - timedelta(hours=1)  # Expired an hour ago
    payload = {"sub": "1", "exp": expire}
    expired_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Token has expired"

def test_missing_sub():
    expire = datetime.now(timezone.utc) + timedelta(hours=1)
    payload = {"exp": expire}  # No sub
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

def test_invalid_sub():
    expire = datetime.now(timezone.utc) + timedelta(hours=1)
    payload = {"sub": "not_an_int", "exp": expire}
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"

def test_nonexistent_user():
    # User ID 999 doesn't exist
    token = create_access_token(user_id=999)
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"
