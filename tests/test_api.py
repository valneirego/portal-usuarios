import os

os.environ["DATABASE_URL"] = "sqlite:///./test_api.db"
os.environ["JWT_SECRET"] = "test-secret-with-at-least-32-bytes-long"

from fastapi.testclient import TestClient

from backend.app.database import Base, engine
from backend.app.main import app

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
client = TestClient(app)


def test_api_authentication_and_permissions():
    created = client.post("/api/v1/auth/register", json={"username": "admin", "password": "Senha123", "cpf": "52998224725", "city": "Sao Paulo"})
    assert created.status_code == 201
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "Senha123"})
    assert login.status_code == 200
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/users/me", headers=headers).json()["role"] == "admin"
    assert len(client.get("/api/v1/admin/users", headers=headers).json()) == 1
