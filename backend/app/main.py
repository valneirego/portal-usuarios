import json

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .core.config import JWT_ALGORITHM, JWT_SECRET
from .database import Base, engine, get_session
from .models import AuditLog, User
from .schemas import (
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
    UserStatusUpdate,
)
from .security import hash_password, issue_token, verify_password

Base.metadata.create_all(bind=engine)
app = FastAPI(title="Portal de Usuários API", version="1.0.0")
bearer = HTTPBearer()


def audit(session: Session, action: str, resource: str, actor_id: int | None = None, metadata: dict | None = None) -> None:
    session.add(AuditLog(actor_id=actor_id, action=action, resource=resource, metadata_json=json.dumps(metadata or {})))


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer), session: Session = Depends(get_session)) -> User:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = session.get(User, int(payload["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    if not user or not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessão inválida")
    return user


def admin_required(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão de administrador necessária")
    return user


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/auth/register", response_model=UserResponse, status_code=201)
def register(payload: UserCreate, session: Session = Depends(get_session)) -> User:
    if session.scalar(select(User).where((User.username == payload.username) | (User.cpf == payload.cpf))):
        raise HTTPException(status_code=409, detail="Usuário ou CPF já cadastrado")
    role = "admin" if session.scalar(select(User.id).limit(1)) is None else "user"
    user = User(username=payload.username, password_hash=hash_password(payload.password), cpf=payload.cpf, city=payload.city, role=role)
    session.add(user)
    session.flush()
    audit(session, "user_registered", f"users/{user.id}", user.id, {"role": role})
    session.commit()
    session.refresh(user)
    return user


@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, session: Session = Depends(get_session)) -> TokenResponse:
    user = session.scalar(select(User).where(User.username == payload.username))
    if not user or not user.active or not verify_password(payload.password, user.password_hash):
        audit(session, "login_failed", "auth/login", None, {"username": payload.username})
        session.commit()
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    audit(session, "login_succeeded", f"users/{user.id}", user.id)
    session.commit()
    return TokenResponse(access_token=issue_token(user.id, user.role))


@app.get("/api/v1/users/me", response_model=UserResponse)
def me(user: User = Depends(current_user)) -> User:
    return user


@app.get("/api/v1/admin/users", response_model=list[UserResponse])
def users(session: Session = Depends(get_session), _: User = Depends(admin_required)) -> list[User]:
    return list(session.scalars(select(User).order_by(User.created_at.desc())))


@app.patch("/api/v1/admin/users/{user_id}/status", response_model=UserResponse)
def update_status(user_id: int, payload: UserStatusUpdate, session: Session = Depends(get_session), admin: User = Depends(admin_required)) -> User:
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    user.active = payload.active
    audit(session, "user_status_changed", f"users/{user_id}", admin.id, {"active": payload.active})
    session.commit()
    session.refresh(user)
    return user
