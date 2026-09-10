# Portal de Usuários

Projeto de gestão de usuários com cliente desktop em CustomTkinter e uma API REST independente em FastAPI. Foi desenhado como demonstração de práticas de produto: autenticação, RBAC, auditoria, testes, CI e execução em containers.

## Arquitetura

```text
CustomTkinter (cliente local)      FastAPI (backend HTTP)
         │                                   │
         └─────────────── JWT ───────────────┘
                                             │
                                 SQLAlchemy / PostgreSQL
                                             │
                                      auditoria e migrações
```

## Destaques

- Cadastro, login e perfil com CPF, CEP automático, foto e endereço
- Senhas com PBKDF2-HMAC-SHA256, salt e política de senha forte
- Bloqueio local após tentativas inválidas e recuperação demonstrativa por CPF
- API REST versionada em `/api/v1`, JWT Bearer, RBAC (`admin` e `user`) e OpenAPI em `/docs`
- Logs de auditoria para cadastro, login e alterações administrativas
- Painel administrativo desktop: pesquisa, ativação/desativação e CSV
- SQLAlchemy 2 preparado para SQLite local e PostgreSQL
- Docker Compose, health check, GitHub Actions, Ruff e Pytest

## Desenvolvimento local

```powershell
python -m pip install -r requirements-dev.txt
python main.py
python -m uvicorn backend.app.main:app --reload
python -m pytest -q
```

A documentação interativa estará em `http://127.0.0.1:8000/docs`.

## Docker / PostgreSQL

```powershell
Copy-Item .env.example .env
# Edite JWT_SECRET com um valor aleatório de pelo menos 32 caracteres.
docker compose up --build
```

O backend estará em `http://localhost:8000`; use a migração inicial em `alembic/versions/001_create_users_and_audit_logs.sql` no pipeline de produção.

## Qualidade

```powershell
python -m ruff check .
python -m pytest -q
```

## Segurança e produção

Nunca versione `.env`, bancos locais, fotos ou exportações. Para produção, mantenha o segredo JWT num cofre de segredos, use HTTPS, aplique as migrações no deploy e substitua a recuperação por CPF por fluxo de token enviado por e-mail.
