# ADR 001 — Separar cliente desktop e backend

## Contexto

O primeiro protótipo concentrava interface, autenticação e SQLite no mesmo processo. Essa abordagem é simples, porém limita auditoria, integrações e uso por múltiplos clientes.

## Decisão

Manter o CustomTkinter como cliente desktop e introduzir uma API FastAPI versionada. A API usa JWT, papéis `admin` e `user`, SQLAlchemy e PostgreSQL via Docker em produção.

## Consequências

O projeto ganha fronteiras claras, documentação OpenAPI, testes de integração e possibilidade de clientes web/mobile. Em contrapartida, exige gerenciamento de segredos, banco remoto e deploy da API.
