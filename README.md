# Portal de Usuários

Aplicação desktop em Python para gestão de usuários, criada com CustomTkinter e SQLite. O projeto demonstra autenticação, perfil, integração com API, administração local e testes automatizados.

## Recursos

- Cadastro, login e edição de perfil com CPF validado
- Consulta automática de CEP via ViaCEP
- Foto de perfil armazenada localmente
- Estado civil, cor de pele e endereço completo
- Senhas protegidas com PBKDF2-HMAC-SHA256 e salt aleatório
- Senha forte: mínimo de 8 caracteres, letra maiúscula e número
- Bloqueio de conta por 15 minutos após 5 erros consecutivos
- Redefinição de senha mediante usuário e CPF
- Primeiro usuário é administrador; painel para pesquisar, ativar/desativar contas e exportar CSV
- Tema claro/escuro
- Migrações automáticas: bancos das versões anteriores são preservados

## Tecnologias

Python, CustomTkinter, SQLite, Pillow, ViaCEP e Pytest.

## Executar

```powershell
python -m pip install -r requirements.txt
python main.py
```

## Testes

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Estrutura

```text
main.py                 interface, regras de negócio e persistência
tests/test_database.py  testes de autenticação e banco de dados
requirements.txt        dependências da aplicação
```

> A recuperação de senha por CPF é apropriada apenas para demonstração local. Em produção, substitua-a por e-mail/token, use criptografia de dados sensíveis, auditoria e um servidor de banco de dados.
