# Contribuindo

1. Crie uma branch curta e descritiva a partir de `master`.
2. Instale as ferramentas: `python -m pip install -r requirements-dev.txt`.
3. Antes do pull request, execute:

```powershell
python -m ruff check .
python -m pytest -q
```

4. Mantenha commits pequenos, com uma responsabilidade clara, e nunca inclua dados pessoais ou segredos.
