# Política de segurança

Não publique vulnerabilidades, tokens, CPF ou outras informações pessoais em issues públicas.

Para relatar uma falha, abra uma discussão privada com o responsável pelo repositório contendo impacto, passos para reproduzir e uma sugestão de correção. O objetivo é responder em até 7 dias.

## Regras operacionais

- Nunca versione `.env`, bancos SQLite, fotos ou exportações.
- Em produção, use um segredo JWT com pelo menos 32 bytes em um cofre de segredos.
- Sirva a API exclusivamente por HTTPS atrás de um proxy reverso.
- Troque o fluxo demonstrativo de recuperação por CPF por token de uso único enviado por e-mail.
