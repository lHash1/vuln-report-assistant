# Registro de uso de IA no desenvolvimento

Este arquivo documenta como utilizei IA (assistente de chat) durante o desenvolvimento
deste projeto: o que foi aceito, o que foi corrigido e como validei os resultados.

| Data | Etapa | O que pedi à IA | O que a IA entregou | Validação / ajuste |
|------|-------|-----------------|---------------------|--------------------|
| 2026-11-10 | Estrutura do repositório | Plano de pastas, .gitignore e fluxo de Git | Estrutura e comandos | Executei no Kali. O push falhou por e-mail privado (GH007); corrigi usando o endereço noreply real da minha conta |
| 2026-11-10 | Parser do Nmap | Esqueleto do parser de XML | Função `parse_nmap` | Testei com fixture sintética (pytest, 2 testes passando) |
| 2026-11-10 | Configuração da API | Passo a passo para configurar a API do Gemini | Script de teste e uso de `.env` | Cometi o erro de colocar a chave real no `.env.example` (arquivo versionado); percebi e corrigi antes de qualquer commit. Também expus a chave numa conversa e a substituí por uma nova |
| 2026-11-10 | Teste do `load_dotenv` | Script de teste da chave | Script com `load_dotenv()` sem caminho | Falhou (`AssertionError`) ao rodar via stdin. Corrigi passando o caminho `.env` explicitamente |
| 2026-11-10 | Escolha do modelo | Qual modelo do Gemini usar | Sugeriu `gemini-2.5-flash` | Indisponível para novas contas (erro 404). Listei os modelos pela própria API e troquei. Lição: nomes de modelos mudam, então ficam no `.env` e não no código |
| 2026-11-10 | Erro 503 da API | Como contornar sobrecarga do modelo | Script com novas tentativas e modelos alternativos | `gemini-3.8-flash` falhou 3 vezes (503) e `gemini-3.5-flash` respondeu. Vou incorporar retry e fallback ao `analyzer.py` |
