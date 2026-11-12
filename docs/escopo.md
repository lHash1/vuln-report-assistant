# Escopo da análise

O scan do laboratório (Metasploitable 2, configuração padrão) encontrou **23 portas abertas**.
A análise manual de referência e a avaliação da IA cobrem apenas as **10 primeiras portas abertas, em ordem numérica**.

## Por que reduzir o escopo
- **Prazo:** o projeto foi desenvolvido em poucos dias, e a pesquisa manual de cada serviço em fontes públicas (NVD, Exploit-DB, CWE) leva tempo.
- **Pouca informação de versão:** muitas das portas restantes não retornaram versão no `nmap -sV`, o que limita uma análise baseada em CVEs.

## Como o escopo foi definido
O critério (as 10 primeiras portas por ordem numérica) foi fixado **antes** de executar o modelo de IA e não depende de nenhum resultado. O esqueleto original com 23 portas foi commitado antes da redução, e a decisão está registrada no histórico do Git.

## Como a análise de referência foi produzida
- Pesquisa feita por mim a partir de fontes públicas (NVD com busca por CPE, Exploit-DB/searchsploit, CWE/MITRE). O método de classificação (pelo CVE mais grave associado ao serviço) foi sugerido por um assistente de IA, e a porta 21 foi influenciada por um assistente antes da escrita. A referência foi depois corrigida em arquivos separados (`evaluation/ground_truth_corrections.md`). Detalhes em `docs/ai_usage_log.md`.
- Commitada **antes** da execução do modelo, e não é editada depois disso. Correções ficam em arquivo separado.
- As portas 139 e 445 compartilham o mesmo serviço (Samba) e a mesma causa raiz, então seus resultados não são independentes.

## O que isso significa
- O scan bruto (`samples/lab01_metasploitable2.xml`) permanece completo.
- As conclusões da avaliação valem para essas 10 portas e **não** podem ser generalizadas para o scan inteiro.
- Esta é uma limitação conhecida do projeto (ver `limitations.md`).

## Regra de classificação de risco

Definida **depois** da pesquisa inicial, e não antes. O prompt v1 enviado ao modelo não continha estas definições.

| Rótulo | Nota CVSS v2 |
|---|---|
| critico | 9.0 a 10.0 |
| alto | 7.0 a 8.9 |
| medio | 4.0 a 6.9 |
| baixo | abaixo de 4.0 |

- A nota vem do NVD (v2) e nunca da classificação da IA.
- A CVE precisa se aplicar ao produto, à versão, à plataforma e à configuração do alvo. CVE não confirmada não sustenta classificação.
- Versão do produto desconhecida resulta em `indeterminado`.
- Portas sem CVE aplicável (23 e 512) recebem julgamento por CWE, reportado à parte e fora das métricas.
- O tipo de impacto (DoS, execução remota) não muda a faixa.
- Detalhes e limitações: `docs/limitations.md`.
