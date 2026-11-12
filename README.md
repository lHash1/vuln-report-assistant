# vuln-report-assistant

Transforma resultados de scan Nmap (`-sV`, XML) em relatórios executivos priorizados por risco, usando um LLM (Gemini) com validação da saída e avaliação contra uma análise manual.

O projeto é um estudo de **eficiência e qualidade** de um LLM nessa tarefa, não uma ferramenta pronta para produção. Os resultados valem para um único laboratório e 10 portas (veja [Limitações](#limitações)).

## Resumo dos resultados

Alvo: Metasploitable 2 (VM do próprio laboratório), 23 portas abertas no scan, **10 primeiras portas** avaliadas (21, 22, 23, 25, 53, 80, 111, 139, 445, 512). Modelo `gemini-3.5-flash`, prompt v1, temperatura 0, uma execução.

- **Contra a referência original (10 portas):** risco idêntico em 1 de 10 (porta 21, cuja referência foi influenciada por um assistente de IA; sem ela, 0 de 9). Diferença de no máximo 1 nível em 5 de 10. A IA ficou abaixo da referência em 8 portas e acima em 1 (porta 22).
- **A referência original tinha problemas:** pelo menos 6 das 9 portas com CVE citado não tinham CVE aplicável (produto, plataforma, componente ou versão errados). Ela foi corrigida em arquivos separados, e a original (commit `936cd74`) não foi editada.
- **Contra a referência corrigida (6 portas, 5 causas independentes):** idêntico em 3 de 6 portas (2 de 5 causas); diferença de no máximo 1 nível em 5 de 6 (4 de 5). A concordância sobe de 1 para 3 de 6 quase só por causa do Samba (139/445), e os rótulos coincidem por razões diferentes.
- **Alucinação não foi o problema.** O único CVE citado pela IA existe e se aplica. O problema foi a aplicabilidade dos CVEs da referência original.
- 4 portas ficaram fora das métricas: 25 e 111 (`indeterminado`, versão do produto desconhecida) e 23 e 512 (julgamento por CWE, fora da regra de CVE).

Contagens, não percentuais, porque n é pequeno. Detalhes, interpretação e achados sobre o método: [`results.md`](results.md).

## Como funciona

```
scan Nmap (XML)
   └─ src/parser.py          extrai portas, serviços e versões
        └─ src/analyzer.py   envia ao LLM, valida a saída (JSON) -> ai_output.json
             ├─ src/cve_check.py          confere se os CVEs citados existem no NVD
             ├─ src/report.py             gera o relatório executivo (Markdown)
             ├─ src/compare.py            compara IA x análise manual original
             └─ src/compare_corrigido.py  compara IA x original x referência corrigida
```

Ferramentas auxiliares: `src/manual_template.py` (esqueleto da análise manual a partir do scan) e `src/triagem_nvd.py` (candidatos de CVE no NVD por CPE).

O `parser.py` descarta `extrainfo`, `ostype` e o CPE, então o modelo recebe só o que o banner informa (por exemplo, nunca vê "(Ubuntu) DAV/2"). Isso é parte do que a avaliação mede e está descrito em [`docs/limitations.md`](docs/limitations.md).

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # preencha LLM_API_KEY e LLM_MODEL
```

Variáveis do `.env` (nunca faça commit dele):

| Variável | Uso |
|---|---|
| `LLM_API_KEY` | chave da API do Gemini |
| `LLM_MODEL` | modelo principal |
| `LLM_FALLBACK_MODELS` | modelos alternativos, separados por vírgula, usados se o principal falhar |

## Uso

Todos os comandos rodam a partir da raiz do repositório, como módulos.

```bash
# ver o que o parser extrai do scan
python -m src.parser samples/lab01_metasploitable2.xml

# analisar com o LLM (chama a API do Gemini)
python -m src.analyzer samples/lab01_metasploitable2.xml --limite 10 --saida /tmp/minha_saida.json

# conferir os CVEs citados (consulta a API pública do NVD)
python -m src.cve_check /tmp/minha_saida.json /tmp/minha_cve_check.json

# relatório executivo
python -m src.report /tmp/minha_saida.json /tmp/minha_cve_check.json /tmp/relatorio.md
```

> **Atenção:** sem `--saida`, o `analyzer.py` grava em `evaluation/ai_output_lab01.json`, que é a saída avaliada neste projeto. Use sempre `--saida` com outro caminho para não sobrescrevê-la.

Reproduzir as comparações com os arquivos versionados (não chama o LLM):

```bash
python -m src.compare samples/manual_analysis_lab01.json evaluation/ai_output_lab01.json evaluation/cve_check_lab01.json evaluation/comparison_auto.md
python -m src.compare_corrigido samples/manual_analysis_lab01.json evaluation/ai_output_lab01.json evaluation/corrections_lab01.json evaluation/comparison_corrected.md
```

Esses dois comandos reescrevem `evaluation/comparison_auto.md` e `evaluation/comparison_corrected.md`. Para só conferir, aponte a saída para `/tmp`.

## Testes

```bash
pytest -q
```

São 9 testes (`parser` e `analyzer`). **Não há testes automatizados** para `compare.py`, `compare_corrigido.py`, `report.py`, `cve_check.py` nem `triagem_nvd.py`. A conferência desses scripts foi manual, contra cálculo à mão.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `src/` | código |
| `tests/` | testes e fixture sintética |
| `samples/` | scan do laboratório e referência manual original (congelada) |
| `evaluation/` | saída da IA (bruta e validada), comparações, referência corrigida e evidências em texto (`evidencia_*.txt`) |
| `results.md` | resultados e interpretação |
| `docs/escopo.md` | escopo, critério de seleção das portas e regra de classificação de risco |
| `docs/limitations.md` | limitações |
| `docs/ai_usage_log.md` | registro de uso de IA no desenvolvimento |

## Limitações

Resumo; a lista completa está em [`docs/limitations.md`](docs/limitations.md).

- 10 portas, 1 host, 1 execução, 1 modelo, 1 versão de prompt. A variação entre execuções não foi medida.
- A referência é de um analista júnior, sem revisão de terceiros, e a corrigida também não é verdade absoluta.
- **Evidência assimétrica:** a referência corrigida usou dados colhidos no alvo depois da execução (`dpkg`, `testparm`, `smb-os-discovery`, algoritmos SSH, recursão DNS, rastreadores de distribuição) que o modelo nunca viu. A diferença entre IA e referência mistura erro do modelo com falta de informação.
- A regra de classificação (CVSS v2) foi escrita **depois** da pesquisa inicial, e o prompt v1 não definia os rótulos de risco ao modelo.
- A regra usa só a nota: a porta 80 é apenas DoS e mesmo assim fica em `alto`, e o CVE-2007-2447 (Samba), com exploit público para a versão exata, fica em `medio`. Para o Samba, `medio` é limite inferior: o CVE-2012-1182 não foi confirmado, nem excluído.
- Portas 139 e 445 são a mesma causa, e 25 e 111 ficaram `indeterminado`.

## Uso responsável

- Os scans ativos foram feitos **somente contra a VM do próprio laboratório** (Metasploitable 2), com comandos de leitura. Nenhuma vulnerabilidade foi explorada.
- Use esta ferramenta apenas em sistemas que você tem autorização para testar.
- As evidências são transcritas como texto. O repositório não contém capturas de tela.

## Uso de IA no desenvolvimento

Assistentes de IA ajudaram no código, nos scripts de análise e em rascunhos de documentos. O que foi pedido, entregue e como foi validado está em [`docs/ai_usage_log.md`](docs/ai_usage_log.md), incluindo os pontos em que a IA influenciou a referência (método de classificação e porta 21).

## Licença

MIT. Veja [`LICENSE`](LICENSE).
