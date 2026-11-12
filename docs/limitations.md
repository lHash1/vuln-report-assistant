# Limitações

Este documento lista o que limita as conclusões do projeto. Os resultados valem para as 10 primeiras portas abertas do Lab 01 (Metasploitable 2) e para uma execução do modelo, e não devem ser generalizados.

## 1. Tamanho da amostra
- Escopo: 10 portas (21, 22, 23, 25, 53, 80, 111, 139, 445, 512), escolhidas pelo número da porta, critério fixado antes de rodar o modelo.
- Só 6 portas têm referência corrigida determinada, e 139 e 445 são a mesma causa (Samba), então são 5 causas independentes.
- Por isso o projeto reporta contagens (ex.: 3 de 6), não percentuais. Uma porta muda a conclusão.

## 2. A referência manual é de uma pessoa só
- A análise de referência foi feita por um pentester júnior, sem revisão de terceiros.
- A versão original (congelada no commit 936cd74) citava uma CVE por porta, e pelo menos 6 de 9 não sustentavam a classificação (portas 25, 53, 111, 139, 445 e 512): produto errado, plataforma errada ou versão não confirmada.
- A correção está em arquivos separados (`evaluation/corrections_lab01.json`, `evaluation/ground_truth_corrections.md`). A original não foi editada, e as duas comparações são mantidas.

## 3. Evidência assimétrica entre modelo e referência
- O modelo recebeu só a saída do `parser.py`, que descarta `extrainfo`, `ostype` e o CPE. Ele nunca viu, por exemplo, "(Ubuntu) DAV/2".
- A referência corrigida usou evidência colhida depois, que o modelo nunca viu: `smb-os-discovery`, métodos de autenticação e algoritmos SSH, recursão DNS, `dpkg` e `testparm` da VM, e rastreadores de distribuição.
- A comparação mede, portanto, "modelo só com banner" contra "referência com acesso ao alvo". Não mede a capacidade do modelo com a mesma informação.

## 4. Regra de classificação escrita depois da pesquisa
- A regra (CVSS v2: crítico 9.0–10.0, alto 7.0–8.9, médio 4.0–6.9, baixo < 4.0) foi definida depois da pesquisa inicial, não antes.
- O prompt v1 não dava definição dos rótulos de risco ao modelo. Parte da diferença entre modelo e referência pode ser diferença de escala, não de julgamento.
- A regra usa só a nota, não distingue tipo de impacto. A porta 80 (CVE-2011-3192) é só DoS e fica em `alto` pela nota v2 de 7.8 (o Ubuntu classifica como Medium).
- A regra por nota também subestima o que é mais alcançável na prática: o CVE-2007-2447 (Samba) tem exploit público para a versão exata e a configuração necessária ativa, mas nota v2 de 6.0 (`medio`).

## 5. Samba (portas 139 e 445)
- A classificação `medio` usa o CVE-2007-2447 (v2 6.0, vetor `AV:N/AC:M/Au:S/C:P/I:P/A:P`). Ele reprova os critérios de triagem (nota ≥ 7.0 e Au:N) e entrou como exceção explícita, definida depois de ver o resultado.
- `medio` é limite inferior. O CVE-2012-1182 (nota v2 10.0 lida manualmente no NVD) é **não confirmado**, não rejeitado: o rastreador Debian não tem entrada para 3.0.x, não foi achada página no rastreador do Ubuntu e o aviso do samba.org não foi verificado. A consulta automática ao NVD para essa CVE retornou HTTP 503 e não foi repetida.
- No rastreador do Ubuntu, a página do CVE-2007-2447 mostrou só as releases 7.04, 6.10 e 6.06 LTS. Não foi possível determinar se há linha para a 8.04. Nem o rastreador Debian nem o do Ubuntu confirmam ou excluem correção para o `samba 3.0.20-0.1ubuntu1` instalado.
- 139 e 445 dependem da mesma causa e são contadas como uma nas "causas independentes".

## 6. Portas fora das métricas
- Indeterminadas: 25 (versão do Postfix desconhecida; a CVE da referência original era do Exim) e 111 (o `2` do rpcbind é versão de protocolo; a CVE original era do 389 Directory Server).
- Julgamento por CWE, fora da regra de CVE: 23 (Telnet, texto claro) e 512 (rexecd, texto claro e autenticação fraca). Nos dois casos a diferença para o modelo é de 1 nível, mas não entra nos números.

## 7. Backports e versões
- Portas 53 e 80: a versão instalada na VM está abaixo da versão corrigida no rastreador do Ubuntu 8.04 (`dpkg --compare-versions`). Isso sustenta a classificação, mas não prova exploração.
- Nenhuma vulnerabilidade foi explorada. Exploração está fora do escopo, e as varreduras ativas foram somente de leitura, contra a VM do próprio laboratório.

## 8. Ferramentas
- `cve_check.py` só verifica se a CVE existe no NVD e guarda a nota v3.1 primeiro. A regra usa v2, então as notas armazenadas ali não servem para classificar (ex.: CVE-2011-2523, v3.1 9.8 contra v2 10.0).
- O filtro de triagem (≥ 7.0, AV:N, Au:N) eliminaria o CVE-2007-2447, e as candidatas ordenadas por nota trouxeram CVEs de outra plataforma ou produto (CVE-2008-0122, CVE-2010-0425, CVE-2008-3844). Leitura manual das descrições foi necessária.
- `compare.py` não tem testes automatizados.

## 9. Uso de IA
- Foi avaliada uma única saída do modelo (`gemini-3.5-flash`, prompt v1, temperatura 0). A variação entre execuções não foi medida.
- A segunda rodada do laço de revalidação reenvia o mesmo prompt com temperatura 0, então não é uma nova tentativa de fato.
- O método de classificação pelo pior CVE alcançável foi sugerido por um assistente de IA, e a classificação da porta 21 foi influenciada por um assistente. Detalhes em `docs/ai_usage_log.md`.

## 10. Fora de escopo
- As outras 13 portas abertas do scan.
- PHP 5.2.4 e aplicações web.
- Exploração, escaneamento da rede doméstica e qualquer alvo que não seja a VM do laboratório.
