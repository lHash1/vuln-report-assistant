# Correções à análise manual de referência

A análise original (`samples/manual_analysis_lab01.json`, commit 936cd74) não foi alterada. Esta página registra as correções feitas depois, com fonte pública e evidência coletada no laboratório. Os dados estruturados estão em `corrections_lab01.json`.

## Observações
- A pesquisa original foi feita por um analista júnior. Vários CVEs foram associados ao produto, à plataforma ou ao componente errado.
- O método "classificar pelo CVE mais grave associado ao serviço" foi sugerido por um assistente de IA e favoreceu CVEs de nota alta sem checar plataforma ou componente.
- A regra de classificação (CVSS v2: critico 9.0-10.0, alto 7.0-8.9, medio 4.0-6.9, baixo <4.0) foi escrita depois da pesquisa inicial.
- Evidências (scans de SMB, DNS e SSH, `dpkg`, `testparm`) foram coletadas depois da execução da IA. O modelo nunca as viu.
- Um CVE sem confirmação não sustenta classificação. Versão desconhecida resulta em `indeterminado`.
- Porta 21: a referência original foi influenciada por um assistente de IA antes da escrita (fonte original: "memória; corrigido após consulta").

## Tabela

| Porta | Original | Corrigido | CVE | Nota v2 | Estado |
|---|---|---|---|---|---|
| 21 | critico | critico | CVE-2011-2523 | 10.0 | determinado |
| 22 | baixo | baixo | CVE-2008-5161 | 2.6 | determinado (cifras CBC confirmadas) |
| 23 | critico | - | CWE (sem CVE) | - | julgamento, reportado à parte |
| 25 | critico | - | - | - | indeterminado (versão desconhecida) |
| 53 | alto | alto | CVE-2012-1667 | 8.5 | determinado (recursão ativa; Ubuntu 8.04: corrigido em 1:9.4.2.dfsg.P2-2ubuntu0.10, instalado 1:9.4.2-10) |
| 80 | critico | alto | CVE-2011-3192 | 7.8 | determinado (Ubuntu 8.04: corrigido em 2.2.8-1ubuntu0.21, instalado 2.2.8-1ubuntu0.15; apenas DoS) |
| 111 | alto | - | - | - | indeterminado |
| 139 | critico | medio | CVE-2007-2447 | 6.0 | determinado, limite inferior |
| 445 | critico | medio | CVE-2007-2447 | 6.0 | idem 139 (mesma causa) |
| 512 | critico | - | CWE (sem CVE) | - | julgamento, reportado à parte |

## Samba (139/445)
CVE-2007-2447: a versão confere (3.0.20), existe exploit público para essa versão (Exploit-DB 16320), `username map script` está ativo (`testparm -s`) e o pacote `3.0.20-0.1ubuntu1` não mostra correção.
CVE-2012-1182: a faixa do NVD inclui 3.0.20, mas o advisory do fornecedor não foi verificado e o rastreador Debian não tem entrada para 3.0.x. Não sustenta classificação, e a nota `medio` é um limite inferior. Se fosse confirmado, a classificação seria `critico`.
Exceção à triagem: CVE-2007-2447 tem nota v2 6.0 e foi mantido pelo exploit público e pela configuração confirmada. Vetor v2 no NVD: AV:N/AC:M/Au:S/C:P/I:P/A:P (Au:S e nota < 7.0: reprova os critérios de triagem). O rastreador do Ubuntu não confirma nem exclui correção para o samba 3.0.20-0.1ubuntu1 (não foi possível determinar se há linha para a 8.04); o `medio` é limite inferior.

## Candidatos avaliados e rejeitados

| Porta | CVE | Motivo |
|---|---|---|
| 53 | CVE-2008-0122 | Falha na libbind ("as used in libc in FreeBSD"), não no named |
| 80 | CVE-2010-0425 | mod_isapi, "when running on Windows" |
| 22 | CVE-2008-3844 | Pacotes RHEL adulterados, fora das fontes oficiais |
| 22 | CVE-2015-5600 | Exige keyboard-interactive; `evidencia_ssh_auth_methods.txt` mostra só publickey e password (testado com o usuário msfadmin) |

## Observações sem classificação (fora da regra por CVE)
- Porta 22: autenticação por senha habilitada; algoritmos fracos oferecidos (arcfour, hmac-md5, diffie-hellman-group1-sha1).

## Lição de método
Ordenar por nota CVSS escolhe CVEs que casam com produto e versão, mas não com plataforma, componente ou configuração. Uma regra baseada só em nota também subestima CVEs praticamente alcançáveis, como o CVE-2007-2447.
