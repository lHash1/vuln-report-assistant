# Resultados

Avaliação de uma análise de risco feita por LLM (modelo `gemini-3.5-flash`, prompt v1, temperatura 0, uma execução) sobre um scan Nmap do Metasploitable 2. Escopo: 1 host, 10 portas (veja `docs/escopo.md`). Os números valem para essas 10 portas e não podem ser generalizados.

A saída validada da IA veio de revalidação do arquivo bruto (`evaluation/raw/`), não de uma segunda chamada ao modelo.

## 1. Comparação com a referência original (10 portas)

Referência: `samples/manual_analysis_lab01.json`, congelada no commit 936cd74. Detalhes em `evaluation/comparison_auto.md`.

- Risco idêntico: 1 de 10 (porta 21). A referência da porta 21 foi influenciada por um assistente de IA. Sem ela, 0 de 9.
- Diferença de no máximo 1 nível: 5 de 10 (4 de 9 sem a porta 21).
- A IA foi mais baixa que a referência em 8 portas e mais alta em 1 (porta 22).

A referência original tinha problemas. Das 9 portas com CVE citado (8 CVEs distintos: 139 e 445 são o mesmo serviço, Samba, e receberam o mesmo CVE), pelo menos 6 não sustentavam a classificação (portas 25, 53, 111, 139, 445 e 512), porque o CVE era de outro produto, outra plataforma, outro componente ou outra versão. O CVE da porta 80 casa com o produto e a versão, mas exige módulo de terceiros. Em 139 e 445 a resposta igual não foi descuido: são o mesmo serviço, e o scan só informava `Samba smbd 3.X - 4.X`, sem versão exata nem o que cada porta fazia. O problema foi o CVE-2015-0240, que cobre o Samba 3.5.x em diante e não podia ser confirmado só com o banner (a VM roda 3.0.20). Por isso a referência foi corrigida (seção 2) e a comparação original foi mantida, sem substituição.

## 2. Referência corrigida

Regra (CVSS v2, definida **depois** da pesquisa inicial): crítico 9.0-10.0, alto 7.0-8.9, médio 4.0-6.9, baixo <4.0. CVE sem confirmação não sustenta classificação. Versão desconhecida resulta em `indeterminado`.

| Porta | Original | Corrigido | Base da correção |
|---|---|---|---|
| 21 | critico | critico | CVE-2011-2523, v2 10.0 |
| 22 | baixo | baixo | CVE-2008-5161, v2 2.6; cifras CBC confirmadas |
| 53 | alto | alto | CVE-2012-1667, v2 8.5; recursão ativa; instalado abaixo da versão corrigida no Ubuntu 8.04 |
| 80 | critico | alto | CVE-2011-3192, v2 7.8 (apenas DoS); instalado abaixo da versão corrigida no Ubuntu 8.04 |
| 139/445 | critico | medio (limite inferior) | CVE-2007-2447, v2 6.0; `username map script` ativo |
| 23, 512 | critico | julgamento por CWE | fora da regra, que cobre só CVEs |
| 25, 111 | critico, alto | indeterminado | versão do produto desconhecida |

Detalhes e candidatos rejeitados: `evaluation/ground_truth_corrections.md` e `evaluation/corrections_lab01.json`.

### Métricas (6 portas, 5 causas independentes; 139 e 445 são a mesma causa)

| Comparação | Idêntico | ≤ 1 nível |
|---|---|---|
| Original vs. corrigido | 3 de 6 (3 de 5 causas) | 4 de 6 (4 de 5) |
| IA vs. corrigido | 3 de 6 (2 de 5 causas) | 5 de 6 (4 de 5) |
| IA vs. original (mesmas portas) | 1 de 6 (1 de 5 causas) | 2 de 6 (2 de 5) |


Contagens absolutas, porque n é pequeno. Não use percentuais.

## 3. Como interpretar

- **A concordância da IA sobe de 1 para 3 de 6, mas quase tudo vem do Samba.** A correção moveu a referência para `medio`, o rótulo da IA. Os rótulos coincidem por razões diferentes: a IA não tinha versão e classificou pelo protocolo; a referência corrigida usa um CVE confirmado com evidência que o modelo nunca viu (`smb-os-discovery`, `testparm`, `dpkg`).
- **Porta 22:** a correção confirmou o `baixo` original, e a IA (`alto`) continua dois níveis acima. Nesta porta a correção não se moveu em direção à IA. A justificativa da IA ("versão antiga, candidata a falhas") não cita CVE.
- **Porta 53:** o rótulo original (`alto`) coincide com o corrigido, mas o CVE original era de uma build Windows. Rótulo certo, raciocínio errado.
- **Alucinação não foi o problema.** A IA citou 1 CVE (CVE-2011-2523), que existe no NVD e se aplica à versão. A referência original é que associou CVEs ao serviço errado. `cve_check.py` só verifica se o CVE existe, não se ele se aplica, e a aplicabilidade foi conferida manualmente.
- **A IA foi conservadora ao citar CVEs, mas nem sempre nos rótulos.** Com só o banner, ela marcou versões como "candidatas" e deixou de citar CVEs. Isso reduz risco de afirmação falsa, mas subestima: a IA ficou abaixo da referência corrigida nas portas 53 e 80 e abaixo da original em 8 portas. Nos rótulos ela não foi sempre conservadora: na porta 22 ficou dois níveis acima, sem citar CVE.
- **Portas 23 e 512 (julgamento por CWE):** a referência original dizia `critico` e a IA `alto`, diferença de 1 nível em ambas. Ficam fora das métricas porque a regra cobre só CVEs.

## 4. Achados sobre o método

- **Classificar pelo CVE mais grave** (método sugerido por um assistente de IA) escolheu CVEs que casam com produto e versão, mas não com plataforma, componente ou configuração. Quatro CVEs candidatos foram rejeitados na correção: CVE-2008-0122 (porta 53, libbind/FreeBSD), CVE-2010-0425 (porta 80, `mod_isapi`, só Windows), CVE-2008-3844 (porta 22, pacotes Red Hat adulterados) e CVE-2015-5600 (porta 22, exige keyboard-interactive, que não é oferecido). Todos vieram da triagem ordenada por nota.
- **A regra por nota subestima o CVE mais alcançável.** O CVE-2007-2447 tem exploit público para a versão exata e a configuração necessária ativa no alvo, mas v2 6.0 (`medio`). Vetor v2: `AV:N/AC:M/Au:S/C:P/I:P/A:P`. Reprova os dois critérios da triagem (nota ≥ 7.0 e Au:N), então entrou como exceção explícita pós-hoc. A descrição do NVD diz que atacantes remotos alcançam a função (1), `SamrChangePassword`, com `username map script` habilitado; só as funções (2) e (3) citam usuário autenticado. A nota usada é a v2 6.0 e o `medio` é limite inferior.
- **CVE-2012-1182** tem faixa no NVD que inclui o Samba 3.0.20, mas o advisory do fornecedor não foi confirmado e o rastreador Debian não tem entrada para 3.0.x. Por isso o `medio` é um limite inferior. Se fosse confirmado, seria `critico`.
- **A porta 80 é só DoS.** O `alto` vem da nota v2 7.8 (o Ubuntu classifica como Medium). A regra por nota não distingue tipo de impacto.

## 5. Limitações

- 10 portas, 1 host, 1 execução, 1 versão de prompt, 1 modelo.
- A referência é de um analista júnior e não é verdade absoluta. A referência corrigida também não é.
- A correção usou evidências que o modelo não viu (scans adicionais, `dpkg`, `testparm`). A diferença entre IA e referência corrigida mistura erro da IA com falta de informação.
- A regra de classificação foi escrita depois da pesquisa inicial, e o prompt v1 não continha definição dos rótulos.
- 139 e 445 não são independentes. 25 e 111 ficaram `indeterminado`; 23 e 512 dependem de julgamento.
- Backports: nas portas 53 e 80 a versão instalada está abaixo da corrigida no rastreador do Ubuntu 8.04. Para o Samba, o rastreador Debian não tem entrada para 3.0.x, e não consegui determinar se o rastreador do Ubuntu tem linha para a 8.04: nenhum dos dois confirma ou exclui correção para o `3.0.20-0.1ubuntu1`.
- Fora de escopo: PHP 5.2.4, aplicações web e as 13 portas restantes.
