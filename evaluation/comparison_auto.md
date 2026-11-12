# Comparação automática: IA vs. análise manual (rascunho)

> Gerado por `src/compare.py`. A análise final fica em `results.md`.

| Porta | Serviço | Referência | IA | Diferença | CVEs em comum | CVEs só da IA | CVEs só da referência |
|---|---|---|---|---|---|---|---|
| 21 * | vsftpd 2.3.4 | critico | critico | igual | CVE-2011-2523 | - | - |
| 22 | OpenSSH 4.7p1 Debian 8ubuntu1 | baixo | alto | IA +2 | - | - | CVE-2008-5161 |
| 23 | Linux telnetd | critico | alto | IA -1 | - | - | - |
| 25 | Postfix smtpd | critico | baixo | IA -3 | - | - | CVE-2019-10149 |
| 53 | ISC BIND 9.4.2 | alto | medio | IA -1 | - | - | CVE-2008-4163 |
| 80 | Apache httpd 2.2.8 | critico | medio | IA -2 | - | - | CVE-2017-3167 |
| 111 | rcpbind 2 | alto | medio | IA -1 | - | - | CVE-2016-4992 |
| 139 | Samba smbd 3.X - 4.X | critico | medio | IA -2 | - | - | CVE-2015-0240 |
| 445 | Samba smbd 3.X - 4.X | critico | medio | IA -2 | - | - | CVE-2015-0240 |
| 512 | netkit-rsh rexecd | critico | alto | IA -1 | - | - | CVE-2023-38336 |

\* Porta cuja referência foi influenciada por um assistente de IA antes da análise manual.

## Métricas (todas as portas)
- Portas comparadas: 10
- Risco idêntico: 1/10
- Diferença de no máximo 1 nível: 5/10
- IA mais alarmista que a referência: 1 | menos alarmista: 8

## Métricas (sem as portas influenciadas)
- Portas comparadas: 9
- Risco idêntico: 0/9
- Diferença de no máximo 1 nível: 4/9
- IA mais alarmista que a referência: 1 | menos alarmista: 8

## CVEs citados pela IA
- Total de citações: 1
- Não encontrados no NVD: 0
- Ausentes da análise de referência (precisam de verificação manual de aplicabilidade): 0

## Portas sem resposta válida da IA
nenhuma
