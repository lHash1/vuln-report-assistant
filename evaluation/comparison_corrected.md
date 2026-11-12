# Comparação com a referência corrigida (rascunho)

> Gerado por `src/compare_corrigido.py`. A análise original não foi alterada; veja `comparison_auto.md` para a comparação original.

| Porta | Serviço | Original | Corrigido | Estado | IA | IA vs original | IA vs corrigido |
|---|---|---|---|---|---|---|---|
| 21 | vsftpd 2.3.4 | critico | critico | determinado | critico | igual | igual |
| 22 | OpenSSH 4.7p1 Debian 8ubuntu1 | baixo | baixo | determinado | alto | +2 | +2 |
| 23 | Linux telnetd | critico | - | julgamento_cwe | alto | -1 | - |
| 25 | Postfix smtpd | critico | - | indeterminado | baixo | -3 | - |
| 53 | ISC BIND 9.4.2 | alto | alto | determinado | medio | -1 | -1 |
| 80 | Apache httpd 2.2.8 | critico | alto | determinado | medio | -2 | -1 |
| 111 | rcpbind 2 | alto | - | indeterminado | medio | -1 | - |
| 139 | Samba smbd 3.X - 4.X | critico | medio | determinado | medio | -2 | igual |
| 445 | Samba smbd 3.X - 4.X | critico | medio | determinado | medio | -2 | igual |
| 512 | netkit-rsh rexecd | critico | - | julgamento_cwe | alto | -1 | - |

## Métricas (portas com correção determinada ou provisória)

**Original vs. corrigido**
- Idêntico: 3 de 6 portas (3 de 5 causas independentes)
- Diferença de no máximo 1 nível: 4 de 6 (4 de 5)
- Original mais alto: 3 | mais baixo: 0

**IA vs. corrigido**
- Idêntico: 3 de 6 portas (2 de 5 causas independentes)
- Diferença de no máximo 1 nível: 5 de 6 (4 de 5)
- IA mais alto: 1 | mais baixo: 2

**IA vs. original (mesmas portas)**
- Idêntico: 1 de 6 portas (1 de 5 causas independentes)
- Diferença de no máximo 1 nível: 2 de 6 (2 de 5)
- IA mais alto: 1 | mais baixo: 4

Contagens absolutas: n é pequeno, então não use percentuais. A referência corrigida usa evidências que a IA nunca viu.

Portas `indeterminado` ou de julgamento por CWE ficam fora destas métricas (veja a tabela para os valores original e da IA).
