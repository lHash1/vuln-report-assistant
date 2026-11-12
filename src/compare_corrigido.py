"""Compara original, corrigido e IA, apenas nas portas com correção determinada.

Uso: python -m src.compare_corrigido <manual.json> <ai_output.json> <corrections.json> <saida.md>
"""
import json
import sys

ORDEM = {"baixo": 0, "medio": 1, "alto": 2, "critico": 3}
CONTA = {"determinado", "provisorio"}
MESMA_CAUSA = {445: 139}  # 139 e 445 são o mesmo serviço (Samba)


def carregar(caminho):
    with open(caminho, encoding="utf-8") as fh:
        return json.load(fh)


def fmt(d):
    return "-" if d is None else ("igual" if d == 0 else f"{d:+d}")


def bloco(titulo, pares, nome_a):
    """pares: (porta, rotulo_a, rotulo_b). Delta = nível(a) - nível(b)."""
    def stats(lst):
        d = [ORDEM[a] - ORDEM[b] for _, a, b in lst]
        return (len(d), sum(x == 0 for x in d), sum(abs(x) <= 1 for x in d),
                sum(x > 0 for x in d), sum(x < 0 for x in d))
    indep = [p for p in pares if p[0] not in MESMA_CAUSA]
    if not pares:
        return f"**{titulo}**\n- Sem dados comparáveis.\n"
    n, ig, prox, mais, menos = stats(pares)
    ni, igi, proxi, _, _ = stats(indep)
    return (f"**{titulo}**\n"
            f"- Idêntico: {ig} de {n} portas ({igi} de {ni} causas independentes)\n"
            f"- Diferença de no máximo 1 nível: {prox} de {n} ({proxi} de {ni})\n"
            f"- {nome_a} mais alto: {mais} | mais baixo: {menos}\n")


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    base, ia, cor = (carregar(p) for p in sys.argv[1:4])
    b = {a["porta"]: a for a in base["achados"]}
    i = {a["porta"]: a for a in ia["achados"]}
    c = {p["porta"]: p for p in cor["portas"]}

    linhas, contam = [], []
    for porta in base["escopo"]["portas"]:
        ro = b[porta]["risco"].strip().lower()
        ra = i[porta]["risco"] if porta in i else None
        rc = c.get(porta, {}).get("risco_corrigido")
        st = c.get(porta, {}).get("status", "sem_correcao")
        entra = st in CONTA and rc in ORDEM and ra in ORDEM
        if entra:
            contam.append((porta, ro, rc, ra))
        d_ia_o = ORDEM[ra] - ORDEM[ro] if ra in ORDEM and ro in ORDEM else None
        d_ia_c = ORDEM[ra] - ORDEM[rc] if entra else None
        linhas.append(f"| {porta} | {b[porta].get('servico', '')} | {ro} | {rc or '-'} | "
                      f"{st} | {ra or 'sem resposta'} | {fmt(d_ia_o)} | {fmt(d_ia_c)} |")

    out = ["# Comparação com a referência corrigida (rascunho)", "",
           "> Gerado por `src/compare_corrigido.py`. A análise original não foi alterada; "
           "veja `comparison_auto.md` para a comparação original.", "",
           "| Porta | Serviço | Original | Corrigido | Estado | IA | IA vs original | IA vs corrigido |",
           "|---|---|---|---|---|---|---|---|"] + linhas
    out += ["", "## Métricas (portas com correção determinada ou provisória)", "",
            bloco("Original vs. corrigido", [(p, o, rc) for p, o, rc, _ in contam], "Original"),
            bloco("IA vs. corrigido", [(p, a, rc) for p, _, rc, a in contam], "IA"),
            bloco("IA vs. original (mesmas portas)", [(p, a, o) for p, o, _, a in contam], "IA"),
            "Contagens absolutas: n é pequeno, então não use percentuais. "
            "A referência corrigida usa evidências que a IA nunca viu.",
            "", "Portas `indeterminado` ou de julgamento por CWE ficam fora destas métricas "
            "(veja a tabela para os valores original e da IA)."]
    with open(sys.argv[4], "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"Escrito em {sys.argv[4]}")


if __name__ == "__main__":
    main()
