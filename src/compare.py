"""Compara a análise da IA com a análise manual de referência.

Uso: python -m src.compare <manual.json> <ai_output.json> <cve_check.json> <saida.md>
"""
import json
import os
import sys
import unicodedata

ORDEM = {"baixo": 0, "medio": 1, "alto": 2, "critico": 3}
# Porta 21: a resposta foi revelada por um assistente de IA antes da análise manual.
PORTAS_INFLUENCIADAS = {21}


def normaliza(t: str) -> str:
    t = unicodedata.normalize("NFKD", t.strip().lower())
    return "".join(c for c in t if not unicodedata.combining(c))


def carregar(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def resumo(linhas: list[dict]) -> str:
    comp = [l for l in linhas if l["delta"] is not None]
    n = len(comp)
    if n == 0:
        return "- Sem dados comparáveis."
    exatos = sum(1 for l in comp if l["delta"] == 0)
    prox = sum(1 for l in comp if abs(l["delta"]) <= 1)
    maior = sum(1 for l in comp if l["delta"] > 0)
    menor = sum(1 for l in comp if l["delta"] < 0)
    return (
        f"- Portas comparadas: {n}\n"
        f"- Risco idêntico: {exatos}/{n}\n"
        f"- Diferença de no máximo 1 nível: {prox}/{n}\n"
        f"- IA mais alarmista que a referência: {maior} | menos alarmista: {menor}"
    )


def main() -> None:
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    base = carregar(sys.argv[1])
    ia = carregar(sys.argv[2])
    status_cve = {}
    if os.path.exists(sys.argv[3]):
        status_cve = {r["cve"]: r["status"] for r in carregar(sys.argv[3])}

    b_por_porta = {a["porta"]: a for a in base["achados"]}
    i_por_porta = {a["porta"]: a for a in ia["achados"]}

    linhas = []
    ia_cves_total = ia_cves_inexistentes = ia_cves_fora_base = 0
    for porta in base["escopo"]["portas"]:
        b, a = b_por_porta.get(porta), i_por_porta.get(porta)
        rb = normaliza(b["risco"]) if b else None
        ra = a["risco"] if a else None
        delta = ORDEM[ra] - ORDEM[rb] if rb in ORDEM and ra in ORDEM else None

        cb = {c.strip().upper() for c in (b or {}).get("cves_que_conheco", [])}
        ci = set((a or {}).get("cves_citados", []))
        so_ia = sorted(ci - cb)
        ia_cves_total += len(ci)
        ia_cves_fora_base += len(so_ia)
        ia_cves_inexistentes += sum(1 for c in ci if status_cve.get(c) == "nao_encontrado")

        linhas.append({
            "porta": porta,
            "servico": (b or {}).get("servico", ""),
            "rb": rb or "-", "ra": ra or "sem resposta", "delta": delta,
            "comuns": sorted(ci & cb),
            "so_ia": [f"{c} ({status_cve.get(c, 'não verificado')})" for c in so_ia],
            "so_base": sorted(cb - ci),
        })

    def fmt_delta(d):
        return "-" if d is None else ("igual" if d == 0 else f"IA {d:+d}")

    out = ["# Comparação automática: IA vs. análise manual (rascunho)", "",
           "> Gerado por `src/compare.py`. A análise final fica em `results.md`.", "",
           "| Porta | Serviço | Referência | IA | Diferença | CVEs em comum | CVEs só da IA | CVEs só da referência |",
           "|---|---|---|---|---|---|---|---|"]
    for l in linhas:
        marca = " *" if l["porta"] in PORTAS_INFLUENCIADAS else ""
        out.append(
            f"| {l['porta']}{marca} | {l['servico']} | {l['rb']} | {l['ra']} | {fmt_delta(l['delta'])} | "
            f"{', '.join(l['comuns']) or '-'} | {', '.join(l['so_ia']) or '-'} | {', '.join(l['so_base']) or '-'} |"
        )
    out += ["", "\\* Porta cuja referência foi influenciada por um assistente de IA antes da análise manual.", "",
            "## Métricas (todas as portas)", resumo(linhas), "",
            "## Métricas (sem as portas influenciadas)",
            resumo([l for l in linhas if l["porta"] not in PORTAS_INFLUENCIADAS]), "",
            "## CVEs citados pela IA",
            f"- Total de citações: {ia_cves_total}",
            f"- Não encontrados no NVD: {ia_cves_inexistentes}",
            f"- Ausentes da análise de referência (precisam de verificação manual de aplicabilidade): {ia_cves_fora_base}",
            "", "## Portas sem resposta válida da IA", f"{ia['portas_sem_resposta'] or 'nenhuma'}", ""]

    with open(sys.argv[4], "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    print(f"Escrito em {sys.argv[4]}")


if __name__ == "__main__":
    main()
