"""Gera o relatório executivo em Markdown a partir da saída validada da IA.

Uso: python -m src.report <ai_output.json> <cve_check.json> <saida.md>
"""
import json
import os
import sys

ROTULO = {"critico": "Crítico", "alto": "Alto", "medio": "Médio", "baixo": "Baixo"}
ORDEM = ["critico", "alto", "medio", "baixo"]


def esc(t: str) -> str:
    return str(t).replace("|", "\\|").replace("\n", " ")


def main() -> None:
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as fh:
        ia = json.load(fh)
    status = {}
    if os.path.exists(sys.argv[2]):
        with open(sys.argv[2], encoding="utf-8") as fh:
            status = {r["cve"]: r["status"] for r in json.load(fh)}

    achados = sorted(ia["achados"], key=lambda a: (ORDEM.index(a["risco"]), a["porta"]))
    meta = ia["meta"]

    out = [
        "# Relatório executivo de vulnerabilidades (laboratório)", "",
        "> **Rascunho gerado por IA e que deve ser verificado por um analista.** "
        "Versões detectadas por banner são candidatas a vulneráveis, não confirmadas. "
        f"Modelo: {meta['modelo_usado']} | Prompt: {meta['versao_prompt']} | Data (UTC): {meta['data_utc'][:10]}.",
        "", "## Resumo executivo", "", ia["resumo_executivo"] or "(sem resumo)", "",
        "## Prioridades", "",
        "| Risco | Porta | Serviço | Por quê | Recomendação |", "|---|---|---|---|---|",
    ]
    for a in achados:
        out.append(f"| {ROTULO[a['risco']]} | {a['porta']} | {esc(a['servico'])} | "
                   f"{esc(a['justificativa'])} | {esc(a['mitigacao'])} |")

    out += ["", "## CVEs citados pela IA (status no NVD)", ""]
    algum = False
    for a in achados:
        for c in a["cves_citados"]:
            algum = True
            out.append(f"- Porta {a['porta']}: {c} ({status.get(c, 'não verificado')})")
    if not algum:
        out.append("- Nenhum CVE citado.")
    out.append("")

    with open(sys.argv[3], "w", encoding="utf-8") as fh:
        fh.write("\n".join(out))
    print(f"Escrito em {sys.argv[3]}")


if __name__ == "__main__":
    main()
