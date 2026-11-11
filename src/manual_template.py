"""Gera o esqueleto da análise manual a partir de um scan Nmap (XML).

Não usa IA: apenas lista as portas abertas para o analista preencher.
"""
import json
import sys

from src.parser import parse_nmap


def build_template(xml_path: str, lab: str) -> dict:
    achados = []
    for f in parse_nmap(xml_path):
        achados.append({
            "host": f["host"],
            "porta": f["port"],
            "protocolo": f["protocol"],
            "servico": " ".join(
                p for p in (f["product"], f["version"]) if p
            ) or f["service"],
            "risco": "",  # critico | alto | medio | baixo
            "justificativa": "",
            "cves_que_conheco": [],
            "fonte": "",  # ex.: "memória", "NVD", "CTF"
            "mitigacao": "",
        })
    return {"lab": lab, "analista": "Pedro Luz", "achados": achados}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Uso: python -m src.manual_template <scan.xml> <saida.json>")
    template = build_template(sys.argv[1], "Metasploitable 2 (configuração padrão)")
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(template, fh, indent=2, ensure_ascii=False)
    print(f"Esqueleto criado em {sys.argv[2]} com {len(template['achados'])} portas.")
