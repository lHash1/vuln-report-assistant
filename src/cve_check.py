"""Verifica na API do NVD se os CVEs citados pela IA existem.

Existir no NVD NÃO significa que o CVE se aplica ao produto/versão do scan.
Isso precisa ser conferido manualmente (busca por CPE).

Uso: python -m src.cve_check <ai_output.json> <saida.json>
"""
import json
import sys
import time
import urllib.error
import urllib.request

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
PAUSA = 6.5  # limite sem chave: ~5 requisições a cada 30 s


def consultar(cve: str) -> dict:
    try:
        with urllib.request.urlopen(URL + cve, timeout=30) as r:
            dados = json.load(r)
    except urllib.error.HTTPError as e:
        status = "nao_encontrado" if e.code == 404 else f"erro_http_{e.code}"
        return {"cve": cve, "status": status}
    except Exception:  # noqa: BLE001
        return {"cve": cve, "status": "erro_rede"}

    vulns = dados.get("vulnerabilities", [])
    if not vulns:
        return {"cve": cve, "status": "nao_encontrado"}

    c = vulns[0]["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    cvss = None
    for chave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = c.get("metrics", {}).get(chave)
        if m:
            cvss = {"versao": chave, "nota": m[0]["cvssData"]["baseScore"]}
            break
    return {"cve": cve, "status": "existe", "descricao": desc[:200], "cvss": cvss}


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("Uso: python -m src.cve_check <ai_output.json> <saida.json>")
    with open(sys.argv[1], encoding="utf-8") as fh:
        ia = json.load(fh)

    cves = sorted({c for a in ia["achados"] for c in a["cves_citados"]})
    print(f"{len(cves)} CVEs únicos para consultar (~{int(len(cves) * PAUSA)} s)")

    resultados = []
    for cve in cves:
        r = consultar(cve)
        print(f"  {cve}: {r['status']}")
        resultados.append(r)
        time.sleep(PAUSA)

    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(resultados, fh, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
