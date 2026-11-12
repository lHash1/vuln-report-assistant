"""Triagem de CVEs do NVD para um CPE (somente leitura; a decisão final é manual).

Uso: python -m src.triagem_nvd <cpe> [nota_minima_v2]
Sinaliza CVEs que mencionam outra plataforma, biblioteca ou cadeia de suprimento.
"""
import json
import sys
import urllib.parse
import urllib.request

SUSPEITOS = ["windows", "win32", "red hat", "rhel", "fedora", "freebsd", "netbsd",
             "solaris", "hp-ux", "mac os", "libbind", "trojan", "third-party",
             "when running on", "non-default", "if configured"]


def nota_v2(cve):
    m = cve.get("metrics", {}).get("cvssMetricV2")
    if not m:
        return None, "", ""
    d = m[0]["cvssData"]
    return d.get("baseScore"), d.get("accessVector", ""), d.get("authentication", "")


def main():
    cpe = sys.argv[1]
    minimo = float(sys.argv[2]) if len(sys.argv) > 2 else 7.0
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"cpeName": cpe})
    dados = json.load(urllib.request.urlopen(url, timeout=60))
    itens = []
    for v in dados["vulnerabilities"]:
        c = v["cve"]
        nota, vetor, auth = nota_v2(c)
        desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
        kev = "KEV" if c.get("cisaExploitAdd") else ""
        sinais = [s for s in SUSPEITOS if s in desc.lower()]
        itens.append((nota or 0, c["id"], vetor, auth, kev, desc, sinais))
    itens.sort(reverse=True)
    triagem = [i for i in itens if i[2] == "NETWORK" and i[3] == "NONE" and i[0] >= minimo]
    limpos = [i for i in triagem if not i[6]]
    print(f"{len(itens)} CVEs; {len(triagem)} NETWORK/sem autenticação/nota >= {minimo}; "
          f"{len(limpos)} sem sinal de outra plataforma\n")
    for nota, cid, vetor, auth, kev, desc, sinais in triagem:
        aviso = f"  [SINAL: {', '.join(sinais)}]" if sinais else ""
        print(f"{cid}  v2={nota}  {kev}{aviso}\n  {desc[:300]}\n")


if __name__ == "__main__":
    main()
