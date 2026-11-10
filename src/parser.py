import xml.etree.ElementTree as ET


def parse_nmap(path: str) -> list[dict]:
    """Lê um XML do Nmap (-oX) e retorna as portas abertas como lista de dicts."""
    findings = []
    root = ET.parse(path).getroot()

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr")

        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            findings.append({
                "host": addr,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })
    return findings


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        sys.exit("Uso: python -m src.parser <arquivo_scan.xml>")
    print(json.dumps(parse_nmap(sys.argv[1]), indent=2, ensure_ascii=False))
