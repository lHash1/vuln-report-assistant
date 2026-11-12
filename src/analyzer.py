"""Analisa um scan Nmap com um LLM (Gemini) e valida a resposta.

Uso:
    python -m src.analyzer samples/lab01_metasploitable2.xml --limite 10 \
        --saida evaluation/ai_output_lab01.json
"""
import argparse
import json
import os
import re
import sys
import time
import unicodedata
from datetime import datetime, timezone

from dotenv import load_dotenv

from src.parser import parse_nmap

RISCOS = ("critico", "alto", "medio", "baixo")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
VERSAO_PROMPT = "v1"

PROMPT = """Você é um analista de segurança júnior apoiando uma equipe.
Recebeu o resultado de um scan Nmap (-sV) de um ambiente de laboratório.
Avalie o risco de CADA porta listada, usando APENAS as informações fornecidas.

Regras:
- "risco" deve ser exatamente um de: critico, alto, medio, baixo.
- Se a versão não foi informada, diga isso na justificativa e não presuma uma versão.
- Versão detectada por banner é candidata a vulnerável, não confirmada.
- Só cite CVEs se tiver alta confiança de que se aplicam ao produto E à versão informados.
  Se não tiver certeza, deixe a lista vazia. NÃO invente CVEs.
- Se o risco vem do protocolo ou da configuração (ex.: texto claro) e não de uma versão, diga isso.
- "justificativa": 1 a 2 frases em português. "mitigacao": 1 frase em português.
- "resumo_executivo": 3 a 5 frases em português para um gestor sem conhecimento técnico:
  o que é mais urgente e por quê, sem jargão.

Responda SOMENTE com JSON neste formato:
{
  "resumo_executivo": "texto",
  "achados": [
    {
      "porta": "<número da porta>",
      "risco": "<critico|alto|medio|baixo>",
      "justificativa": "texto",
      "cves_citados": ["CVE-AAAA-NNNN"],
      "mitigacao": "texto"
    }
  ]
}

Dados do scan:
{dados}
"""


def normaliza(texto: str) -> str:
    t = unicodedata.normalize("NFKD", texto.strip().lower())
    return "".join(c for c in t if not unicodedata.combining(c))


def rotulo(f: dict) -> str:
    if f["product"]:
        return " ".join(p for p in (f["product"], f["version"]) if p)
    if f["version"]:
        return f'{f["service"]} {f["version"]}'
    return f["service"] or "desconhecido"


def montar_prompt(findings: list[dict]) -> str:
    dados = [
        {
            "porta": f["port"],
            "protocolo": f["protocol"],
            "servico_nmap": f["service"],
            "produto": f["product"],
            "versao": f["version"],
        }
        for f in findings
    ]
    return PROMPT.replace("{dados}", json.dumps(dados, indent=2, ensure_ascii=False))


def chamar_llm(client, prompt: str, modelos: list[str], tentativas: int = 3):
    """Tenta cada modelo com espera exponencial. Retorna (modelo, texto)."""
    from google.genai import types

    ultimo_erro = "desconhecido"
    for modelo in modelos:
        for t in range(1, tentativas + 1):
            try:
                r = client.models.generate_content(
                    model=modelo,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json", temperature=0
                    ),
                )
                if r.text:
                    return modelo, r.text
                ultimo_erro = "resposta vazia"
            except Exception as e:  # noqa: BLE001
                ultimo_erro = f"{type(e).__name__}: {str(e)[:120]}"
            print(f"  [{modelo}] tentativa {t}/{tentativas}: {ultimo_erro}", file=sys.stderr)
            if "404" in ultimo_erro:  # modelo inexistente: não adianta repetir
                break
            time.sleep(2 ** t)
    raise RuntimeError(f"Nenhum modelo respondeu. Último erro: {ultimo_erro}")


def converte_porta(valor):
    """Converte a porta para int. Aceita 21 ou "21"; rejeita bool e valores não numéricos."""
    if isinstance(valor, bool):
        return None
    if isinstance(valor, int):
        return valor
    if isinstance(valor, str) and valor.strip().isdigit():
        return int(valor.strip())
    return None


def validar(texto: str, portas_esperadas: list[int]) -> dict:
    """Valida o JSON do modelo. Itens inválidos vão para 'descartados'."""
    limpo = re.sub(r"^```(?:json)?\s*|\s*```$", "", texto.strip())
    bruto = json.loads(limpo)
    if not isinstance(bruto, dict) or not isinstance(bruto.get("achados"), list):
        raise ValueError("JSON sem a lista 'achados'")

    achados, descartados, vistas = [], [], set()
    for item in bruto["achados"]:
        motivo = None
        if not isinstance(item, dict):
            motivo = "item não é um objeto"
        else:
            porta = converte_porta(item.get("porta"))
            risco = normaliza(str(item.get("risco", "")))
            if porta not in portas_esperadas:
                motivo = "porta fora do escopo"
            elif porta in vistas:
                motivo = "porta duplicada"
            elif risco not in RISCOS:
                motivo = f"risco inválido: {item.get('risco')!r}"
            elif not str(item.get("justificativa", "")).strip():
                motivo = "justificativa vazia"
        if motivo:
            descartados.append({"motivo": motivo, "item": item})
            continue

        cves = item.get("cves_citados") or []
        if not isinstance(cves, list):
            cves = []
        cves = [str(c).strip().upper() for c in cves]
        vistas.add(porta)
        achados.append({
            "porta": porta,
            "risco": risco,
            "justificativa": str(item["justificativa"]).strip(),
            "cves_citados": [c for c in cves if CVE_RE.match(c)],
            "cves_formato_invalido": [c for c in cves if not CVE_RE.match(c)],
            "mitigacao": str(item.get("mitigacao", "")).strip(),
        })

    return {
        "resumo_executivo": str(bruto.get("resumo_executivo", "")).strip(),
        "achados": achados,
        "descartados": descartados,
        "portas_sem_resposta": [p for p in portas_esperadas if p not in vistas],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Analisa um scan Nmap com LLM")
    ap.add_argument("scan")
    ap.add_argument("--limite", type=int, default=10)
    ap.add_argument("--saida", default="evaluation/ai_output_lab01.json")
    args = ap.parse_args()

    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

    findings = parse_nmap(args.scan)[: args.limite]
    portas = [f["port"] for f in findings]
    rotulos = {f["port"]: rotulo(f) for f in findings}

    from google import genai

    client = genai.Client(api_key=os.environ["LLM_API_KEY"])
    modelos = [os.environ["LLM_MODEL"]] + [
        m.strip() for m in os.environ.get("LLM_FALLBACK_MODELS", "").split(",") if m.strip()
    ]
    modelos = list(dict.fromkeys(modelos))

    prompt = montar_prompt(findings)
    os.makedirs("evaluation/raw", exist_ok=True)

    resultado, modelo_usado = None, None
    for rodada in (1, 2):
        modelo_usado, texto = chamar_llm(client, prompt, modelos)
        carimbo = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        with open(f"evaluation/raw/ai_raw_{carimbo}_{rodada}.txt", "w", encoding="utf-8") as fh:
            fh.write(texto)
        try:
            resultado = validar(texto, portas)
            break
        except ValueError as e:
            print(f"Resposta inválida na rodada {rodada}: {e}", file=sys.stderr)

    if resultado is None:
        sys.exit("Resposta inválida duas vezes. Veja evaluation/raw/.")

    for a in resultado["achados"]:
        a["servico"] = rotulos[a["porta"]]

    saida = {
        "meta": {
            "modelo_usado": modelo_usado,
            "data_utc": datetime.now(timezone.utc).isoformat(),
            "versao_prompt": VERSAO_PROMPT,
            "arquivo_scan": args.scan,
            "limite": args.limite,
            "portas_no_escopo": portas,
        },
        **resultado,
    }
    with open(args.saida, "w", encoding="utf-8") as fh:
        json.dump(saida, fh, indent=2, ensure_ascii=False)

    print(f"Modelo: {modelo_usado}")
    print(f"Achados válidos: {len(resultado['achados'])}/{len(portas)}")
    print(f"Descartados: {len(resultado['descartados'])}")
    print(f"Portas sem resposta: {resultado['portas_sem_resposta']}")
    print(f"Saída: {args.saida}")


if __name__ == "__main__":
    main()
