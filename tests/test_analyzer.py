import json

from src.analyzer import validar


def _resp(achados):
    return json.dumps({"resumo_executivo": "x", "achados": achados})


def _item(porta=21, risco="critico", **extra):
    base = {"porta": porta, "risco": risco, "justificativa": "texto",
            "cves_citados": [], "mitigacao": "m"}
    base.update(extra)
    return base


def test_aceita_item_valido():
    r = validar(_resp([_item()]), [21])
    assert len(r["achados"]) == 1
    assert r["portas_sem_resposta"] == []


def test_descarta_risco_invalido():
    r = validar(_resp([_item(risco="gravíssimo")]), [21])
    assert r["achados"] == []
    assert len(r["descartados"]) == 1


def test_aponta_portas_sem_resposta():
    r = validar(_resp([_item(21)]), [21, 22])
    assert r["portas_sem_resposta"] == [22]


def test_separa_cve_com_formato_invalido():
    r = validar(_resp([_item(cves_citados=["cve-2011-2523", "CVE-XX"])]), [21])
    assert r["achados"][0]["cves_citados"] == ["CVE-2011-2523"]
    assert r["achados"][0]["cves_formato_invalido"] == ["CVE-XX"]


def test_aceita_cerca_markdown():
    texto = "```json\n" + _resp([_item()]) + "\n```"
    assert len(validar(texto, [21])["achados"]) == 1


def test_validar_aceita_porta_como_texto():
    import json
    from src.analyzer import validar

    texto = json.dumps({
        "resumo_executivo": "x",
        "achados": [{
            "porta": "21", "risco": "critico", "justificativa": "j",
            "cves_citados": [], "mitigacao": "m",
        }],
    })
    r = validar(texto, [21, 22])
    assert r["descartados"] == []
    assert r["achados"][0]["porta"] == 21
    assert r["portas_sem_resposta"] == [22]


def test_validar_rejeita_porta_invalida():
    import json
    from src.analyzer import validar

    itens = [
        {"porta": "abc", "risco": "alto", "justificativa": "j"},
        {"porta": True, "risco": "alto", "justificativa": "j"},
    ]
    r = validar(json.dumps({"resumo_executivo": "x", "achados": itens}), [21])
    assert r["achados"] == []
    assert len(r["descartados"]) == 2
