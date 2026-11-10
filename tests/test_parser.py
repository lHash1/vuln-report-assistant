from src.parser import parse_nmap

FIXTURE = "tests/fixtures/sample_scan.xml"


def test_only_open_ports_are_returned():
    findings = parse_nmap(FIXTURE)
    assert [f["port"] for f in findings] == [21, 80]


def test_service_fields_are_extracted():
    ftp = parse_nmap(FIXTURE)[0]
    assert ftp["host"] == "192.168.56.101"
    assert ftp["product"] == "vsftpd"
    assert ftp["version"] == "2.3.4"
