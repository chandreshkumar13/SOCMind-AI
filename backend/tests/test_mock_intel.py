"""Mock threat-intelligence honesty (C9).

The mock dataset must not present invented vendor counts ('48/72 vendors') or well-known public hashes (the SHA-256 of an
empty file, of the word 'test') as malware. Mock results are labelled as mock, and a missing vendor count is None, not '0/72'.
"""
import hashlib

from app.tools import mock_intel

WELL_KNOWN_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",   # SHA-256 of an empty file
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",   # SHA-256 of the word 'test'
    "d41d8cd98f00b204e9800998ecf8427e",                                   # MD5 of an empty file
}


def test_no_well_known_public_hash_is_in_the_malicious_mock_dataset():
    assert not (set(mock_intel.KNOWN_MALICIOUS_HASHES) & WELL_KNOWN_HASHES)


def test_every_malicious_mock_hash_is_a_clearly_synthetic_label():
    for value, label in mock_intel.KNOWN_MALICIOUS_HASHES.items():
        assert label.startswith("MOCK sample:"), label
        assert "vendors" not in label and "/72" not in label, label
        assert len(value) == 64


def test_the_mock_hashes_are_derived_from_synthetic_labels_not_real_samples():
    expected = {hashlib.sha256(("socmind-mock-sample:" + name).encode()).hexdigest() for name in (
        "powershell-downloader", "cobalt-strike-style-loader", "file-encryptor", "lsass-dumper", "registry-autorun")}
    assert set(mock_intel.KNOWN_MALICIOUS_HASHES) == expected


def test_an_unknown_hash_has_no_invented_vendor_count():
    result = mock_intel.query_mock_hash_reputation("a" * 64)
    assert result["reputation"] == "UNKNOWN"
    assert result["detection_ratio"] is None
    assert "/72" not in result["evidence"] and "/72" not in str(result)


def test_a_known_mock_hash_is_malicious_but_still_carries_no_vendor_count():
    value = next(iter(mock_intel.KNOWN_MALICIOUS_HASHES))
    result = mock_intel.query_mock_hash_reputation(value)
    assert result["reputation"] == "MALICIOUS"
    assert result["detection_ratio"] is None
    assert "mock" in result["evidence"].lower()
    assert "/72" not in str(result)


def test_the_empty_file_hash_is_not_reported_as_malware():
    result = mock_intel.query_mock_hash_reputation("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert result["reputation"] == "UNKNOWN"
