from cybercheck.utils.threat_intel import extract_cves_from_text, enrich_blob


def test_extract_cves_from_text_dedupes_and_sorts():
    blob = "Impact to CVE-2024-3094 and CVE-2023-34362 plus CVE-2024-3094 duplicates"
    result = extract_cves_from_text(blob)
    assert result == ["CVE-2023-34362", "CVE-2024-3094"]


def test_enrich_blob_returns_structured_metadata():
    blob = "CVE-2023-4863 shows up in Chrome and CVE-2022-22965 in Spring"
    enriched = enrich_blob(blob)
    assert any(item["cve"] == "CVE-2023-4863" and item["cvss"] >= 8 for item in enriched)
    assert any(item["product"] == "Spring Framework" for item in enriched)
