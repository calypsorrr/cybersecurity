from cybercheck.utils.inspector import analyze_email_text, analyze_uploaded_file


def test_media_header_mismatch_flags_issue():
    # Executable header disguised as media should raise warnings
    payload = b"MZ" + b"\x00" * 50
    result = analyze_uploaded_file("song.mp3", payload)

    assert result["risk_level"] == "high"
    assert any(issue["type"] == "Executable masquerading as media" for issue in result["issues"])


def test_email_analysis_detects_phishing_signals():
    raw_email = (
        "From: sender@example.com\n"
        "Reply-To: scams@evil.com\n"
        "Subject: \n\n"
        "This is urgent, verify your password at http://evil.test now."
    )

    result = analyze_email_text(raw_email)

    issue_types = {issue["type"] for issue in result["issues"]}
    assert "Reply-To mismatch" in issue_types
    assert "Empty subject" in issue_types
    assert "Phishing language" in issue_types
    assert "Link present" in issue_types
    assert result["risk_level"] == "high"
