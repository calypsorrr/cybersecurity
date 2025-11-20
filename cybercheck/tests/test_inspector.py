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


def test_email_analysis_catches_display_and_link_spoofing():
    raw_email = (
        "From: Bank.com Security <alerts@dodgy.biz>\n"
        "Reply-To: handler@payments.ru\n"
        "Subject: Important account notice\n"
        "Content-Type: text/html\n\n"
        "Your account will be suspended if you do not respond immediately. "
        "<a href=\"http://phish.test/login\">https://bank.com/login</a>"
    )

    result = analyze_email_text(raw_email)

    issue_types = {issue["type"] for issue in result["issues"]}
    assert "Display name/domain mismatch" in issue_types
    assert "Foreign Reply-To domain" in issue_types
    assert "Misleading hyperlink" in issue_types
    assert "Urgent/threatening language" in issue_types


def test_email_analysis_flags_priority_invoice_attachment():
    raw_email = (
        "From: billing@example.com\n"
        "Subject: Invoice attached\n"
        "X-Priority: 1 (Highest)\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\n\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain\n\n"
        "Please see attached invoice.\n"
        "--BOUNDARY\n"
        "Content-Type: application/pdf\n"
        "Content-Disposition: attachment; filename=\"invoice_2024.pdf\"\n\n"
        "%PDF-1.4\n"
        "--BOUNDARY--\n"
    )

    result = analyze_email_text(raw_email)

    issue_types = {issue["type"] for issue in result["issues"]}
    assert "High-priority invoice attachment" in issue_types
    assert "Attachment present" in issue_types
