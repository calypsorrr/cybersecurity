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


def test_email_analysis_surfaces_spf_and_return_path_issues():
    raw_email = (
        "Return-Path: <bounce@mailer.fake>\n"
        "From: Trusted Sender <info@example.com>\n"
        "Reply-To: handler@reply.example.com\n"
        "Authentication-Results: spf=softfail (sender SPF record not authorized)\n\n"
        "Hello"
    )

    result = analyze_email_text(raw_email)

    issue_types = {issue["type"] for issue in result["issues"]}
    assert "Return-Path mismatch" in issue_types
    assert "SPF validation failure" in issue_types


def test_email_analysis_detects_fake_emailer_headers():
    raw_email = (
        "From: Spoofed <sender@example.com>\n"
        "Subject: Test\n"
        "Received: from mail.emkei.cz (mail.emkei.cz [203.0.113.10])\n\n"
        "Body"
    )

    result = analyze_email_text(raw_email)

    issue_types = {issue["type"] for issue in result["issues"]}
    assert "Fake emailer detected" in issue_types


def test_uploaded_file_detects_truncated_image_body():
    payload = b"\xff\xd8\xff" + b"\x00" * 20  # JPEG header without end marker

    result = analyze_uploaded_file("photo.jpg", payload)

    issue_types = {issue["type"] for issue in result["issues"]}
    assert "Corrupted media body" in issue_types
    assert result["risk_level"] in {"medium", "high"}


def test_uploaded_file_flags_html_polyglot_and_metadata():
    polyglot = b"\xff\xd8\xff" + b"JFIF\x00" + b"<html><script>alert(1)</script></html>" + b"\xff\xd9"

    result = analyze_uploaded_file("avatar.jpeg", polyglot)

    issue_types = {issue["type"] for issue in result["issues"]}
    assert "Embedded HTML content" in issue_types
    assert "Embedded script tag" in issue_types
    assert "JFIF segment present" in result["metadata"]["metadata_flags"]
