"""Flask integration tests. Translation and the zero-shot model are disabled
in conftest.py, so these run offline."""

PHISH_SMS = ("Dear customer, your SBI account will be blocked today. Update KYC immediately at "
             "http://sbi-kyc-update.xyz/verify or share OTP to avoid suspension.")


def test_index(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Analyze URL" in r.data and b"Analyze Threat" in r.data
    assert b"99.2%" not in r.data  # the old hard-coded "Detection Rate" must be gone


def test_health_reports_components(client):
    d = client.get("/api/health").get_json()
    c = d["components"]
    assert c["threat_intel"] == {"configured": False, "provider": "none"}
    assert c["translation"]["enabled"] is False
    assert "url_model" in c and "message_spam_classifier" in c


def test_api_analyze_url(client):
    r = client.post("/api/analyze-url", json={"url": "http://paypa1.com/signin/verify"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["status"] == "ok"
    assert 0 <= d["score"] <= 100
    exp = d["explanation"]
    assert {"model_evidence", "heuristic_evidence", "external_evidence",
            "score_breakdown", "recommendations", "limitations"} <= set(exp)
    assert "typosquat" in {i["id"] for i in exp["heuristic_evidence"]["indicators"]}


def test_api_analyze_url_validation(client):
    assert client.post("/api/analyze-url", json={}).status_code == 400
    assert client.post("/api/analyze-url", json={"url": 5}).status_code == 400
    assert client.post("/api/analyze-url", data="x", content_type="text/plain").status_code == 400
    r = client.post("/api/analyze-url", json={"url": "ftp://example.com"})
    assert r.status_code == 400 and "http" in r.get_json()["message"]


def test_url_page_renders_explanation(client):
    r = client.post("/analyze-url", data={"url": "http://192.168.4.2/bank/login.php"})
    assert r.status_code == 200
    html = r.data.decode()
    assert "Machine-Learning Evidence" in html
    assert "Rule-Based Indicators" in html
    assert "IP address used as host" in html
    assert "How the Score Was Calculated" in html
    assert "Threat Intelligence" in html


def test_url_page_invalid_input_shows_error(client):
    r = client.post("/analyze-url", data={"url": "javascript:alert(1)"})
    assert r.status_code == 400
    assert b"form-error" in r.data


def test_message_analysis_still_works(client):
    r = client.post("/analyze", data={"message": PHISH_SMS})
    assert r.status_code == 200
    html = r.data.decode()
    assert "Threat Evidence" in html
    assert "sbi-kyc-update.xyz" in html
    assert "src-url-analysis" in html  # URL evidence is tagged with its source


def test_api_message_uses_url_engine(client):
    d = client.post("/api/analyze-message", json={"message": PHISH_SMS}).get_json()
    assert d["status"] == "ok"
    u = d["url_info"]["urls"][0]
    assert u["suspicious"] is True
    assert u["heuristic_score"] > 0
    assert d["score"] > 60
    assert all("source" in e for e in d["evidence"])


def test_legit_looking_sms_with_high_risk_link_is_not_whitelisted(client):
    msg = ("Rs 2,500.00 debited from A/c XX4821. Avl Bal: Rs 18,342.50. UPI Ref 402981738281. "
           "Not you? http://192.168.4.2/hdfc/login.php")
    d = client.post("/api/analyze-message", json={"message": msg}).get_json()
    assert d["url_info"]["max_risk"] > 60
    assert d["legit"]["is_legitimate"] is False
    assert d["score"] >= d["url_info"]["max_risk"]


def test_legitimate_bank_sms_not_flagged(client):
    msg = "Rs 2,500.00 debited from A/c XX4821 on 24-Sep-26. Avl Bal: Rs 18,342.50. UPI Ref 402981738281. HDFC Bank"
    d = client.post("/api/analyze-message", json={"message": msg}).get_json()
    assert d["legit"]["is_legitimate"] is True
    assert d["score"] <= 20


def test_leet_normalisation_does_not_hide_lookalike_domains(client):
    # Regression: URLs used to be analysed after leet decoding, which turned
    # amaz0n.com into amazon.com (an official domain).
    d = client.post("/api/analyze-message",
                    json={"message": "Your parcel is held, pay fee at http://amaz0n.com/track"}).get_json()
    u = d["url_info"]["urls"][0]
    assert "amaz0n.com" in u["url"]
    assert "Official brand domain" not in u["flags"]
    assert any("amazon" in f.lower() for f in u["flags"])


def test_spam_model_reports_no_signal_for_unknown_vocabulary(flask_app):
    p, signal = flask_app.spam_probability("qwxz zzvq plmk")
    assert signal is False and p == 0.0
    p, signal = flask_app.spam_probability("WINNER!! You have won a free prize, call now to claim")
    assert signal is True and p > 0.5


def test_message_too_long(client, flask_app):
    big = "a " * (flask_app.settings.max_message_chars)
    assert client.post("/api/analyze-message", json={"message": big}).status_code == 400


def test_feedback_roundtrip_and_validation(client):
    ok = client.post("/feedback", json={"analysis_id": "t1", "message": "m", "score": 70,
                                        "risk_label": "High Risk", "is_correct": True})
    assert ok.status_code == 200 and ok.get_json()["stats"]["total"] >= 1
    assert client.post("/feedback", json={"score": "high"}).status_code == 400
    assert client.post("/feedback", json={"score": 500}).status_code == 400
    assert client.post("/feedback", json={"score": 5, "is_correct": "yes"}).status_code == 400


def test_api_404_is_json(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and r.get_json()["status"] == "error"
