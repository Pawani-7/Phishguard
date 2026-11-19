from scoring import analyse, risk_level


def test_risk_level_boundaries():
    assert risk_level(0) == "Low"
    assert risk_level(1) == "Low"
    assert risk_level(2) == "Medium"
    assert risk_level(3) == "Medium"
    assert risk_level(4) == "High"
    assert risk_level(5) == "High"


def test_safe_link_is_low():
    result = analyse("https://www.google.com")
    assert result["score"] == 0
    assert result["level"] == "Low"
    assert result["reasons"] == []


def test_medium_link():
    # no HTTPS (+1), word 'login' (+1) = 2
    result = analyse("http://example.com/login")
    assert result["score"] == 2
    assert result["level"] == "Medium"


def test_lookalike_link_is_high():
    # no HTTPS (+1), word 'login' (+1), imitates paypal (+3) = 5
    result = analyse("http://paypa1.com/login")
    assert result["score"] == 5
    assert result["level"] == "High"


def test_high_link():
    # IP (+3), @ (+3), no HTTPS (+1), word secure and login (+1) = 8
    result = analyse("http://secure-login@192.168.1.1/bank.com")
    assert result["score"] == 8
    assert result["level"] == "High"


def test_reasons_explain_the_result():
    result = analyse("http://paypa1.com/login")
    assert len(result["reasons"]) == 3 
    assert any("paypal" in reason for reason in result["reasons"])


def test_url_shortener_scores_two():
    result = analyse("https://bit.ly/abc")
    assert result["score"] == 2
    assert result["level"] == "Medium"


def test_long_link_adds_one_point():
    result = analyse("https://example.com/" + "a" * 80)
    assert result["score"] == 1


def test_blank_input_is_invalid():
    assert analyse("  ")["level"] == "Invalid"
    assert analyse("")["level"] == "Invalid"


def test_at_in_path_is_not_flagged():
    # an @ after the first slash is harmless, e.g. medium.com/@name
    result = analyse("https://medium.com/@someone")
    assert result["score"] == 0


def test_risky_tld_alone_is_low():
    # risky ending .xyz (+1) = 1
    result = analyse("https://abc.xyz")
    assert result["score"] == 1
    assert result["level"] == "Low"

def test_risky_tld_plus_no_https_is_medium():
    result = analyse("http://example.xyz")
    assert result["score"] == 2
    assert result["level"] == "Medium"