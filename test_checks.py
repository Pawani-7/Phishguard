from checks import (
    get_host,
    is_long_url,
    has_ip_address,
    has_at_symbol,
    has_many_subdomains,
    uses_https,
    find_suspicious_words,
    impersonates_brand,
    has_many_hyphens_or_digits,
    uses_url_shortener,
)


#--------------- get_host (helper) ------------

def test_get_host_basic():
    assert get_host("https://www.Google.com/search?q=1") =="www.google.com"


def test_get_host_no_scheme():
    assert get_host("example.com/path") == "example.com"


def test_get_host_ignores_user_info():
    assert get_host("https://google.com@evil.com") == "evil.com"


def test_get_host_empty_and_invalid():
    assert get_host("") == ""
    assert get_host("https://[bad") ==""


#--------------- Check 1: long URL -----------

def test_long_url():
    assert is_long_url("https://example.com/" + "a" * 80)
    assert not is_long_url("http://example.com")


def test_long_url_boundary():
    assert not is_long_url("a" * 75)
    assert is_long_url("a" * 76)


#-------------- Check 2: IP address ----------

def test_ip_address_ipv4():
    assert has_ip_address("http://192.168.1.1/login")
    assert has_ip_address("http://google.com@192.168.1.1")
    assert not has_ip_address("http://example.com/login")
    assert not has_ip_address("http://256.1.1.1")


def test_ip_address_ipv6():
    assert has_ip_address("http://[::1]:8080/")


#------------- Check 3: @ symbol -------------

def test_at_symbol():
    assert has_at_symbol("http://google.com@evil.com")
    assert not has_at_symbol("http://google.com")


#------------- Check 4 :many subdomains -------------

def test_many_subdomains():
    assert has_many_subdomains("http://login.bank.secure.example.com")
    assert not has_many_subdomains("http://www.example.com")
    assert not has_many_subdomains("https://www.example.co.in")


def test_many_subdoains_custom_limit():
    assert has_many_subdomains("http://a.b.example.com", limit=2)
    assert not has_many_subdomains("http://a.b.example.com")


#------------- Check 5: HTTPS --------------

def test_uses_https():
    assert uses_https("https://example.com")
    assert uses_https("HTTPS://EXAMPLE.COM")
    assert not uses_https("http://example.com")
    assert not uses_https("example.com")


#------------- Check 6: suspicious words --------------

def test_suspicious_words_found():
    found = find_suspicious_words("http://example.com/login/verify")
    assert set(found) == {"login", "verify"}


def test_suspicious_words_none_and_case():
    assert find_suspicious_words("https://www.wikipedia.org") ==[]
    assert find_suspicious_words("HTTP://EXAMPLE.COM/LOGIN") ==["login"]


#------------- Check 7: look-alike brand ---------------

def test_brand_lookalike_detected():
    assert impersonates_brand("http://www.paypa1.com/login") =="paypal"
    assert impersonates_brand("http://faceb00k.com") == "facebook"
    assert impersonates_brand("http://rnicrosoft.com") == "microsoft"


def test_brand_official_doamins_ok():
    assert impersonates_brand("https://www.paypal.com/signin") is None
    assert impersonates_brand("https://mail.google.com") is None
    assert impersonates_brand("http://example.com") is None


def test_brand_trick_doamins():
    assert impersonates_brand("http://paypal.com.evil.com") == "paypal"
    assert impersonates_brand("http://secure-paypal-login.com") == "paypal"


#-------------- Check 8: hyphens or digits ------------

def test_hyphens_or_digits_true():
    assert has_many_hyphens_or_digits("http://secure-login-paypal-verify.com")
    assert has_many_hyphens_or_digits("http://abc12345.com")


def test_hyphens_or_digits_false():
    assert not has_many_hyphens_or_digits("http://my-site.com")
    assert not has_many_hyphens_or_digits("http://example123.com")
    assert not has_many_hyphens_or_digits("http://192.168.1.1")


#-------------- Check 9: URL shortener ----------------

def test_url_shortener():
    assert uses_url_shortener("https://bit.ly/abc123")
    assert uses_url_shortener("https://www.bit.ly/x")
    assert uses_url_shortener("https://tinyurl.com/x")
    assert not uses_url_shortener("https://example.com")
    