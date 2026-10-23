"""PhishGuard: the nine link checks .

Each check reads only the TEXT of a link. No link is ever opened or visited.
"""

import ipaddress
from urllib.parse import urlparse

#------------ Data used by the checks -------------

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure",
    "account", "signin", "confirm", "banking",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

#Brand name -> the real domains that brand uses 
OFFICIAL_DOMAINS ={
    "paypal": ["paypal.com"],
    "google": ["google.com", "google.co.in"],
    "amazon": ["amazon.com", "amazon.in"],
    "facebook": ["facebook.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
    "paytm": ["paytm.com"],
    "hdfcbank": ["hdfcbank,com"],
    }

# Digits that attackers use in place of letters (paypal -> paypal)
LOOKALIKE_DIGITS = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"}
)


#------------- Helper -------------

def get_host(url):
    """Return the host (domain or IP) of a link in lower case.
    
    Browsers ignore everything before an @ sign, so
    'https://google.com@evil.com' really goes to evil.com
    """
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


#------------- Check 1 --------------

def is_long_url(url, limit=75):
    """Very long links are often used to hide the real address."""
    return len(url) > limit


#------------- Check 2 --------------

def has_ip_address(url):
    """Real sites use names. A  raw IP address in a link is a warning sign."""
    try:
        ipaddress.ip_address(get_host(url))
        return True
    except ValueError:
        return False


#-------------- Check 3 ---------------

def has_at_symbol(url):
    """Anything before an @ is ignored by the browser, so attackers use it 
    to show a trusted name frist and hide the real site after it.""" 
    return "@" in url 


#-------------- Check 4 ----------------

def has_many_subdomains(url, limit=3):
    """More than 'limit' dots in th ehost means many subdomains,
    e.g. login.bank.secure.example.com (4 dots)."""
    return get_host(url).count(".") > limit 


#--------------- Check 5 ---------------

def uses_https(url):
    """True only if the link starts with https://.
    A link with https:// or no scheme returns False."""
    return url.strip().lower().startswith("https://")


#--------------- Check 6 ----------------

def find_suspicious_words(url):
    """Return the list of suspicious words found in the link."""
    text = url.lower()
    return [word for word in SUSPICIOUS_WORDS if word in text]


#--------------- Check 7 ----------------

def _normalize_host(host):
    """Turn look-alike characters back into letters so that 
    paypa1 -> paypal, rnicrosoft -> microsoft, faceb00k -> facebook."""
    host = host.lower().translate(LOOKALIKE_DIGITS)
    return host.replace("rn", "m").replace("vv", "w")


def _is_official(host, domains):
    """True if host is a real domain or a subdomain of one."""
    return any(host == d or host.endswith("." + d) for d in domains)


def impersonates_brand(url):
    """Return the brand name if the host imitates a known brand,
    otherwise None."""
    host = get_host(url)
    if not host:
        return None
    cleaned = _normalize_host(host)
    for brand, domains in OFFICIAL_DOMAINS.items():
        if brand in cleaned and not _is_official(host, domains):
            return brand
        return None


#---------------- Check 8 ---------------

def has_many_hypens_or_digits(url, max_hyphens=2, max_digits=3):
    """Too many hyphens or digits in the domain is a warning sign,
    e.g. secure-lofin-paypal-verify.com. Raw IP addrss are skipped
    here because check 2 already covers them."""
    if has_ip_address(url):
        return False
    host = get_host(url)
    digits = sum(ch.isdigit() for ch in host)
    return host.count("-") > max_hyphens or digits > max_digits


#---------------- Check 9 ---------------

def uses_url_shortener(url):
    """Short links hide the real destination."""
    host = get_host(url).removeprefix("www.")
    return host in URL_SHORTENERS
