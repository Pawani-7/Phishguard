"""PhishGuard: scoring engine.

Runs the nine checks from checks.py, adds a weighted point for each 
warning sign, and returns a risk level with the reasons.
Links are only analysed as text. They are never opened.
"""

from checks import(
    is_long_url,
    has_ip_address,
    has_at_symbol,
    has_many_subdomains,
    uses_https,
    find_suspicious_words,
    impersonates_brand,
    has_many_hypens_or_digits,
    uses_url_shortener,
)

# Initial weights (they will be tuned after testing on your link set)
WEIGHTS = {
    "long_url": 1,
    "ip_address": 3,
    "at_symbol": 3,
    "many_subdomains": 2,
    "no_https": 1,
    "suspicious_words": 1,
    "brand_lookalike": 3,
    "hyphens_digits": 1,
    "url_shortener": 2,
}

# Score limits: 0-2 Low, 3-5 Medium, 6 or more High
LOW_MAX = 2
MEDIUM_MAX = 5


def risk_level(score):
    """Turn a score into Low, Medium, High."""
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


def analyse(url):
    """Check a link and retuen a dicitionary with:
    url, score, level and reasons (a list of plain-language sentences.)"""
    if not url or not url.strip():
        return {
            "url": url,
            "score": 0,
            "level": "Invalid",
            "reasons": ["No link was entered"],
        }
    
    score = 0
    reasons = []
 
    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(f"{reason} (+{points})")
 
    if is_long_url(url):
        add(WEIGHTS["long_url"], "The link is very long")
 
    if has_ip_address(url):
        add(WEIGHTS["ip_address"], "Uses an IP address instead of a domain name")
 
    if has_at_symbol(url):
        add(WEIGHTS["at_symbol"], "Contains an @ symbol that can hide the real site")
 
    if has_many_subdomains(url):
        add(WEIGHTS["many_subdomains"], "Has too many subdomains")
 
    if not uses_https(url):
        add(WEIGHTS["no_https"], "Does not use HTTPS")
 
    words = find_suspicious_words(url)
    if words:
        add(WEIGHTS["suspicious_words"],
            "Contains suspicious words: " + ", ".join(words))
 
    brand = impersonates_brand(url)
    if brand:
        add(WEIGHTS["brand_lookalike"],
            f"Looks like it is imitating '{brand}'")
 
    if has_many_hypens_or_digits(url):
        add(WEIGHTS["hyphens_digits"],
            "Domain has many hyphens or digits")
 
    if uses_url_shortener(url):
        add(WEIGHTS["url_shortener"],
            "Uses a URL shortener that hides the real destination")
 
    return {
        "url": url,
        "score": score,
        "level": risk_level(score),
        "reasons": reasons,
    }

