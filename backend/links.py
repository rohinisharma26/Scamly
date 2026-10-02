import ipaddress
import re
from urllib.parse import urlparse

# ---------- Finding links ----------

# Endings accepted for links written without http:// or www.
_BARE_TLDS = (
    "com|net|org|info|xyz|top|site|online|click|link|club|shop|biz|co|io|me|ly|gl|app|live|"
    "support|help|vip|icu|cc|tk|ml|ga|cf|gq|work|in|us|uk|de|ru|cn|ai|to|ws|pw|buzz|rest|"
    "store|tech|page|bond|cyou|sbs|lol"
)

LINK_PATTERN = re.compile(
    r"""(?<![@\w.-])(?:
        (?:https?://|www\.)[^\s<>"']+
        |
        (?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:""" + _BARE_TLDS + r""")(?:\.[a-z]{2})?(?![\w-])(?::\d+)?(?:/[^\s<>"']*)?
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def extract_links(text: str) -> list[str]:
    """Links with or without http://, in order, without duplicates. Email domains are skipped."""
    seen = set()
    links = []
    for match in LINK_PATTERN.finditer(text):
        raw = match.group(0).rstrip(".,;:!?)]}'\"")
        key = raw.lower()
        if raw and key not in seen:
            seen.add(key)
            links.append(raw)
    return links


# ---------- Checking one link ----------

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd",
    "ow.ly", "buff.ly", "shorturl.at", "t.ly",
}

RISKY_TLDS = {
    "xyz", "top", "click", "online", "site", "icu", "vip", "cc", "tk", "ml", "ga", "cf",
    "gq", "live", "support", "work", "rest", "buzz", "bond", "cyou", "sbs", "pw", "lol",
}

# Add brands here: name as it appears in a web address -> its real domains
BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca"],
    "google": ["google.com", "google.co.in", "google.co.uk"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "flipkart": ["flipkart.com"],
}

_LOOKALIKE_DIGITS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
_RANK = {"high": 3, "medium": 2, "low": 1}


def _registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _flag(code: str, label: str, severity: str, explanation: str) -> dict:
    return {"type": code, "label": label, "severity": severity, "explanation": explanation}


def analyze_link(raw: str) -> dict:
    """Checks the address itself. It never visits the link."""
    result = {"url": raw, "domain": None, "flags": [], "level": "none"}

    has_scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.IGNORECASE))
    try:
        parsed = urlparse(raw if has_scheme else "http://" + raw)
        host = (parsed.hostname or "").lower()
        username = parsed.username
    except ValueError:
        result["flags"].append(_flag("malformed", "Malformed address", "medium",
                                     "This address is written in an unusual way that is hard to read."))
        result["level"] = "medium"
        return result

    if not host:
        return result
    result["domain"] = host
    flags = result["flags"]

    # Raw IP address instead of a name
    try:
        ipaddress.ip_address(host)
        flags.append(_flag("ip_address", "Uses a number instead of a name", "high",
                           "The link points to a raw IP address. Real companies almost always use their own name."))
        is_ip = True
    except ValueError:
        is_ip = False

    # "paypal.com@evil.com" trick
    if username:
        flags.append(_flag("userinfo_trick", "Hidden destination", "high",
                           "Text before the @ sign is ignored by browsers. The link really goes to " + host + "."))

    # Look-alike letters from other alphabets
    if "xn--" in host:
        flags.append(_flag("punycode", "Look-alike characters", "medium",
                           "The address uses special characters that can imitate normal letters."))

    if is_ip:
        return _finish(result)

    registrable = _registrable(host)
    tld = host.rsplit(".", 1)[-1]

    # Link shorteners
    if registrable in SHORTENERS or host in SHORTENERS:
        flags.append(_flag("shortener", "Shortened link", "medium",
                           "A link shortener hides where you will land, so you can't judge the destination first."))

    # Risky ending
    if tld in RISKY_TLDS:
        flags.append(_flag("risky_tld", "Uncommon ending (." + tld + ")", "medium",
                           "This ending is cheap and often used for throwaway scam sites, though real sites use it too."))

    # Plain http
    if has_scheme and parsed.scheme.lower() == "http":
        flags.append(_flag("no_https", "Not encrypted (http)", "low",
                           "The link doesn't use HTTPS. Real login and payment pages almost always do."))

    # Imitating a known brand
    tokens = re.split(r"[.\-]", host)
    for token in tokens:
        normalized = token.translate(_LOOKALIKE_DIGITS)
        for brand, official in BRANDS.items():
            if normalized == brand or (normalized.startswith(brand) and len(normalized) - len(brand) <= 6):
                if registrable in official:
                    continue
                swapped = normalized != token
                exact = normalized == brand
                severity = "high" if (swapped or exact) else "medium"
                reason = "uses look-alike characters" if swapped else "puts the name in a different site"
                flags.append(_flag("brand_lookalike", "May imitate " + brand.title(), severity,
                                   "This address " + reason + ". The real site is " + official[0] +
                                   ", but this link goes to " + registrable + "."))
                break
        else:
            continue
        break

    # Long or hyphen-heavy names
    first_label = registrable.split(".")[0]
    if len(first_label) > 25 or first_label.count("-") >= 3:
        flags.append(_flag("odd_name", "Unusually long name", "low",
                           "Very long or hyphen-heavy names are common in fake sites."))

    # Many subdomains
    if len(host.split(".")) >= 5:
        flags.append(_flag("many_subdomains", "Many nested parts", "low",
                           "Long chains of subdomains can hide the real site name at the end."))

    return _finish(result)


def _finish(result: dict) -> dict:
    if result["flags"]:
        result["level"] = max(result["flags"], key=lambda f: _RANK[f["severity"]])["severity"]
    return result


def analyze_links(text: str, limit: int = 10) -> list[dict]:
    return [analyze_link(link) for link in extract_links(text)[:limit]]


# ---------- Quick self-test: python links.py ----------

if __name__ == "__main__":
    sample = (
        "Verify at secure-chase-auth.net/review or http://paypa1-secure.com now. "
        "Pay via bit.ly/x9 or http://192.168.4.7/login. Real: https://www.paypal.com/signin. "
        "Trick: http://paypal.com@evil.example.top/a. Mail support@totally-real-bank.com. Done."
    )
    for item in analyze_links(sample):
        print(item["url"], "->", item["level"], [f["type"] for f in item["flags"]])