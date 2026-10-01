import re

# ---------- Extraction ----------

def extract_urls(text: str) -> list[str]:
    pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(pattern, text)

def extract_emails(text: str) -> list[str]:
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(pattern, text)

def extract_phone_numbers(text: str) -> list[str]:
    pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
    return re.findall(pattern, text)

# ---------- Indicator rules ----------

INDICATOR_RULES = [
    {
        "type": "urgency",
        "severity": "medium",
        "patterns": [
            r'\bURGENT\b', r'\bact now\b', r'\bimmediately\b', r'\bright away\b',
            r'\bexpire[sd]?\s+(today|soon)\b', r'\bwithin \d+ ?(hours?|hrs?|minutes?|mins?)\b',
            r'\blast (chance|warning)\b',
        ],
        "explanation": "Creates pressure to act quickly, a common tactic to stop you from thinking it through."
    },
    {
        "type": "reward",
        "severity": "medium",
        "patterns": [
            r'\byou.{0,10}(won|selected|winner)\b', r'\bclaim your (reward|prize)\b',
            r'\bfree (gift|prize)\b',
        ],
        "explanation": "Unsolicited reward or prize framing, often used to lower your guard."
    },
    {
        "type": "verification_pressure",
        "severity": "high",
        "patterns": [
            r'\bverify (your )?(identity|account|details|information|payment)\b',
            r'\bconfirm your (password|pin|card|details)\b',
            r'\bre-?authenticate\b',
        ],
        "explanation": "Pushes you to hand over sensitive information under pressure."
    },
    {
        "type": "payment_request",
        "severity": "high",
        "patterns": [
            r'\bpay (a|the|an) (small )?(fee|deposit|charge)\b', r'\bgift cards?\b',
            r'\bwire transfer\b', r'\bsend (money|payment|a payment)\b',
            r'\b(registration|processing|activation|customs|release) (fee|charge)\b',
            r'\bpay (in|with) (bitcoin|crypto\w*)\b',
        ],
        "explanation": "Requests for payment, especially via gift cards, wire transfer or upfront fees, are a strong scam signal."
    },
    {
        "type": "authority_impersonation",
        "severity": "medium",
        "patterns": [
            r'\b(bank|irs|government|police)\b.{0,20}\b(department|office|division)\b',
            r'\bthis is (your )?(bank|the irs|the police|customer support|tech support|microsoft support|apple support)\b',
        ],
        "explanation": "Invokes a trusted authority to make the message seem legitimate."
    },
    {
        "type": "job_offer",
        "severity": "medium",
        "patterns": [
            r'\b(job|work) (offer|opportunity)\b', r'\bwork from home\b',
            r'\bearn \$?\d[\d,]*\s?(per|a|/)\s?(day|week|hour)\b',
            r'\bnow hiring\b',
        ],
        "explanation": "An unsolicited job offer. Real employers rarely message out of the blue, and they never charge you to start."
    },
    {
        "type": "delivery_fee",
        "severity": "medium",
        "patterns": [
            r'\b(parcel|package|delivery|shipment)\b.{0,40}\b(on hold|held|failed|pending|undeliverable)\b',
            r'\bcustoms? (fee|duty)\b',
        ],
        "explanation": "Claims a delivery problem that only a small fee or a link can fix, a common trick to collect card details."
    },
    {
        "type": "threat",
        "severity": "high",
        "patterns": [
            r'\b(account|card) (will be|has been) (suspended|locked|closed|blocked)\b',
            r'\bfunds will be (forfeited|frozen)\b', r'\bfunds will forfeit\b',
            r'\blegal action\b', r'\barrest\b',
        ],
        "explanation": "Threatens a bad outcome to scare you into acting before you can check."
    },
    {
        "type": "secrecy",
        "severity": "medium",
        "patterns": [
            r"\bdon'?t tell anyone\b", r'\bkeep (this|it) (secret|confidential)\b',
            r'\bdo not call\b',
        ],
        "explanation": "Discourages you from checking with someone else, which scammers rely on."
    },
    {
        "type": "suspicious_link",
        "severity": "medium",
        "patterns": [
            r'\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy)/\S+',
            r'\b[\w-]*(?:paypa1|amaz0n|g00gle|micros0ft|faceb00k)[\w.-]*\.[a-z]{2,}\b',
            r'\b(?:secure|login|verify|account|auth)[\w-]*\.(?:net|xyz|top|info|site|online|click)\b',
        ],
        "explanation": "A shortened or look-alike web address that may hide where the link really goes."
    },
]

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}

def find_indicators(text: str) -> list[dict]:
    """Every match from every rule. Matches may overlap."""
    found = []
    for rule in INDICATOR_RULES:
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                found.append({
                    "start": match.start(),
                    "end": match.end(),
                    "type": rule["type"],
                    "severity": rule["severity"],
                    "explanation": rule["explanation"],
                })
    return found

def resolve_overlaps(annotations: list[dict]) -> list[dict]:
    """Keep non-overlapping spans. When two overlap, keep the higher severity, then the longer one."""
    ranked = sorted(
        annotations,
        key=lambda a: (-SEVERITY_RANK.get(a["severity"], 0), -(a["end"] - a["start"]), a["start"]),
    )
    kept = []
    for a in ranked:
        if all(a["end"] <= k["start"] or a["start"] >= k["end"] for k in kept):
            kept.append(a)
    kept.sort(key=lambda a: a["start"])
    return kept

def detect_indicators(text: str) -> list[dict]:
    return resolve_overlaps(find_indicators(text))

# ---------- Archetypes (checked in order, most specific first) ----------

ARCHETYPES = [
    {
        "name": "Fake Job / Recruitment Scam",
        "requires_any": ["job_offer"],
        "requires_all_of_any_group": [["payment_request", "verification_pressure", "urgency"]],
        "why": "An unsolicited job offer combined with a fee, personal-information request or pressure to act."
    },
    {
        "name": "Delivery / Parcel Fee Scam",
        "requires_any": ["delivery_fee"],
        "requires_all_of_any_group": [["payment_request", "urgency", "suspicious_link"]],
        "why": "A delivery problem paired with a small fee, a link or a deadline."
    },
    {
        "name": "Prize / Lottery Scam",
        "requires_any": ["reward"],
        "requires_all_of_any_group": [["urgency", "verification_pressure", "payment_request"]],
        "why": "An unsolicited reward or prize paired with pressure to act, verify details or pay."
    },
    {
        "name": "Fake Bank / Account Alert",
        "requires_any": ["verification_pressure", "threat"],
        "requires_all_of_any_group": [["urgency", "authority_impersonation", "threat", "suspicious_link"]],
        "why": "Warns of a problem with your account and pressures you to verify details or act fast."
    },
    {
        "name": "Gift Card / Urgent Payment Scam",
        "requires_any": ["payment_request"],
        "requires_all_of_any_group": [["urgency", "secrecy"]],
        "why": "Urgent language combined with a request for payment, often through gift cards."
    },
]

def classify_archetype(annotations: list[dict]) -> dict | None:
    found_types = {a["type"] for a in annotations}

    for archetype in ARCHETYPES:
        has_required = any(t in found_types for t in archetype["requires_any"])
        has_group = all(
            any(t in found_types for t in group)
            for group in archetype["requires_all_of_any_group"]
        )
        if has_required and has_group:
            return {"name": archetype["name"], "why": archetype["why"]}

    return None

# ---------- Quick self-test: python analyzer.py ----------

if __name__ == "__main__":
    samples = {
        "bank": "URGENT: Your account has been placed on hold. Verify your account immediately or funds will be forfeited.",
        "gift": "Hey, are you at your desk? I need you to send a gift card for a client right away. Act now, I'm in a meeting.",
        "parcel": "Your parcel is on hold. Act now and pay a fee to release your delivery, or it expires today.",
        "job": "Congratulations! We have a work from home job opportunity paying $500 per day. Send a registration fee of $50 to start immediately.",
        "prize": "URGENT! You have won a free prize. Verify your account immediately to claim your reward.",
    }
    for name, text in samples.items():
        found = find_indicators(text)
        shown = resolve_overlaps(found)
        arch = classify_archetype(found)
        print(f"{name}: {len(shown)} highlights -> {arch['name'] if arch else 'no pattern'}")