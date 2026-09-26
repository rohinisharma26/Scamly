import re

def extract_urls(text: str) -> list[str]:
    pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(pattern, text)

def extract_emails(text: str) -> list[str]:
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return re.findall(pattern, text)

def extract_phone_numbers(text: str) -> list[str]:
    pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}'
    return re.findall(pattern, text)

INDICATOR_RULES = [
    {
        "type": "urgency",
        "severity": "medium",
        "patterns": [r'\bURGENT\b', r'\bact now\b', r'\bimmediately\b', r'\bexpire[sd]?\s+(today|soon)\b'],
        "explanation": "Creates pressure to act quickly, a common tactic to stop you from thinking it through."
    },
    {
        "type": "reward",
        "severity": "medium",
        "patterns": [r'\byou.{0,10}(won|selected|winner)\b', r'\bclaim your (reward|prize)\b', r'\bfree (gift|prize)\b'],
        "explanation": "Unsolicited reward or prize framing, often used to lower your guard."
    },
    {
        "type": "verification_pressure",
        "severity": "high",
        "patterns": [r'\bverify your (details|account|identity)\b', r'\bconfirm your (password|pin|card)\b'],
        "explanation": "Pushes you to hand over sensitive information under pressure."
    },
    {
        "type": "payment_request",
        "severity": "high",
        "patterns": [r'\bpay (a|the) fee\b', r'\bgift card\b', r'\bwire transfer\b', r'\bsend (money|payment)\b'],
        "explanation": "Requests for payment, especially via gift cards or wire transfer, are a strong scam signal."
    },
    {
        "type": "authority_impersonation",
        "severity": "medium",
        "patterns": [r'\b(bank|irs|government|police)\b.{0,20}\b(department|office|division)\b'],
        "explanation": "Invokes a trusted authority to make the message seem legitimate."
    },
]

def detect_indicators(text: str) -> list[dict]:
    annotations = []
    for rule in INDICATOR_RULES:
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                annotations.append({
                    "start": match.start(),
                    "end": match.end(),
                    "type": rule["type"],
                    "severity": rule["severity"],
                    "explanation": rule["explanation"]
                })
    annotations.sort(key=lambda a: a["start"])
    return annotations
ARCHETYPES = [
    {
        "name": "Fake Job / Recruitment Scam",
        "requires_any": ["payment_request"],
        "requires_all_of_any_group": [["urgency", "verification_pressure", "reward"]],
        "why": "Combines urgency or verification pressure with a request for payment or personal information."
    },
    {
        "name": "Prize / Lottery Scam",
        "requires_any": ["reward"],
        "requires_all_of_any_group": [["urgency", "verification_pressure"]],
        "why": "An unsolicited reward or prize paired with pressure to act or verify details."
    },
    {
        "name": "Fake Bank / Account Alert",
        "requires_any": ["verification_pressure"],
        "requires_all_of_any_group": [["urgency", "authority_impersonation"]],
        "why": "Impersonates a bank or authority and pressures you to verify account details."
    },
    {
        "name": "Tech-Support / Payment Scam",
        "requires_any": ["payment_request"],
        "requires_all_of_any_group": [["urgency"]],
        "why": "Urgent language combined with a request for payment."
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

if __name__ == "__main__":
    sample = "URGENT! Verify your account at http://paypa1-secure.com or call 555-123-4567. Contact us at support@totally-real-bank.com"
    print("URLs:", extract_urls(sample))
    print("Emails:", extract_emails(sample))
    print("Phones:", extract_phone_numbers(sample))
    print("Indicators:", detect_indicators(sample))