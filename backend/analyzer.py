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

if __name__ == "__main__":
    sample = "URGENT! Verify your account at http://paypa1-secure.com or call 555-123-4567. Contact us at support@totally-real-bank.com"
    print("URLs:", extract_urls(sample))
    print("Emails:", extract_emails(sample))
    print("Phones:", extract_phone_numbers(sample))
    print("Indicators:", detect_indicators(sample))