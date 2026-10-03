# Written, fixed content (not AI generated) so the explanations stay consistent.
# It describes the general shape of each scam so people can recognize it.
# It deliberately contains no message scripts, links or instructions for running a scam.

PLAYBOOKS = {
    "Fake Job / Recruitment Scam": {
        "stages": [
            {"title": "The hook",
             "detail": "An unexpected message promises easy pay, flexible hours or remote work, often through WhatsApp, Telegram or text."},
            {"title": "Building trust",
             "detail": "It sounds professional. You may get a \"contract\", a friendly manager, or a small first task that seems to pay."},
            {"title": "The ask",
             "detail": "You are asked to pay a fee for training, equipment or registration, or to hand over ID and bank details for \"payroll\"."},
            {"title": "Escalation",
             "detail": "More payments are requested, with a promise of a refund later. Then the contact goes quiet."},
        ],
        "do_instead": [
            "Look the company up yourself and contact it through its official website.",
            "A real employer never asks you to pay to start work.",
            "Don't share ID or bank details before a verified contract.",
        ],
    },
    "Delivery / Parcel Fee Scam": {
        "stages": [
            {"title": "The notice",
             "detail": "A text or email says a parcel is held, missed or needs an address update."},
            {"title": "The link",
             "detail": "It sends you to a page that imitates a courier or post office."},
            {"title": "The small fee",
             "detail": "You are asked for a tiny customs or redelivery fee, and for your card details to pay it."},
            {"title": "The aftermath",
             "detail": "The card details are used for real purchases. A follow-up call from a fake \"bank\" may try to take more."},
        ],
        "do_instead": [
            "Check tracking in the courier's official app or website, typed in yourself.",
            "Don't enter card details on a page you reached from a message.",
            "If you already did, call your bank on the number printed on your card.",
        ],
    },
    "Prize / Lottery Scam": {
        "stages": [
            {"title": "The win",
             "detail": "A message says you won a prize or lottery you never entered."},
            {"title": "The urgency",
             "detail": "You must reply or claim quickly, or the prize disappears."},
            {"title": "The fees",
             "detail": "To \"release\" the prize you are asked to pay a fee or tax, or to share ID and bank details."},
            {"title": "More demands",
             "detail": "After you pay, new fees appear. The prize never arrives."},
        ],
        "do_instead": [
            "You can't win a contest you didn't enter.",
            "Real prizes never require an upfront payment.",
            "Ignore the message and block the sender.",
        ],
    },
    "Fake Bank / Account Alert": {
        "stages": [
            {"title": "The alert",
             "detail": "A message says your account is locked, a payment is on hold, or suspicious activity was found."},
            {"title": "The pressure",
             "detail": "There is a short deadline and a threat of closure or lost funds."},
            {"title": "The link or call",
             "detail": "You are sent to a fake login page or a phone number that reaches the scammer."},
            {"title": "The takeover",
             "detail": "Your login, one-time code or card details are captured and used to move money."},
        ],
        "do_instead": [
            "Ignore the links and numbers in the message.",
            "Open your bank's app yourself, or call the number on your card.",
            "Never share a one-time code or PIN with anyone, even \"bank staff\".",
        ],
    },
    "Gift Card / Urgent Payment Scam": {
        "stages": [
            {"title": "The request",
             "detail": "Someone you trust, such as a boss, relative or friend, messages that they need a quick favor and can't talk."},
            {"title": "The pressure",
             "detail": "It is urgent and often secret, and a phone call is somehow impossible."},
            {"title": "The payment",
             "detail": "You are asked to buy gift cards or send money and share the codes."},
            {"title": "More requests",
             "detail": "Once you pay, another urgent need appears."},
        ],
        "do_instead": [
            "Call the person on a number you already have.",
            "Real bosses and relatives don't ask for gift card codes by text.",
            "Gift card codes are almost impossible to recover once shared.",
        ],
    },
}


def get_playbook(archetype_name: str | None) -> dict | None:
    if not archetype_name:
        return None
    return PLAYBOOKS.get(archetype_name)