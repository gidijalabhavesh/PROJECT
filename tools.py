import re
from typing import Any
from urllib.parse import urlparse

from model import ExtractedEntities, RedFlag, ScamAnalysisResult


URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>]+|\b[a-zA-Z0-9-]+\.(?:xyz|top|site|online|apk|club|ru|cn|click|buzz)\b[^\s<>]*",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\w)")
UPI_PATTERN = re.compile(r"\b[a-zA-Z0-9._-]{2,256}@[a-zA-Z]{2,64}\b")


ORGANIZATIONS = {
    "SBI": ("sbi", "state bank of india", "yono"),
    "HDFC": ("hdfc",),
    "ICICI": ("icici",),
    "Axis Bank": ("axis bank", "axisbank"),
    "PhonePe": ("phonepe", "phone pe"),
    "Google Pay": ("google pay", "gpay"),
    "Paytm": ("paytm",),
}


def extract_urls(text: str) -> list[str]:
    urls = []
    for match in URL_PATTERN.findall(text):
        cleaned = match.rstrip(".,;:!?)]}")
        urls.append(cleaned)
    return list(dict.fromkeys(urls))


def inspect_url_heuristics(url: str) -> dict[str, Any]:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = (parsed.hostname or "").lower()
    high_risk_tlds = (".xyz", ".top", ".club", ".click", ".site", ".ru", ".cn", ".buzz")
    is_ip_address = bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain))
    shorteners = ("bit.ly", "tinyurl.com", "t.co", "rb.gy")
    return {
        "domain": domain,
        "is_suspicious_tld": domain.endswith(high_risk_tlds),
        "is_raw_ip": is_ip_address,
        "is_shortener": domain in shorteners,
    }


def verify_sender_header(sender: str) -> dict[str, str]:
    cleaned = sender.strip()
    if re.fullmatch(r"[A-Za-z]{2}-[A-Za-z0-9]{6}", cleaned):
        return {"type": "OFFICIAL_SHORTCODE", "status": "Matches a common Indian SMS header format; this does not prove authenticity."}
    if re.fullmatch(r"(?:\+?91[\s-]?)?[6-9]\d{9}", cleaned):
        return {"type": "PERSONAL_MOBILE", "status": "Personal mobile sender; verify any claimed bank or payment request independently."}
    return {"type": "UNKNOWN_OR_CUSTOM", "status": "Sender identity is unverified."}


def analyze_message(content: str, sender: str = "Unknown") -> ScamAnalysisResult:
    text = content.lower()
    urls = extract_urls(content)
    url_checks = [inspect_url_heuristics(url) for url in urls]
    sender_check = verify_sender_header(sender)
    flags: list[RedFlag] = []
    score = 0
    category = "Other"

    organization = next(
        (name for name, terms in ORGANIZATIONS.items() if any(term in text for term in terms)),
        None,
    )
    kyc = any(term in text for term in ("kyc", "account deactivated", "account suspended", "account blocked"))
    urgency = any(term in text for term in ("immediately", "urgent", "expires", "within 12", "within 24", "today"))
    requests_pin_to_receive = any(term in text for term in ("upi pin", "upi-pin")) and any(
        term in text for term in ("receive", "refund", "reward", "payment", "cashback", "bonus", "prize")
    )
    remote_access = any(term in text for term in (".apk", "anydesk", "teamviewer", "rustdesk", "screen sharing"))
    if remote_access:
        score = 98
        category = "Remote_Access_Trojan"
        flags.append(RedFlag(indicator="Remote access or app install", explanation="Installing an APK or screen-sharing tool at a stranger's request can give them control of your device."))
    if requests_pin_to_receive:
        score = max(score, 99)
        category = "Fraudulent_UPI_Request"
        flags.append(RedFlag(indicator="UPI PIN requested to receive money", explanation="A UPI PIN authorizes a debit; it is never needed to receive a refund, prize, or payment."))
    if kyc and urls:
        score = max(score, 92 if urgency else 82)
        category = "KYC_Suspension"
        flags.append(RedFlag(indicator="KYC threat with a link", explanation="A message combining account suspension or KYC pressure with a link may lead to credential theft."))

    for url, check in zip(urls, url_checks):
        if check["is_suspicious_tld"] or check["is_raw_ip"]:
            score = max(score, 88)
            if category == "Other":
                category = "Phishing_Link"
            flags.append(RedFlag(indicator="Suspicious link", explanation=f"{check['domain']} uses a high-risk domain ending or raw IP address. Do not open it."))
        elif check["is_shortener"]:
            score = max(score, 65)
            flags.append(RedFlag(indicator="Shortened link", explanation="The destination is hidden behind a URL shortener. Verify it independently before opening."))

    if organization and sender_check["type"] == "PERSONAL_MOBILE":
        score = max(score, 72)
        if category == "Other":
            category = "Impersonation_Bank_Official"
        flags.append(RedFlag(indicator="Unofficial sender", explanation=f"A personal mobile number is claiming to represent {organization}. Contact the organization using its official app or number."))

    if urgency and score:
        score = min(100, score + 4)
        flags.append(RedFlag(indicator="Artificial urgency", explanation="Pressure to act immediately is a common tactic used to prevent careful verification."))

    transaction_notice = any(term in text for term in ("debited", "credited")) and any(term in text for term in ("upi ref", "transaction id", "a/c"))
    if not flags and transaction_notice:
        category = "Legitimate_Notification"
        score = 4
    elif not flags:
        score = 8 if not urls else 20
        if urls:
            category = "Phishing_Link"
            flags.append(RedFlag(indicator="Unverified link", explanation="A link alone cannot establish whether a message is genuine. Open the official service directly instead."))
            score = 35

    if score >= 90:
        risk_level = "CRITICAL"
    elif score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    elif score >= 15:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    is_scam = score >= 40 and category != "Legitimate_Notification"
    if is_scam:
        actions = [
            "Do not click links, install apps, share OTPs, or enter your UPI PIN.",
            "Contact your bank or payment provider through its official app or the number on your card.",
            "If money was lost, call India's cybercrime helpline at 1930 and report at cybercrime.gov.in.",
        ]
    else:
        actions = [
            "Do not share OTPs, passwords, CVV, or UPI PIN with anyone.",
            "Verify unexpected requests directly in your bank's official app or website.",
        ]

    entities = ExtractedEntities(
        urls=urls,
        phone_numbers=list(dict.fromkeys(PHONE_PATTERN.findall(content))),
        upi_ids=list(dict.fromkeys(UPI_PATTERN.findall(content))),
        claimed_organization=organization,
    )
    return ScamAnalysisResult(
        is_scam=is_scam,
        scam_category=category,
        risk_level=risk_level,
        risk_score=score,
        extracted_entities=entities,
        red_flags=flags,
        recommended_actions=actions,
        helpline_guidance="If you have lost money in India, call 1930 immediately and file a report at cybercrime.gov.in. For non-emergencies, contact your bank using its official app or card number.",
    )
