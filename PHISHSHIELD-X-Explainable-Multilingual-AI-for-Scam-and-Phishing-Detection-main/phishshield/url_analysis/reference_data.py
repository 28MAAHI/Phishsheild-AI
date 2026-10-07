"""
Static reference lists used by the rule-based URL heuristics.

These lists are hand-maintained, NOT threat intelligence: they contain no
known-bad URLs or domains. They describe what legitimate brands look like
(official registered domains) and generic URL properties (shorteners,
TLDs). Extend them as needed; none of them is exhaustive.
"""

# Brand keyword -> official *registered* domains (eTLD+1, as returned by
# tldextract with PSL private domains enabled). A brand keyword appearing in a
# host whose registered domain is not listed here is reported as possible
# brand impersonation. Missing official domains cause false positives, so
# add a brand's domains here before relying on that brand's check.
BRAND_OFFICIAL_DOMAINS = {
    # Indian banks / payments / services (from the original app's lists)
    "sbi":        {"sbi.co.in", "onlinesbi.sbi", "sbicard.com"},
    "hdfc":       {"hdfcbank.com", "hdfc.com"},
    "icici":      {"icicibank.com"},
    "axisbank":   {"axisbank.com"},
    "kotak":      {"kotak.com"},
    "yesbank":    {"yesbank.in"},
    "idfc":       {"idfcfirstbank.com"},
    "rbi":        {"rbi.org.in"},
    "irctc":      {"irctc.co.in"},
    "npci":       {"npci.org.in"},
    "paytm":      {"paytm.com"},
    "phonepe":    {"phonepe.com"},
    "razorpay":   {"razorpay.com"},
    "flipkart":   {"flipkart.com"},
    "bajajfinserv": {"bajajfinserv.in"},
    # Global brands frequently targeted by phishing
    "amazon":     {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca"},
    "google":     {"google.com", "google.co.in", "gpay.com"},
    "gmail":      {"google.com", "gmail.com"},
    "microsoft":  {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"},
    "outlook":    {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "office365":  {"office.com", "microsoft.com", "microsoftonline.com"},
    "apple":      {"apple.com", "icloud.com"},
    "icloud":     {"icloud.com", "apple.com"},
    "paypal":     {"paypal.com"},
    "netflix":    {"netflix.com"},
    "facebook":   {"facebook.com", "fb.com"},
    "instagram":  {"instagram.com"},
    "whatsapp":   {"whatsapp.com"},
    "linkedin":   {"linkedin.com"},
    "dropbox":    {"dropbox.com"},
    "docusign":   {"docusign.com", "docusign.net"},
    "fedex":      {"fedex.com"},
    "dhl":        {"dhl.com", "dhl.de"},
    "ebay":       {"ebay.com", "ebay.in", "ebay.co.uk"},
    "adobe":      {"adobe.com"},
    "github":     {"github.com"},
    "coinbase":   {"coinbase.com"},
    "binance":    {"binance.com"},
    "metamask":   {"metamask.io"},
}

# Every official domain from the map above (includes the original app's allow-list).
OFFICIAL_DOMAINS = set().union(*BRAND_OFFICIAL_DOMAINS.values())

# Brand keywords shorter than this are only matched as a whole host token
# (split on "." and "-") to avoid matching inside unrelated words.
SHORT_BRAND_LEN = 5

# Brands checked for typosquatting (registered-domain label lookalikes).
TYPOSQUAT_TARGETS = {
    label.split(".")[0]: brand
    for brand, domains in BRAND_OFFICIAL_DOMAINS.items()
    for label in domains
    if len(label.split(".")[0]) >= 5
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly",
    "s.id", "v.gd", "bl.ink", "short.io", "lnkd.in",
}

# TLDs that public abuse reports have repeatedly listed as over-represented in
# phishing. This is a weak, configurable signal: most domains under these TLDs
# are not malicious.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "icu", "buzz", "click",
    "rest", "cyou", "zip", "mov",
}

# Words that commonly appear in credential-harvesting URLs.
SENSITIVE_WORDS = (
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification",
    "account", "update", "secure", "security", "banking", "confirm",
    "password", "passwd", "webscr", "unlock", "suspend", "billing",
    "authenticate", "wallet", "recover",
)

EXECUTABLE_EXTENSIONS = (".exe", ".scr", ".apk", ".bat", ".cmd", ".msi", ".jar", ".vbs", ".ps1")
