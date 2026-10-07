"""
╔══════════════════════════════════════════════════════════════════╗
║  PhishShield X 2.1                                             ║
║  Explainable Phishing Detection & Risk Scoring                  ║
║                                                                 ║
║  Message analysis (this file):                                  ║
║  • Multilingual analysis (langdetect + optional translation)   ║
║  • Attack pattern taxonomy (17 scam categories)                ║
║  • Evidence-based word-level highlighting                      ║
║  • Attack flow extraction                                      ║
║  • Adversarial robustness testing                              ║
║  • Human feedback loop                                          ║
║                                                                 ║
║  URL analysis (phishshield/ package):                           ║
║  • Lexical URL model + rule-based indicators + risk engine     ║
║  • Explanations that separate model and rule evidence          ║
╚══════════════════════════════════════════════════════════════════╝

Run:  python app.py      Configure with environment variables (see README).
"""

import os, re, json, uuid, sqlite3, threading, logging, html as html_mod
from datetime import datetime
import joblib
from flask import Flask, render_template, request, redirect, url_for, jsonify

from phishshield.config import Settings
from phishshield.scoring import risk_band
from phishshield.service import URLAnalysisService
from phishshield.threat_intel import ThreatIntelError, build_provider
from phishshield.url_analysis import InvalidURLError

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("phishshield")

settings = Settings.from_env()

# Optional dependencies: each one only enables a feature, so a missing
# package degrades that feature instead of stopping the app.
try:
    from deep_translator import GoogleTranslator
except ImportError:
    GoogleTranslator = None
    log.warning("deep-translator not installed: non-English messages will not be translated.")
try:
    from langdetect import detect, DetectorFactory
    DetectorFactory.seed = 0  # langdetect is random by default; make results repeatable
except ImportError:
    detect = None
    log.warning("langdetect not installed: language detection disabled (assuming English).")
try:
    from urlextract import URLExtract
except ImportError:
    URLExtract = None

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # reject request bodies over 1 MB

# ═══════════════════════════════════════════════════════════════
#  MODEL LOADING  (timeout-protected, never hangs)
# ═══════════════════════════════════════════════════════════════
ml_pipeline = None
zs_classifier = None

try:
    ml_pipeline = joblib.load(settings.spam_model_path)
    print("[OK] Message spam classifier loaded.")
except Exception as e:
    print(f"[FAIL] Message spam classifier: {e}")

# URL phishing detection: trained URL model + heuristics + threat intel from the
# separate threat-intel API service (only when THREAT_INTEL_API_URL is set).
threat_intel_provider = build_provider(settings)
url_service = URLAnalysisService.from_settings(settings, threat_intel=threat_intel_provider)
print("[OK] URL model loaded." if url_service.model else
      "[INFO] URL model not available — URL analysis uses heuristic indicators only.")
print(f"[OK] Threat intelligence: {settings.threat_intel_api_url}" if threat_intel_provider.configured else
      "[INFO] Threat intelligence not configured (set THREAT_INTEL_API_URL).")


def _load_zs():
    global zs_classifier
    try:
        from transformers import pipeline as hf_pipeline
        # ONLY load from local cache — never attempt a download
        # (downloading blocks the GIL and freezes Flask)
        os.environ["HF_HUB_OFFLINE"] = "1"
        zs_classifier = hf_pipeline("zero-shot-classification",
                                    model="facebook/bart-large-mnli")
        print("[OK] Zero-Shot loaded (from cache).")
    except Exception as e:
        print(f"[INFO] ZS model not cached — rule-based fallback active.")
        print(f"       To cache: python -c \"from transformers import pipeline; pipeline('zero-shot-classification', model='facebook/bart-large-mnli')\"")
    finally:
        # Restore env for any other library that needs it
        if "HF_HUB_OFFLINE" in os.environ:
            del os.environ["HF_HUB_OFFLINE"]

if settings.enable_zero_shot:
    _t = threading.Thread(target=_load_zs, daemon=True)
    _t.start(); _t.join(timeout=settings.zero_shot_timeout)
    if _t.is_alive():
        print(f"[WARN] ZS model timed out ({settings.zero_shot_timeout:.0f}s). Using rule-based fallback.")
else:
    print("[INFO] Zero-shot model disabled by configuration — rule-based fallback active.")

url_extractor = None
if URLExtract is not None:
    try:
        url_extractor = URLExtract()
    except Exception as e:
        log.warning("urlextract failed to initialise (%s); using regex URL extraction.", e)

_URL_FALLBACK_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:/[^\s<>\"']*)?",
    re.IGNORECASE)


def find_urls(text):
    if url_extractor is not None:
        try:
            return url_extractor.find_urls(text)
        except Exception:
            log.exception("urlextract failed; falling back to regex")
    return [m.group().rstrip(".,;:!?)") for m in _URL_FALLBACK_RE.finditer(text)]


# ═══════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════
LANG_NAMES = {
    "en":"English","hi":"Hindi","ta":"Tamil","te":"Telugu","kn":"Kannada",
    "ml":"Malayalam","bn":"Bengali","mr":"Marathi","gu":"Gujarati",
    "pa":"Punjabi","ur":"Urdu","es":"Spanish","fr":"French","de":"German",
    "pt":"Portuguese","ar":"Arabic","zh":"Chinese","ja":"Japanese",
    "ko":"Korean","ru":"Russian","fi":"Finnish","it":"Italian",
    "nl":"Dutch","sv":"Swedish",
}

BRANDS = {
    "sbi":"State Bank of India","hdfc":"HDFC Bank","icici":"ICICI Bank",
    "axis":"Axis Bank","rbi":"Reserve Bank of India","irctc":"IRCTC",
    "amazon":"Amazon","flipkart":"Flipkart","fedex":"FedEx","dhl":"DHL",
    "paytm":"Paytm","phonepe":"PhonePe","google":"Google",
    "microsoft":"Microsoft","kotak":"Kotak Mahindra Bank",
    "yes bank":"Yes Bank","idfc":"IDFC First Bank","bob":"Bank of Baroda",
    "canara":"Canara Bank","pnb":"Punjab National Bank",
    "gpay":"Google Pay","razorpay":"Razorpay","whatsapp":"WhatsApp",
    "netflix":"Netflix","apple":"Apple",
}

# URL shorteners and official brand domains now live in
# phishshield/url_analysis/reference_data.py, used by the URL pipeline.


# ═══════════════════════════════════════════════════════════════
#  MODULE 0 — TEXT NORMALIZATION  &  ADVERSARIAL DETECTION
# ═══════════════════════════════════════════════════════════════
HOMOGLYPH_MAP = {
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y',
    'А':'A','Е':'E','О':'O','Р':'P','С':'C','Х':'X','У':'Y',
    'В':'B','Н':'H','К':'K','М':'M','Т':'T','і':'i','ї':'i','ё':'e',
}
LEET_DECODE = {'0':'o','@':'a','3':'e','1':'i','$':'s','5':'s',
               '7':'t','4':'a','!':'i','|':'l'}

def normalize_adversarial(text):
    """Strip adversarial tricks; return (cleaned_text, list_of_transforms)."""
    transforms = []
    # 1) Zero-width chars
    zw = re.sub(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]', '', text)
    if zw != text: transforms.append("Removed zero-width / invisible characters"); text = zw
    # 2) Unicode homoglyphs → Latin
    hg = ''.join(HOMOGLYPH_MAP.get(c, c) for c in text)
    if hg != text: transforms.append("Normalized Unicode homoglyphs (Cyrillic → Latin)"); text = hg
    # 3) Spacing attack: "V e r i f y" → "Verify"
    def _fix_sp(m):
        return m.group().replace(' ', '')
    sp = re.sub(r'(?<!\w)([A-Za-z] ){3,}[A-Za-z](?!\w)', _fix_sp, text)
    if sp != text: transforms.append("Collapsed letter-spacing attack"); text = sp
    # 4) Leet speak in word context
    out = list(text); changed = False
    for i, c in enumerate(out):
        if c in LEET_DECODE:
            prev_a = i > 0 and (out[i-1].isalpha())
            next_a = i < len(out)-1 and (out[i+1].isalpha() if isinstance(out[i+1],str) and len(out[i+1])==1 else False)
            if prev_a or next_a:
                out[i] = LEET_DECODE[c]; changed = True
    if changed: transforms.append("Decoded leet-speak substitutions"); text = ''.join(out)
    return text, transforms

def generate_adversarial_variants(text):
    """Create three deterministic adversarial versions of the text."""
    # Leet speak
    lm = {'a':'@','e':'3','i':'1','o':'0','s':'$','t':'7',
           'A':'@','E':'3','I':'1','O':'0','S':'$','T':'7'}
    lt = list(text); n = 0
    for i, c in enumerate(lt):
        if c in lm: n += 1;  (lt.__setitem__(i, lm[c]) if n % 2 == 0 else None)
    leet = ''.join(lt)
    # Unicode homoglyphs
    hm = {'a':'а','e':'е','o':'о','p':'р','c':'с','A':'А','E':'Е','O':'О'}
    ut = list(text); n = 0
    for i, c in enumerate(ut):
        if c in hm: n += 1; (ut.__setitem__(i, hm[c]) if n % 3 == 0 else None)
    uni = ''.join(ut)
    # Spacing
    words = text.split(); sp = []
    for j, w in enumerate(words):
        sp.append(' '.join(list(w)) if len(w) > 4 and j % 3 == 0 else w)
    spacing = ' '.join(sp)
    return {'leet_speak': leet, 'unicode': uni, 'spacing': spacing}


# ═══════════════════════════════════════════════════════════════
#  MODULE 1 — LANGUAGE INTELLIGENCE
# ═══════════════════════════════════════════════════════════════
def language_intelligence(text):
    lang_code = "en"
    if detect is not None:
        try: lang_code = detect(text)
        except Exception: lang_code = "en"
    lang_name = LANG_NAMES.get(lang_code, lang_code.upper())
    latin = len(re.findall(r'[a-zA-Z]', text))
    total = len(re.findall(r'\w', text)) or 1
    code_mixed = lang_code != "en" and (latin / total) > 0.25
    english = text
    translated = False
    translation_note = None
    if lang_code != "en":
        # Translation uses Google Translate over the network (deep-translator).
        # It is optional: when disabled or unreachable, the original text is analysed.
        if not settings.enable_translation:
            translation_note = "Translation disabled by configuration; original text analysed."
        elif GoogleTranslator is None:
            translation_note = "Translation library not installed; original text analysed."
        else:
            try:
                english = GoogleTranslator(source="auto", target="en").translate(text) or text
                translated = english != text
            except Exception as e:
                log.warning("Translation failed: %s", e)
                translation_note = "Translation service unavailable; original text analysed."
    return {"code":lang_code,"name":lang_name,"code_mixed":code_mixed,
            "original":text,"english":english,"translated":translated,
            "translation_note":translation_note}


# ═══════════════════════════════════════════════════════════════
#  MODULE 2 — LEGITIMATE MESSAGE CLASSIFIER
# ═══════════════════════════════════════════════════════════════
LEGIT_PATTERNS = [
    r'(?:rs\.?|inr|₹)\s*[\d,]+(?:\.\d{1,2})?\s+(?:has been\s+)?(?:debited|credited)\s+(?:from|to)',
    r'(?:debited|credited)\s+(?:rs\.?|inr|₹)\s*[\d,]+',
    r'(?:a/?c\s*(?:no\.?\s*)?[xX*]+\d{3,6})\s+(?:debited|credited)',
    r'(?:available|avl\.?|total|closing)\s+(?:bal(?:ance)?|bal\.?)\s*(?:is\s*)?(?:rs\.?|inr|₹)',
    r'(?:bal(?:ance)?)\s*:?\s*(?:rs\.?|inr|₹)\s*[\d,]+',
    r'(?:upi|neft|imps|rtgs)\s+(?:txn|transaction|transfer)',
    r'(?:upi)\s*(?:ref|id|txn)\s*(?:no\.?\s*)?:?\s*\d{8,}',
    r'(?:txn|transaction)\s*#?\s*\d{6,}',
    r'(?:ref\s*(?:no\.?\s*)?:?\s*\d{6,})',
    r'(?:your\s+)?(?:otp|one.time.password)\s+(?:is|:)\s*\d{4,8}',
    r'\b\d{4,8}\b\s+is\s+(?:your|the)\s+(?:otp|one.time.password|verification\s+code)',
    r'(?:payment|transfer|txn)\s+(?:of\s+)?(?:rs\.?|inr|₹)\s*[\d,]+\s+(?:to|from)\s+\w+\s+(?:successful|completed)',
    r'(?:successfully)\s+(?:paid|transferred|sent)\s+(?:rs\.?|inr|₹)',
    r'(?:emi|instalment)\s+(?:of\s+)?(?:rs\.?|inr|₹)\s*[\d,]+\s+(?:is\s+)?(?:due|debited|paid)',
    r'(?:card|debit\s+card|credit\s+card)\s+(?:ending|xx)\s*\d{4}\s+(?:used|charged|debited)',
    r'(?:atm)\s+(?:withdrawal|cash\s+withdrawal)',
    r'(?:new\s+)?(?:login|sign.in)\s+(?:detected|successful|from)',
    r'(?:your\s+)?(?:order|shipment|package)\s+(?:#?\w+\s+)?(?:has been|is)\s+(?:shipped|dispatched|delivered|out for delivery)',
]
SCAM_OVERRIDE_PATTERNS = [
    r'(?:share|send|tell|give|provide|enter|submit)\s+(?:your\s+)?(?:otp|pin|password|cvv|card\s+number)',
    r'(?:account|card|service)\s+(?:will be|shall be|is being)\s+(?:blocked|suspended|closed|terminated|deactivated|frozen)',
    r'(?:click|tap|visit|open)\s+(?:the\s+)?(?:link|url|button)\s+(?:below|here|now|immediately)',
    r'(?:send|transfer|pay|deposit)\s+(?:rs\.?|inr|₹)\s*[\d,]+\s+(?:to|into|at)',
    r'(?:call|contact|dial)\s+(?:us\s+)?(?:immediately|urgently|now)\s+(?:at|on)',
    r'(?:update|verify|complete|submit)\s+(?:your\s+)?(?:kyc|pan|aadhaar|identity)',
]

def classify_legitimate(text):
    lower = text.lower()
    legit_matches = 0; category = None
    cats = ["Bank Transaction Alert","Bank Transaction Alert","Bank Transaction Alert",
            "Balance Notification","Balance Notification",
            "Transfer Confirmation","Transfer Confirmation","Transfer Confirmation","Transfer Confirmation",
            "OTP Delivery","OTP Delivery",
            "Payment Confirmation","Payment Confirmation",
            "EMI/Bill Alert","Card Transaction Alert","ATM Withdrawal Alert",
            "Login Activity Alert","Delivery Notification"]
    for i, pat in enumerate(LEGIT_PATTERNS):
        if re.search(pat, lower, re.IGNORECASE):
            legit_matches += 1
            category = category or cats[min(i, len(cats)-1)]
    if not legit_matches:
        return {"is_legitimate":False,"confidence":0.0,"category":None,
                "has_scam_overrides":False,"reasons":[]}
    scam_overrides = sum(1 for p in SCAM_OVERRIDE_PATTERNS if re.search(p, lower, re.IGNORECASE))
    has_ref = bool(re.search(r'(?:ref|txn|id)\s*(?:no\.?\s*)?:?\s*\d{6,}', lower))
    has_masked = bool(re.search(r'(?:a/?c|account|card)\s*[xX*]+\d{2,6}', lower))
    has_amount = bool(re.search(r'(?:rs\.?|inr|₹)\s*[\d,]+', lower))
    bonus = sum([has_ref, has_masked, has_amount])
    reasons = []
    if has_ref: reasons.append("Contains transaction reference number")
    if has_masked: reasons.append("Contains masked account/card number")
    if has_amount: reasons.append("Contains specific transaction amount")
    conf = min(0.5 + legit_matches * 0.15 + bonus * 0.1, 0.98)
    if scam_overrides:
        conf *= max(0.1, 1.0 - scam_overrides * 0.35)
        reasons.append(f"⚠ {scam_overrides} scam indicator(s) also present")
    if len(text) < 250 and legit_matches >= 1: conf = min(conf + 0.05, 0.98)
    is_legit = legit_matches > 0 and scam_overrides == 0 and conf > 0.4
    if scam_overrides == 1 and legit_matches >= 3 and bonus >= 2:
        is_legit = True
    return {"is_legitimate":is_legit,"confidence":round(conf,2),
            "category":category if is_legit else None,
            "has_scam_overrides":scam_overrides>0,"reasons":reasons}


# ═══════════════════════════════════════════════════════════════
#  MODULE 3 — BRAND IMPERSONATION
# ═══════════════════════════════════════════════════════════════
def brand_impersonation(text, is_legitimate=False):
    lower = text.lower()
    found = [{"key":k,"name":v} for k,v in BRANDS.items() if k in lower]
    if is_legitimate:
        for b in found: b["is_legitimate_mention"] = True
    return found


# ═══════════════════════════════════════════════════════════════
#  MODULE 4 — URL INTELLIGENCE
# ═══════════════════════════════════════════════════════════════
URL_SUSPICIOUS_THRESHOLD = 40   # URL scores above this count as suspicious ("Suspicious" band and up)
URL_HIGH_RISK_THRESHOLD = 60    # URL scores above this ("High Risk" and up) set a floor on the message score


def url_intelligence(text):
    """Analyse every URL in a message with the dedicated URL pipeline
    (phishshield.service: URL model + rule-based indicators).

    Must be given the ORIGINAL message text: the adversarial normaliser's
    leet-speak decoding would rewrite lookalike domains (amaz0n -> amazon)
    and hide exactly the evidence we are looking for.
    """
    urls = list(dict.fromkeys(find_urls(text)))  # dedupe, keep order
    results = []; total_risk = 0
    for url in urls:
        try:
            analysis = url_service.analyze(url)
        except InvalidURLError as e:
            results.append({"url":url,"flags":[f"Not analysed: {e}"],"risk":0,
                            "suspicious":False,"model_probability":None,"heuristic_score":None})
            continue
        exp = analysis["explanation"]
        fired = exp["heuristic_evidence"]["indicators"]
        flags = [i["title"] for i in fired]
        if exp["heuristic_evidence"]["trusted_domain"]:
            flags.insert(0, "Official brand domain")
        if not flags: flags.append("No rule-based issues detected")
        risk = analysis["score"]; total_risk = max(total_risk, risk)
        results.append({
            "url":url, "flags":flags, "risk":risk, "risk_label":analysis["risk"]["label"],
            "suspicious":risk > URL_SUSPICIOUS_THRESHOLD,
            "model_probability":exp["model_evidence"].get("probability"),
            "heuristic_score":exp["heuristic_evidence"]["score"],
        })
    return {"urls":results,"count":len(urls),"max_risk":total_risk}


# ═══════════════════════════════════════════════════════════════
#  MODULE 5 — SOCIAL ENGINEERING ANALYSIS  (ZS + rule fallback)
# ═══════════════════════════════════════════════════════════════
SE_LABELS = ["urgency or time limit","fear or threat",
             "authority or official institution","reward or lottery or prize",
             "curiosity or secret information","trust exploitation or impersonation"]
SE_DISPLAY = ["Urgency","Fear","Authority","Reward","Curiosity","Trust"]

def _rule_se(text):
    lower = text.lower()
    def _sc(kws):
        h = sum(1 for k in kws if k in lower)
        return min(round((h / max(len(kws)*0.15,1))*100), 95)
    return {
        "Urgency": _sc(["urgent","immediately","right now","asap","within 24","expire",
            "expiring","last chance","hurry","act now","time limit","deadline",
            "limited time","final notice","final warning","today only","hours left",
            "minutes left","quickly","fast","don't delay","before midnight"]),
        "Fear": _sc(["blocked","suspended","terminated","closed","frozen","illegal",
            "arrested","police","court","legal action","warrant","penalty","fine",
            "compromised","hacked","unauthorized","fraud detected","security alert",
            "threat","locked","disabled","violation","criminal",
            "kill","murder","die","death","harm","hurt","destroy","kidnap",
            "shoot","stab","torture","threaten","blackmail","bomb","attack",
            "eliminate","assassinate","dangerous"]),
        "Authority": _sc(["bank","rbi","reserve bank","government","ministry","police",
            "customs","tax department","income tax","official","department","authorized",
            "verified","certified","regulation","compliance","central bank","federal",
            "supreme court","cyber cell","cbi"]),
        "Reward": _sc(["won","winner","congratulations","prize","lottery","reward",
            "cashback","bonus","free","gift","selected","lucky","jackpot","claim your",
            "million","lakh","crore"]),
        "Curiosity": _sc(["secret","exclusive","confidential","private","shocking",
            "revealed","hidden","leaked","insider","classified","mystery",
            "you won't believe"]),
        "Trust": _sc(["dear customer","dear user","valued customer","trusted",
            "we noticed","we detected","your account","on your behalf",
            "for your safety","for your security","team","helpdesk",
            "support team","customer care"]),
    }

def social_engineering_analysis(text, is_legitimate=False):
    if zs_classifier:
        try:
            res = zs_classifier(text, SE_LABELS, multi_label=True)
            scores = {SE_DISPLAY[i]: round(res["scores"][res["labels"].index(SE_LABELS[i])]*100)
                      for i in range(len(SE_LABELS))}
        except: scores = _rule_se(text)
    else:
        scores = _rule_se(text)
    if is_legitimate:
        scores = {k: max(0, round(v*0.35)) for k,v in scores.items()}
    return scores


# ═══════════════════════════════════════════════════════════════
#  MODULE 6 — INTENT / ATTACK PATTERN DETECTION  (ZS + rules)
# ═══════════════════════════════════════════════════════════════
INTENT_LABELS = [
    "Credential or password theft","OTP or verification code theft",
    "UPI payment scam","Fake KYC verification scam",
    "Bank account suspension threat","Police or authority impersonation",
    "Government department impersonation","Investment or crypto scam",
    "Lottery or prize scam","Delivery or customs payment scam",
    "Job offer or registration fee scam","Tech support or virus alert scam",
    "Romance or emotional manipulation scam","SIM swap or mobile verification scam",
    "Loan approval scam","Tax refund scam","Charity or donation scam",
    "Legitimate bank transaction notification",
    "Legitimate OTP delivery for authentication",
    "Legitimate order or delivery update",
    "Normal personal or business communication",
]
INTENT_SHORT = {
    "Credential or password theft":"Credential Theft",
    "OTP or verification code theft":"OTP Theft",
    "UPI payment scam":"UPI Payment Scam",
    "Fake KYC verification scam":"Fake KYC Scam",
    "Bank account suspension threat":"Account Suspension Threat",
    "Police or authority impersonation":"Police Impersonation",
    "Government department impersonation":"Govt. Impersonation",
    "Investment or crypto scam":"Investment / Crypto Scam",
    "Lottery or prize scam":"Lottery / Prize Scam",
    "Delivery or customs payment scam":"Delivery Scam",
    "Job offer or registration fee scam":"Job Scam",
    "Tech support or virus alert scam":"Tech Support Scam",
    "Romance or emotional manipulation scam":"Romance Scam",
    "SIM swap or mobile verification scam":"SIM Swap Scam",
    "Loan approval scam":"Loan Scam",
    "Tax refund scam":"Tax Refund Scam",
    "Charity or donation scam":"Charity Scam",
    "Legitimate bank transaction notification":"Bank Notification ✓",
    "Legitimate OTP delivery for authentication":"OTP Delivery ✓",
    "Legitimate order or delivery update":"Delivery Update ✓",
    "Normal personal or business communication":"Normal Message ✓",
}
LEGIT_INTENT_LABELS = {
    "Legitimate bank transaction notification",
    "Legitimate OTP delivery for authentication",
    "Legitimate order or delivery update",
    "Normal personal or business communication",
}

def _rule_intent(text):
    lower = text.lower()
    rules = [
        ("Credential Theft",False,["password","login","credential","username","sign in","enter your password","verify your identity"]),
        ("OTP Theft",False,["share otp","send otp","tell otp","give otp","provide otp","enter otp","share your otp","otp to avoid"]),
        ("OTP Delivery ✓",True,["your otp is","otp:","verification code is"]),
        ("UPI Payment Scam",False,["upi payment","pay rs","pay inr","send money","transfer amount","pay ₹","collect request"]),
        ("Fake KYC Scam",False,["kyc","update kyc","verify kyc","pan card","aadhaar","complete verification","submit documents"]),
        ("Account Suspension Threat",False,["account blocked","account suspended","account will be","deactivated","frozen","terminated"]),
        ("Bank Notification ✓",True,["debited from","credited to","available balance","avl bal","txn ref","transaction ref","upi ref","neft ref"]),
        ("Police Impersonation",False,["arrest warrant","cyber crime","fir filed","cbi","narcotics","legal action against you"]),
        ("Investment / Crypto Scam",False,["invest","crypto","bitcoin","trading","stock tip","guaranteed returns","double your money","forex"]),
        ("Lottery / Prize Scam",False,["lottery","winner","prize","jackpot","claim your","congratulations you have been selected"]),
        ("Delivery Scam",False,["customs fee","delivery fee","pay shipping","package held","clearance fee","import duty"]),
        ("Delivery Update ✓",True,["shipped","dispatched","out for delivery","delivered to","your order","tracking"]),
        ("Job Scam",False,["job offer","registration fee","work from home","earn daily","part time job","data entry job"]),
        ("Tech Support Scam",False,["virus","malware","your computer","tech support","call microsoft","security alert","infected"]),
        ("Loan Scam",False,["loan approved","pre-approved loan","instant loan","processing fee","loan offer"]),
        ("Romance Scam",False,["i love you","send money darling","western union","gift card","stuck abroad"]),
        ("Tax Refund Scam",False,["tax refund","irs","income tax refund","pending refund"]),
        ("Normal Message ✓",True,["how are you","hello","thanks","thank you","see you","meeting","schedule"]),
    ]
    best = ("Unknown", 0, False); top3 = []
    for name, legit, kws in rules:
        hits = sum(1 for k in kws if k in lower)
        if hits:
            # Keyword matches are very specific → high confidence.
            # 1 hit = 55%, 2 hits = 72%, 3+ hits = 85%+
            sc = min(55 + hits * 17, 95)
            top3.append({"intent":name,"confidence":sc})
            if sc > best[1]: best = (name, sc, legit)
    top3.sort(key=lambda x: x["confidence"], reverse=True)
    if not top3: top3 = [{"intent":"Unknown","confidence":0}]
    return {"intent":best[0],"confidence":best[1],"top3":top3[:3],"is_legit_intent":best[2]}

def intent_detection(text):
    if zs_classifier:
        try:
            # multi_label=True uses independent sigmoid per label (70-90%+ for
            # clear matches) instead of softmax which spreads probability thin
            # across all 21 labels (~8% even for perfect matches).
            res = zs_classifier(text, INTENT_LABELS, multi_label=True)
            # Sort by score descending (multi_label doesn't guarantee sorted)
            pairs = sorted(zip(res["labels"], res["scores"]),
                           key=lambda x: x[1], reverse=True)
            top3 = [{"intent": INTENT_SHORT.get(lbl, lbl),
                      "confidence": round(sc * 100)}
                     for lbl, sc in pairs[:3]]
            return {"intent": top3[0]["intent"], "confidence": top3[0]["confidence"],
                    "top3": top3, "is_legit_intent": pairs[0][0] in LEGIT_INTENT_LABELS}
        except: pass
    return _rule_intent(text)


# ═══════════════════════════════════════════════════════════════
#  MODULE 7 — EVIDENCE-BASED WORD HIGHLIGHTING
# ═══════════════════════════════════════════════════════════════
HIGHLIGHT_CATS = {
    "urgency": {
        "words":["immediately","urgent","urgently","right now","asap","hurry",
                 "act now","limited time","expire","expiring","last chance",
                 "final notice","final warning","within 24 hours","quickly",
                 "don't delay","today only","before midnight","fast","rush",
                 "hours left","time limit","deadline"],
        "color":"#f59e0b","label":"⏰ Urgency",
        "explanation":"Creates time pressure to prevent rational thinking",
    },
    "threat": {
        "words":["suspended","blocked","terminated","closed","frozen","deactivated",
                 "disabled","locked","restricted","penalty","fine","legal action",
                 "arrested","warrant","court","criminal","violation","illegal",
                 "unauthorized","compromised","hacked","fraud",
                 "kill","murder","die","death","harm","hurt","attack","bomb",
                 "destroy","kidnap","shoot","stab","rape","torture","threaten",
                 "blackmail","eliminate","execute","assassinate","strangle",
                 "burn","blood","bleed","bury","slash","dangerous"],
        "color":"#ef4444","label":"😨 Threat",
        "explanation":"Threatens negative consequences to induce fear",
    },
    "credential_request": {
        "words":["verify","confirm","update","validate","authenticate","submit",
                 "enter your","provide your","share your","send your","tell your",
                 "otp","pin","password","cvv","card number","account number",
                 "aadhaar","pan card","kyc","login","sign in","credentials"],
        "color":"#a855f7","label":"🔑 Credential Request",
        "explanation":"Attempts to extract sensitive credentials or personal data",
    },
    "financial": {
        "words":["payment","pay now","transfer","deposit","send money","wire",
                 "processing fee","registration fee","advance fee","charges",
                 "upi","bank account","credit card","debit card","wallet"],
        "color":"#3b82f6","label":"💰 Financial",
        "explanation":"References financial transactions or payment requests",
    },
    "reward": {
        "words":["congratulations","winner","won","prize","lottery","reward",
                 "cashback","bonus","gift","jackpot","selected","lucky","claim",
                 "free","million","lakh","crore"],
        "color":"#22c55e","label":"🎁 Reward Lure",
        "explanation":"Promises prizes or benefits to bait the victim",
    },
    "impersonation": {
        "words":["dear customer","dear user","valued customer","dear account holder",
                 "we noticed","we detected","we have received","security team",
                 "support team","helpdesk","customer care","from the desk of",
                 "official notice","authorized","government of"],
        "color":"#06b6d4","label":"🎭 Impersonation",
        "explanation":"Poses as a trusted entity to gain credibility",
    },
    "action_request": {
        "words":["click here","click below","click the link","tap here","visit",
                 "open the link","download","install","call us","contact us",
                 "reply with","respond immediately","call this number"],
        "color":"#f97316","label":"👆 Action Request",
        "explanation":"Directs victim to perform a specific action",
    },
}

def highlight_evidence(text):
    """Find suspicious words in the message, return highlights + safe HTML."""
    highlights = []
    for cat, cfg in HIGHLIGHT_CATS.items():
        for word in cfg["words"]:
            for m in re.finditer(re.escape(word), text, re.IGNORECASE):
                highlights.append({
                    "word":m.group(),"start":m.start(),"end":m.end(),
                    "category":cat,"label":cfg["label"],
                    "explanation":cfg["explanation"],"color":cfg["color"],
                })
    # De-overlap: sort by start, keep longest, skip overlapping
    highlights.sort(key=lambda h: (h["start"], -(h["end"]-h["start"])))
    filtered = []; last_end = -1
    for h in highlights:
        if h["start"] >= last_end:
            filtered.append(h); last_end = h["end"]
    # Build HTML
    parts = []; pos = 0
    for h in filtered:
        parts.append(html_mod.escape(text[pos:h["start"]]))
        parts.append(
            f'<mark class="hl" style="background:{h["color"]}18;color:{h["color"]};'
            f'border-bottom:2px solid {h["color"]};padding:1px 4px;border-radius:3px;'
            f'cursor:help" title="{html_mod.escape(h["explanation"])}">'
            f'{html_mod.escape(h["word"])}</mark>')
        pos = h["end"]
    parts.append(html_mod.escape(text[pos:]))
    return filtered, ''.join(parts)


# ═══════════════════════════════════════════════════════════════
#  MODULE 8 — ATTACK FLOW EXTRACTION
# ═══════════════════════════════════════════════════════════════
def extract_attack_flow(highlights, se, intent_info, brands, url_info, legit_info):
    """Extract the sequential attack pattern as a flowchart."""
    if legit_info and legit_info.get("is_legitimate"):
        return []
    flow = []
    hl_cats = {h["category"] for h in highlights}
    # 1) Hook
    if brands:
        flow.append({"stage":"Impersonation","desc":f"Poses as {brands[0]['name']}","icon":"🎭"})
    elif "impersonation" in hl_cats or se.get("Trust",0)>30:
        flow.append({"stage":"Trust Building","desc":"Establishes false credibility","icon":"🤝"})
    # 2) Emotional manipulation
    if se.get("Fear",0)>25 or "threat" in hl_cats:
        flow.append({"stage":"Create Fear","desc":"Threatens negative consequences","icon":"😨"})
    if se.get("Urgency",0)>25 or "urgency" in hl_cats:
        flow.append({"stage":"Apply Urgency","desc":"Pressures immediate action","icon":"⏰"})
    if se.get("Reward",0)>35 or "reward" in hl_cats:
        flow.append({"stage":"Offer Reward","desc":"Promises prize or benefit","icon":"🎁"})
    # 3) Action
    if "action_request" in hl_cats:
        flow.append({"stage":"Request Action","desc":"Directs to click, call, or reply","icon":"👆"})
    # 4) Collection
    if "credential_request" in hl_cats:
        flow.append({"stage":"Credential Theft","desc":"Attempts to steal passwords/OTP/KYC","icon":"🔑"})
    if url_info.get("max_risk",0)>URL_SUSPICIOUS_THRESHOLD:
        flow.append({"stage":"Malicious Link","desc":"Directs to suspicious URL","icon":"🔗"})
    if "financial" in hl_cats:
        flow.append({"stage":"Financial Extraction","desc":"Attempts to extract money","icon":"💰"})
    return flow


# ═══════════════════════════════════════════════════════════════
#  MODULE 9 — RISK FUSION ENGINE
# ═══════════════════════════════════════════════════════════════
def risk_fusion(ml_proba, url_info, brands, se, intent_info, legit_info=None):
    if legit_info and legit_info.get("is_legitimate") and legit_info.get("confidence",0)>0.5:
        return min(max(2, round(ml_proba*5)), 8)
    imp_brands = [b for b in brands if not b.get("is_legitimate_mention")]
    risk  = ml_proba * 30
    risk += (url_info["max_risk"]/100) * 15
    risk += min(len(imp_brands)*5, 10)
    max_se = max(se.values()) if se else 0
    avg_se = sum(se.values())/len(se) if se else 0
    hi_se  = sum(1 for v in se.values() if v>60)
    risk += (max_se/100)*25 + (avg_se/100)*20
    if intent_info.get("is_legit_intent") and intent_info.get("confidence",0)>40:
        risk *= 0.4
    if max_se>70 and risk<42: risk=42
    if hi_se>=2 and risk<55: risk=55
    if hi_se>=3 and risk<65: risk=68
    if max_se>85 and risk<65: risk=67
    if imp_brands and (se.get("Urgency",0)>55 or se.get("Fear",0)>55): risk=max(risk,82)
    if not intent_info.get("is_legit_intent") and intent_info["intent"]!="Unknown":
        if intent_info["confidence"]>40 and max_se>50: risk=max(risk,65)
        if intent_info["confidence"]>60 and max_se>60: risk=max(risk,78)
    # A message is at least as dangerous as a High Risk / Critical link it carries.
    if url_info.get("max_risk",0) > URL_HIGH_RISK_THRESHOLD:
        risk = max(risk, url_info["max_risk"])
    return min(round(risk), 100)

def risk_label(score):
    # Shared with the URL risk engine so both analysers use identical bands.
    return risk_band(score)


# ═══════════════════════════════════════════════════════════════
#  MODULE 10 — EXPLAINABLE AI  (evidence builder)
# ═══════════════════════════════════════════════════════════════
# Evidence "source" tags shown in the UI so users can tell learned-model
# evidence apart from hand-written rules.
SRC_MODEL = "model"          # trained classifier output
SRC_RULES = "rules"          # keyword / regex / heuristic rules
SRC_URL   = "url-analysis"   # URL pipeline (URL model + URL rules, see URL card)

def _nlp_source():
    """Social-engineering and intent scores come from the zero-shot model
    when it is loaded, otherwise from keyword rules."""
    return SRC_MODEL if zs_classifier else SRC_RULES

def build_evidence(english, ml_proba, url_info, brands, se, intent_info,
                   legit_info=None, highlights=None, ml_signal=True):
    ev = []
    if legit_info and legit_info.get("is_legitimate"):
        ev.append({"icon":"✅","source":SRC_RULES,"text":f"Legitimate: {legit_info['category']} (rule confidence {legit_info['confidence']*100:.0f}%)"})
        for r in legit_info.get("reasons",[]):
            if not r.startswith("⚠"): ev.append({"icon":"📋","source":SRC_RULES,"text":r})
        if ml_signal and ml_proba>0.5:
            ev.append({"icon":"🤖","source":SRC_MODEL,"text":f"SMS spam classifier flagged spam ({ml_proba*100:.0f}%) — overridden by legitimate-notification rules"})
        lb = [b for b in brands if b.get("is_legitimate_mention")]
        if lb:
            ev.append({"icon":"🏦","source":SRC_RULES,"text":f"Mentions {', '.join(b['name'] for b in lb)} (legitimate context)"})
        return ev
    if not ml_signal:
        ev.append({"icon":"🤖","source":SRC_MODEL,"text":"SMS spam classifier: no signal (none of the message's words are in its English vocabulary)"})
    elif ml_proba>0.5:
        ev.append({"icon":"🤖","source":SRC_MODEL,"text":f"SMS spam classifier: spam ({ml_proba*100:.0f}% probability)"})
    if url_info["count"]>0:
        ev.append({"icon":"🔗","source":SRC_RULES,"text":f"Contains {url_info['count']} link(s)"})
    for u in url_info["urls"]:
        if u["suspicious"]:
            parts = []
            if u.get("model_probability") is not None:
                parts.append(f"URL model {u['model_probability']*100:.0f}% phishing")
            if u.get("heuristic_score") is not None:
                parts.append(f"rules {u['heuristic_score']} pts")
            ev.append({"icon":"⚠️","source":SRC_URL,
                       "text":f"Suspicious URL {u['url']} — risk {u['risk']}/100 ({'; '.join(parts)}): {', '.join(u['flags'])}"})
    if url_info.get("max_risk",0) > URL_HIGH_RISK_THRESHOLD:
        ev.append({"icon":"📈","source":SRC_RULES,
                   "text":f"Message risk set to at least its riskiest link's score ({url_info['max_risk']}/100)"})
    imp = [b for b in brands if not b.get("is_legitimate_mention")]
    if imp:
        ev.append({"icon":"🏦","source":SRC_RULES,"text":f"Mentions brand(s) outside a legitimate-notification pattern: {', '.join(b['name'] for b in imp)}"})
    for tactic, sc in se.items():
        if sc>65: ev.append({"icon":"🧠","source":_nlp_source(),"text":f"High {tactic.lower()} manipulation ({sc}%)"})
    otp_req = re.search(r'(?:share|send|tell|give|provide|enter)\s+(?:your\s+)?otp', english.lower())
    otp_del = re.search(r'(?:your\s+)?otp\s+(?:is|:)\s*\d{4,8}', english.lower())
    if otp_req and not otp_del:
        ev.append({"icon":"🔑","source":SRC_RULES,"text":"Explicitly requests OTP / verification code"})
    if not intent_info.get("is_legit_intent") and intent_info["intent"]!="Unknown" and intent_info["confidence"]>30:
        ev.append({"icon":"🎯","source":_nlp_source(),"text":f"Attack pattern: {intent_info['intent']} ({intent_info['confidence']}%)"})
    # Highlight-based evidence
    if highlights:
        cats_found = set()
        for h in highlights:
            if h["category"] not in cats_found:
                cats_found.add(h["category"])
                ev.append({"icon":"🔍","source":SRC_RULES,"text":f"{h['label']}: \"{h['word']}\" — {h['explanation']}"})
    return ev


def build_negative_evidence(se, url_info, brands, highlights):
    """Build 'why NOT spam' evidence for safe messages."""
    neg = []
    if url_info["count"]==0:
        neg.append("No URLs in the message")
    elif url_info["max_risk"]<=20:
        neg.append("All URLs scored Safe in URL analysis")
    if not brands or all(b.get("is_legitimate_mention") for b in brands):
        neg.append("No brand impersonation detected")
    hl_cats = {h["category"] for h in (highlights or [])}
    if "credential_request" not in hl_cats:
        neg.append("No credential / password requests")
    if "financial" not in hl_cats:
        neg.append("No financial extraction attempts")
    if se.get("Urgency",0)<30:
        neg.append("No urgency manipulation")
    if se.get("Fear",0)<30:
        neg.append("No fear / threat tactics")
    if "impersonation" not in hl_cats:
        neg.append("No impersonation indicators")
    if "action_request" not in hl_cats:
        neg.append("No suspicious action requests")
    return neg


# ═══════════════════════════════════════════════════════════════
#  MODULE 11 — RECOMMENDATIONS
# ═══════════════════════════════════════════════════════════════
def build_recommendation(score, brands, se, intent_info, legit_info=None):
    recs = []
    if legit_info and legit_info.get("is_legitimate"):
        recs.append("This appears to be a standard automated notification.")
        if legit_info.get("category"):
            recs.append(f"Message type: {legit_info['category']}.")
        recs.append("No action required — routine alert.")
        if brands: recs.append(f"If in doubt, verify via the official {brands[0]['name']} app.")
        return recs
    if score>40: recs.append("Exercise caution — do not respond impulsively.")
    if score>60:
        recs.append("Do NOT click any links in this message.")
        recs.append("Do NOT share OTP, PIN, or passwords with anyone.")
    if score>80:
        recs.append("Block the sender immediately.")
        recs.append("Report to your telecom provider or cyber cell (1930).")
    imp = [b for b in brands if not b.get("is_legitimate_mention")]
    if imp: recs.append(f"Contact {imp[0]['name']} via their official website to verify.")
    if intent_info["intent"] in ["UPI Payment Scam","Investment / Crypto Scam","Loan Scam"]:
        recs.append("Do NOT make any payments or transfers.")
    if intent_info["intent"] in ["OTP Theft","Credential Theft","Fake KYC Scam","SIM Swap Scam"]:
        recs.append("Never share OTP, CVV, or login credentials.")
    if intent_info["intent"] in ["Police Impersonation","Govt. Impersonation"]:
        recs.append("Verify sender identity via official government websites.")
    if not recs: recs.append("No immediate action required. Message appears safe.")
    return recs


# ═══════════════════════════════════════════════════════════════
#  SMS SPAM CLASSIFIER  (TF-IDF + Naive Bayes, message text only)
# ═══════════════════════════════════════════════════════════════
def spam_probability(text):
    """Return (probability_of_spam, has_signal).

    The classifier was trained on English SMS messages. When none of the
    input's words are in its vocabulary (most URLs, untranslated non-English
    text) it can only return its class prior (~0.50), which is not evidence.
    In that case we report has_signal=False and a probability of 0.
    """
    if ml_pipeline is None:
        return 0.0, False
    cleaned = re.sub(r"[^a-z\s]", "", text.lower())
    try:
        vec = ml_pipeline.named_steps["vectorizer"].transform([cleaned])
        if vec.nnz == 0:
            return 0.0, False
        return float(ml_pipeline.predict_proba([cleaned])[0][1]), True
    except Exception:
        log.exception("Spam classifier failed")
        return 0.0, False


# ═══════════════════════════════════════════════════════════════
#  MODULE 12 — ADVERSARIAL ROBUSTNESS TESTING
# ═══════════════════════════════════════════════════════════════
def adversarial_robustness_test(text, original_score, original_label):
    """Run fast analysis on adversarial variants to test robustness."""
    variants = generate_adversarial_variants(text)
    results = {"original":{"text":text[:120],"score":original_score,"label":original_label}}
    for name, vtxt in variants.items():
        ml_p, _ = spam_probability(vtxt)
        lg = classify_legitimate(vtxt)
        se_v = _rule_se(vtxt)
        in_v = _rule_intent(vtxt)
        br_v = brand_impersonation(vtxt, lg.get("is_legitimate",False))
        ur_v = url_intelligence(vtxt)
        sc = risk_fusion(ml_p, ur_v, br_v, se_v, in_v, lg)
        results[name] = {"text":vtxt[:120],"score":sc,"label":risk_label(sc)["label"]}
    is_threat = original_score >= 40
    all_sc = [r["score"] for r in results.values()]
    results["robust"] = all(s>=30 for s in all_sc) if is_threat else all(s<50 for s in all_sc)
    return results


# ═══════════════════════════════════════════════════════════════
#  MODULE 13 — FEEDBACK STORAGE  (SQLite)
# ═══════════════════════════════════════════════════════════════
FEEDBACK_DB = settings.feedback_db_path

def _init_db():
    try:
        conn = sqlite3.connect(FEEDBACK_DB)
        conn.execute("""CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            message TEXT,
            score INTEGER,
            risk_label TEXT,
            attack_type TEXT,
            language TEXT,
            is_correct INTEGER,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.commit(); conn.close()
    except sqlite3.Error as e:
        log.error("Feedback database unavailable (%s): %s", FEEDBACK_DB, e)

def store_feedback(aid, msg, score, rl, atype, lang, correct):
    conn = sqlite3.connect(FEEDBACK_DB)
    try:
        conn.execute("INSERT INTO feedback (analysis_id,message,score,risk_label,attack_type,language,is_correct) VALUES (?,?,?,?,?,?,?)",
                     (aid, msg[:500], score, rl, atype, lang, 1 if correct else 0))
        conn.commit()
    finally:
        conn.close()

def get_feedback_stats():
    # "accuracy" here is the share of user ratings marked correct (user
    # agreement), not a measured detection accuracy.
    try:
        conn = sqlite3.connect(FEEDBACK_DB)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM feedback"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM feedback WHERE is_correct=1"); correct = cur.fetchone()[0]
        conn.close()
        return {"total":total,"correct":correct,"incorrect":total-correct,
                "accuracy":round((correct/total)*100,1) if total else 0}
    except sqlite3.Error: return {"total":0,"correct":0,"incorrect":0,"accuracy":0}

_init_db()


def _load_url_model_metrics():
    """Held-out test metrics of the loaded URL model, for display only."""
    if url_service.model is None:
        return None
    test = url_service.model.metrics.get("test") or {}
    if not test:
        return None
    return {"f1": test.get("f1"), "accuracy": test.get("accuracy"),
            "precision": test.get("precision"), "recall": test.get("recall"),
            "roc_auc": test.get("roc_auc"), "n": test.get("n")}

URL_MODEL_METRICS = _load_url_model_metrics()


def _page(**ctx):
    """Render index.html with the context every page needs."""
    ctx.setdefault("result_ready", False)
    ctx.setdefault("url_result", None)
    ctx.setdefault("mode", "message")
    return render_template("index.html", feedback_stats=get_feedback_stats(),
                           url_model_metrics=URL_MODEL_METRICS,
                           max_message_chars=settings.max_message_chars,
                           max_url_length=settings.max_url_length, **ctx)


# ═══════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def index():
    return _page()


def analyze_message(user_input):
    """Run the full message pipeline and return the template context."""
    # ── Step 1: Normalize adversarial tricks ──
    normalized, norm_transforms = normalize_adversarial(user_input)

    # ── Step 2: Legitimate check ──
    legit_info = classify_legitimate(normalized)

    # ── Step 3: Language ──
    lang_info = language_intelligence(normalized)
    english = lang_info["english"]
    if lang_info["code"] != "en" and not legit_info["is_legitimate"]:
        le = classify_legitimate(english)
        if le["is_legitimate"]: legit_info = le

    # ── Step 4: ML classifier (SMS spam model, message text) ──
    ml_proba, ml_signal = spam_probability(english)
    is_spam = ml_signal and ml_proba > 0.5

    # ── Step 5: URL analysis ──
    # URLs are analysed from the original text (only invisible characters
    # removed): leet/homoglyph normalisation would rewrite lookalike domains.
    url_info  = url_intelligence(re.sub(r'[​‌‍‎‏﻿­]', '', user_input))
    if legit_info.get("is_legitimate") and url_info["max_risk"] > URL_HIGH_RISK_THRESHOLD:
        # A genuine-looking notification carrying a High Risk link is a classic
        # phishing pattern, so the URL evidence overrides the legitimate match.
        legit_info = {**legit_info, "is_legitimate":False, "category":None, "has_scam_overrides":True,
                      "reasons":legit_info.get("reasons",[]) + [
                          f"⚠ Contains a High Risk URL ({url_info['max_risk']}/100); legitimate-notification match overridden"]}

    # ── Step 6–8: Multi-signal analysis ──
    brands    = brand_impersonation(english, legit_info.get("is_legitimate",False))
    se        = social_engineering_analysis(english, legit_info.get("is_legitimate",False))
    intent_info = intent_detection(english)

    # ── Step 9: Evidence highlighting ──
    highlights, highlighted_html = highlight_evidence(normalized)

    # ── Step 10: Override for legitimate ──
    if legit_info.get("is_legitimate") and legit_info.get("confidence",0)>0.5:
        is_spam = False

    # ── Step 11: Risk fusion ──
    score     = risk_fusion(ml_proba, url_info, brands, se, intent_info, legit_info)
    risk_info = risk_label(score)

    # ── Step 12: Evidence & recs ──
    evidence  = build_evidence(english, ml_proba, url_info, brands, se, intent_info, legit_info, highlights,
                               ml_signal=ml_signal)
    neg_evidence = build_negative_evidence(se, url_info, brands, highlights)
    recs      = build_recommendation(score, brands, se, intent_info, legit_info)

    # ── Step 13: Attack flow ──
    attack_flow = extract_attack_flow(highlights, se, intent_info, brands, url_info, legit_info)

    # ── Step 14: Adversarial robustness ──
    adversarial = adversarial_robustness_test(normalized, score, risk_info["label"])

    # ── Step 15: Analysis ID ──
    analysis_id = str(uuid.uuid4())[:8]

    return dict(
        user_input=user_input,
        lang=lang_info,
        url_info=url_info,
        brands=brands,
        se=se,
        se_source=_nlp_source(),
        intent=intent_info,
        ml_proba=ml_proba,
        ml_signal=ml_signal,
        is_spam=is_spam,
        score=score,
        risk=risk_info,
        evidence=evidence,
        neg_evidence=neg_evidence,
        recs=recs,
        legit=legit_info,
        highlights=highlights,
        highlighted_html=highlighted_html,
        attack_flow=attack_flow,
        adversarial=adversarial,
        analysis_id=analysis_id,
        norm_transforms=norm_transforms,
    )


def _message_input_error(user_input):
    if not user_input:
        return "Please paste a message to analyse."
    if len(user_input) > settings.max_message_chars:
        return f"Message is too long ({len(user_input):,} characters; limit {settings.max_message_chars:,})."
    return None


@app.route("/analyze", methods=["GET","POST"])
def analyze():
    if request.method == "GET":
        return redirect(url_for("index"))
    user_input = request.form.get("message","").strip()
    error = _message_input_error(user_input)
    if error:
        return _page(user_input=user_input, error=error), 400 if user_input else 200
    return _page(result_ready=True, **analyze_message(user_input))


@app.route("/analyze-url", methods=["GET","POST"])
def analyze_url_page():
    if request.method == "GET":
        return redirect(url_for("index"))
    url = request.form.get("url","").strip()
    if not url:
        return _page(mode="url", error="Please enter a URL to analyse.")
    try:
        result = url_service.analyze(url)
    except InvalidURLError as e:
        return _page(mode="url", url_input=url, error=str(e)), 400
    return _page(mode="url", url_input=url, url_result=result,
                 analysis_id=str(uuid.uuid4())[:8])


# ── JSON API ────────────────────────────────────────────────────
def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


@app.route("/api/analyze-url", methods=["POST"])
@app.route("/api/analyze", methods=["POST"])
def api_analyze_url():
    data = _json_body()
    if data is None or not isinstance(data.get("url"), str):
        return jsonify({"status":"error","message":"Send JSON like {\"url\": \"https://example.com\"}."}), 400
    try:
        result = url_service.analyze(data["url"])
    except InvalidURLError as e:
        return jsonify({"status":"error","message":str(e)}), 400
    return jsonify({"status":"ok", **result})


@app.route("/api/analyze-message", methods=["POST"])
def api_analyze_message():
    data = _json_body()
    if data is None or not isinstance(data.get("message"), str):
        return jsonify({"status":"error","message":"Send JSON like {\"message\": \"text\"}."}), 400
    message = data["message"].strip()
    error = _message_input_error(message)
    if error:
        return jsonify({"status":"error","message":error}), 400
    ctx = analyze_message(message)
    keys = ("score","risk","lang","legit","intent","se","se_source","ml_proba","ml_signal",
            "is_spam","url_info","brands","evidence","neg_evidence","recs","attack_flow",
            "norm_transforms","adversarial")
    return jsonify({"status":"ok", **{k: ctx[k] for k in keys}})


LATEST_MAX_LIMIT = 50
LATEST_MAX_ANALYZE = 25


def _defang(url):
    """Display form that cannot be clicked or auto-linked: hxxp://evil[.]com/."""
    return re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE).replace(".", "[.]")


@app.route("/api/threat-intel/latest", methods=["GET"])
def api_threat_intel_latest():
    """Latest URLs from the threat-intel API, fetched server-side (the browser never
    calls that service). With analyze=true each URL is also scored by PhishShield,
    reusing the record already fetched instead of looking it up again."""
    client = getattr(threat_intel_provider, "client", None)
    if client is None:
        return jsonify({"status": "error", "available": False,
                        "message": "Threat intelligence is not configured (set THREAT_INTEL_API_URL)."}), 503
    try:
        limit = int(request.args.get("limit", 10))
        page = int(request.args.get("page", 1))
    except ValueError:
        return jsonify({"status": "error", "message": "limit and page must be integers"}), 400
    if not 1 <= limit <= LATEST_MAX_LIMIT or page < 1:
        return jsonify({"status": "error", "message": f"limit must be 1-{LATEST_MAX_LIMIT}, page >= 1"}), 400
    analyze = request.args.get("analyze", "false").lower() in ("1", "true", "yes")
    if analyze and limit > LATEST_MAX_ANALYZE:
        return jsonify({"status": "error", "message": f"limit must be <= {LATEST_MAX_ANALYZE} with analyze=true"}), 400

    try:
        result = client.latest(limit=limit, page=page, source=request.args.get("source") or None,
                               threat_type=request.args.get("threat_type") or None)
    except ThreatIntelError as e:
        log.warning("Latest threat intel unavailable: %s", e)
        return jsonify({"status": "error", "available": False,
                        "message": f"Live threat intelligence unavailable: {e}"}), 503

    items = []
    for rec in result.items:
        item = {"intel": rec.to_dict(), "display_url": _defang(rec.url)}
        if analyze:
            try:
                r = url_service.analyze(rec.url, external_outcome=threat_intel_provider.outcome_for_record(rec))
                item["analysis"] = {"score": r["score"], "risk": r["risk"], "verdict": r["verdict"]}
            except InvalidURLError as e:
                item["analysis"] = {"error": str(e)}
        items.append(item)
    return jsonify({"status": "ok", "available": True, "count": len(items),
                    "pagination": {"page": result.page, "limit": result.limit, "total": result.total,
                                   "has_next": result.has_next},
                    "skipped_invalid": result.skipped_invalid, "items": items})


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "ok",
        "components": {
            **url_service.status(),
            "threat_intel_api": url_service.threat_intel_health(),
            "message_spam_classifier": {"loaded": ml_pipeline is not None},
            "zero_shot_model": {"loaded": zs_classifier is not None,
                                "enabled": settings.enable_zero_shot},
            "language_detection": {"available": detect is not None},
            "translation": {"enabled": settings.enable_translation,
                            "available": GoogleTranslator is not None,
                            "note": "Uses Google Translate over the network when enabled."},
        },
    })


@app.route("/feedback", methods=["POST"])
def feedback():
    data = _json_body()
    if not data: return jsonify({"status":"error","message":"No data"}), 400
    score = data.get("score", 0)
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 100:
        return jsonify({"status":"error","message":"score must be a number between 0 and 100"}), 400
    if not isinstance(data.get("is_correct", True), bool):
        return jsonify({"status":"error","message":"is_correct must be true or false"}), 400
    def _s(key, limit=200):
        v = data.get(key, "")
        return str(v)[:limit] if v is not None else ""
    try:
        store_feedback(
            aid=_s("analysis_id", 64) or "unknown",
            msg=_s("message", 500),
            score=int(score),
            rl=_s("risk_label", 50),
            atype=_s("attack_type", 100),
            lang=_s("language", 50),
            correct=data.get("is_correct", True),
        )
    except sqlite3.Error as e:
        log.error("Could not store feedback: %s", e)
        return jsonify({"status":"error","message":"Feedback could not be saved."}), 503
    stats = get_feedback_stats()
    return jsonify({"status":"ok","message":"Feedback recorded. Thank you!",
                    "stats":stats})


# ── Error handlers ──────────────────────────────────────────────
def _wants_json():
    return request.path.startswith("/api/") or request.path == "/feedback"


@app.errorhandler(413)
def too_large(e):
    msg = "Request body is too large (limit 1 MB)."
    if _wants_json(): return jsonify({"status":"error","message":msg}), 413
    return _page(error=msg), 413


@app.errorhandler(404)
def not_found(e):
    if _wants_json(): return jsonify({"status":"error","message":"Not found"}), 404
    return _page(error="Page not found."), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"status":"error","message":"Method not allowed"}), 405


@app.errorhandler(500)
def server_error(e):
    log.exception("Unhandled error on %s", request.path)
    if _wants_json(): return jsonify({"status":"error","message":"Internal server error"}), 500
    return _page(error="Something went wrong while analysing. Please try again."), 500


if __name__ == "__main__":
    app.run(debug=settings.debug, host=settings.host, port=settings.port, use_reloader=False)
