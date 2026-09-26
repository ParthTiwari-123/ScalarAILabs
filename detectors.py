"""
detectors.py
------------
Regex-based detectors for "structured" PII plus a wrapper around spaCy's
NER model for "unstructured" PII.
"""

import re
from dataclasses import dataclass
from typing import List, Callable

try:
    import spacy
    _NLP = spacy.load("en_core_web_sm")
except Exception:  # pragma: no cover
    _NLP = None


@dataclass
class Span:
    start: int
    end: int
    pii_type: str
    text: str

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


# ---------------------------------------------------------------------------
# Structured / regex detectors
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

_PHONE_PLUS_RE = re.compile(
    r"\+\s?\d{1,3}[\s\-]?(?:\(?\d{2,5}\)?[\s\-]?){1,4}\d{2,4}"
)
# Updated to include "received" for contextual matching like "received at"
_PHONE_CONTEXT_RE = re.compile(
    r"(?:Tel(?:ephone)?|Mob(?:ile)?|Phone|Contact(?: No\.?)?|Fax|Call|received)\s*(?:is|as|at|recorded as)?\s*[:\-]?\s*"
    r"(\+?\d[\d\s\-]{7,14}\d)",
    re.IGNORECASE,
)

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

_MONTHS = (
    "January|February|March|April|May|June|July|August|September|"
    "October|November|December"
)
DOB_RE = re.compile(
    r"(?:Date of Birth|D\.?O\.?B\.?|Born on)\s*(?:is|as|recorded as)?\s*[:\-]?\s*"
    r"(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}"
    r"|\d{1,2}(?:st|nd|rd|th)?\s+(?:%s)[,]?\s+\d{4}"
    r"|(?:%s)\s+\d{1,2}[,]?\s+\d{4})" % (_MONTHS, _MONTHS),
    re.IGNORECASE,
)

_ADDRESS_KEYWORDS = (
    r"Road|Street|St\.|Village|Nagar|Marg|Lane|Chowk|Tower|Floor|Wing|"
    r"Building|Bldg|Complex|Society|Colony|Sector|Block|District|Taluka|"
    r"Tehsil|Pune|Mumbai|Delhi|Bangalore|Bengaluru|Chennai|Kolkata|"
    r"Hyderabad|Maharashtra|Gujarat|Karnataka|Tamil Nadu|Farms|Estate|"
    r"Park|Campus|Plot|Survey No"
)
_ADDRESS_KEYWORD_RE = re.compile(_ADDRESS_KEYWORDS)
_PIN_RE = re.compile(r"(?<!\d)\d{3}\s?\d{3}(?!\d)")
_ADDRESS_BOUNDARY_RE = re.compile(r"[.;\n:]")
_ADDRESS_PREAMBLE_RE = re.compile(r"^\s*(?:Ticket|Case|Ref(?:erence)?)?\s*#?\d{3,}\s*-\s*", re.IGNORECASE)


def _luhn_ok(digits: str) -> bool:
    digits = [int(d) for d in digits]
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def find_emails(text: str) -> List[Span]:
    return [Span(m.start(), m.end(), "EMAIL", m.group()) for m in EMAIL_RE.finditer(text)]


def find_phones(text: str) -> List[Span]:
    spans = []
    for m in _PHONE_PLUS_RE.finditer(text):
        digit_count = sum(c.isdigit() for c in m.group())
        if 8 <= digit_count <= 14:
            spans.append(Span(m.start(), m.end(), "PHONE", m.group()))
    for m in _PHONE_CONTEXT_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        spans.append(Span(s, e, "PHONE", m.group(1)))
    return spans


def find_ssns(text: str) -> List[Span]:
    return [Span(m.start(), m.end(), "SSN", m.group()) for m in SSN_RE.finditer(text)]


def find_ip_addresses(text: str) -> List[Span]:
    return [Span(m.start(), m.end(), "IP_ADDRESS", m.group()) for m in IP_RE.finditer(text)]


def find_credit_cards(text: str) -> List[Span]:
    spans = []
    for m in _CC_CANDIDATE_RE.finditer(text):
        raw = m.group()
        digits = re.sub(r"[ \-]", "", raw)
        if len(digits) in (13, 14, 15, 16, 17, 18, 19) and _luhn_ok(digits):
            spans.append(Span(m.start(), m.end(), "CREDIT_CARD", raw))
    return spans


def find_dates_of_birth(text: str) -> List[Span]:
    spans = []
    for m in DOB_RE.finditer(text):
        spans.append(Span(m.start(1), m.end(1), "DATE_OF_BIRTH", m.group(1)))
    return spans


def find_addresses(text: str) -> List[Span]:
    spans = []
    for m in _PIN_RE.finditer(text):
        pin_start, pin_end = m.start(), m.end()
        window_start = pin_start
        search_from = max(0, pin_start - 200)
        boundary_matches = list(_ADDRESS_BOUNDARY_RE.finditer(text, search_from, pin_start))
        if boundary_matches:
            window_start = boundary_matches[-1].end()
        candidate = text[window_start:pin_end]
        stripped = _ADDRESS_PREAMBLE_RE.sub("", candidate)
        offset = len(candidate) - len(stripped)
        if _ADDRESS_KEYWORD_RE.search(stripped):
            spans.append(Span(window_start + offset, pin_end, "ADDRESS", stripped.strip()))
    return spans


# ---------------------------------------------------------------------------
# Unstructured detectors (spaCy NER)
# ---------------------------------------------------------------------------

_ORG_STOPWORDS = {
    "companies act", "the companies act", "sebi", "the sebi", "bse", "nse",
    "rbi", "gst", "sme", "ipo", "qib", "nii", "rii", "ebitda", "gaap", "ind as",
    "server ip", "ip", "server", "contact", "email", "phone", "date",
    "address", "note", "ref", "id", "tel", "fax", "website", "email id",
}

_PLACE_NAMES = {
    "maharashtra", "gujarat", "karnataka", "tamil nadu", "kerala",
    "rajasthan", "punjab", "haryana", "bihar", "odisha", "telangana",
    "andhra pradesh", "west bengal", "uttar pradesh", "madhya pradesh",
    "pune", "mumbai", "delhi", "bangalore", "bengaluru", "chennai",
    "kolkata", "hyderabad", "india",
}

_GENERIC_DEFINED_TERMS = {
    "the", "a", "an", "of", "and", "or", "for", "to", "our", "its", "their",
    "equity", "shares", "share", "net", "proceeds", "registered", "office",
    "corporate", "offer", "offered", "committee", "bid", "bids", "bidder",
    "bidders", "amount", "acknowledgement", "slip", "allotment", "book",
    "running", "lead", "managers", "manager", "escrow", "account", "demat",
    "price", "band", "floor", "cap", "red", "herring", "prospectus",
    "draft", "final", "fresh", "issue", "issuer", "sale", "retail",
    "individual", "investors", "investor", "anchor", "syndicate",
    "underwriting", "underwriters", "statutory", "auditors", "auditor",
    "secretarial", "compliance", "officer", "board", "key", "managerial",
    "personnel", "kmp", "articles", "association", "memorandum",
    "materials", "contracts", "documents", "inspection", "general",
    "information", "risk", "factors", "financial", "statements",
    "restated", "management", "discussion", "analysis", "capital",
    "structure", "objects", "basis", "listing", "application", "asba",
    "self", "certified", "banks", "registrar", "transfer", "agent",
    "agents", "legal", "counsel", "advisors", "advisor", "merchant",
    "bankers", "banker", "lenders", "lender", "term", "working", "loan",
    "credit", "facility", "rating", "agency", "agencies", "grading",
    "expert", "report", "shareholders", "shareholder", "promoter",
    "promoters", "selling", "non-institutional", "institutional",
    "portion", "designated", "intermediaries", "operations", "master",
    "circular", "inter", "alia", "mutual", "funds", "fund", "qualified",
    "buyers", "buyer", "non", "institutional", "portion", "period",
    "directors", "forms", "upi", "icdr", "thereto", "corrigenda", "sec",
    "wealth", "size", "eligibility", "total", "aggregate", "reservation",
    "among", "details", "public", "type", "weighted", "average",
    "acquisition", "cost", "name", "value", "face", "regulation",
    "regulations", "requirements", "disclosure", "disclosures", "mail",
    "telephone",
    "limited", "ltd", "llp", "inc", "corp", "corporation", "bank", "trust",
    "group", "company", "co", "enterprises", "industries", "holdings",
    "ventures", "capital", "partners", "associates", "consultants",
    "systems", "technologies", "solutions",
}

_PERSON_STOPWORDS = {"director", "promoter", "chairman", "managing director"}

_COMPANY_SUFFIX_RE = re.compile(
    r"\b[A-Z][A-Za-z0-9&.,\- ]{2,80}?\b(?:Private\s+)?Limited\b|"
    r"\b[A-Z][A-Za-z0-9&.,\- ]{2,80}?\bLLP\b|"
    r"\b[A-Z][A-Za-z0-9&.,\- ]{2,80}?\bPvt\.?\s?Ltd\.?\b"
)


def _is_generic_defined_term(entity_text: str) -> bool:
    words = re.findall(r"[A-Za-z]+", entity_text.lower())
    if not words:
        return False
    if all(w in _PLACE_NAMES for w in [entity_text.strip().lower()]):
        return True
    return all(w in _GENERIC_DEFINED_TERMS for w in words)


def find_names_and_companies(text: str) -> List[Span]:
    spans: List[Span] = []
    person_first_names = set()
    org_candidates: List[Span] = []

    if _NLP is not None:
        for chunk_start in range(0, len(text), 100_000):
            chunk = text[chunk_start:chunk_start + 100_000]
            doc = _NLP(chunk)
            for ent in doc.ents:
                norm = ent.text.strip().lower()
                if (ent.label_ == "PERSON" and norm not in _PERSON_STOPWORDS
                        and len(ent.text.split()) >= 2
                        and not any(ch.isdigit() for ch in ent.text)
                        and not _is_generic_defined_term(ent.text)):
                    spans.append(Span(chunk_start + ent.start_char, chunk_start + ent.end_char, "PERSON", ent.text))
                    for tok in ent.text.split():
                        person_first_names.add(tok.strip(".,").lower())
                elif ent.label_ in ("ORG",) and norm not in _ORG_STOPWORDS and len(ent.text) > 3:
                    if _is_generic_defined_term(ent.text):
                        continue
                    has_digit = any(ch.isdigit() for ch in ent.text)
                    has_suffix = bool(re.search(
                        r"\b(Limited|Ltd|LLP|Inc|Corp|Bank|Group|Trust|Company|Co\.)\b",
                        ent.text, re.IGNORECASE))
                    if has_digit and not has_suffix:
                        continue
                    org_candidates.append(Span(chunk_start + ent.start_char, chunk_start + ent.end_char, "COMPANY", ent.text))

    for span in org_candidates:
        if len(span.text.split()) == 1 and span.text.strip(".,").lower() in person_first_names:
            continue
        spans.append(span)

    for m in _COMPANY_SUFFIX_RE.finditer(text):
        if not _is_generic_defined_term(m.group()):
            spans.append(Span(m.start(), m.end(), "COMPANY", m.group()))

    return spans


DETECTORS: List[Callable[[str], List[Span]]] = [
    find_emails,
    find_ip_addresses,
    find_ssns,
    find_credit_cards,
    find_dates_of_birth,
    find_phones,
    find_addresses,
    find_names_and_companies,
]


def detect_all(text: str) -> List[Span]:
    all_spans: List[Span] = []
    for detector in DETECTORS:
        for span in detector(text):
            if not any(span.overlaps(existing) for existing in all_spans):
                all_spans.append(span)
    all_spans.sort(key=lambda s: s.start)
    return all_spans