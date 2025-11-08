import re
from urllib.parse import urlparse
import html

# --- Config / Indicators ---
URGENT_WORDS = [
    "urgent", "immediately", "verify", "update", "account locked",
    "password", "bank", "confirm", "click here", "suspended",
    "payment may be delayed", "limited access", "action required"
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "valued member", "sir/madam", "dear colleague"
]

SUSPICIOUS_TLDS = ["xyz", "top", "club", "info", "cc", "pw"]
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".msi", ".com.exe", ".pdf.exe"
]

CREDENTIAL_REQUESTS = [
    "enter your password", "provide your credentials",
    "confirm your identity", "update your payment", "reset your account",
    "verify your identity", "submit your password"
]

TRUSTED_BRAND_KEYWORDS = [
    "brightfuture", "yourcompany", "company", "hr", "payroll", "accounts"
]

# --- Utilities ---

def extract_headers_and_body(raw_text):
    headers = {}
    parts = raw_text.splitlines()
    header_lines, body_lines = [], []
    in_headers = True
    for line in parts:
        if in_headers and line.strip() == "":
            in_headers = False
            continue
        if in_headers:
            header_lines.append(line)
        else:
            body_lines.append(line)
    for h in header_lines:
        m = re.match(r"^(From|Reply-To|Subject|To|CC):\s*(.+)$", h, re.I)
        if m:
            headers[m.group(1).lower()] = m.group(2).strip()
    body = "\n".join(body_lines).strip()
    return (headers, body) if headers else ({}, raw_text)


def find_links(text):
    return re.findall(r"https?://[^\s'\"<>)+,;]+", text, flags=re.I)


def extract_html_anchors(text):
    anchors = []
    for m in re.finditer(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', text, flags=re.I | re.S):
        href = m.group(1).strip()
        anchor_text = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', m.group(2))).strip()
        anchors.append((html.unescape(anchor_text), href))
    return anchors


def hostname_from_url(url):
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if "@" in host:
            host = host.split("@")[-1]
        if ":" in host:
            host = host.split(":")[0]
        return host
    except Exception:
        return ""


def get_registered_domain(host):
    host = host.lower().strip(".")
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and len(labels) >= 3:
        return ".".join(labels[-3:])
    else:
        return ".".join(labels[-2:])


def find_embedded_domain(host):
    tokens = re.findall(r"[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+", host)
    tokens = sorted(set(tokens), key=lambda s: -len(s))
    reg = get_registered_domain(host)
    for t in tokens:
        t_reg = get_registered_domain(t)
        if t_reg and t_reg != reg and '.' in t:
            return t_reg
    return None


def contains_unicode_homograph(host):
    if host.startswith("xn--") or "xn--" in host:
        return True
    try:
        host.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


def suspicious_attachment_filenames(text):
    suspicious = []
    for m in re.finditer(r'(filename|name)=["\']?([^"\';\s>]+)', text, flags=re.I):
        fname = m.group(2).lower()
        if any(fname.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) or re.search(r'\.\w+\.\w+$', fname):
            suspicious.append(fname)
    return suspicious


# --- Main Detection Function ---

def detect_phishing_advanced(raw_text):
    headers, body = extract_headers_and_body(raw_text)
    text_for_analysis = (body or raw_text).lower()
    score = 0
    reasons = []
    details = {
        "headers": headers,
        "links": [],
        "hosts": [],
        "registered_domains": [],
        "anchors": [],
        "suspicious_attachments": [],
        "flags": []
    }

    # Headers
    from_header = headers.get("from", "")
    replyto_header = headers.get("reply-to", "")
    subject_header = headers.get("subject", "")
    if from_header:
        reasons.append(f"From header present: {from_header}")
    if replyto_header and from_header and replyto_header.lower() not in from_header.lower():
        score += 2
        reasons.append(f"From vs Reply-To mismatch: From='{from_header}' Reply-To='{replyto_header}'")
        details["flags"].append("from_replyto_mismatch")

    links = find_links(raw_text)
    anchors = extract_html_anchors(raw_text)
    for a_text, href in anchors:
        details["anchors"].append((a_text, href))
    links = list(dict.fromkeys(links))
    details["links"] = links

    seen_hosts = []
    for link in links:
        host = hostname_from_url(link)
        if not host:
            continue
        reg_dom = get_registered_domain(host)
        details["hosts"].append(host)
        details["registered_domains"].append(reg_dom)
        if contains_unicode_homograph(host):
            score += 3
            reasons.append(f"Punycode / unicode domain detected: {host}")
        if link.lower().startswith("http://"):
            score += 1
            reasons.append(f"Unsecured (http) link found: {link}")
        if any(host.endswith("." + tld) for tld in SUSPICIOUS_TLDS):
            score += 1
            reasons.append(f"Link uses suspicious TLD: {host}")
        embedded = find_embedded_domain(host)
        if embedded:
            score += 3
            reasons.append(f"Embedded/tricky domain: host='{host}' inner='{embedded}' (registered='{reg_dom}')")
        if re.search(r'\.(exe|scr|bat|com\.)', link, flags=re.I):
            score += 3
            reasons.append(f"Executable/obfuscated file in URL: {link}")
        seen_hosts.append((host, reg_dom, embedded))

    for anchor_text, href in details["anchors"]:
        href_host = hostname_from_url(href)
        doms_in_text = re.findall(r"[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+\.[a-z]{2,}", anchor_text, flags=re.I)
        if doms_in_text and href_host and doms_in_text[0].lower() not in href_host:
            score += 2
            reasons.append(f"Anchor text/domain mismatch: '{doms_in_text[0]}' vs '{href_host}'")
        if anchor_text.strip().lower() in ("click here", "review", "here", "verify") and href_host and not any(k in href_host for k in TRUSTED_BRAND_KEYWORDS):
            score += 1
            reasons.append(f"Generic anchor text linking to external host: '{anchor_text}' -> {href_host}")

    # Content-based checks
    urgency_hits = [w for w in URGENT_WORDS if re.search(r'\b' + re.escape(w) + r'\b', text_for_analysis)]
    if urgency_hits:
        score += min(len(set(urgency_hits)), 4)
        reasons.append(f"Urgency words found: {', '.join(sorted(set(urgency_hits)))}")

    for greet in GENERIC_GREETINGS:
        if greet in text_for_analysis:
            score += 1
            reasons.append(f"Generic greeting used: '{greet}'")

    cred_hits = [p for p in CREDENTIAL_REQUESTS if p in text_for_analysis]
    if cred_hits:
        score += 3
        reasons.append(f"Credential/sensitive info phrases: {', '.join(set(cred_hits))}")

    long_tokens = re.findall(r"\b[a-z]{12,}\b", text_for_analysis)
    if len(long_tokens) > 4:
        score += 1
        reasons.append("Multiple unusually long alphabetic tokens detected")

    suspicious_fnames = suspicious_attachment_filenames(raw_text)
    if suspicious_fnames:
        score += 2
        reasons.append(f"Suspicious attachment filenames: {', '.join(suspicious_fnames)}")
        details["suspicious_attachments"] = suspicious_fnames

    if from_header:
        m = re.search(r'@([A-Za-z0-9\.\-]+)', from_header)
        if m:
            from_domain = m.group(1).lower()
            from_reg = get_registered_domain(from_domain)
            for _, reg_dom, embedded in seen_hosts:
                if reg_dom and from_reg and reg_dom != from_reg:
                    score += 2
                    reasons.append(f"Links point to '{reg_dom}' but From header domain is '{from_domain}'")
                    break

    # Deduplicate reasons
    seen = set()
    clean_reasons = []
    for r in reasons:
        if r not in seen:
            clean_reasons.append(r)
            seen.add(r)

    # Verdict
    if score >= 8:
        verdict = "⚠️ High chance of PHISHING"
        color = "red"
    elif 4 <= score < 8:
        verdict = "⚠️ Suspicious - possibly phishing"
        color = "orange"
    else:
        verdict = "✅ Safe / Low risk"
        color = "green"

    return {
        "verdict": verdict,
        "score": score,
        "reasons": clean_reasons,
        "details": details,
        "color": color,
        "subject": subject_header
    }
