import re
import smtplib

import dns.resolver

# 1. Common Disposable & Reserved Domains List (Aap ise expand kar sakte hain)
DISPOSABLE_DOMAINS = {'mailinator.com', '10minutemail.com', 'tempmail.com', 'trashmail.com'}
RESERVED_DOMAINS = {'example.com', 'example.org', 'test.com', 'localhost'}

def verify_email_advanced(email):
    email = email.strip()
    score = 100
    checks = []
    
    # -------------------------------------------------------------
    # Step A: Format & Syntax Validation
    # -------------------------------------------------------------
    email_regex = r'^[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$'
    if not re.fullmatch(email_regex, email):
        return "Fake/Malicious", 0, "Failed: Invalid email syntax/format."
    checks.append("Format: Valid")

    local_part, domain = email.split('@')
    domain = domain.lower()

    # -------------------------------------------------------------
    # Step B: Reserved & Test Domains Check
    # -------------------------------------------------------------
    if domain in RESERVED_DOMAINS:
        score -= 50
        checks.append("Reserved Domain detected (e.g., example.com)")

    # -------------------------------------------------------------
    # Step C: Disposable Domain Check
    # -------------------------------------------------------------
    if domain in DISPOSABLE_DOMAINS:
        score -= 80
        checks.append("Disposable/Temporary email provider detected.")

    # -------------------------------------------------------------
    # Step D: DNS & MX Record Lookup
    # -------------------------------------------------------------
    mx_records = []
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_records = [str(r.exchange) for r in records]
        if mx_records:
            checks.append(f"MX Records found: {len(mx_records)}")
        else:
            score -= 40
            checks.append("No MX records found.")
    except Exception:
        score -= 60
        checks.append("DNS lookup failed or domain does not exist.")
        return "Fake/Malicious", max(0, score), " | ".join(checks)

    # -------------------------------------------------------------
    # Step E: SMTP Handshake Simulation (Mailbox Existence Check)
    # -------------------------------------------------------------
    # Note: Kuch mail servers (jaise Gmail/Yahoo) SMTP check par block kar dete hain,
    # isliye ise try-except mein rakhte hain taaki app crash na ho.
    smtp_verified = False
    if mx_records and score > 40:
        try:
            # Pehle MX server se connect karein
            mx_server = mx_records[0].rstrip('.')
            server = smtplib.SMTP(timeout=5)
            server.connect(mx_server)
            server.helo('verify-app.local')
            server.mail('test@verify-app.local')
            code, message = server.rcpt(email)
            server.quit()
            
            # SMTP code 250 matlab mailbox exist karta hai
            if code == 250:
                smtp_verified = True
                checks.append("SMTP: Mailbox active and verified.")
            else:
                score -= 30
                checks.append(f"SMTP: Mailbox rejected or doesn't exist (Code: {code})")
        except Exception:
            # Kai baar servers connection timeout ya firewall ki wajah se block karte hain
            checks.append("SMTP Check skipped/blocked by target mail server firewall.")

    # -------------------------------------------------------------
    # Step F: Final Scoring & Status Decision
    # -------------------------------------------------------------
    if score >= 80:
        status = "Safe"
    elif 40 <= score < 80:
        status = "Suspicious"
    else:
        status = "Fake/Malicious"

    details = f"Score: {score}/100 | " + " | ".join(checks)
    return status, max(0, min(100, score)), details