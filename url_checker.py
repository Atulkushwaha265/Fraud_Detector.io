import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = lambda: None

try:
    import requests
except ImportError:
    requests = None

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    import whois
except ImportError:
    whois = None


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# CONFIGURATION
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "bank",
    "secure",
    "update",
    "account",
    "signin",
    "confirm",
    "password",
    "credential",
    "wallet",
    "payment",
    "billing",
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".club",
    ".gq",
    ".ml",
    ".work",
    ".click",
]

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
]

ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


# =========================================================
# ABUSEIPDB
# =========================================================

def check_abuseipdb(ip_address):
    """
    Check an IP address against AbuseIPDB.

    Returns:
        (confidence_score, message)

    confidence_score:
        Integer 0-100 if the check succeeds.
        None if the check is unavailable.
    """

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    if not api_key:
        return (
            None,
            "AbuseIPDB: Check unavailable - API key not configured.",
        )

    try:
        response = requests.get(
            ABUSEIPDB_ENDPOINT,
            headers={
                "Accept": "application/json",
                "Key": api_key,
            },
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
            },
            timeout=8,
        )

        # Invalid API key
        if response.status_code == 401:
            return (
                None,
                "AbuseIPDB: Invalid API key.",
            )

        # Forbidden
        if response.status_code == 403:
            return (
                None,
                "AbuseIPDB: API access forbidden.",
            )

        # Rate limit
        if response.status_code == 429:
            return (
                None,
                "AbuseIPDB: Rate limit reached.",
            )

        response.raise_for_status()

        data = response.json().get("data", {})

        confidence = int(
            data.get("abuseConfidenceScore", 0)
        )

        reports = int(
            data.get("totalReports", 0)
        )

        return (
            confidence,
            (
                f"AbuseIPDB: Confidence {confidence}% "
                f"({reports} reports)."
            ),
        )

    except requests.Timeout:
        return (
            None,
            "AbuseIPDB: Request timed out.",
        )

    except requests.ConnectionError:
        return (
            None,
            "AbuseIPDB: Connection failed.",
        )

    except requests.RequestException:
        return (
            None,
            "AbuseIPDB: Request failed.",
        )

    except (ValueError, TypeError):
        return (
            None,
            "AbuseIPDB: Invalid response received.",
        )


# =========================================================
# DNS CHECK
# =========================================================

def check_dns(hostname):
    """
    Resolve hostname to an IPv4 address.

    Returns:
        (ip_address, message)
    """

    try:
        ip_address = socket.gethostbyname(hostname)

        return (
            ip_address,
            f"DNS: Resolved to {ip_address}.",
        )

    except socket.gaierror:
        return (
            None,
            "DNS: Domain could not be resolved.",
        )

    except socket.timeout:
        return (
            None,
            "DNS: Resolution timed out.",
        )

    except OSError:
        return (
            None,
            "DNS: Resolution failed.",
        )


# =========================================================
# SSL CERTIFICATE CHECK
# =========================================================

def check_ssl_certificate(hostname):
    """
    Validate HTTPS SSL/TLS certificate.

    Returns:
        (success, message)
    """

    try:
        context = ssl.create_default_context()

        with (
            socket.create_connection(
                (hostname, 443),
                timeout=8,
            ) as sock,
            context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as secure_socket,
        ):
            certificate = secure_socket.getpeercert()

            not_after = certificate.get("notAfter")

            if not_after is None:
                return (
                    False,
                    "SSL: Certificate expiry date unavailable.",
                )

            expiry_date = datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            current_time = datetime.now(timezone.utc)

            if expiry_date < current_time:
                return (
                    False,
                    "SSL: Certificate has expired.",
                )

            remaining_days = (
                expiry_date - current_time
            ).days

            return (
                True,
                (
                    "SSL: Certificate is valid. "
                    f"Expires in approximately {remaining_days} days."
                ),
            )

    except ssl.CertificateError:
        return (
            False,
            "SSL: Certificate hostname verification failed.",
        )

    except ssl.SSLError:
        return (
            False,
            "SSL: TLS/certificate validation failed.",
        )

    except socket.timeout:
        return (
            False,
            "SSL: Connection timed out.",
        )

    except OSError:
        return (
            False,
            "SSL: HTTPS connection failed.",
        )

    except ValueError:
        return (
            False,
            "SSL: Certificate data could not be parsed.",
        )


# =========================================================
# REDIRECT CHECK
# =========================================================

def check_redirects(url):
    """
    Analyze HTTP redirects.

    Returns:
        (redirect_count, message)
    """

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/153.0.0.0 Safari/537.36"
                )
            },
            stream=True,
        )

        redirect_count = len(response.history)

        final_url = response.url

        if redirect_count == 0:
            message = "Redirect: No redirects detected."

        else:
            message = (
                f"Redirect: {redirect_count} hop(s) detected. "
                f"Final URL: {final_url}"
            )

        response.close()

        return (
            redirect_count,
            message,
        )

    except requests.Timeout:
        return (
            None,
            "Redirect: Check unavailable - request timed out.",
        )

    except requests.ConnectionError:
        return (
            None,
            "Redirect: Check unavailable - connection failed.",
        )

    except requests.RequestException:
        return (
            None,
            "Redirect: Check unavailable - HTTP request failed.",
        )


# =========================================================
# WHOIS / DOMAIN AGE
# =========================================================

def check_domain_age(domain):
    """
    Check domain creation date using WHOIS.

    Returns:
        (age_days, message)
    """

    try:
        if whois is None:
            raise ImportError
        whois_data = whois.whois(domain)

        creation_date = whois_data.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return (
                None,
                "WHOIS: Domain creation date unavailable.",
            )

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )
        else:
            creation_date = creation_date.astimezone(
                timezone.utc
            )

        current_time = datetime.now(timezone.utc)

        age_days = (
            current_time - creation_date
        ).days

        if age_days < 0:
            return (
                None,
                "WHOIS: Invalid domain creation date.",
            )

        return (
            age_days,
            f"WHOIS: Domain is approximately {age_days} days old.",
        )

    except ImportError:
        if requests is None:
            return None, "WHOIS: Domain information unavailable."
        try:
            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                headers={"Accept": "application/rdap+json"},
                timeout=8,
            )
            response.raise_for_status()
            events = response.json().get("events", [])
            registration_event = next(
                (event for event in events if event.get("eventAction") == "registration"),
                None,
            )
            if not registration_event:
                return None, "WHOIS: Domain creation date unavailable."
            creation_date = datetime.fromisoformat(
                registration_event["eventDate"].replace("Z", "+00:00")
            )
            age_days = max(0, (datetime.now(timezone.utc) - creation_date).days)
            return age_days, f"WHOIS: Domain is approximately {age_days} days old."
        except (requests.RequestException, KeyError, TypeError, ValueError):
            return None, "WHOIS: Domain information unavailable."

    except (
        OSError,
        ValueError,
        TypeError,
        AttributeError,
    ):
        return (
            None,
            "WHOIS: Domain information unavailable.",
        )


# =========================================================
# IP ADDRESS DETECTION
# =========================================================

def is_ip_address(hostname):
    """
    Check whether hostname is an IPv4 address.
    """

    try:
        socket.inet_aton(hostname)
        return True

    except OSError:
        return False


# =========================================================
# DOMAIN EXTRACTION
# =========================================================

def extract_domain_information(hostname):
    """
    Extract domain, TLD and subdomain.
    """

    if tldextract is not None:
        extracted = tldextract.extract(hostname)
        domain_name = extracted.domain
        suffix = extracted.suffix
        subdomain = extracted.subdomain
    else:
        parts = hostname.lower().strip('.').split('.')
        domain_name = parts[-2] if len(parts) >= 2 else ''
        suffix = parts[-1] if len(parts) >= 2 else ''
        subdomain = '.'.join(parts[:-2])

    if domain_name and suffix:
        domain = f"{domain_name}.{suffix}"
    else:
        domain = domain_name

    tld = f".{suffix}" if suffix else ""

    return (
        domain,
        domain_name,
        suffix,
        subdomain,
        tld,
    )


# =========================================================
# MAIN URL ANALYZER
# =========================================================

def analyze_url_comprehensive(url):
    """
    Perform comprehensive URL analysis.

    Returns:
        status, score, details
    """

    # -----------------------------------------------------
    # INPUT VALIDATION
    # -----------------------------------------------------

    url = url.strip()

    if not url:
        return (
            "Invalid",
            0,
            "Enter a URL to analyze.",
        )

    # Add protocol if missing
    if not url.startswith(
        ("http://", "https://")
    ):
        url = "https://" + url

    # Parse URL
    parsed = urlparse(url)

    hostname = parsed.hostname

    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
    ):
        return (
            "Invalid",
            0,
            "Invalid URL structure. "
            "Use a valid HTTP/HTTPS URL.",
        )

    score = 100
    checks = []

    # -----------------------------------------------------
    # IP ADDRESS CHECK
    # -----------------------------------------------------

    ip_url = is_ip_address(hostname)

    if ip_url:

        score -= 25

        checks.append(
            "Structure: IP address used instead of a domain."
        )

    # -----------------------------------------------------
    # DOMAIN INFORMATION
    # -----------------------------------------------------

    if ip_url:

        domain = hostname
        domain_name = hostname
        suffix = ""
        subdomain = ""
        tld = ""

    else:

        try:
            (
                domain,
                domain_name,
                suffix,
                subdomain,
                tld,
            ) = extract_domain_information(hostname)

        except Exception:
            return (
                "Invalid",
                0,
                "Unable to extract domain information.",
            )

        if not domain_name or not suffix:

            return (
                "Invalid",
                0,
                "Invalid domain structure.",
            )

    # -----------------------------------------------------
    # HTTPS CHECK
    # -----------------------------------------------------

    is_https = parsed.scheme == "https"

    if is_https:

        checks.append(
            "Protocol: HTTPS is being used."
        )

    else:

        score -= 15

        checks.append(
            "Protocol: HTTP is being used instead of HTTPS."
        )

    # -----------------------------------------------------
    # SUSPICIOUS TLD
    # -----------------------------------------------------

    if tld.lower() in SUSPICIOUS_TLDS:

        score -= 15

        checks.append(
            f"Heuristic: Suspicious TLD detected ({tld})."
        )

    # -----------------------------------------------------
    # URL SHORTENER
    # -----------------------------------------------------

    if domain.lower() in URL_SHORTENERS:

        score -= 10

        checks.append(
            "Heuristic: URL shortener detected."
        )

    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    url_lower = url.lower()

    keyword_matches = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    if keyword_matches:

        # Limit penalty so many repeated keywords
        # don't destroy the entire score.
        score -= min(
            20,
            len(keyword_matches) * 5,
        )

        checks.append(
            "Heuristic: Suspicious keywords found: "
            + ", ".join(keyword_matches)
        )

    # -----------------------------------------------------
    # USERNAME / @ CHECK
    # -----------------------------------------------------

    if parsed.username is not None:

        score -= 20

        checks.append(
            "Structure: URL contains an embedded username."
        )

    # -----------------------------------------------------
    # EXCESSIVE SUBDOMAINS
    # -----------------------------------------------------

    subdomain_parts = [
        part
        for part in subdomain.split(".")
        if part
    ]

    if len(subdomain_parts) > 2:

        score -= 15

        checks.append(
            "Structure: Excessive subdomains detected."
        )

    # -----------------------------------------------------
    # LONG URL
    # -----------------------------------------------------

    if len(url) > 200:

        score -= 10

        checks.append(
            "Heuristic: URL is unusually long."
        )

    # -----------------------------------------------------
    # MANY SPECIAL CHARACTERS
    # -----------------------------------------------------

    special_characters = sum(
        1
        for char in url
        if char in "@%$^{}[]<>"
    )

    if special_characters >= 4:

        score -= 10

        checks.append(
            "Heuristic: Unusual number of special characters."
        )

    # -----------------------------------------------------
    # DNS CHECK
    # -----------------------------------------------------

    ip_addr, dns_message = check_dns(hostname)

    if ip_addr:

        checks.append(dns_message)

    else:

        checks.append(dns_message)

        # Important:
        # DNS failure is not automatically malicious.
        return (
            "Invalid Domain",
            max(0, score),
            " | ".join(checks),
        )

    # -----------------------------------------------------
    # ABUSEIPDB
    # -----------------------------------------------------

    abuse_score, abuse_message = check_abuseipdb(
        ip_addr
    )

    checks.append(abuse_message)

    if abuse_score is not None:

        if abuse_score >= 80:

            score -= 40

            checks.append(
                "Reputation: High IP abuse confidence."
            )

        elif abuse_score >= 50:

            score -= 25

            checks.append(
                "Reputation: Medium IP abuse confidence."
            )

        elif abuse_score > 0:

            score -= 10

            checks.append(
                "Reputation: Some abuse reports detected."
            )

        else:

            checks.append(
                "Reputation: No significant abuse reports."
            )

    # -----------------------------------------------------
    # SSL CERTIFICATE
    # -----------------------------------------------------

    if is_https:

        ssl_success, ssl_message = check_ssl_certificate(
            hostname
        )

        checks.append(ssl_message)

        if not ssl_success:

            # Don't heavily penalize simply because
            # the check was unavailable.
            if (
                "expired" in ssl_message.lower()
                or "validation failed" in ssl_message.lower()
                or "hostname verification failed"
                in ssl_message.lower()
            ):
                score -= 25

    # -----------------------------------------------------
    # REDIRECT ANALYSIS
    # -----------------------------------------------------

    redirect_count, redirect_message = check_redirects(
        url
    )

    checks.append(redirect_message)

    if redirect_count is not None:

        if redirect_count > 2:

            score -= 10

            checks.append(
                "Heuristic: Excessive redirect chain detected."
            )

    # -----------------------------------------------------
    # WHOIS / DOMAIN AGE
    # -----------------------------------------------------

    age_days, whois_message = check_domain_age(
        domain
    )

    checks.append(whois_message)

    if age_days is not None:

        if age_days < 30:

            score -= 25

            checks.append(
                "Warning: Domain is very new "
                "(less than 30 days old)."
            )

        elif age_days < 90:

            score -= 10

            checks.append(
                "Warning: Domain is relatively new."
            )

    # -----------------------------------------------------
    # FINAL SCORE
    # -----------------------------------------------------

    score = max(
        0,
        min(score, 100),
    )

    # -----------------------------------------------------
    # FINAL STATUS
    # -----------------------------------------------------

    if score >= 80:

        status = "Safe"

    elif score >= 40:

        status = "Suspicious"

    else:

        status = "Fake/Malicious"

    # -----------------------------------------------------
    # FINAL DETAILS
    # -----------------------------------------------------

    details = (
        f"Final Risk Score: {score}/100 | "
        + " | ".join(checks)
    )

    return (
        status,
        score,
        details,
    )