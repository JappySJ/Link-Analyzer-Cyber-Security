"""
Dataset generator - produces app/ml/dataset.csv with columns url,label.

    label 0 = benign        label 1 = phishing

HONESTY NOTE (this is in the README too, and is worth saying in the viva)
------------------------------------------------------------------------
These URLs are PROGRAMMATICALLY GENERATED from real-world phishing patterns.
They are not scraped from live PhishTank feeds. That choice is deliberate:

  + the dataset is reproducible - anyone marking this project can regenerate
    the identical file with `python -m app.ml.make_dataset` and no internet;
  + it cannot go stale or 404 the way a URL feed does;
  - the model learns the PATTERNS encoded here, so it will not generalise to a
    novel trick that no pattern in this file represents.

To train on real data instead, drop in any CSV with `url,label` columns and run
    python -m app.ml.train --csv path/to/phishtank.csv
No code changes are needed; the feature pipeline is identical either way.

ANTI-LEAKAGE DESIGN
-------------------
A naive generator makes benign URLs short and clean and phishing URLs long and
ugly, so a single length threshold scores ~99% and the model learns nothing.
To prevent that this generator deliberately includes ~15% HARD rows on both
sides:
  * hard benign   - real domains with 'login'/'secure'/'verify' paths, long
                    query strings, hyphens, deep paths (bank and gov sites
                    genuinely look like this)
  * hard phishing - short, clean, https, no keywords - the attack is only
                    visible in the typosquatted domain itself
That overlap is what stops the metrics being fake.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

from app.config import DATASET_PATH

SEED = 42
TARGET_ROWS = 2400          # ~1200 per class before de-duplication
HARD_FRACTION = 0.15        # share of deliberately ambiguous rows per class

# ---------------------------------------------------------------------------
# 1. Real, popular domains for the benign class (170+ entries)
# ---------------------------------------------------------------------------

BENIGN_DOMAINS = [
    # global tech / search / dev
    "google.com", "www.google.com", "youtube.com", "www.youtube.com",
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "stackexchange.com", "wikipedia.org", "en.wikipedia.org", "mozilla.org",
    "developer.mozilla.org", "python.org", "docs.python.org", "pypi.org",
    "npmjs.com", "nodejs.org", "docker.com", "kubernetes.io", "apache.org",
    "linux.org", "kernel.org", "ubuntu.com", "debian.org", "redhat.com",
    "archlinux.org", "sourceforge.net", "readthedocs.io", "jetbrains.com",
    "visualstudio.com", "code.visualstudio.com", "eclipse.org", "atlassian.com",
    # big platforms
    "microsoft.com", "www.microsoft.com", "office.com", "outlook.com",
    "live.com", "azure.microsoft.com", "apple.com", "support.apple.com",
    "icloud.com", "amazon.com", "amazon.in", "aws.amazon.com", "netflix.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "pinterest.com", "tumblr.com", "quora.com", "medium.com",
    "whatsapp.com", "telegram.org", "discord.com", "slack.com", "zoom.us",
    "dropbox.com", "drive.google.com", "onedrive.live.com", "box.com",
    "spotify.com", "soundcloud.com", "twitch.tv", "steampowered.com",
    "epicgames.com", "roblox.com", "minecraft.net",
    # news / reference
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
    "reuters.com", "bloomberg.com", "forbes.com", "wsj.com", "ft.com",
    "economist.com", "nationalgeographic.com", "sciencedirect.com",
    "nature.com", "arxiv.org", "ieee.org", "acm.org", "springer.com",
    "jstor.org", "researchgate.net", "scholar.google.com",
    # commerce / travel / finance
    "ebay.com", "etsy.com", "walmart.com", "target.com", "bestbuy.com",
    "alibaba.com", "aliexpress.com", "flipkart.com", "myntra.com",
    "snapdeal.com", "shopify.com", "stripe.com", "paypal.com", "visa.com",
    "mastercard.com", "americanexpress.com", "booking.com", "airbnb.com",
    "expedia.com", "tripadvisor.com", "makemytrip.com", "goibibo.com",
    "uber.com", "olacabs.com", "zomato.com", "swiggy.com",
    # Indian services, banks and government (relevant to our college context)
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com", "pnbindia.in", "bankofbaroda.in",
    "unionbankofindia.co.in", "canarabank.com", "rbi.org.in",
    "irctc.co.in", "indianrailways.gov.in", "india.gov.in", "nic.in",
    "uidai.gov.in", "incometax.gov.in", "gst.gov.in", "epfindia.gov.in",
    "passportindia.gov.in", "mygov.in", "digilocker.gov.in", "cowin.gov.in",
    "paytm.com", "phonepe.com", "razorpay.com", "zerodha.com", "groww.in",
    "nseindia.com", "bseindia.com", "policybazaar.com", "lictindia.in",
    # education
    "bitdurg.ac.in", "aicte-india.org", "ugc.gov.in", "nptel.ac.in",
    "swayam.gov.in", "cbse.gov.in", "mit.edu", "stanford.edu", "harvard.edu",
    "ox.ac.uk", "cam.ac.uk", "iitb.ac.in", "iitd.ac.in", "iitm.ac.in",
    "coursera.org", "edx.org", "udemy.com", "khanacademy.org", "geeksforgeeks.org",
    "w3schools.com", "tutorialspoint.com", "freecodecamp.org", "leetcode.com",
    "hackerrank.com", "kaggle.com", "codeforces.com",
    # misc utilities
    "cloudflare.com", "digitalocean.com", "heroku.com", "netlify.com",
    "vercel.com", "godaddy.com", "namecheap.com", "wordpress.org",
    "wordpress.com", "wix.com", "squarespace.com", "adobe.com", "canva.com",
    "figma.com", "notion.so", "trello.com", "asana.com", "salesforce.com",
    "oracle.com", "ibm.com", "intel.com", "nvidia.com", "amd.com", "dell.com",
    "hp.com", "lenovo.com", "samsung.com", "xiaomi.com", "oneplus.in",
]

# Realistic path segments seen on legitimate sites.
BENIGN_PATHS = [
    "", "/", "/about", "/about-us", "/contact", "/products", "/services",
    "/blog", "/news", "/help", "/support", "/docs", "/documentation",
    "/pricing", "/features", "/careers", "/privacy-policy", "/terms",
    "/faq", "/downloads", "/community", "/developers", "/api", "/status",
    "/blog/2024/how-to-get-started", "/docs/getting-started/installation",
    "/help/articles/troubleshooting-common-issues",
    "/products/electronics/laptops", "/category/books/fiction",
    "/en/latest/reference/index.html", "/search", "/sitemap.xml",
    "/news/technology/article-12345", "/user/profile/settings",
    "/watch", "/playlist", "/questions/1234567/how-do-i-parse-json",
    "/wiki/Machine_learning", "/repos/octocat/hello-world",
]

# Query strings a real site would use - benign URLs must not be trivially
# separable by "has a query string".
BENIGN_QUERIES = [
    "", "", "", "",
    "?ref=homepage", "?utm_source=newsletter&utm_medium=email",
    "?page=2", "?sort=popular&order=desc", "?lang=en", "?id=48213",
    "?q=machine+learning&hl=en", "?v=dQw4w9WgXcQ&t=42s",
    "?category=electronics&brand=samsung&sort=price_asc&page=3",
    "?utm_source=google&utm_medium=cpc&utm_campaign=spring_sale&gclid=EAIaIQobChMI",
    "?tab=repositories&type=source", "?filter=recent&limit=50&offset=100",
]

# Legitimate-but-scary-looking paths: real banks and portals use these words.
HARD_BENIGN_PATHS = [
    "/login", "/signin", "/account/login", "/secure/login",
    "/account/security/settings", "/user/account/verify-email",
    "/password/reset", "/account/recovery", "/auth/login?next=/dashboard",
    "/customer/account/login/referer/aHR0cHM6Ly9leGFtcGxl",
    "/personal-banking/login", "/netbanking/secure/login.htm",
    "/my-account/payment-methods/update", "/billing/invoice/2024-08",
    "/settings/security/two-factor-authentication",
    "/account/update-payment-details", "/verify-account",
    "/secure-checkout/payment?order=88213&token=a1b2c3d4e5",
    "/oauth2/authorize?client_id=abc123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid%20profile%20email",
]

# ---------------------------------------------------------------------------
# 2. Building blocks for the phishing class
# ---------------------------------------------------------------------------

PHISH_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "dropbox", "icloud", "outlook",
    "office365", "onedrive", "chase", "wellsfargo", "citibank", "hsbc",
    "bankofamerica", "ebay", "coinbase", "binance", "metamask", "blockchain",
    "dhl", "fedex", "ups", "usps", "irs", "steam", "discord", "telegram",
    "sbi", "hdfc", "icici", "axisbank", "paytm", "phonepe", "irctc",
    "aadhaar", "incometax", "netflix", "spotify", "zoom",
]

# Real typosquats seen in the wild: character swaps, digit-for-letter, doubles.
TYPOSQUATS = [
    "arnazon", "amaz0n", "amazn", "amazon-in", "annazon",
    "faceb00k", "facebok", "facebo0k", "faceboook", "facebbok",
    "g00gle", "gooogle", "goggle", "googie", "gogle",
    "micros0ft", "rnicrosoft", "microsofl", "micrsoft", "micorsoft",
    "paypa1", "paypall", "paypaI", "payp4l", "paipal",
    "app1e", "appie", "aple", "appel",
    "netfIix", "netflixx", "netfilx", "netf1ix",
    "1inkedin", "linkedln", "linkdin",
    "whatsaap", "whatsap", "vvhatsapp",
    "1nstagram", "instagrarn", "instgram",
    "0utlook", "outIook", "outlok",
    "dr0pbox", "dropb0x", "droqbox",
    "c0inbase", "coinbasse", "binnance", "binanc3",
    "sbii", "sb1", "hdfcbnk", "hdfc-bank-in", "1cici", "icic1",
    "irctc-in", "1rctc", "paytrn", "payt m".replace(" ", ""),
]

HIGH_RISK_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".icu", ".buzz",
    ".club", ".online", ".site", ".shop", ".live", ".cam", ".pw", ".cyou",
    ".work", ".monster", ".rest",
]

NORMAL_TLDS = [".com", ".net", ".org", ".info", ".biz", ".co", ".io"]

# Real-world TLD mix for phishing.
#
# Roughly half of live phishing sites sit on ordinary .com/.net domains
# (often legitimate sites that were compromised), NOT on exotic free TLDs.
# Drawing every phishing row from the high-risk list would make ".tk means
# phishing" a perfect rule and hand the model a shortcut that does not exist
# in reality - the metrics would look great and mean nothing.
PHISH_TLD_NORMAL_SHARE = 0.50


def _phish_tld(rng: random.Random) -> str:
    """Pick a TLD for a phishing URL with a realistic high-risk/normal mix."""
    if rng.random() < PHISH_TLD_NORMAL_SHARE:
        return rng.choice(NORMAL_TLDS)
    return rng.choice(HIGH_RISK_TLDS)


PHISH_KEYWORDS = [
    "verify", "secure", "login", "signin", "update", "confirm", "account",
    "security", "authenticate", "validation", "recovery", "unlock",
    "suspended", "locked", "alert", "billing", "payment", "invoice",
    "webscr", "wallet", "support", "helpdesk", "service",
]

PHISH_PATHS = [
    "/login", "/signin", "/verify", "/account/verify", "/secure/login",
    "/update/billing", "/confirm-identity", "/account-suspended",
    "/security-alert", "/unlock-account", "/webscr", "/cgi-bin/webscr",
    "/wallet/restore", "/verify-your-account-now", "/session/expired/relogin",
    "/customer/verify/identity/document-upload",
    "/signin/password/recovery/step2", "/auth/verify/otp",
]

SHORTENER_LOOKALIKES = [
    "bit-ly.tk", "bitly-link.xyz", "tinyurl-go.top", "t-co.icu",
    "goo-gl.ml", "cutt-ly.buzz", "short-url.cf", "rebrand-ly.ga",
    "is-gd.online", "tiny-cc.site",
]

DGA_CONSONANTS = "bcdfghjklmnpqrstvwxz"
DGA_VOWELS = "aeiouy"


def _rand_hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _dga_host(rng: random.Random, min_len: int = 12, max_len: int = 26) -> str:
    """A random-looking domain label, the kind a DGA produces."""
    length = rng.randint(min_len, max_len)
    chars = []
    for i in range(length):
        pool = DGA_CONSONANTS if i % 2 == 0 else DGA_VOWELS
        # Only occasionally - real DGA domains are often pure letters,
        # and over-injecting digits turns num_digits_host into a
        # give-away feature that would not generalise.
        if rng.random() < 0.08:
            pool = "0123456789"
        chars.append(rng.choice(pool))
    return "".join(chars)


def _random_ip(rng: random.Random) -> str:
    """An IP outside the reserved ranges, so it looks like a real host."""
    return "{}.{}.{}.{}".format(
        rng.choice([31, 45, 51, 77, 91, 103, 118, 141, 176, 185, 193, 209]),
        rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254),
    )


# ---------------------------------------------------------------------------
# 3. Benign generators
# ---------------------------------------------------------------------------


# Share of benign URLs that are a bare homepage ("https://google.com").
#
# This number matters more than it looks. The hard-phishing generator emits
# short, path-less URLs such as "https://paypa1.com/", so if almost every
# benign row carried a path the model would quietly learn "no path => phishing"
# and then flag google.com. Homepage URLs are in fact the single most common
# shape of a legitimate link, so a healthy share of them here is both realistic
# and the thing that keeps that bias out of the model.
BENIGN_BARE_DOMAIN_SHARE = 0.32

# Real sites use "www." constantly. The typosquat generator prefixes "www."
# to a share of its output, so without the same habit on the benign side the
# model would learn "www. => phishing" - the same class of artifact as the
# bare-domain one above.
BENIGN_WWW_SHARE = 0.28


def _maybe_www(rng: random.Random, domain: str) -> str:
    """Prepend 'www.' to a plain two-label domain some of the time."""
    if domain.count(".") == 1 and not domain.startswith("www.") and rng.random() < BENIGN_WWW_SHARE:
        return "www." + domain
    return domain



def gen_benign_easy(rng: random.Random) -> str:
    """An ordinary, obviously legitimate URL."""
    domain = _maybe_www(rng, rng.choice(BENIGN_DOMAINS))
    scheme = "https" if rng.random() < 0.93 else "http"

    if rng.random() < BENIGN_BARE_DOMAIN_SHARE:
        # A plain homepage link, with or without the trailing slash.
        return f"{scheme}://{domain}{rng.choice(['', '/'])}"

    path = rng.choice(BENIGN_PATHS)
    query = rng.choice(BENIGN_QUERIES)
    return f"{scheme}://{domain}{path}{query}"


def gen_benign_hard(rng: random.Random) -> str:
    """
    A legitimate URL that LOOKS suspicious.

    Real banks put 'secure' and 'login' in their paths, real shops build long
    tracking query strings, real sites use hyphenated subdomains. Without these
    rows the model would learn "the word login means phishing", which is wrong.
    """
    domain = _maybe_www(rng, rng.choice(BENIGN_DOMAINS))
    # Weighted so ~65% of hard-benign rows actually carry a credential keyword
    # (styles 0 and 2). Those are the rows that teach the model "the word
    # 'login' on sbi.co.in is normal" - without enough of them the keyword
    # feature dominates and real bank login pages get flagged.
    style = rng.choice([0, 0, 0, 1, 2, 2, 2, 3, 4])

    if style == 0:
        return f"https://{domain}{rng.choice(HARD_BENIGN_PATHS)}"

    if style == 1:
        # A long but genuine tracking URL.
        return (
            f"https://{domain}/products/item/{rng.randint(100000, 999999)}"
            f"?utm_source=newsletter&utm_medium=email&utm_campaign=summer-sale-2024"
            f"&utm_content=hero-banner&session={_rand_hex(rng, 24)}"
        )

    if style == 2:
        # A legitimate hyphenated subdomain, e.g. secure-payments.example.com
        prefix = rng.choice(
            ["secure", "login", "account", "my", "portal", "online-banking",
             "secure-payments", "id", "auth", "support"]
        )
        return f"https://{prefix}.{domain}{rng.choice(HARD_BENIGN_PATHS)}"

    if style == 3:
        # Deep but genuine documentation path.
        parts = rng.choice(
            [
                "/docs/en/latest/user-guide/configuration/advanced-settings",
                "/help/en-in/article/how-do-i-reset-my-password-securely",
                "/support/kb/000123/account-verification-process-explained",
                "/en-in/personal/accounts/savings-account/apply-online",
            ]
        )
        return f"https://{domain}{parts}"

    # Legitimate but plain HTTP (older institutional sites really do this).
    return f"http://{domain}{rng.choice(BENIGN_PATHS)}"


# ---------------------------------------------------------------------------
# 4. Phishing generators - one function per real-world pattern
# ---------------------------------------------------------------------------


def gen_phish_brand_subdomain(rng: random.Random) -> str:
    """paypal.secure-login.xyz - the brand sits in a subdomain of attacker land."""
    brand = rng.choice(PHISH_BRANDS)
    kw = rng.choice(PHISH_KEYWORDS)
    tld = _phish_tld(rng)
    attacker = rng.choice(
        [f"{kw}-{rng.choice(PHISH_KEYWORDS)}", f"{kw}{rng.randint(10, 999)}",
         _dga_host(rng, 8, 14), f"{kw}-portal"]
    )
    scheme = rng.choice(["http", "https"])
    return f"{scheme}://{brand}.{attacker}{tld}{rng.choice(PHISH_PATHS)}"


def gen_phish_brand_domain(rng: random.Random) -> str:
    """paypal-secure-verify.tk - brand glued into the registrable domain."""
    brand = rng.choice(PHISH_BRANDS)
    kw = rng.choice(PHISH_KEYWORDS)
    tld = _phish_tld(rng)
    joiner = rng.choice(["-", "-", "-", ""])
    return (
        f"{rng.choice(['http', 'https'])}://{brand}{joiner}{kw}"
        f"{rng.choice(['', '-' + rng.choice(PHISH_KEYWORDS), str(rng.randint(1, 99))])}"
        f"{tld}{rng.choice(PHISH_PATHS)}"
    )


def gen_phish_brand_path(rng: random.Random) -> str:
    """random-host.top/paypal/login - brand hidden in the path."""
    brand = rng.choice(PHISH_BRANDS)
    host = _dga_host(rng, 8, 16)
    tld = _phish_tld(rng)
    return (
        f"{rng.choice(['http', 'https'])}://{host}{tld}/{brand}"
        f"/{rng.choice(PHISH_KEYWORDS)}/{rng.choice(['index.php', 'login.html', 'verify.php', ''])}"
    )


def gen_phish_typosquat(rng: random.Random) -> str:
    """arnazon.com / faceb00k.net - one character off the real brand."""
    typo = rng.choice(TYPOSQUATS)
    tld = _phish_tld(rng)
    path = rng.choice(PHISH_PATHS + ["/", "", "/index.html"])
    return f"{rng.choice(['http', 'https'])}://{rng.choice(['', 'www.', 'secure.', 'login.'])}{typo}{tld}{path}"


def gen_phish_ip_host(rng: random.Random) -> str:
    """http://185.23.44.9/paypal/login - raw IP, no domain at all."""
    ip = _random_ip(rng)
    port = rng.choice(["", "", "", ":8080", ":8443", ":3000"])
    brand = rng.choice(PHISH_BRANDS)
    return f"http://{ip}{port}/{brand}/{rng.choice(PHISH_KEYWORDS)}/index.php"


def gen_phish_dga(rng: random.Random) -> str:
    """A long random host - typical of automatically registered phishing farms."""
    host = _dga_host(rng, 16, 28)
    tld = _phish_tld(rng)
    sub = rng.choice(["", "", f"{_dga_host(rng, 5, 9)}."])
    return f"http://{sub}{host}{tld}/{rng.choice(PHISH_KEYWORDS)}"


def gen_phish_punycode(rng: random.Random) -> str:
    """xn--pypal-4ve.com - IDN homograph attack encoded as punycode."""
    fake = rng.choice(
        ["xn--pypal-4ve", "xn--gogle-jua", "xn--microsft-h3a", "xn--aple-0qa",
         "xn--amazn-yqa", "xn--netflx-vxa", "xn--facebok-6ib", "xn--sb-i4a"]
    )
    tld = _phish_tld(rng)
    return f"https://{fake}{tld}{rng.choice(PHISH_PATHS)}"


def gen_phish_at_symbol(rng: random.Random) -> str:
    """https://google.com@evil.tk/ - the browser goes to evil.tk."""
    brand = rng.choice(PHISH_BRANDS)
    host = _dga_host(rng, 6, 12)
    tld = _phish_tld(rng)
    return f"http://{brand}.com@{host}{tld}{rng.choice(PHISH_PATHS)}"


def gen_phish_encoded(rng: random.Random) -> str:
    """Heavy percent-encoding used to hide the real path from a quick glance."""
    brand = rng.choice(PHISH_BRANDS)
    host = _dga_host(rng, 7, 14)
    tld = _phish_tld(rng)
    encoded = "".join(f"%{rng.choice('0123456789abcdef')}{rng.choice('0123456789abcdef')}"
                      for _ in range(rng.randint(9, 18)))
    return f"http://{host}{tld}/{brand}{encoded}/{rng.choice(PHISH_KEYWORDS)}"


def gen_phish_deep_subdomain(rng: random.Random) -> str:
    """a.b.c.d.evil.tk - deep nesting buries the real domain off-screen."""
    brand = rng.choice(PHISH_BRANDS)
    levels = [brand] + [rng.choice(PHISH_KEYWORDS) for _ in range(rng.randint(3, 5))]
    host = _dga_host(rng, 6, 12)
    tld = _phish_tld(rng)
    return f"http://{'.'.join(levels)}.{host}{tld}{rng.choice(PHISH_PATHS)}"


def gen_phish_shortener_lookalike(rng: random.Random) -> str:
    """bit-ly.tk/xY7q - pretends to be a URL shortener."""
    host = rng.choice(SHORTENER_LOOKALIKES)
    code = "".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                   for _ in range(rng.randint(5, 9)))
    return f"http://{host}/{code}"


def gen_phish_long_url(rng: random.Random) -> str:
    """A very long URL that pushes the real domain out of the address bar."""
    brand = rng.choice(PHISH_BRANDS)
    host = _dga_host(rng, 10, 18)
    tld = _phish_tld(rng)
    filler = "/".join(rng.choice(PHISH_KEYWORDS) for _ in range(rng.randint(5, 9)))
    token = _rand_hex(rng, rng.randint(32, 64))
    return (
        f"http://{brand}.{host}{tld}/{filler}"
        f"?session={token}&redirect=https%3A%2F%2F{brand}.com%2Faccount"
        f"&email=victim%40example.com&ref={_rand_hex(rng, 16)}"
    )


def gen_phish_hard(rng: random.Random) -> str:
    """
    A SHORT, CLEAN phishing URL.

    https://paypa1.com/ has no keywords, no weird TLD, no length anomaly - the
    only signal is the typosquatted domain. These rows stop the model from
    relying purely on "long and ugly = bad".
    """
    style = rng.randint(0, 3)
    if style == 0:
        return f"https://{rng.choice(TYPOSQUATS)}{rng.choice(NORMAL_TLDS)}/"
    if style == 1:
        return f"https://www.{rng.choice(TYPOSQUATS)}.com"
    if style == 2:
        brand = rng.choice(PHISH_BRANDS)
        return f"https://{brand}-{rng.choice(['id', 'my', 'go', 'app'])}.com/"
    return f"https://{_dga_host(rng, 6, 9)}{rng.choice(NORMAL_TLDS)}/{rng.choice(['home', 'start', 'go', 'p'])}"


PHISH_GENERATORS = [
    (gen_phish_brand_subdomain, 14),
    (gen_phish_brand_domain, 14),
    (gen_phish_brand_path, 9),
    (gen_phish_typosquat, 13),
    (gen_phish_ip_host, 9),
    (gen_phish_dga, 9),
    (gen_phish_punycode, 6),
    (gen_phish_at_symbol, 6),
    (gen_phish_encoded, 6),
    (gen_phish_deep_subdomain, 7),
    (gen_phish_shortener_lookalike, 4),
    (gen_phish_long_url, 8),
]


def generate(target_rows: int = TARGET_ROWS, seed: int = SEED) -> list[tuple[str, int]]:
    """Build the full labelled row list, de-duplicated and shuffled."""
    rng = random.Random(seed)
    per_class = target_rows // 2
    hard_count = int(per_class * HARD_FRACTION)

    seen: set[str] = set()
    rows: list[tuple[str, int]] = []

    def add(url: str, label: int) -> bool:
        key = url.lower()
        if key in seen:
            return False
        seen.add(key)
        rows.append((url, label))
        return True

    # --- benign ---
    generated = 0
    attempts = 0
    while generated < per_class - hard_count and attempts < per_class * 60:
        attempts += 1
        if add(gen_benign_easy(rng), 0):
            generated += 1

    generated = 0
    attempts = 0
    while generated < hard_count and attempts < hard_count * 60:
        attempts += 1
        if add(gen_benign_hard(rng), 0):
            generated += 1

    # --- phishing ---
    weighted: list = []
    for func, weight in PHISH_GENERATORS:
        weighted.extend([func] * weight)

    generated = 0
    attempts = 0
    while generated < per_class - hard_count and attempts < per_class * 60:
        attempts += 1
        if add(rng.choice(weighted)(rng), 1):
            generated += 1

    generated = 0
    attempts = 0
    while generated < hard_count and attempts < hard_count * 60:
        attempts += 1
        if add(gen_phish_hard(rng), 1):
            generated += 1

    rng.shuffle(rows)
    return rows


def write_dataset(path: Path = DATASET_PATH, target_rows: int = TARGET_ROWS,
                  seed: int = SEED) -> tuple[int, int]:
    """Generate and write dataset.csv. Returns (benign_count, phishing_count)."""
    rows = generate(target_rows, seed)
    path.parent.mkdir(parents=True, exist_ok=True)

    # newline="" is required by the csv module; utf-8 keeps Windows happy.
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "label"])
        writer.writerows(rows)

    benign = sum(1 for _, label in rows if label == 0)
    phishing = sum(1 for _, label in rows if label == 1)
    return benign, phishing


def main() -> None:
    print("=" * 62)
    print("  LTAT  -  Dataset generator")
    print("=" * 62)

    benign, phishing = write_dataset()
    total = benign + phishing
    balance = (min(benign, phishing) / max(benign, phishing) * 100) if total else 0

    print(f"\n  Output file : {DATASET_PATH}")
    print(f"  Total rows  : {total}")
    print(f"  label=0 (benign)   : {benign:>5}  ({benign / total * 100:.1f}%)")
    print(f"  label=1 (phishing) : {phishing:>5}  ({phishing / total * 100:.1f}%)")
    print(f"  Class balance      : {balance:.1f}%  (100% = perfectly balanced)")
    print(f"  Hard/ambiguous rows: ~{HARD_FRACTION * 100:.0f}% per class, by design")
    print("\n  Next step:  python -m app.ml.train")
    print("=" * 62)


if __name__ == "__main__":
    main()
