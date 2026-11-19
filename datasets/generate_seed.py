"""Generate a SYNTHETIC seed dataset so the pipeline runs end to end offline.

WARNING: this data is template-generated. It is NOT real phishing telemetry.
Metrics measured on it demonstrate that the pipeline works; they say nothing
reliable about real-world accuracy. Replace datasets/messages.csv and
datasets/urls.csv with properly sourced, licence-checked data for research use
(see README, "Using real datasets").

Output columns
  messages.csv: text,label,group   (label 1 = phishing, 0 = legitimate;
                                     group = template id, used for group splits)
  urls.csv:     url,label,group    (group = registered domain)
"""
import csv
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from detector import parse_url  # noqa: E402  (reuse the same URL parser)

BRANDS = ["PayPal", "Amazon", "Microsoft", "Netflix", "Apple", "HDFC Bank", "SBI", "Paytm",
          "Google", "Facebook", "DHL", "FedEx", "Chase", "Wells Fargo", "Instagram", "LinkedIn"]
NAMES = ["Priya", "Rahul", "Anita", "John", "Sarah", "Amit", "Neha", "David", "Kavita", "Mark"]
CITIES = ["Mumbai", "London", "Singapore", "Toronto", "Dubai", "Berlin"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
TIMES = ["9:30 AM", "11:00 AM", "1:15 PM", "3:00 PM", "6:45 PM"]
AMOUNTS = ["$250", "$1,200", "Rs. 4,999", "$89.99", "Rs. 15,000", "$3,400"]
SMALL = ["$1.99", "Rs. 25", "$2.50", "Rs. 49"]

PHISH = [
    "Dear customer, your {brand} account has been suspended due to unusual activity. Verify your identity immediately at {url} to restore access.",
    "{brand} Security Alert: We detected an unauthorized login to your account. Confirm your password within {hours} hours at {url} or your account will be locked.",
    "Congratulations! You have won a {amount} {brand} gift card. Claim your reward now: {url}",
    "Your package could not be delivered because the address is incomplete. Update your delivery details and pay a small fee of {small} at {url}",
    "Final notice: your {brand} payment of {amount} failed. Update your billing information today to avoid service termination. {url}",
    "Action required: your mailbox storage is full. Sign in at {url} to keep receiving email, otherwise your messages will be deleted.",
    "Hello, this is the {brand} fraud department. A payment of {amount} was attempted from your card. If this was not you, reply with your card number and OTP to cancel it.",
    "Your KYC has expired. Update your PAN and Aadhaar details now or your {brand} account will be blocked today. Click {url}",
    "You have received a secure document from {name}. Log in with your email password to view it: {url}",
    "Tax notice: you are eligible for a refund of {amount}. Submit your bank details at {url} within {hours} hours to receive payment.",
    "URGENT: Your {brand} subscription has expired. Renew now to avoid losing access and enter your payment details here {url}",
    "Hi, it's your CEO {name}. I need you to purchase {amount} in gift cards right away and send me the codes. Keep this confidential.",
    "We noticed a sign-in from a new device. If this was not you, secure your {brand} account immediately: {url}",
    "Your account will be deactivated in {hours} hours unless you confirm your details. Click here to verify: {url}",
    "Invoice {inv} is overdue. Open the attached file and enable macros to view the payment details. Pay immediately to avoid legal action.",
    "Dear user, your {brand} password expires today. Click {url} to keep your current password.",
    "Job offer: earn {amount} per week working from home. No experience needed. Send your bank details and ID to {url} to get started.",
    "{brand}: Your account is limited. To restore full access, confirm your identity and update your payment method at {url}",
    "Customs fee pending for your parcel. Pay {small} now at {url} or the shipment will be returned to sender.",
    "Dear {brand} member, claim your exclusive refund of {amount}. Offer expires in {hours} hours. Verify your bank account at {url}",
    "Your electricity bill is overdue and your power will be disconnected tonight. Pay immediately at {url} to avoid disconnection.",
    "Security notice: someone tried to reset your {brand} password. To cancel the request, verify your account now: {url}",
    "You are selected for a government grant of {amount}. Pay the processing fee and share your account number to receive funds.",
    "Re: wire transfer. Please update the beneficiary bank details on the attached invoice and process the payment today. Do not call, I am in a meeting.",
    "Your {brand} wallet has been frozen. Complete the verification at {url} within {hours} hours to unlock it.",
    "Verify your email address to avoid account closure. Failure to respond within {hours} hours will result in permanent suspension. {url}",
    "Crypto alert: we detected suspicious withdrawals on your wallet. Enter your recovery phrase at {url} to secure your funds.",
    "Dear customer your SIM will be blocked in {hours} hours. Update your KYC immediately by clicking {url}",
]

LEGIT = [
    "Hi {name}, are we still on for lunch tomorrow at {time}? Let me know if you want to change the place.",
    "Your {brand} verification code is {code}. Do not share this code with anyone. It expires in 10 minutes.",
    "Reminder: team meeting on {day} at {time} in the main conference room. Please bring your project updates.",
    "Thanks for your order! Your {brand} package has shipped and should arrive by {day}. You can track it from the orders page in the app.",
    "Hi {name}, attached is the report we discussed. Let me know if you have any questions before the review on {day}.",
    "Your monthly statement is now available. You can view it any time by signing in to the official app.",
    "Happy birthday {name}! Hope you have a wonderful day, let's catch up this weekend.",
    "The quarterly budget review has been moved to {day}. Please update your calendar.",
    "Your appointment with Dr. {name} is confirmed for {day} at {time}. Reply C to confirm or call the clinic to reschedule.",
    "Payment of {amount} received. Thank you for your purchase. A receipt has been sent to your email.",
    "Can you pick up some groceries on your way home? We need milk, eggs and bread.",
    "Your {brand} order has been delivered. Rate your experience in the app.",
    "Hi team, the deployment finished successfully. Please review the release notes and report any issues in the channel.",
    "Mom, I reached home safely. Will call you after dinner.",
    "Your flight to {city} departs on {day} at {time}. Check-in opens 24 hours before departure.",
    "Class notes for {day} are uploaded to the shared drive. The assignment is due next week.",
    "Your password was changed successfully. If you did this, no action is needed.",
    "Newsletter: this week's top articles on productivity, design and technology are now live on our blog.",
    "Hello {name}, thank you for contacting support. Your ticket {inv} has been received and we will reply within two business days.",
    "Your EMI of {amount} has been debited from your account. The available balance is shown in the mobile banking app.",
    "Invoice {inv} for {amount} is attached for your records. Payment is due at the end of the month as agreed in the contract.",
    "Don't forget the school parents meeting on {day} at {time}.",
    "Hi {name}, I reviewed your pull request and left a few comments. Looks good overall, just fix the failing test.",
    "Security tip: never share your OTP or password with anyone, including bank staff. We will never ask for it.",
    "Your library book is due on {day}. You can renew it online or at the front desk.",
    "Congratulations on your new job {name}! Let's celebrate this weekend.",
    "Your cab is arriving in 3 minutes. Driver {name} will meet you at the pickup point.",
    "Sale this weekend: {pct} off on selected items in store. Visit us between {time} and closing.",
    "Your {brand} account was accessed from a new device. If this was you, ignore this message. Otherwise review activity in the official app settings.",
    "Meeting notes: we agreed to ship the beta on {day}. Action items have been shared in the project tracker.",
    "Your refund of {amount} for order {inv} has been processed and will appear in 5-7 business days.",
    "Urgent: server maintenance tonight at {time}. Please save your work before then.",
    "Hey {name}, dinner at my place on {day}? I am making pasta.",
    "Your {brand} subscription renews on {day}. No action is needed; manage it any time in your account settings.",
]

WORDS = ["blue", "fern", "maple", "river", "stone", "bright", "green", "north", "harbor", "cedar", "lotus",
         "pixel", "orbit", "swift", "amber", "coral", "delta", "ember", "forge", "grove", "haven", "iris",
         "jade", "lumen", "mesa", "nova", "oak", "pine", "quartz", "ridge", "solar", "tidal", "urban", "vivid"]
NOUNS = ["bakery", "studio", "travel", "tech", "books", "cafe", "fitness", "design", "garden", "clinic",
         "photo", "music", "legal", "events", "foods", "media", "labs", "works"]
KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm", "signin", "billing", "wallet",
            "support", "unlock", "validate", "payment", "recover"]
BRAND_TOKENS = ["paypal", "amazon", "microsoft", "netflix", "apple", "google", "facebook", "paytm", "hdfc",
                "dhl", "fedex", "chase", "instagram", "linkedin", "icloud", "office365"]
BAD_TLDS = ["xyz", "top", "click", "buzz", "tk", "ml", "ga", "cf", "gq", "icu", "rest", "work", "live", "support"]
GOOD_TLDS = ["com", "org", "net", "in", "io", "co.uk", "edu", "com.au", "co.in"]

KNOWN_BENIGN = [
    ("wikipedia.org", ["en", "www"]), ("github.com", ["www", "docs", "gist"]), ("python.org", ["www", "docs"]),
    ("bbc.co.uk", ["www"]), ("nytimes.com", ["www"]), ("amazon.com", ["www", "smile"]),
    ("google.com", ["www", "accounts", "mail", "drive"]), ("microsoft.com", ["www", "support", "learn"]),
    ("paypal.com", ["www"]), ("apple.com", ["www", "support"]), ("stackoverflow.com", ["www"]),
    ("mozilla.org", ["www", "developer"]), ("linkedin.com", ["www"]), ("facebook.com", ["www"]),
    ("netflix.com", ["www", "help"]), ("dropbox.com", ["www"]), ("reddit.com", ["www"]),
    ("youtube.com", ["www"]), ("twitter.com", ["www"]), ("cloudflare.com", ["www", "dash"]),
    ("hdfcbank.com", ["www", "netbanking"]), ("sbi.co.in", ["www", "retail"]), ("irs.gov", ["www"]),
    ("nasa.gov", ["www"]), ("mit.edu", ["www", "web"]), ("khanacademy.org", ["www"]),
    ("spotify.com", ["open", "www"]), ("adobe.com", ["www", "helpx"]), ("fedex.com", ["www"]),
    ("dhl.com", ["www"]), ("zoom.us", ["www"]), ("slack.com", ["www", "app"]), ("medium.com", ["www"]),
    ("ebay.com", ["www"]), ("walmart.com", ["www"]), ("who.int", ["www"]), ("harvard.edu", ["www"]),
]
BENIGN_PATHS = ["/", "/about", "/docs/getting-started", "/search?q=weather", "/login", "/account/signin",
                "/products/1234", "/wiki/Cat", "/help/contact-us", "/blog/2024/release-notes", "/pricing",
                "/downloads/index.html", "/support/article/4421", "/blog/apple-pie-recipe", "/secure/account",
                "/shop/item?id=88123&ref=home&utm_source=mail&utm_campaign=spring", "/verify-email?token=ab12cd34ef56",
                "/wp-content/uploads/2024/05/report.pdf", "/index.php?page=contact", "/account/update-profile",
                "/payment/receipt/883712", "/s/ab12cd34/files"]


def fill_msg(template, rng, phishing):
    brand = rng.choice(BRANDS)
    token = rng.choice(BRAND_TOKENS)
    if phishing:
        url = rng.choice([
            f"http://{token}-{rng.choice(KEYWORDS)}.{rng.choice(BAD_TLDS)}/{rng.choice(KEYWORDS)}",
            f"http://{rng.choice(WORDS)}{rng.choice(WORDS)}.{rng.choice(BAD_TLDS)}/{rng.choice(KEYWORDS)}.php",
            f"https://{token}.{rng.choice(KEYWORDS)}-{rng.choice(WORDS)}.com/auth",
            "bit.ly/" + "".join(rng.choices("abcdefghjkmnpqrstuvwxyz23456789", k=7)),
        ])
    else:
        url = "https://www." + rng.choice(WORDS) + rng.choice(NOUNS) + ".com"
    return template.format(
        brand=brand, url=url, amount=rng.choice(AMOUNTS), small=rng.choice(SMALL),
        hours=rng.choice([2, 6, 12, 24, 48]), name=rng.choice(NAMES), inv=f"INV-{rng.randint(1000, 9999)}",
        time=rng.choice(TIMES), day=rng.choice(DAYS), city=rng.choice(CITIES), code=rng.randint(100000, 999999),
        pct=f"{rng.choice([10, 20, 30, 50])}%")


def make_messages(rng, per_template=14):
    rows = []
    for label, templates in ((1, PHISH), (0, LEGIT)):
        for i, t in enumerate(templates):
            gid = f"{'P' if label else 'L'}{i:02d}"
            seen = set()
            for _ in range(per_template * 3):
                text = fill_msg(t, rng, bool(label))
                if text not in seen:
                    seen.add(text)
                    rows.append((text, label, gid))
                if len(seen) >= per_template:
                    break
    return rows


def rand_host_words(rng, hyphen=False):
    a, b = rng.choice(WORDS), rng.choice(NOUNS if rng.random() < 0.6 else WORDS)
    return f"{a}-{b}" if hyphen else f"{a}{b}"


def typo(brand, rng):
    ops = [lambda s: s.replace("o", "0", 1), lambda s: s.replace("l", "1", 1), lambda s: s.replace("a", "4", 1),
           lambda s: s + s[-1], lambda s: s[:2] + s[3:], lambda s: s.replace("m", "rn", 1)]
    for _ in range(10):
        out = rng.choice(ops)(brand)
        if out != brand:
            return out
    return brand + "x"


def benign_url(rng):
    r = rng.random()
    if r < 0.45:
        dom, subs = rng.choice(KNOWN_BENIGN)
        host = f"{rng.choice(subs)}.{dom}" if rng.random() < 0.8 else dom
        return f"https://{host}{rng.choice(BENIGN_PATHS)}"
    if r < 0.92:
        host = rand_host_words(rng, hyphen=rng.random() < 0.15) + "." + rng.choice(GOOD_TLDS)
        if rng.random() < 0.6:
            host = "www." + host
        scheme = "https" if rng.random() < 0.88 else "http"
        return f"{scheme}://{host}{rng.choice(BENIGN_PATHS)}"
    return rng.choice(["https://bit.ly/", "https://t.co/", "https://tinyurl.com/"]) + "".join(
        rng.choices("abcdefghjkmnpqrstuvwxyz23456789", k=7))


def phishing_url(rng):
    host_kw, brand = rng.choice(KEYWORDS), rng.choice(BRAND_TOKENS)
    hexs = "".join(rng.choices("0123456789abcdef", k=12))
    kw = host_kw if rng.random() > 0.35 else rng.choice(["index.html", "a", "view", "doc", "files", "r" + hexs[:4], ""])
    kind = rng.randrange(10)
    if kind == 0:
        return f"http://{brand}.{rand_host_words(rng, True)}.{rng.choice(BAD_TLDS)}/{kw}"
    if kind == 1:
        return f"http://{brand}-{kw}.{rng.choice(BAD_TLDS + ['com', 'net'])}/login.php?id={hexs}"
    if kind == 2:
        ip = ".".join(str(rng.randint(2, 250)) for _ in range(4))
        return f"http://{ip}/{brand}/{kw}.html"
    if kind == 3:
        return f"https://{typo(brand, rng)}.{rng.choice(['com', 'net', 'co', 'in'])}/{kw}"
    if kind == 4:
        return f"https://secure.{brand}.com.{rand_host_words(rng)}.{rng.choice(BAD_TLDS)}/{kw}"
    if kind == 5:
        tail = f"{rand_host_words(rng)}.{rng.choice(BAD_TLDS)}"
        return f"http://{brand}.com@{tail}/{kw}"
    if kind == 6:
        return f"http://xn--{rng.choice(WORDS)}-{brand}.com/{kw}"
    if kind == 7:
        return (f"https://{rand_host_words(rng)}.{rng.choice(GOOD_TLDS[:4] + BAD_TLDS)}/{brand}/{kw}/"
                f"index.php?session={hexs}&redirect={hexs[::-1]}")
    if kind == 8:
        return f"http://{host_kw}-{brand}-{rng.choice(WORDS)}.{rng.choice(BAD_TLDS)}/"
    return f"https://{rand_host_words(rng, True)}.{rng.choice(['com', 'org', 'net'])}/wp-content/{kw}/{brand}.php"


def make_urls(rng, n_each=700):
    rows, seen = [], set()
    for label, gen in ((0, benign_url), (1, phishing_url)):
        count = 0
        while count < n_each:
            u = gen(rng)
            if u in seen:
                continue
            seen.add(u)
            group = parse_url(u)["reg"]
            rows.append((u, label, group))
            count += 1
    return rows


def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def main(seed=1337):
    rng = random.Random(seed)
    msgs = make_messages(rng)
    urls = make_urls(rng)
    write_csv(HERE / "messages.csv", ["text", "label", "group"], msgs)
    write_csv(HERE / "urls.csv", ["url", "label", "group"], urls)
    (HERE / "SYNTHETIC_DATA.txt").write_text(
        "messages.csv and urls.csv in this folder were generated by generate_seed.py (template-based, synthetic).\n"
        "They are NOT real phishing data. Delete this file when you replace them with real, licence-checked data.\n")
    print(f"Wrote {len(msgs)} synthetic messages and {len(urls)} synthetic URLs to {HERE}")


if __name__ == "__main__":
    main()
