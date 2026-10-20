"""Built-in user advice for suspicious URL classifications."""

ADVICE = {
    "benign": {
        "meaning": "The available model considers this URL more likely benign. This is not proof that the site is safe.",
        "now": ["Check the hostname spelling before entering information.", "Use a bookmark or type the official address yourself."],
        "never": ["Do not treat a SAFE result as a guarantee.", "Do not enter payment or login details if anything seems unexpected."],
    },
    "phishing": {
        "meaning": "The model found patterns associated with attempts to steal passwords, payment information, or identity details.",
        "now": ["Do not sign in or submit personal or payment information.", "Open the organization’s official app or type its known address directly.", "Report the message or link to the organization."],
        "never": ["Do not approve unexpected sign-in prompts or one-time codes.", "Do not reply to the sender or download attachments from the message."],
    },
    "malware": {
        "meaning": "The model associates this URL with malware-related URL patterns; this scan did not open or inspect its content.",
        "now": ["Do not download or run files from this URL.", "If you already downloaded a file, do not open it; remove it and run a reputable security scan."],
        "never": ["Do not disable device security to install a file.", "Do not reuse passwords on a device you suspect is compromised."],
    },
    "defacement": {
        "meaning": "The model associates this URL with defacement patterns, where a site may have been altered without authorization.",
        "now": ["Avoid interacting with the page or entering information.", "Contact the site owner through a separately verified channel."],
        "never": ["Do not assume a familiar domain means its current page is trustworthy.", "Do not follow instructions to install tools or send money."],
    },
}

RECOVERY_STEPS = [
    "Close the page. If you entered a password, change it immediately from the official website or app, using a trusted device.",
    "Change the same password anywhere else you reused it; use unique passwords.",
    "Enable two-factor authentication and revoke unfamiliar active sessions or connected apps.",
    "If you entered bank or card details, contact your bank using the number on your card or official app and ask them to secure the account.",
    "Run an updated security scan. Remove suspicious downloads without opening them.",
    "Report the link to the service it impersonates and to your local cybercrime authority.",
]
