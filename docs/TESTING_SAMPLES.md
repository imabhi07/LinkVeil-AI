# PhishGuard Forensic Testing Samples

This document contains a curated list of raw email samples and malicious URL patterns designed to test the PhishGuard forensic engine. Each sample is mapped to a specific attack vector to validate the "How They Attacked" analytics.

---

## 1. Raw Email Samples (.eml)

### Sample A: Credential Harvesting (The "Fake Login" Trap)
*   **Vector**: Credential Harvesting / Link Obfuscation
*   **Trigger**: High-risk keywords ("suspended", "verify"), unknown sender domain, and lookalike link.

```text
From: Microsoft Security <no-reply@secure-login-verify.com>
Subject: Action Required: Your account will be suspended in 24 hours
Content-Type: text/html

<html>
<body>
  <p>Dear User,</p>
  <p>We detected an unusual login attempt on your Microsoft account from a new location (Moscow, RU).</p>
  <p>To prevent unauthorized access, your account has been temporarily locked. You must verify your identity immediately to restore access.</p>
  <a href="https://msft-auth-portal-secure.xyz/login" style="background: #0078d4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify My Account Now</a>
  <p>If you do not verify within 24 hours, your account will be permanently deactivated for security reasons.</p>
</body>
</html>
```

### Sample B: Financial Pressure (The "Fake Invoice" Scam)
*   **Vector**: Urgency / Financial Lure
*   **Trigger**: Financial keywords ("overdue", "invoice", "payment"), large dollar amounts, and time-sensitive threats.

```text
From: Quickbooks Billing <invoices@qb-office-payments.net>
Subject: OVERDUE: Invoice #INV-882741 is 15 days late
Content-Type: text/html

<html>
<body>
  <div style="font-family: sans-serif; border: 1px solid #ddd; padding: 20px;">
    <h2>Payment Overdue Notice</h2>
    <p>Your subscription for <b>Business Suite Pro</b> has remained unpaid for 15 days.</p>
    <p><b>Amount Due:</b> $1,249.00 USD</p>
    <p>A late fee of $50.00 will be added every 48 hours until payment is received.</p>
    <p>Please review the attached invoice and pay immediately to avoid service interruption.</p>
    <a href="https://billing-portal-direct.com/pay/INV-882741" style="color: blue; text-decoration: underline;">View Invoice and Pay Online</a>
  </div>
</body>
</html>
```

### Sample C: Technical Obfuscation (The "Base64 Bypass")
*   **Vector**: Technical Evasion / Malicious Redirect
*   **Trigger**: Encoded content-transfer, obfuscated payload, and suspicious redirection paths.

```text
From: HR Department <hr-policy@internal-updates.cc>
Subject: 2026 Updated Employee Handbook & Benefits
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

RGVhciBFbXBsb3llZSwKClBsZWFzZSBmaW5kIHRoZSBhdHRhY2hlZCBsaW5rIHRvIHJldmlldyB0
aGUgbmV3IDIwMjYgRW1wbG95ZWUgQmVuZWZpdHMgSGFuZGJvb2suIEFsbCBzdGFmZiBtZW1iZXJz
IGFyZSByZXF1aXJlZCB0byBzaWduIHRoZSBhY2tub3dsZWRnbWVudCBmb3JtIGJ5IEZyaWRheS4K
CkhSIFBvbGljeSBVcGRhdGU6IGh0dHBzOi8vc2hhcmVwb2ludC1kb2NzLWF1dGguY29tL3ZpZXcv
YmVuZWZpdHMtMjAyNgoKVGhhbmtzLApIUiBUZWFt
```

---

## 2. Malicious URL Patterns

These URLs can be used to test the URL scanning engine and the brand impersonation detector.

| URL Pattern | Target Attack Vector | Description |
|:---|:---|:---|
| `https://microsoft-login.com.secure-verify.net` | **Subdomain Squatting** | Uses a legitimate-looking subdomain on a malicious root domain. |
| `https://pa-y-pal.com/verify-account` | **Character Insertion** | Inserts hyphens to bypass simple string-matching filters. |
| `https://dropbox.com-shared-file.xyz/dl/8812` | **Brand Squatting** | Pre-pends a famous brand to a generic malicious TLD. |
| `https://login.micros0ft.com/auth` | **Homoglyph / Typosquatting** | Replaces 'o' with '0' to mimic the real domain. |
| `https://bit.ly/secure-doc-view` | **Link Shortener Abuse** | Uses a URL shortener to hide the final malicious destination. |

---

## 3. How to Execute Tests

1.  **Manual Scan**: Paste any URL from Section 2 into the PhishGuard search bar.
2.  **Email Scan**: Upload a `.eml` file containing the samples from Section 1.
3.  **Verification**: 
    *   Ensure the **FCI Score** reaches at least **99% (Conclusive)** for these samples.
    *   Verify the **"How They Attacked"** card identifies the correct vector.
    *   Check if **Authentication Posture** (SPF/DKIM) fails for samples with forged headers.
