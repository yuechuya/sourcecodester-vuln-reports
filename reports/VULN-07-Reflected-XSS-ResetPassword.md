# VULN-07 — Reflected Cross-Site Scripting in reset_password.php response

> **Audit by:** EVA Security Research
> **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0 — PHP/MySQL (PDO), developer Gon13
> **Audit date:** 2026-10-17 | **Verification:** local deployment, PHP 7.3.4 + MySQL 5.7.26

## 1. Vulnerability Overview / Summary
The response page of reset_password.php embeds the attacker-supplied username into the success message without HTML encoding. A crafted form auto-submit reflects arbitrary markup/script into the victim's browser. The same endpoint is unauthenticated (see VULN-01), so no privileges are needed to reach the sink.

## 2. Affected Component & Version
- **Component:** `reset_password.php (username read line 9; message built lines 25/33; output line 61)`
- **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0. No patched version exists.

## 3. Vulnerability Type & Risk Level
- **Class (VulDB):** Cross Site Scripting
- **CWE-79: Improper Neutralization of Input During Web Page Generation**
- **Severity:** Medium
- **CVSS 3.1 vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` — **5.6**

## 4. Vulnerability Location (file:line)
```php
// reset_password.php
$username = trim($_POST['username']);        // line 9 - attacker-controlled
...
$message = "Success! Password for user '<strong>$username</strong>' has been updated.";  // line 25
...
<?= $message ?>                              // line 61 - echoed unencoded into HTML
```

## 5. Root Cause Analysis
Short-hand echo of a string built from raw request input; no htmlspecialchars() anywhere in the response path. Because the handler is unauthenticated, the sink is reachable by anyone.

## 6. Preconditions
The victim must be made to submit a POST to reset_password.php with the attacker's payload (auto-submitting form, or chained from VULN-01/04).

## 7. Reproduction Steps
1. Host a page with a hidden form targeting reset_password.php.
2. Auto-submit username=<payload>&password=x.
3. The response page renders the payload inside the success alert.

## 8. PoC / EXP
```bash
<form method="POST" action="http://<TARGET>/reset_password.php" id="f">
  <input name="username" value="<img src=x onerror=alert(document.cookie)>">
  <input name="password" value="x">
</form><script>f.submit()</script>
```

## 9. Verification Results
Executed against the local deployment:

  POST /smart_attendance/reset_password.php
  body: username=<img src=x onerror=alert('RXSS')>&password=x
  response HTML:
    Success! Password for user '<strong><img src=x onerror=alert('RXSS')></strong>' has been updated.

The payload was reflected verbatim into the HTML document.

## 10. Impact
Arbitrary JavaScript execution in the context of the application origin for any visitor lured into submitting the form (e.g., cookie theft, action forgery as the victim).

## 11. Remediation
```php
php$message = "Success! Password for user '<strong>" . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . "</strong>' has been updated.";
// and escape at output: <?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?>
```


## 12. References & Timeline
- **Audit by:** EVA Security Research
- **Identification:** 2026-10-17
- **Vendor notification:** not yet sent (SourceCodester is a distribution portal; no vendor patch process exists)
- **CVE:** TBD (submission package for the VulDB workflow)
