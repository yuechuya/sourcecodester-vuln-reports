# VULN-06 — Session Fixation on Login (login.php)

> **Audit by:** EVA Security Research
> **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0 — PHP/MySQL (PDO), developer Gon13
> **Audit date:** 2026-10-17 | **Verification:** local deployment, PHP 7.3.4 + MySQL 5.7.26

## 1. Vulnerability Overview / Summary
login.php starts a session and populates it with the authenticated user id, but never calls session_regenerate_id(). A session identifier chosen/planted by an attacker before the victim logs in remains valid after login, so the attacker obtains an authenticated administrator session.

## 2. Affected Component & Version
- **Component:** `login.php (session_start line 3; session population lines 17-18; no regeneration)`
- **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0. No patched version exists.

## 3. Vulnerability Type & Risk Level
- **Class (VulDB):** Session Fixation
- **CWE-384: Session Fixation**
- **Severity:** High
- **CVSS 3.1 vector:** `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` — **6.8**

## 4. Vulnerability Location (file:line)
```php
// login.php
session_start();                                   // line 3
...
if ($account && password_verify($pass, $account['password'])) {
    $_SESSION['user_id'] = $account['id'];          // line 17 - privilege granted
    $_SESSION['username'] = $account['username'];   // line 18
    header("Location: index.php");                  // line 19 - session ID NOT regenerated
    exit;
}
```

## 5. Root Cause Analysis
The session identifier is not rotated on privilege change. Any pre-authentication session id (which PHP accepts from the PHPSESSID cookie) becomes an authenticated session id. Combined with the missing HttpOnly flag (see VULN-04) and the absence of any session binding, fixation is directly exploitable once the attacker can make the victim's browser use a chosen id.

## 6. Preconditions
The attacker must be able to plant a PHPSESSID cookie value in the victim's browser (e.g. via a subdomain cookie, a MITM on plaintext HTTP, or the stored XSS in VULN-04), and the victim must log in during the attack window.

## 7. Reproduction Steps
1. Attacker obtains any valid session id from the application (GET /login.php sets PHPSESSID).
2. Attacker plants that id in the victim's browser.
3. Victim logs in normally.
4. Attacker replays the same id - the session is now authenticated as the admin.

## 8. PoC / EXP
```bash
# 1) obtain a pre-auth session id
curl -s -c prepost.txt "http://<TARGET>/login.php"     # PHPSESSID=<S>
# 2) victim logs in with cookie PHPSESSID=<S> (planted via any vector)
# 3) attacker replays the same id:
curl -s -b "PHPSESSID=<S>" "http://<TARGET>/index.php"   # 200 - authenticated dashboard
```

## 9. Verification Results
Executed against the local deployment:

  pre-login session id:  poegdill95lkakekmedc4a8tuh  (issued by GET /login.php)
  admin login performed while presenting exactly that id
  GET /index.php with only that cookie -> 200, Dashboard ("TOTAL STUDENTS", "Real-time Activity Log")

The identifier survived the login unchanged and granted access - session fixation confirmed.

## 10. Impact
Full administrative account takeover without stealing any credential, defeating logout-based controls (the attacker holds the same id). Enables silent persistence.

## 11. Remediation
```php
phpif ($account && password_verify($pass, $account['password'])) {
    session_regenerate_id(true);        // rotate on privilege change - MUST
    $_SESSION['user_id'] = $account['id'];
    $_SESSION['username'] = $account['username'];
    // also: bind session to request fingerprint and re-validate periodically
}
```
- Set `session.use_strict_mode=1` so uninitialized ids are not accepted.
- HttpOnly + SameSite=Strict + Secure on the session cookie.

## 12. References & Timeline
- **Audit by:** EVA Security Research
- **Identification:** 2026-10-17
- **Vendor notification:** not yet sent (SourceCodester is a distribution portal; no vendor patch process exists)
- **CVE:** TBD (submission package for the VulDB workflow)
