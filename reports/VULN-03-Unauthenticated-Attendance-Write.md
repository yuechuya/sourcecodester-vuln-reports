# VULN-03 — Unauthenticated Attendance Record Injection (api/attendance_handler.php)

> **Audit by:** EVA Security Research
> **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0 — PHP/MySQL (PDO), developer Gon13
> **Audit date:** 2026-10-17 | **Verification:** local deployment, PHP 7.3.4 + MySQL 5.7.26

## 1. Vulnerability Overview / Summary
The AJAX endpoint that records attendance (api/attendance_handler.php) contains no authentication check at all. While the kiosk scanner page requires a login, the API it calls can be invoked directly, letting any unauthenticated remote attacker insert arbitrary attendance records (IN/OUT, Present/Late) for any student code - i.e. forge attendance - and probe the student database.

## 2. Affected Component & Version
- **Component:** `api/attendance_handler.php (lines 1-130; entry line 8, parameter line 9, insert lines 110-111)`
- **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0. No patched version exists.

## 3. Vulnerability Type & Risk Level
- **Class (VulDB):** Missing Authentication for Critical Function
- **CWE-306: Missing Authentication for Critical Function**
- **Severity:** Medium
- **CVSS 3.1 vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` — **6.5**

## 4. Vulnerability Location (file:line)
```php
// api/attendance_handler.php
header('Content-Type: application/json');
require '../includes/db.php';               // line 4 - NO includes/auth.php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = $_POST['student_code'] ?? '';  // line 9 - no session, no token, no signature
    ...
    $stmt = $pdo->prepare("SELECT * FROM students WHERE student_code = ?");  // line 17
    ...
        $insert = $pdo->prepare("INSERT INTO attendance_logs (student_code, type, status, subject) VALUES (?, ?, ?, ?)"); // line 110
        if ($insert->execute([$code, $intent, $status, $subject_name])) {   // line 111
```

## 5. Root Cause Analysis
Authentication was applied to the UI page (scan_attendance.php includes auth.php) but not to the JSON API behind it - the classic 'page-gated, API-open' pattern. The endpoint trusts any POST body and writes rows into attendance_logs, and echoes back the student's full_name, which doubles as an unauthenticated student-existence oracle.

## 6. Preconditions
None. Network access; knowledge/guess of a student_code format (the code is also enumerable via the response oracle).

## 7. Reproduction Steps
1. Register or know any student_code (public self-registration exists at student_signup.php).
2. POST the code directly to api/attendance_handler.php with no cookie/session.
3. A row is inserted into attendance_logs and a success JSON is returned; repeating alternates IN/OUT.

## 8. PoC / EXP
```bash
# Forge an attendance record without any authentication
curl -s -X POST "http://<TARGET>/api/attendance_handler.php" --data "student_code=STU-2024-001"

# -> {"status":"success","message":"In: <subject> (PRESENT)","student":"<full name>","time":"..."}
# Oracle for unknown codes:
#   {"status":"error","message":"Student not registered!"}
```

## 9. Verification Results
Executed against the local deployment with NO cookie/session:

  POST /smart_attendance/api/attendance_handler.php  student_code=XTEST-001
  resp: {"status":"success","message":"In: Audit Test (LATE)","student":"<script>alert('XSS-POC')<\/script>","time":"07:18 PM"}
  DB:  attendance_logs row id=2 (student_code=XTEST-001, type=IN, status=Late) created

The write succeeded without authentication and the response disclosed the stored student name.

## 10. Impact
Integrity of the entire attendance dataset can be destroyed at scale (mass forging of Present/Late records for any student). The response oracle allows unauthenticated enumeration of valid student codes and names (personal data).

## 11. Remediation
```php
<?php
require '../includes/auth.php';   // enforce the same session gate as the UI page
// additionally: restrict the kiosk use-case with a per-kiosk token,
// rate-limit, and validate student_code against an allowlist pattern.
```
- Return generic errors (no student-name echo).

## 12. References & Timeline
- **Audit by:** EVA Security Research
- **Identification:** 2026-10-17
- **Vendor notification:** not yet sent (SourceCodester is a distribution portal; no vendor patch process exists)
- **CVE:** TBD (submission package for the VulDB workflow)
