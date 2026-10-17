# VULN-08 — Hard-coded Database Credentials (includes/db.php)

> **Audit by:** EVA Security Research
> **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0 — PHP/MySQL (PDO), developer Gon13
> **Audit date:** 2026-10-17 | **Verification:** local deployment, PHP 7.3.4 + MySQL 5.7.26

## 1. Vulnerability Overview / Summary
The database connection parameters are hard-coded in the source with the XAMPP default root account and an empty password. The full source is publicly downloadable, so every deployment that keeps the default account exposes its database to anyone who obtains the package (or the file).

## 2. Affected Component & Version
- **Component:** `includes/db.php (lines 4-6)`
- **Product:** Smart Attendance System with QR Code Scanner (SourceCodester #18702), v1.0. No patched version exists.

## 3. Vulnerability Type & Risk Level
- **Class (VulDB):** Use of Hard-coded Credentials
- **CWE-798: Use of Hard-coded Credentials**
- **Severity:** High
- **CVSS 3.1 vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` — **7.3**

## 4. Vulnerability Location (file:line)
```php
// includes/db.php
$host = 'localhost';
$user = 'root';          // line 5 - default XAMPP superuser
$pass = '';              // line 6 - empty password, hard-coded
$dbname = 'attendance_db';
$pdo = new PDO("mysql:host=$host;dbname=$dbname", $user, $pass);   // line 13
```

## 5. Root Cause Analysis
Connection secrets are embedded in application code (a classic student-project pattern, documented in the project's setup instructions). No environment indirection, no dedicated least-privilege DB user.

## 6. Preconditions
The attacker needs a network path to the MySQL service of a deployment that uses these credentials (any instance following the project's default setup instructions).

## 7. Reproduction Steps
1. Obtain the public source package (or read includes/db.php from an exposed deployment).
2. Connect to the target's MySQL with root / empty password on the configured host.
3. Full read/write on attendance_db (and with root, on every database of that server).

## 8. PoC / EXP
```bash
# from the public package: $user='root'; $pass=''
mysql -h <TARGET-DB-HOST> -u root attendance_db -e "SHOW TABLES; SELECT * FROM users;"

# local proof of the credential set being functional (test instance):
mysql -h 127.0.0.1 -u root attendance_db   # (empty password accepted on default XAMPP setups)
```

## 9. Verification Results
Static verification: includes/db.php lines 4-6 contain the literal root/empty-password pair; the same pair is documented in the SourceCodester installation instructions, confirming default deployments use it. (Dynamic exploitation against a third-party deployment was not performed and is out of scope.)

## 10. Impact
On any deployment that follows the documented setup, the MySQL server - including all student PII and password hashes - is readable and writable with superuser rights; with root, other databases on the same server are also exposed.

## 11. Remediation
```php
php// 1) Dedicated least-privilege user, credentials from environment/config outside the web root
$user = getenv('DB_USER');
$pass = getenv('DB_PASS');
// 2) Never ship root credentials; restrict the app user to its own schema
//    GRANT SELECT,INSERT,UPDATE,DELETE ON attendance_db.* TO 'app'@'localhost';
// 3) Rotate any credential that has ever been committed to the package
```


## 12. References & Timeline
- **Audit by:** EVA Security Research
- **Identification:** 2026-10-17
- **Vendor notification:** not yet sent (SourceCodester is a distribution portal; no vendor patch process exists)
- **CVE:** TBD (submission package for the VulDB workflow)
