# VulDB 提交包 — Smart Attendance System（SourceCodester #18702）

> 生成日期：2026-10-17 ｜ 审计：EVA Security Research
> 目标产品：Smart Attendance System with QR Code Scanner (PHP/MySQL) v1.0，SourceCodester 项目页 #18702（Gon13，2026-04-10 上传）
> 查重结论：2026-10-17 检索 cve.org / NVD / vuldb.com 索引，**该产品无任何已分配 CVE**（同站点的 Pizzafy、Inventory、BRPMS、Online Food Ordering 等均已有 CVE，本项目没有）。

## 一、提交前准备

1. 注册 VulDB 账号（vuldb.com，免费；CVE 分配不向提交者收费，其商业模式是数据订阅）。
2. 每个漏洞**单独提交一次**（VulDB 会把一个提交里的多个洞拆成多条，重复提交只会被合并成 contributor，不发新 CVE）。
3. 提交前再跑一次查重：确认该洞没有已分配 CVE、也没有其他 CNA 正在处理（VulDB 官方 Submission Policy 明确要求）。
4. 提交表单必填：**vendor / product / affected versions / vulnerability class**；CVSS 向量、详细描述、PoC、截图都会提高通过率（无法验证的提交会被推迟或拒绝，弱提交有拉黑机制）。

## 二、本包 8 个发现（按建议提交顺序）

| # | 标题（表单用） | 类型 | CWE | CVSS 3.1 | 报告文件 |
|---|---|---|---|---|---|
| 1 | SourceCodester Smart Attendance System reset_password.php 未授权密码重置 | Missing Authentication for Critical Function | CWE-306 | 9.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | VULN-01-Unauthenticated-Password-Reset.md |
| 2 | SourceCodester Smart Attendance System create_admin.php 未授权管理员创建 | Missing Authentication for Critical Function | CWE-306 | 9.1 同上 | VULN-02-Unauthenticated-Admin-Creation.md |
| 3 | SourceCodester Smart Attendance System attendance_handler.php 未授权考勤写入 | Missing Authentication for Critical Function | CWE-306 | 6.5 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` | VULN-03-Unauthenticated-Attendance-Write.md |
| 4 | SourceCodester Smart Attendance System student_signup.php 存储型 XSS（注册→JSON→DOM） | Cross Site Scripting | CWE-79 | 5.6 `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | VULN-04-Stored-XSS-Chain.md |
| 5 | SourceCodester Smart Attendance System delete_student.php CSRF 删除 | Cross Site Request Forgery | CWE-352 | 4.3 `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | VULN-05-CSRF-Student-Deletion.md |
| 6 | SourceCodester Smart Attendance System login.php 会话固定 | Session Fixation | CWE-384 | 6.8 `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` | VULN-06-Session-Fixation.md |
| 7 | SourceCodester Smart Attendance System reset_password.php 反射型 XSS | Cross Site Scripting | CWE-79 | 5.6 `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | VULN-07-Reflected-XSS-ResetPassword.md |
| 8 | SourceCodester Smart Attendance System db.php 硬编码数据库凭据 | Use of Hard-coded Credentials | CWE-798 | 7.3 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` | VULN-08-Hardcoded-DB-Credentials.md |

表单字段建议值（所有条目相同）：
- **Vendor:** SourceCodester
- **Product:** Smart Attendance System with QR Code Scanner（别名 AttendancePro / Cet_smart_attendance）
- **Affected version:** 1.0（唯一公开版本，无修复版本）
- **Description/Details：** 直接粘贴对应报告的第 1、4、5、7、8、10、11 节（概述/位置/根因/复现/PoC/影响/修复）
- **Reference URL：** SourceCodester 项目页 `https://www.sourcecodester.com/php/18702/smart-attendance-system-qr-code-scanner-phpmysql.html`

## 三、时间线预期（依据 VulDB 官方 SLA 与朋友案例实测）

- 提交后 2-12 小时启动处理，审核通常 2-5 个工作日；
- 该产品无厂商 CNA 覆盖 ⇒ **审核通过当场分配 CVE**（官方 Submission Policy 原文）；
- 参考朋友案例：9/10 提交 → 10/6 CVE 发布（约 26 天，含协调披露）；
- 8 条全部通过 ≈ 6-8 个新 CVE（存在个别被 moderation 认为价值不足而拒的可能，1/2/3 三条最稳）。

## 四、本地验证证据

全部 8 项均在本机实测通过（PHP 7.3.4 + MySQL 5.7.26，127.0.0.1），完整记录：
`raw/verify_smart_attendance.txt`（T1-T10）。报告第 9 节为实测结果，可直接作为提交材料的 Verification 部分。

## 五、注意事项

- PoC 中的 `<TARGET>` 是占位符，提交前无需替换（朋友案例同样用占位符通过 moderation）；
- 载荷统一用无害化形式（alert/文档域内），未包含任何真实外联地址；
- 署名：CVE 记录会列 reporter（VulDB 用户名），可在账号设置里抑制；
- 同一漏洞不要向其他 CNA/平台重复提交（VulDB 政策明确要求，且会被合并）。
