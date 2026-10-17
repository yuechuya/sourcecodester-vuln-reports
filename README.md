# SourceCodester Vulnerability Reports

公开的 SourceCodester 学生作品白盒审计报告仓库，用于：
1. 作为 VulDB CNA 提交时的 PoC 公开引用链接
2. 同行复用审计方法
3. 漏洞复现验证

## 收录项目

### Smart Attendance System (SourceCodester #18702)

8 个漏洞，全部通过三遍强初审（T1 静态 + T2 动态控制组 + T3 对抗矩阵）。

| ID | 标题 | CVSS 3.1 |
|----|------|----------|
| [VULN-01](./reports/VULN-01-Unauthenticated-Password-Reset.md) | 未授权密码重置 | 9.1 CRITICAL |
| [VULN-02](./reports/VULN-02-Unauthenticated-Admin-Creation.md) | 未授权管理员账户创建 | 9.1 CRITICAL |
| [VULN-03](./reports/VULN-03-Unauthenticated-Attendance-Write.md) | 未授权考勤写入 | 6.5 MEDIUM |
| [VULN-04](./reports/VULN-04-Stored-XSS-Chain.md) | 存储型 XSS 链 | 5.6 MEDIUM |
| [VULN-05](./reports/VULN-05-CSRF-Student-Deletion.md) | CSRF 学生删除 | 4.3 MEDIUM |
| [VULN-06](./reports/VULN-06-Session-Fixation.md) | 会话固定 | 6.8 HIGH |
| [VULN-07](./reports/VULN-07-Reflected-XSS-ResetPassword.md) | 反射型 XSS（reset_password） | 5.6 MEDIUM |
| [VULN-08](./reports/VULN-08-Hardcoded-DB-Credentials.md) | 硬编码数据库凭据 | 7.3 HIGH |

完整审计过程、源文件 SHA-256 留痕、三遍初审输出见 [smart-attendance-system/](./smart-attendance-system/)。

## 提交指南

[VulDB CNA 提交指南](./README-SUBMISSION-GUIDE.md)

## 方法学

每份报告遵循 12 段式 VulDB CNA 模板（vendor / product / version / CVE assignment rationale / vulnerability type / CVSS 3.1 / weakness enumeration / impact / attack vector / PoC / remediation / references）。

提交前全部经过三遍强初审：
- **T1 静态**：源码 file:line 正向断言 + 反向断言（防护本应存在但不存在）
- **T2 动态**：每条主张配反证控制组（端到端真实 HTTP 验证）
- **T3 对抗**：归属 / 影响真实性 / 默认安装可达 / 原创性查重 / 版本区间 / 报告文本 / 修复有效性 7 维矩阵

## 致谢

- 审计方法借鉴 [hackliu/Vulnerability-Reports](https://github.com/hackliu/Vulnerability-Reports)
- 提交渠道优先 VulDB CNA（MITRE 授权 CVE Numbering Authority）

## 免责声明

所有报告仅用于白盒安全研究、漏洞披露合规与学术交流。请勿用于任何未授权的攻击行为。