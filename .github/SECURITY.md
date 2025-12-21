# Security Policy

## 🔒 Our Commitment to Security

Security is a core principle of the Crusoe IDP project. We take the security of our platform and our users’ data seriously. This document outlines our security policies, how to report vulnerabilities, and what to expect from our security response process.

-----

## 📋 Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Security Response Process](#security-response-process)
- [Security Best Practices](#security-best-practices)
- [Security Architecture](#security-architecture)
- [Known Security Considerations](#known-security-considerations)
- [Security Updates](#security-updates)
- [Bug Bounty Program](#bug-bounty-program)
- [Security Contacts](#security-contacts)

-----

## ✅ Supported Versions

We actively support the following versions with security updates:

|Version|Supported         |End of Support|
|-------|------------------|--------------|
|main   |:white_check_mark:|Current       |
|0.1.x  |:white_check_mark:|TBD           |
|< 0.1  |:x:               |Unsupported   |

**Note:** We recommend always running the latest version from the `main` branch for the most up-to-date security patches.

-----

## 🚨 Reporting a Vulnerability

### **CRITICAL: Do NOT Report Security Vulnerabilities Publicly**

**Please DO NOT:**

- Open public GitHub issues for security vulnerabilities
- Discuss security issues in public forums, chat, or social media
- Share exploit code publicly before we’ve had time to address the issue

### **Reporting Methods**

We provide multiple secure channels for reporting security vulnerabilities:

#### **1. GitHub Security Advisories (Preferred)**

Use GitHub’s private security vulnerability reporting:

1. Go to https://github.com/crusoe-island/secure-idp/security/advisories
1. Click “New draft security advisory”
1. Fill in the details about the vulnerability
1. Submit the advisory

This creates a private discussion thread with the security team.

#### **2. Email**

Send an encrypted email to our security team:

**Email:** security@crusoe-island.com

**PGP Key Fingerprint:** `XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX`

[Download our PGP public key](https://crusoe-island.com/security/pgp-key.asc)

#### **3. Security Hotline (Critical Issues Only)**

For critical vulnerabilities actively being exploited:

**Phone:** +31-XXX-XXXXXX (24/7 emergency line)

### **What to Include in Your Report**

Please provide as much information as possible to help us understand and reproduce the issue:

```
**Vulnerability Type:**
[ ] Authentication bypass
[ ] Authorization flaw
[ ] SQL injection
[ ] Cross-site scripting (XSS)
[ ] Remote code execution
[ ] Information disclosure
[ ] Denial of service
[ ] Other: ___________

**Affected Component:**
[ ] Backstage portal
[ ] Terraform modules
[ ] Kubernetes manifests
[ ] CI/CD pipelines
[ ] Container images
[ ] API endpoints
[ ] Other: ___________

**Severity Assessment:**
[ ] Critical (Remote code execution, complete system compromise)
[ ] High (Authentication bypass, data breach)
[ ] Medium (Information disclosure, privilege escalation)
[ ] Low (Minor information leak, edge case)

**Detailed Description:**
[Describe the vulnerability]

**Steps to Reproduce:**
1. 
2. 
3. 

**Proof of Concept:**
[Code, screenshots, or detailed explanation]

**Potential Impact:**
[What could an attacker do with this vulnerability?]

**Suggested Fix:**
[If you have ideas for how to fix it]

**Your Contact Information:**
Name: 
Email: 
PGP Key (optional): 
Preferred contact method: 
```

### **What NOT to Include**

For your security and ours:

- ❌ Do not include actual passwords, API keys, or credentials
- ❌ Do not include production data or PII
- ❌ Do not test vulnerabilities on production systems
- ❌ Do not perform denial-of-service attacks

-----

## 🔄 Security Response Process

### **Timeline**

We are committed to responding quickly to security reports:

|Timeline    |Action                                            |
|------------|--------------------------------------------------|
|**24 hours**|Initial acknowledgment of your report             |
|**72 hours**|Preliminary assessment and severity classification|
|**7 days**  |Detailed investigation and remediation plan       |
|**30 days** |Fix implemented and tested (for most issues)      |
|**90 days** |Public disclosure (coordinated with reporter)     |

**Note:** Timeline may vary based on complexity. We’ll keep you informed throughout.

### **Response Steps**

1. **Acknowledgment**: We confirm receipt of your report within 24 hours
1. **Assessment**: We validate and assess the severity of the issue
1. **Investigation**: We investigate the scope and impact
1. **Remediation**: We develop and test a fix
1. **Disclosure**: We coordinate public disclosure with you
1. **Recognition**: We credit you in our security advisories (if desired)

### **Severity Classification**

We use the CVSS 3.1 scoring system:

- **Critical (9.0-10.0)**: Immediate action required
  - Remote code execution without authentication
  - Complete system compromise
  - Mass data breach
- **High (7.0-8.9)**: Urgent action required
  - Authentication bypass
  - Privilege escalation to admin
  - Significant data exposure
- **Medium (4.0-6.9)**: Important to fix
  - Limited information disclosure
  - Denial of service
  - Cross-site scripting
- **Low (0.1-3.9)**: Should be fixed
  - Minor information leaks
  - Low-impact vulnerabilities
  - Edge cases

### **Our Commitments**

✅ We will respond to all legitimate security reports  
✅ We will keep you informed of our progress  
✅ We will credit you for responsible disclosure (if desired)  
✅ We will not take legal action against security researchers acting in good faith  
✅ We will coordinate disclosure timing with you

-----

## 🛡️ Security Best Practices

### **For Users of Crusoe IDP**

1. **Keep Updated**
- Always use the latest version
- Subscribe to security advisories
- Apply security patches promptly
1. **Secure Configuration**
- Enable multi-factor authentication (MFA)
- Use strong, unique passwords
- Rotate credentials regularly
- Never commit secrets to Git
1. **Access Control**
- Follow principle of least privilege
- Review access permissions regularly
- Use Azure AD groups for role management
- Enable audit logging
1. **Network Security**
- Use private endpoints where possible
- Enable network policies in Kubernetes
- Configure firewall rules appropriately
- Use VPN for administrative access
1. **Monitoring**
- Review Azure Sentinel alerts
- Monitor Defender for Cloud recommendations
- Check security logs regularly
- Set up alerting for suspicious activity

### **For Contributors**

1. **Code Security**
- Run pre-commit hooks before every commit
- Never commit secrets or credentials
- Use parameterized queries (no SQL injection)
- Validate all user input
- Use secure random number generation
1. **Dependencies**
- Keep dependencies up to date
- Review Dependabot alerts
- Scan for vulnerabilities before merging
- Use only trusted dependencies
1. **Infrastructure as Code**
- Follow security baselines
- Use Azure Policy for governance
- Enable encryption by default
- Implement network segmentation
1. **Testing**
- Write security tests
- Test authentication and authorization
- Verify input validation
- Check for common vulnerabilities (OWASP Top 10)

-----

## 🏗️ Security Architecture

### **Defense-in-Depth Layers**

Our platform implements multiple layers of security controls:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Identity & Access Management                  │
│  • Azure AD with MFA                                    │
│  • Conditional Access policies                          │
│  • Privileged Identity Management (PIM)                 │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Network Security                              │
│  • Private endpoints (no public IPs)                    │
│  • Azure Firewall for egress filtering                  │
│  • Network Security Groups (NSGs)                       │
│  • DDoS Protection                                      │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Platform Security                             │
│  • Private AKS cluster                                  │
│  • Kubernetes RBAC                                      │
│  • Network policies (Calico)                            │
│  • Pod Security Standards                               │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Application Security                          │
│  • Container image scanning                             │
│  • SAST/DAST in CI/CD                                   │
│  • Dependency vulnerability scanning                    │
│  • Secret scanning                                      │
├─────────────────────────────────────────────────────────┤
│  Layer 5: Data Security                                 │
│  • Encryption at rest (AES-256)                         │
│  • Encryption in transit (TLS 1.3)                      │
│  • Azure Key Vault for secrets                          │
│  • Backup encryption                                    │
├─────────────────────────────────────────────────────────┤
│  Layer 6: Monitoring & Response                         │
│  • Azure Sentinel (SIEM)                                │
│  • Microsoft Defender for Cloud                         │
│  • Container Insights                                   │
│  • Automated incident response                          │
└─────────────────────────────────────────────────────────┘
```

### **Security Controls**

- **Authentication**: Azure AD with MFA required
- **Authorization**: Role-Based Access Control (RBAC)
- **Encryption**: TLS 1.3 in transit, AES-256 at rest
- **Secrets Management**: Azure Key Vault (no secrets in code)
- **Network Isolation**: Private endpoints, no public IPs
- **Audit Logging**: 90-day retention, immutable logs
- **Vulnerability Scanning**: Automated daily scans
- **Incident Response**: Automated playbooks with Azure Sentinel

-----

## ⚠️ Known Security Considerations

### **Current Limitations**

We believe in transparency. Here are known security considerations:

1. **Development Environment**
- Dev environment uses less restrictive security policies for easier development
- **Mitigation**: Never use dev environment for production data
1. **Third-Party Dependencies**
- We rely on external packages that may have vulnerabilities
- **Mitigation**: Automated dependency scanning, regular updates, Dependabot alerts
1. **Shared Responsibility Model**
- Azure platform security is Microsoft’s responsibility
- Application and configuration security is our responsibility
- **Mitigation**: Follow Azure Security Benchmark, regular audits
1. **Container Base Images**
- Base images may contain vulnerabilities before patches are available
- **Mitigation**: Daily image scanning, automated rebuilds, minimal base images

### **Out of Scope**

The following are explicitly out of scope for security reports:

- ❌ Denial of service attacks against test/dev environments
- ❌ Social engineering attacks against team members
- ❌ Physical security of our infrastructure (handled by Azure)
- ❌ Vulnerabilities in third-party services we don’t control
- ❌ Issues affecting only outdated/unsupported versions
- ❌ Issues requiring significant user interaction or unlikely user actions
- ❌ Low-severity issues without clear security impact

-----

## 🔄 Security Updates

### **How We Communicate Security Updates**

1. **GitHub Security Advisories**
- Published for all confirmed vulnerabilities
- Available at: https://github.com/crusoe-island/secure-idp/security/advisories
1. **Release Notes**
- Security fixes highlighted in CHANGELOG.md
- Tagged with `[SECURITY]` prefix
1. **Security Mailing List**
- Subscribe: security-announce@crusoe-island.com
- Receive notifications of critical updates
1. **GitHub Watch**
- Watch the repository for release notifications
- Enable “Security alerts” in your GitHub settings

### **Update Recommendations**

- **Critical**: Apply within 24 hours
- **High**: Apply within 7 days
- **Medium**: Apply within 30 days
- **Low**: Apply in next regular update cycle

### **Automated Updates**

We recommend enabling:

- ✅ Dependabot for dependency updates
- ✅ Automated container image rebuilds
- ✅ Azure Policy for compliance enforcement
- ✅ Azure Sentinel for threat detection

-----

## 💰 Bug Bounty Program

### **Current Status**

We are currently developing a formal bug bounty program. In the meantime:

- We deeply appreciate responsible security research
- We will publicly credit researchers (if desired)
- We may provide rewards on a case-by-case basis for significant findings

### **Future Plans**

We plan to launch a formal bug bounty program that will include:

- Defined scope and rules of engagement
- Monetary rewards based on severity
- Recognition and hall of fame
- Clear legal safe harbor

**Stay tuned for updates!**

-----

## 📞 Security Contacts

### **Security Team**

**General Security Inquiries:**

- Email: security@crusoe-island.com
- Response time: 24-48 hours (business days)

**Critical Security Issues:**

- Email: security@crusoe-island.com (mark as URGENT)
- Phone: +31-XXX-XXXXXX (24/7 emergency line)
- Response time: Within hours

**Security Team Members:**

- Willem van Heemstra - Security Domain Expert
- [Add other team members]

### **PGP Public Keys**

For encrypted communications:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP public key block would go here]
-----END PGP PUBLIC KEY BLOCK-----
```

Download: https://crusoe-island.com/security/pgp-key.asc

Fingerprint: `XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX`

-----

## 🔐 Security Hall of Fame

We thank the following researchers for responsibly disclosing security issues:

<!-- 
2024-XX-XX - [Researcher Name] - [Brief description]
-->

*Be the first to contribute to our security!*

-----

## 📚 Additional Resources

### **Security Documentation**

- [Threat Model](docs/architecture/threat-model.md)
- [Defense-in-Depth Strategy](docs/architecture/defense-in-depth.md)
- [Security Guide](docs/security/security-guide.md)
- [Incident Response Playbook](docs/security/incident-response.md)
- [Compliance Framework](docs/security/compliance.md)

### **Security Tools**

- [Pre-commit hooks](.pre-commit-config.yaml)
- [Security scanning workflows](.github/workflows/)
- [Security policies](terraform/policies/)

### **External Resources**

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

-----

## 📜 Legal

### **Safe Harbor**

We support security research and will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations and data destruction
- Do not exploit vulnerabilities beyond demonstrating their existence
- Report vulnerabilities promptly and in accordance with this policy
- Do not violate any laws in the course of their research

### **Responsible Disclosure**

We request that you:

- Give us reasonable time to fix vulnerabilities before public disclosure
- Do not access data that isn’t yours
- Do not perform attacks that could harm our systems or users
- Act in good faith throughout the disclosure process

### **Privacy**

- We will keep your identity confidential unless you request otherwise
- We will not share your report with third parties without your permission
- Your personal information will be handled in accordance with GDPR

-----

## ✅ Acknowledgments

This security policy is based on industry best practices and inspired by:

- [GitHub’s Security Policy](https://github.com/github/.github/blob/main/SECURITY.md)
- [OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)
- [CERT Guide to Coordinated Vulnerability Disclosure](https://vuls.cert.org/confluence/display/CVD)

-----

## 📝 Version History

|Version|Date      |Changes                |
|-------|----------|-----------------------|
|1.0    |2024-12-21|Initial security policy|

-----

**Last Updated:** December 21, 2024

**Questions?** Contact us at security@crusoe-island.com

*Thank you for helping keep Crusoe IDP and our users safe!* 🔒

-----

**Remember:** Security is everyone’s responsibility. If you see something, say something.
