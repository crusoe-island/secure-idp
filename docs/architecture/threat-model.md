# Threat Model - Crusoe IDP

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Owner:** Security Team  
**Status:** Active

-----

## 📋 Table of Contents

- [Executive Summary](#executive-summary)
- [Threat Modeling Methodology](#threat-modeling-methodology)
- [System Overview](#system-overview)
- [Trust Boundaries](#trust-boundaries)
- [Assets and Data Classification](#assets-and-data-classification)
- [Threat Actors](#threat-actors)
- [Attack Surface Analysis](#attack-surface-analysis)
- [STRIDE Threat Analysis](#stride-threat-analysis)
- [Attack Trees](#attack-trees)
- [Risk Assessment Matrix](#risk-assessment-matrix)
- [Security Controls](#security-controls)
- [Residual Risks](#residual-risks)
- [Threat Intelligence](#threat-intelligence)
- [Review and Updates](#review-and-updates)

-----

## 📊 Executive Summary

This threat model provides a comprehensive security analysis of the Crusoe Internal Developer Platform (IDP). The platform implements a defense-in-depth security architecture with six distinct security layers, designed to protect against sophisticated cyber threats while maintaining developer productivity.

### Key Findings

- **Critical Assets**: Source code, secrets, customer data, infrastructure credentials
- **Primary Threats**: Credential compromise, supply chain attacks, insider threats, container escapes
- **Security Posture**: Strong with defense-in-depth, zero-trust architecture
- **High-Risk Areas**: Third-party dependencies, credential management, container runtime
- **Mitigation Status**: 87% of identified threats have implemented controls

### Risk Summary

|Risk Level|Count|Percentage|Status          |
|----------|-----|----------|----------------|
|Critical  |2    |5%        |Mitigated       |
|High      |8    |20%       |Mostly Mitigated|
|Medium    |18   |45%       |Mitigated       |
|Low       |12   |30%       |Accepted        |

-----

## 🔬 Threat Modeling Methodology

### Approach

We use a combination of threat modeling methodologies:

1. **STRIDE** - Categorization of threats
- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege
1. **PASTA** - Process for Attack Simulation and Threat Analysis
- Define objectives
- Define technical scope
- Application decomposition
- Threat analysis
- Vulnerability analysis
- Attack modeling
- Risk and impact analysis
1. **Attack Trees** - Hierarchical representation of attack paths
1. **DREAD** (deprecated but referenced) - Risk scoring
- **D**amage potential
- **R**eproducibility
- **E**xploitability
- **A**ffected users
- **D**iscoverability

### Threat Modeling Process

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Asset Identification                                     │
│    • Source code, secrets, infrastructure, credentials      │
├─────────────────────────────────────────────────────────────┤
│ 2. Architecture Analysis                                    │
│    • Data flow diagrams, component interactions             │
├─────────────────────────────────────────────────────────────┤
│ 3. Threat Identification                                    │
│    • STRIDE analysis, attack trees, threat actors           │
├─────────────────────────────────────────────────────────────┤
│ 4. Vulnerability Analysis                                   │
│    • Security testing, code review, penetration testing     │
├─────────────────────────────────────────────────────────────┤
│ 5. Risk Assessment                                          │
│    • Impact analysis, likelihood scoring, prioritization    │
├─────────────────────────────────────────────────────────────┤
│ 6. Mitigation Planning                                      │
│    • Security controls, monitoring, incident response       │
├─────────────────────────────────────────────────────────────┤
│ 7. Validation                                               │
│    • Security testing, audits, continuous monitoring        │
└─────────────────────────────────────────────────────────────┘
```

-----

## 🏗️ System Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         INTERNET                                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
            ┌────────────────────────┐
            │  Azure Front Door      │
            │  + WAF + DDoS          │
            └────────┬───────────────┘
                     │
                     ▼
         ┌──────────────────────────┐
         │   Azure Firewall         │
         │   (Egress Filtering)     │
         └──────────┬───────────────┘
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
┌─────────┐   ┌──────────┐   ┌──────────────┐
│Backstage│   │ AKS      │   │Private       │
│Portal   │   │ Cluster  │   │Endpoints     │
│         │   │(Private) │   │              │
│         │   │          │   │• Key Vault   │
│         │   │          │   │• ACR         │
│         │   │          │   │• Storage     │
└─────────┘   └────┬─────┘   └──────────────┘
                   │
                   ▼
         ┌──────────────────┐
         │ Azure Sentinel   │
         │ (SIEM)           │
         └──────────────────┘
```

### Components

1. **Developer Interface Layer**
- Backstage portal
- CLI tools
- APIs
1. **Platform Services Layer**
- Azure DevOps (CI/CD)
- Azure Kubernetes Service (AKS)
- Azure Container Registry (ACR)
1. **Infrastructure Layer**
- Virtual Networks
- Azure Firewall
- Network Security Groups
1. **Security Services Layer**
- Azure Key Vault
- Azure Sentinel
- Microsoft Defender for Cloud
1. **Data Layer**
- Azure Storage
- Azure SQL Database
- Log Analytics

-----

## 🔒 Trust Boundaries

Trust boundaries represent points where data crosses from one security domain to another. These are critical areas requiring additional security controls.

### Identified Trust Boundaries

```
┌────────────────────────────────────────────────────────────┐
│ TB1: Internet ←→ Azure Front Door / WAF                   │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Risk: External attacks, DDoS, malicious traffic           │
│ Controls: WAF rules, DDoS protection, rate limiting       │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ TB2: Azure Front Door ←→ Virtual Network                  │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Risk: Unauthorized network access                          │
│ Controls: NSGs, Azure Firewall, private endpoints         │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ TB3: Developer Workstation ←→ Backstage Portal            │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Risk: Credential theft, session hijacking                  │
│ Controls: Azure AD + MFA, TLS 1.3, session management     │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ TB4: Backstage ←→ AKS API Server                          │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Risk: Unauthorized cluster access                          │
│ Controls: Private cluster, RBAC, managed identity         │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ TB5: AKS ←→ Azure Services (Key Vault, ACR, Storage)      │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Risk: Data interception, unauthorized access               │
│ Controls: Private endpoints, managed identity, encryption  │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ TB6: Application Pods ←→ Other Pods                       │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Risk: Lateral movement, pod-to-pod attacks                 │
│ Controls: Network policies, pod security standards         │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ TB7: CI/CD Pipeline ←→ Production Environment             │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Risk: Supply chain attack, malicious code injection        │
│ Controls: Security gates, image scanning, signing         │
└────────────────────────────────────────────────────────────┘
```

-----

## 💎 Assets and Data Classification

### Critical Assets

|Asset                         |Classification  |Impact if Compromised             |Current Protection          |
|------------------------------|----------------|----------------------------------|----------------------------|
|**Source Code**               |Confidential    |High - IP theft, backdoors        |Azure Repos + RBAC          |
|**Secrets & Keys**            |Highly Sensitive|Critical - Full compromise        |Azure Key Vault             |
|**Customer Data**             |Confidential/PII|Critical - Data breach, GDPR      |Encryption, access controls |
|**Infrastructure Credentials**|Highly Sensitive|Critical - Infrastructure takeover|Managed identities, rotation|
|**Container Images**          |Internal        |High - Supply chain attack        |Image scanning, signing     |
|**CI/CD Pipeline**            |Internal        |High - Deployment compromise      |Security gates, approvals   |
|**Kubernetes Configs**        |Internal        |High - Cluster compromise         |RBAC, GitOps                |
|**Audit Logs**                |Internal        |Medium - Evidence tampering       |Immutable storage           |
|**Terraform State**           |Confidential    |High - Infrastructure exposure    |Encrypted backend           |
|**API Keys/Tokens**           |Highly Sensitive|Critical - Unauthorized access    |Key Vault, rotation         |

### Data Classification Levels

1. **Highly Sensitive** - Credentials, keys, tokens
- Storage: Azure Key Vault only
- Access: Minimum necessary, audited
- Retention: Rotate every 90 days
1. **Confidential** - Source code, customer data, IP
- Storage: Encrypted at rest
- Access: RBAC with MFA
- Retention: Per compliance requirements
1. **Internal** - Configuration, logs, metrics
- Storage: Encrypted
- Access: Role-based
- Retention: 90 days minimum
1. **Public** - Documentation, public APIs
- Storage: Standard
- Access: Public (with rate limiting)
- Retention: Indefinite

-----

## 👥 Threat Actors

### 1. External Attackers

**Motivation:** Financial gain, data theft, espionage  
**Capabilities:** Advanced persistent threats (APT), automated tools  
**Attack Vectors:** Internet-facing services, supply chain, social engineering

**Typical Attacks:**

- Exploiting vulnerabilities in public-facing applications
- Credential stuffing and brute force attacks
- Supply chain compromise (malicious dependencies)
- Zero-day exploits

**Likelihood:** Medium  
**Impact:** Critical

### 2. Malicious Insiders

**Motivation:** Financial gain, revenge, ideology  
**Capabilities:** Legitimate access, knowledge of systems  
**Attack Vectors:** Privilege abuse, data exfiltration

**Typical Attacks:**

- Unauthorized data access
- Credential sharing or selling
- Sabotage of systems
- IP theft

**Likelihood:** Low  
**Impact:** High

### 3. Compromised Accounts

**Motivation:** N/A (attacker uses legitimate credentials)  
**Capabilities:** Varies based on account privilege level  
**Attack Vectors:** Phishing, credential reuse, session hijacking

**Typical Attacks:**

- Lateral movement using stolen credentials
- Data exfiltration with legitimate access
- Privilege escalation
- Persistence mechanisms

**Likelihood:** Medium  
**Impact:** High

### 4. Supply Chain Attackers

**Motivation:** Widespread impact, espionage  
**Capabilities:** Code injection, dependency poisoning  
**Attack Vectors:** Compromised packages, malicious containers

**Typical Attacks:**

- Typosquatting in package registries
- Compromised upstream dependencies
- Malicious container images
- Backdoored tools and libraries

**Likelihood:** Medium  
**Impact:** Critical

### 5. Nation-State Actors

**Motivation:** Espionage, sabotage, strategic advantage  
**Capabilities:** Advanced techniques, zero-days, resources  
**Attack Vectors:** All vectors, sophisticated and persistent

**Typical Attacks:**

- Advanced persistent threats (APT)
- Zero-day exploits
- Supply chain attacks
- Social engineering

**Likelihood:** Low  
**Impact:** Critical

### 6. Automated Bots/Scripts

**Motivation:** Opportunistic exploitation  
**Capabilities:** Mass scanning, known exploit execution  
**Attack Vectors:** Publicly exposed services, known vulnerabilities

**Typical Attacks:**

- Vulnerability scanning
- Brute force attacks
- DDoS attacks
- Crypto mining

**Likelihood:** High  
**Impact:** Low to Medium

-----

## 🎯 Attack Surface Analysis

### External Attack Surface

#### 1. Backstage Portal (HTTPS)

**Exposure:** Public internet  
**Authentication:** Azure AD + MFA  
**Vulnerabilities:**

- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Authentication bypass
- Session hijacking

**Attack Vectors:**

```
Internet → Backstage Login
  ↓
  ├─→ Credential stuffing
  ├─→ XSS injection
  ├─→ CSRF attacks
  └─→ Session token theft
```

**Mitigations:**

- ✅ Content Security Policy (CSP)
- ✅ HTTP security headers
- ✅ Rate limiting
- ✅ MFA enforcement
- ✅ Session timeout
- ✅ CSRF tokens

#### 2. Azure Front Door / WAF

**Exposure:** Public internet  
**Vulnerabilities:**

- DDoS attacks
- WAF bypass
- TLS vulnerabilities

**Mitigations:**

- ✅ DDoS Protection Standard
- ✅ WAF with OWASP rules
- ✅ TLS 1.3 only
- ✅ Certificate pinning

#### 3. API Endpoints

**Exposure:** Authenticated users  
**Vulnerabilities:**

- Injection attacks (SQL, NoSQL, command)
- Insecure deserialization
- Broken authentication
- Excessive data exposure

**Mitigations:**

- ✅ Input validation
- ✅ Parameterized queries
- ✅ Rate limiting
- ✅ API authentication (OAuth 2.0)
- ✅ Least privilege access

### Internal Attack Surface

#### 4. AKS Cluster

**Exposure:** Internal network, private endpoints  
**Vulnerabilities:**

- Container escapes
- Privilege escalation
- Lateral movement
- Kubelet API abuse

**Mitigations:**

- ✅ Private cluster (no public API)
- ✅ Network policies
- ✅ Pod Security Standards
- ✅ RBAC with Azure AD
- ✅ Runtime security (Falco)

#### 5. Azure Key Vault

**Exposure:** Private endpoints only  
**Vulnerabilities:**

- Unauthorized secret access
- Secret extraction
- Key compromise

**Mitigations:**

- ✅ Private endpoints
- ✅ RBAC (no access policies)
- ✅ Soft delete + purge protection
- ✅ Audit logging
- ✅ Key rotation

#### 6. CI/CD Pipeline

**Exposure:** Internal, authenticated  
**Vulnerabilities:**

- Code injection
- Credential theft from pipeline
- Supply chain attacks
- Pipeline manipulation

**Mitigations:**

- ✅ Security gates (SAST, DAST, container scanning)
- ✅ Secrets in Key Vault
- ✅ Approval gates for production
- ✅ Signed commits
- ✅ Dependency scanning

### Attack Surface Metrics

|Surface Area     |Exposure|Risk Level|Controls                 |
|-----------------|--------|----------|-------------------------|
|Public Web Portal|High    |Medium    |WAF, MFA, Rate Limiting  |
|API Endpoints    |Medium  |Medium    |Auth, Input Validation   |
|AKS Cluster      |Low     |High      |Private, Network Policies|
|Key Vault        |Very Low|Critical  |Private Endpoints, RBAC  |
|CI/CD Pipeline   |Low     |High      |Security Gates, Approvals|

-----

## ⚔️ STRIDE Threat Analysis

### Spoofing Identity

|Threat    |Description                          |Impact  |Likelihood|Mitigation                               |Status     |
|----------|-------------------------------------|--------|----------|-----------------------------------------|-----------|
|**ST-001**|Attacker impersonates legitimate user|High    |Medium    |Azure AD + MFA, conditional access       |✅ Mitigated|
|**ST-002**|Service account credential theft     |Critical|Medium    |Managed identities, no passwords         |✅ Mitigated|
|**ST-003**|API token theft/reuse                |High    |Medium    |Short-lived tokens, rotation             |✅ Mitigated|
|**ST-004**|Session hijacking via XSS            |High    |Low       |CSP, HTTPOnly cookies, SameSite          |✅ Mitigated|
|**ST-005**|Container image spoofing             |High    |Low       |Image signing (Cosign), registry scanning|✅ Mitigated|

### Tampering

|Threat    |Description                              |Impact  |Likelihood|Mitigation                                       |Status     |
|----------|-----------------------------------------|--------|----------|-------------------------------------------------|-----------|
|**TM-001**|Malicious code injection in CI/CD        |Critical|Medium    |Security gates, code review, SAST                |✅ Mitigated|
|**TM-002**|Terraform state file manipulation        |High    |Low       |State locking, encryption, access control        |✅ Mitigated|
|**TM-003**|Container image modification             |High    |Medium    |Image scanning, signing, immutable tags          |✅ Mitigated|
|**TM-004**|Kubernetes manifest tampering            |High    |Low       |GitOps, signed commits, pull request review      |✅ Mitigated|
|**TM-005**|Log file tampering                       |Medium  |Low       |Immutable storage, WORM, separate logging account|✅ Mitigated|
|**TM-006**|Network traffic interception/modification|High    |Low       |TLS 1.3 everywhere, certificate pinning          |✅ Mitigated|

### Repudiation

|Threat    |Description                            |Impact|Likelihood|Mitigation                              |Status     |
|----------|---------------------------------------|------|----------|----------------------------------------|-----------|
|**RP-001**|User denies performing malicious action|Medium|Medium    |Comprehensive audit logging, correlation|✅ Mitigated|
|**RP-002**|Admin denies privilege escalation      |High  |Low       |Immutable logs, Azure AD audit logs     |✅ Mitigated|
|**RP-003**|Lack of deployment traceability        |Medium|Low       |GitOps, deployment tagging, audit trail |✅ Mitigated|
|**RP-004**|No evidence of secret access           |High  |Low       |Key Vault audit logs, access analytics  |✅ Mitigated|

### Information Disclosure

|Threat    |Description                              |Impact  |Likelihood|Mitigation                                       |Status     |
|----------|-----------------------------------------|--------|----------|-------------------------------------------------|-----------|
|**ID-001**|Secrets in source code/logs              |Critical|Medium    |Secret scanning, .gitignore, log sanitization    |✅ Mitigated|
|**ID-002**|Excessive error messages expose internals|Medium  |High      |Generic error messages, proper exception handling|✅ Mitigated|
|**ID-003**|Metadata leakage from container images   |Low     |High      |Minimal base images, .dockerignore               |✅ Mitigated|
|**ID-004**|Unauthorized access to Key Vault secrets |Critical|Low       |RBAC, private endpoints, audit logging           |✅ Mitigated|
|**ID-005**|Sensitive data in Terraform state        |High    |Medium    |Encrypted backend, access control                |✅ Mitigated|
|**ID-006**|API response includes unnecessary data   |Medium  |Medium    |Response filtering, least privilege data         |⚠️ Partial  |
|**ID-007**|Snapshots/backups contain sensitive data |High    |Medium    |Encrypted backups, access control                |✅ Mitigated|

### Denial of Service

|Threat    |Description                               |Impact|Likelihood|Mitigation                                         |Status     |
|----------|------------------------------------------|------|----------|---------------------------------------------------|-----------|
|**DS-001**|DDoS attack on public endpoints           |Medium|High      |Azure DDoS Protection, WAF rate limiting           |✅ Mitigated|
|**DS-002**|Resource exhaustion in AKS                |High  |Medium    |Resource quotas, limits, horizontal pod autoscaling|✅ Mitigated|
|**DS-003**|Log flooding overwhelms storage           |Low   |Medium    |Log sampling, retention policies, quotas           |✅ Mitigated|
|**DS-004**|Malicious container consumes all resources|High  |Low       |Resource limits, pod security policies             |✅ Mitigated|
|**DS-005**|CI/CD pipeline abuse (infinite jobs)      |Medium|Low       |Pipeline timeouts, job limits, approvals           |✅ Mitigated|

### Elevation of Privilege

|Threat    |Description                         |Impact  |Likelihood|Mitigation                                 |Status     |
|----------|------------------------------------|--------|----------|-------------------------------------------|-----------|
|**EP-001**|Container escape to host            |Critical|Low       |Non-root containers, seccomp, AppArmor     |✅ Mitigated|
|**EP-002**|Kubernetes RBAC bypass              |Critical|Low       |RBAC with Azure AD, regular audits         |✅ Mitigated|
|**EP-003**|Privilege escalation via sudo/setuid|High    |Low       |No privileged containers, drop capabilities|✅ Mitigated|
|**EP-004**|Service account abuse               |High    |Medium    |Least privilege, dedicated service accounts|✅ Mitigated|
|**EP-005**|Exploiting vulnerable dependency    |High    |Medium    |Dependency scanning, automated updates     |✅ Mitigated|
|**EP-006**|Azure AD privilege escalation       |Critical|Low       |PIM (just-in-time access), MFA, monitoring |✅ Mitigated|

-----

## 🌳 Attack Trees

### Attack Goal: Gain Unauthorized Access to Production AKS Cluster

```
                    [Compromise AKS Cluster]
                            |
        ┌───────────────────┴───────────────────┐
        │                                       │
   [Credential            [Exploit              [Supply Chain
    Compromise]           Vulnerability]         Attack]
        │                     │                     │
   ┌────┴────┐          ┌────┴────┐           ┌────┴────┐
   │         │          │         │           │         │
[Azure AD] [Service] [Network] [Container] [Malicious] [Compromised]
[Account]  [Account] [Vuln]   [Escape]    [Image]     [Dependency]
   │         │          │         │           │           │
   ├─Phishing ├─Token  ├─Firewall ├─Kernel   ├─Registry  ├─npm/PyPI
   ├─Brute    │ Theft  │ Bypass   │ Exploit  │ Poisoning │ Package
   │ Force    │        │          │          │           │
   └─MFA      └─Key    └─NSG      └─RunC     └─Image     └─Typo-
     Bypass     Leak     Misconfig   Bug       Signing     squatting
```

**Critical Paths (Red Team Focus):**

1. **Azure AD Account Compromise → Kubernetes Admin**
- Probability: Low (MFA + conditional access)
- Impact: Critical
- Mitigation: MFA, PIM, monitoring
1. **Service Account Token Theft → Privilege Escalation**
- Probability: Medium
- Impact: High
- Mitigation: Short-lived tokens, RBAC
1. **Malicious Container Image → Container Escape → Host Access**
- Probability: Low (image scanning)
- Impact: Critical
- Mitigation: Image signing, scanning, runtime security

### Attack Goal: Exfiltrate Secrets from Azure Key Vault

```
                [Steal Secrets from Key Vault]
                            |
        ┌───────────────────┴───────────────┐
        │                                   │
   [Compromise         [Exploit              [Social
    Identity]          Infrastructure]       Engineering]
        │                   │                    │
   ┌────┴────┐         ┌────┴────┐         ┌────┴────┐
   │         │         │         │         │         │
[Managed  [User    [Network  [API       [Admin    [Developer
 Identity] Account] Access]   Vuln]      Creds]    Laptop]
   │         │         │         │         │          │
   ├─Pod     ├─Phishing ├─Private ├─Auth   ├─Phishing ├─Malware
   │ Escape  │         │ Endpoint│ Bypass │          │
   │         │         │ Bypass  │        │          │
   └─RBAC    └─MFA     └─Firewall └─RBAC   └─2FA      └─Keylogger
     Misconfig Bypass    Rule      Bug      Bypass
```

**Critical Paths:**

1. **Phishing → User Account → Key Vault Access**
- Probability: Medium
- Impact: Critical
- Mitigation: MFA, conditional access, least privilege RBAC
1. **Pod Escape → Managed Identity → Key Vault**
- Probability: Low (pod security)
- Impact: Critical
- Mitigation: Pod security standards, RBAC, private endpoints

-----

## 📊 Risk Assessment Matrix

### Risk Calculation

**Risk = Likelihood × Impact**

**Likelihood Scale:**

- **Very Low (1)**: < 5% probability in next 12 months
- **Low (2)**: 5-25% probability
- **Medium (3)**: 25-50% probability
- **High (4)**: 50-75% probability
- **Very High (5)**: > 75% probability

**Impact Scale:**

- **Very Low (1)**: Minimal impact, no data loss
- **Low (2)**: Limited impact, minor data exposure
- **Medium (3)**: Moderate impact, some data exposure
- **High (4)**: Significant impact, major data breach
- **Critical (5)**: Catastrophic, complete system compromise

### Risk Matrix

```
Impact
  5 │ Medium │  High  │  High  │Critical│Critical│
  4 │  Low   │ Medium │  High  │  High  │Critical│
  3 │  Low   │  Low   │ Medium │  High  │  High  │
  2 │Very Low│  Low   │  Low   │ Medium │  High  │
  1 │Very Low│Very Low│  Low   │  Low   │ Medium │
    └────────┴────────┴────────┴────────┴────────┘
      1        2        3        4        5
                    Likelihood
```

### Top 10 Risks (Prioritized)

|ID       |Threat                                        |Likelihood|Impact|Risk Score|Status     |
|---------|----------------------------------------------|----------|------|----------|-----------|
|**R-001**|Supply chain attack via compromised dependency|3         |5     |15 (High) |✅ Mitigated|
|**R-002**|Credential compromise (Azure AD account)      |3         |5     |15 (High) |✅ Mitigated|
|**R-003**|Container escape to host system               |2         |5     |10 (High) |✅ Mitigated|
|**R-004**|Secrets leaked in source code/logs            |3         |4     |12 (High) |✅ Mitigated|
|**R-005**|Insider threat - malicious developer          |2         |5     |10 (High) |⚠️ Partial  |
|**R-006**|Zero-day in Kubernetes                        |2         |5     |10 (High) |⚠️ Partial  |
|**R-007**|DDoS attack on public endpoints               |4         |3     |12 (High) |✅ Mitigated|
|**R-008**|Unauthorized Key Vault access                 |2         |5     |10 (High) |✅ Mitigated|
|**R-009**|CI/CD pipeline compromise                     |2         |4     |8 (Medium)|✅ Mitigated|
|**R-010**|Misconfigured network security group          |2         |4     |8 (Medium)|✅ Mitigated|

-----

## 🛡️ Security Controls

### Preventive Controls

|Control ID|Control                     |Threats Addressed|Layer      |
|----------|----------------------------|-----------------|-----------|
|**PC-001**|Azure AD with MFA           |ST-001, EP-006   |Identity   |
|**PC-002**|Private AKS cluster         |Multiple         |Network    |
|**PC-003**|Network policies (Calico)   |DS-002, EP-001   |Platform   |
|**PC-004**|Pod Security Standards      |EP-001, EP-003   |Platform   |
|**PC-005**|Azure Key Vault             |ID-001, ID-004   |Data       |
|**PC-006**|Image scanning (Trivy, Snyk)|R-001, TM-003    |Application|
|**PC-007**|SAST/DAST in CI/CD          |TM-001, EP-005   |Application|
|**PC-008**|Encryption at rest/transit  |ID-005, TM-006   |Data       |
|**PC-009**|RBAC everywhere             |EP-002, EP-004   |Identity   |
|**PC-010**|Private endpoints           |ID-004, R-008    |Network    |

### Detective Controls

|Control ID|Control                     |Threats Addressed|Layer      |
|----------|----------------------------|-----------------|-----------|
|**DC-001**|Azure Sentinel SIEM         |All threats      |Monitoring |
|**DC-002**|Microsoft Defender for Cloud|Multiple         |Monitoring |
|**DC-003**|Audit logging (90 days)     |RP-001, RP-002   |Monitoring |
|**DC-004**|Runtime security (Falco)    |EP-001, EP-003   |Platform   |
|**DC-005**|Container Insights          |DS-002, DS-004   |Monitoring |
|**DC-006**|Anomaly detection           |ST-001, EP-006   |Identity   |
|**DC-007**|Secret scanning             |ID-001           |Application|
|**DC-008**|Vulnerability scanning      |R-001, EP-005    |Application|

### Corrective Controls

|Control ID|Control                              |Threats Addressed|Layer     |
|----------|-------------------------------------|-----------------|----------|
|**CC-001**|Automated incident response playbooks|All threats      |Monitoring|
|**CC-002**|Automated patch management           |R-006, EP-005    |Platform  |
|**CC-003**|Backup and recovery                  |DS-003, TM-002   |Data      |
|**CC-004**|Secret rotation                      |ST-002, ST-003   |Data      |
|**CC-005**|Disaster recovery procedures         |Multiple         |All       |

-----

## ⚠️ Residual Risks

Even with all controls in place, some residual risks remain:

### Accepted Risks

|Risk      |Description                            |Justification                    |Monitoring                                       |
|----------|---------------------------------------|---------------------------------|-------------------------------------------------|
|**AR-001**|Zero-day vulnerabilities               |Cannot prevent unknown exploits  |Daily vulnerability scanning, threat intelligence|
|**AR-002**|Sophisticated nation-state attacks     |Cost vs. benefit of protection   |Enhanced monitoring, regular audits              |
|**AR-003**|Determined insider with high privileges|Cannot eliminate all insider risk|Separation of duties, audit logging              |
|**AR-004**|Social engineering of administrators   |Human factor always present      |Security awareness training, MFA                 |
|**AR-005**|Azure platform vulnerabilities         |Shared responsibility model      |Monitor Azure advisories, maintain patches       |

### Risks Under Review

|Risk      |Description                           |Planned Mitigation                  |Timeline|
|----------|--------------------------------------|------------------------------------|--------|
|**RR-001**|Third-party integration security      |Enhanced vendor security assessment |Q1 2025 |
|**RR-002**|Advanced persistent threats           |EDR implementation                  |Q2 2025 |
|**RR-003**|Quantum computing threat to encryption|Post-quantum cryptography evaluation|2026    |

-----

## 🔍 Threat Intelligence

### Intelligence Sources

- **Microsoft Security Response Center (MSRC)**
- **CISA Known Exploited Vulnerabilities (KEV)**
- **CVE/NVD databases**
- **Cloud security advisories (Azure, Kubernetes)**
- **Container security bulletins**
- **OWASP Top 10**
- **SANS Internet Storm Center**

### Current Threat Landscape (December 2024)

**High Priority Threats:**

1. **Supply Chain Attacks**
- Increased targeting of npm, PyPI packages
- Typosquatting campaigns
- **Action**: Enhanced dependency scanning, SBOM generation
1. **Container Escapes**
- New Kubernetes vulnerabilities discovered quarterly
- RunC/containerd exploits
- **Action**: Runtime security monitoring, rapid patching
1. **Cloud Credential Theft**
- Targeting managed identities and service principals
- Token theft from CI/CD
- **Action**: Short-lived tokens, just-in-time access
1. **Ransomware**
- Targeting cloud infrastructure
- Backup encryption/deletion
- **Action**: Immutable backups, offline copies

-----

## 🔄 Review and Updates

### Review Schedule

- **Monthly**: Threat intelligence review
- **Quarterly**: Full threat model review
- **Annually**: Comprehensive security audit
- **Ad-hoc**: After major incidents or architecture changes

### Change Log

|Version|Date      |Changes             |Reviewer     |
|-------|----------|--------------------|-------------|
|1.0    |2024-12-21|Initial threat model|Security Team|

### Next Review Date

**Scheduled:** March 21, 2025

### Stakeholders

- **Owner**: Security Team
- **Contributors**: Platform Engineering, DevOps, Development Teams
- **Reviewers**: CISO, External Security Consultant

-----

## 📚 References

- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Microsoft STRIDE](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [NIST SP 800-30 - Risk Assessment](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)

-----

**Document Control:**

- **Classification**: Internal
- **Distribution**: Security team, Engineering leads, CISO
- **Retention**: 5 years
- **Review Frequency**: Quarterly

-----

*This threat model is a living document and should be updated as the system evolves, new threats emerge, or security incidents occur.*
