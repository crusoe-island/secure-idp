# Security Guide - Crusoe IDP

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Owner:** Security Team  
**Status:** Active

-----

## 📋 Table of Contents

- [Introduction](#introduction)
- [Security Roles and Responsibilities](#security-roles-and-responsibilities)
- [Getting Started Securely](#getting-started-securely)
- [Authentication and Access Control](#authentication-and-access-control)
- [Secrets Management](#secrets-management)
- [Secure Development Practices](#secure-development-practices)
- [Container Security](#container-security)
- [Infrastructure as Code Security](#infrastructure-as-code-security)
- [Network Security Guidelines](#network-security-guidelines)
- [Data Protection](#data-protection)
- [CI/CD Pipeline Security](#cicd-pipeline-security)
- [Kubernetes Security](#kubernetes-security)
- [Incident Response](#incident-response)
- [Compliance and Auditing](#compliance-and-auditing)
- [Security Tools Reference](#security-tools-reference)
- [Common Security Mistakes](#common-security-mistakes)
- [Security Checklist](#security-checklist)
- [FAQ](#faq)

-----

## 🎯 Introduction

### Purpose

This guide provides practical security guidance for everyone using the Crusoe Internal Developer Platform (IDP). Whether you’re a developer deploying applications, an operator managing infrastructure, or a security professional auditing the platform, this guide will help you work securely and effectively.

### Audience

- **Developers**: Building and deploying applications
- **Platform Engineers**: Managing infrastructure and platform services
- **Security Team**: Implementing security controls and responding to incidents
- **DevOps Engineers**: Operating CI/CD pipelines
- **New Team Members**: Getting started with the platform

### How to Use This Guide

```
For quick reference:
  → Check the Security Checklist at the end
  → Search for specific topics in the TOC
  → Review Common Security Mistakes

For comprehensive guidance:
  → Read section by section
  → Follow the examples
  → Complete the security training

For incident response:
  → Jump to Incident Response section
  → Follow the runbooks
  → Contact security team
```

### Security Philosophy

> **“Security is everyone’s responsibility, but we make it easy to do the right thing.”**

Our platform is designed with:

- **Security by default**: Secure configurations out of the box
- **Shift left**: Security early in the development process
- **Defense-in-depth**: Multiple layers of protection
- **Zero trust**: Verify everything, trust nothing
- **Least privilege**: Minimum necessary access

-----

## 👥 Security Roles and Responsibilities

### Security Team

**Responsibilities:**

- Define security policies and standards
- Conduct security assessments and audits
- Respond to security incidents
- Provide security training and guidance
- Manage security tooling

**Contact:**

- Email: security@crusoe-island.com
- Slack: #security
- Emergency: +XX-XXX-XXX-XXXX (24/7)

### Platform Engineering Team

**Responsibilities:**

- Implement security controls in infrastructure
- Maintain platform security posture
- Configure and monitor security tools
- Assist with security incidents
- Keep platform components patched and updated

**Contact:**

- Email: platform@crusoe-island.com
- Slack: #platform

### Developers

**Responsibilities:**

- Write secure code
- Handle secrets properly (use Key Vault)
- Fix security vulnerabilities in dependencies
- Follow secure development practices
- Report security concerns

### DevOps Engineers

**Responsibilities:**

- Secure CI/CD pipelines
- Implement security gates
- Manage deployment credentials
- Monitor pipeline security alerts

### All Team Members

**Responsibilities:**

- Complete security awareness training
- Use strong, unique passwords
- Enable MFA on all accounts
- Report suspicious activity
- Follow the principle of least privilege

-----

## 🚀 Getting Started Securely

### Day 1: Onboarding Security Checklist

```yaml
☐ Identity Setup
  ☐ Azure AD account created
  ☐ MFA enabled (Microsoft Authenticator preferred)
  ☐ Backup MFA method configured
  ☐ Password meets requirements (14+ chars, complexity)
  ☐ Conditional Access policies acknowledged

☐ Access Provisioning
  ☐ Assigned to correct Azure AD groups
  ☐ Kubernetes RBAC roles assigned
  ☐ Least privilege access verified
  ☐ No standing admin privileges (PIM only)

☐ Workstation Security
  ☐ Company laptop with full disk encryption
  ☐ Endpoint protection (Microsoft Defender) running
  ☐ OS and software up to date
  ☐ Screen lock enabled (15 min timeout)
  ☐ No root/admin rights on personal machine

☐ Tools and Training
  ☐ Security awareness training completed
  ☐ Azure CLI installed and configured
  ☐ kubectl installed and configured
  ☐ Pre-commit hooks installed (see below)
  ☐ Read security documentation
  ☐ Know how to report security issues

☐ Communication Channels
  ☐ Joined #security Slack channel
  ☐ Subscribed to security announcements
  ☐ Emergency contact information saved
```

### Setting Up Your Development Environment

#### 1. Install Pre-Commit Hooks

Pre-commit hooks catch security issues before they reach version control.

```bash
# Install pre-commit
pip install pre-commit

# Navigate to repository
cd /path/to/secure-idp

# Install hooks
pre-commit install

# Test hooks
pre-commit run --all-files
```

**What gets checked:**

- ✅ Secrets detection (detect-secrets)
- ✅ Terraform validation and security (tfsec)
- ✅ YAML linting
- ✅ Trailing whitespace
- ✅ Large files
- ✅ Private keys

#### 2. Configure Git Signing

Sign your commits to verify authenticity.

```bash
# Generate GPG key
gpg --full-generate-key

# List keys
gpg --list-secret-keys --keyid-format=long

# Configure Git
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true

# Add to GitHub
gpg --armor --export YOUR_KEY_ID
# Paste into GitHub Settings → SSH and GPG keys
```

#### 3. Azure CLI Authentication

```bash
# Login with Azure AD
az login

# Verify account
az account show

# Set subscription
az subscription set --subscription "Production"

# Get AKS credentials (uses your Azure AD identity)
az aks get-credentials \
  --resource-group rg-aks-prod \
  --name aks-idp-prod \
  --overwrite-existing

# Verify access (should use Azure AD)
kubectl get nodes
```

**Important:**

- ❌ Never use service principal credentials locally
- ❌ Never share kubeconfig files
- ✅ Always use `az login` for authentication
- ✅ Credentials expire and refresh automatically

-----

## 🔐 Authentication and Access Control

### Multi-Factor Authentication (MFA)

**Requirements:**

- MFA is **required** for all accounts
- No exceptions (including service accounts)

**Setup Microsoft Authenticator (Recommended):**

```
1. Install Microsoft Authenticator app
   iOS: App Store
   Android: Google Play Store

2. Login to portal.azure.com
   → Profile → Security info
   → Add method → Authenticator app

3. Follow setup wizard
   → Scan QR code with app
   → Verify setup

4. Configure backup method
   → Phone number for SMS (backup only)
```

**Using MFA:**

```bash
# Azure CLI login with MFA
az login

# Browser opens → Enter password → MFA prompt
# Approve in Microsoft Authenticator

# Token cached for ~90 days
# Refresh when needed: az account get-access-token
```

### Conditional Access

Your access is subject to conditional access policies:

**Policies Applied:**

|Policy                  |Condition              |Action                        |
|------------------------|-----------------------|------------------------------|
|Require MFA             |All users, all apps    |Require MFA                   |
|Block Legacy Auth       |All users              |Block                         |
|Require Compliant Device|Accessing production   |Require compliant device      |
|Geographic Restriction  |Outside allowed regions|Block or MFA                  |
|Risk-Based              |High sign-in risk      |Block                         |
|Admin Protection        |Admin roles            |Require MFA + compliant device|

**What This Means:**

- ✅ You’ll need MFA for every login
- ✅ Your device must be company-managed for production access
- ⚠️ VPN may be required for certain locations
- ❌ Old authentication methods (SMTP, POP3) are blocked

### Privileged Identity Management (PIM)

**Zero Standing Privileges:**

No one has permanent admin rights. Instead:

```
Regular Access:
  Developer → Can deploy to dev/staging
  Platform Engineer → Can manage infrastructure
  Security Team → Can view logs and alerts

Admin Access (Time-Limited):
  Request via PIM → Approval → Active for max 8 hours
```

**How to Request Admin Access:**

```bash
# Option 1: Azure Portal
1. Go to portal.azure.com
2. Search "Privileged Identity Management"
3. My Roles → Activate
4. Select role (e.g., "AKS Cluster Admin")
5. Provide justification (e.g., "Incident INC-1234")
6. Submit (auto-approved for P0 incidents)

# Option 2: Azure CLI (if enabled)
az rest --method post \
  --url "https://api.azuread.microsoft.com/beta/privilegedAccess/azureResources/roleAssignmentRequests" \
  --body '{
    "roleDefinitionId": "ROLE_ID",
    "resourceId": "RESOURCE_ID",
    "justification": "Incident INC-1234",
    "schedule": {
      "type": "Once",
      "duration": "PT4H"
    }
  }'
```

**Best Practices:**

- ✅ Request only when needed (just-in-time)
- ✅ Use shortest duration possible
- ✅ Always provide ticket number in justification
- ✅ Deactivate when done (don’t wait for expiration)
- ❌ Don’t request “just in case”

### Role-Based Access Control (RBAC)

**Azure AD Groups:**

|Group                   |Access Level                                |Use Case             |
|------------------------|--------------------------------------------|---------------------|
|`IDP-Developers`        |Read: All, Write: Dev namespaces            |Daily development    |
|`IDP-Platform-Engineers`|Read/Write: Infrastructure                  |Platform management  |
|`IDP-Security-Team`     |Read: All resources, Write: Security configs|Security operations  |
|`IDP-Prod-Deployers`    |Write: Production namespaces (via CI/CD)    |Automated deployments|

**Kubernetes RBAC:**

```yaml
# Developer access to dev namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developers
  namespace: dev
subjects:
- kind: Group
  name: "IDP-Developers"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit  # Can create/update but not delete namespace
  apiGroup: rbac.authorization.k8s.io
```

**Checking Your Access:**

```bash
# What can I do in this namespace?
kubectl auth can-i --list --namespace=production

# Can I create deployments in production?
kubectl auth can-i create deployments --namespace=production

# Can I delete pods?
kubectl auth can-i delete pods --namespace=production
```

-----

## 🔑 Secrets Management

### The Golden Rule

> **NEVER commit secrets to Git. Ever. No exceptions.**

### Using Azure Key Vault

**All secrets must be stored in Azure Key Vault.**

#### Storing Secrets

```bash
# Create a secret
az keyvault secret set \
  --vault-name kv-idp-prod \
  --name "database-password" \
  --value "SuperSecretP@ssw0rd123!" \
  --description "Production database password"

# View secret (requires permission)
az keyvault secret show \
  --vault-name kv-idp-prod \
  --name "database-password" \
  --query "value" \
  -o tsv

# List secrets (metadata only)
az keyvault secret list \
  --vault-name kv-idp-prod
```

#### Accessing Secrets from Applications

**Method 1: CSI Driver (Recommended for Kubernetes)**

```yaml
# SecretProviderClass
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: app-secrets
  namespace: production
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    userAssignedIdentityID: "CLIENT_ID"
    keyvaultName: "kv-idp-prod"
    objects: |
      array:
        - |
          objectName: database-password
          objectType: secret
          objectVersion: ""
        - |
          objectName: api-key
          objectType: secret
    tenantId: "TENANT_ID"

---
# Pod using secrets
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: production
spec:
  serviceAccountName: app-sa
  containers:
  - name: app
    image: myapp:1.0.0
    volumeMounts:
    - name: secrets-store
      mountPath: "/mnt/secrets"
      readOnly: true
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: database-password  # Synced from Key Vault
          key: password
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "app-secrets"
```

**Method 2: Azure SDK (for non-Kubernetes apps)**

```python
# Python example
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Use Managed Identity (no credentials in code!)
credential = DefaultAzureCredential()
client = SecretClient(
    vault_url="https://kv-idp-prod.vault.azure.net/",
    credential=credential
)

# Get secret
secret = client.get_secret("database-password")
db_password = secret.value

# Use the secret
# ... connect to database ...
```

**Method 3: Environment Variables (CI/CD)**

```yaml
# Azure DevOps Pipeline
steps:
- task: AzureKeyVault@2
  inputs:
    azureSubscription: 'Production'
    KeyVaultName: 'kv-idp-prod'
    SecretsFilter: 'database-password,api-key'
    RunAsPreJob: true

- script: |
    echo "Connecting to database..."
    # Secrets available as environment variables
    # DATABASE_PASSWORD and API_KEY
  env:
    DB_PASS: $(database-password)
```

### Secret Rotation

**Automatic Rotation Schedule:**

|Secret Type              |Rotation Frequency   |Process                    |
|-------------------------|---------------------|---------------------------|
|Database passwords       |90 days              |Automated (Azure Key Vault)|
|API keys                 |90 days              |Manual + notification      |
|Certificates             |30 days before expiry|Automated (cert-manager)   |
|SSH keys                 |180 days             |Manual + notification      |
|Service principal secrets|90 days              |Automated                  |

**Rotation Notifications:**

```
30 days before expiration:
  → Email to secret owner
  → Slack notification in #security
  
7 days before expiration:
  → Daily email reminder
  → Ticket created in Jira
  
Expired:
  → Secret marked as expired (still accessible for 7 days)
  → Incident created
  → Manager notified
```

### What NOT to Do

```bash
# ❌ WRONG: Secrets in code
db_password = "SuperSecret123!"

# ❌ WRONG: Secrets in config files
database:
  password: SuperSecret123!

# ❌ WRONG: Secrets in environment variables (in Dockerfile)
ENV DB_PASSWORD=SuperSecret123!

# ❌ WRONG: Secrets in Git (even if deleted later)
git commit -m "Add config" config.yaml  # Contains password

# ❌ WRONG: Hardcoded in Terraform
resource "azurerm_sql_server" "main" {
  administrator_login_password = "SuperSecret123!"
}

# ✅ CORRECT: Reference from Key Vault
data "azurerm_key_vault_secret" "db_password" {
  name         = "database-password"
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_sql_server" "main" {
  administrator_login_password = data.azurerm_key_vault_secret.db_password.value
}
```

### Secret Scanning

**Automated Secret Detection:**

Pre-commit hooks and CI/CD pipelines automatically scan for secrets.

**If you accidentally commit a secret:**

```bash
# 1. IMMEDIATELY rotate the secret
az keyvault secret set \
  --vault-name kv-idp-prod \
  --name "compromised-secret" \
  --value "NewSecretValue456!"

# 2. Contact security team
#    Email: security@crusoe-island.com
#    Slack: #security

# 3. Remove from Git history
#    (Security team will help with this)

# 4. Document incident
#    Create ticket in incident tracker
```

-----

## 💻 Secure Development Practices

### Code Security

#### 1. Input Validation

**Always validate and sanitize user input.**

```python
# ❌ WRONG: No validation
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

# ✅ CORRECT: Parameterized query
def get_user(user_id):
    # Validate input
    if not isinstance(user_id, int) or user_id < 0:
        raise ValueError("Invalid user ID")
    
    # Parameterized query prevents SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
```

```javascript
// ❌ WRONG: Unescaped output (XSS vulnerability)
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Results for: ${query}</h1>`);
});

// ✅ CORRECT: Escaped output
app.get('/search', (req, res) => {
  const query = validator.escape(req.query.q);
  res.render('search', { query: query });
});

// Or use a template engine that auto-escapes
```

#### 2. Authentication and Authorization

```python
# ❌ WRONG: No authentication
@app.route('/api/user/<user_id>')
def get_user(user_id):
    return User.query.get(user_id)

# ✅ CORRECT: Authentication + Authorization
@app.route('/api/user/<user_id>')
@requires_auth  # Must be logged in
def get_user(user_id):
    current_user = get_current_user()
    
    # Authorization: Can only access own data (unless admin)
    if str(current_user.id) != user_id and not current_user.is_admin:
        abort(403)
    
    return User.query.get(user_id)
```

#### 3. Cryptography

**Use established libraries. Don’t roll your own crypto.**

```python
# ❌ WRONG: Weak hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# ❌ WRONG: Weak algorithm
from Crypto.Cipher import DES
cipher = DES.new(key)

# ✅ CORRECT: Strong password hashing
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)

# Verify
try:
    ph.verify(hash, password)
except:
    # Invalid password
    pass

# ✅ CORRECT: Strong encryption
from cryptography.fernet import Fernet
key = Fernet.generate_key()  # Store in Key Vault!
f = Fernet(key)
encrypted = f.encrypt(b"Secret data")
decrypted = f.decrypt(encrypted)
```

#### 4. Error Handling

**Don’t leak sensitive information in error messages.**

```python
# ❌ WRONG: Detailed error to user
try:
    db.connect(host, user, password)
except Exception as e:
    return f"Database connection failed: {str(e)}", 500

# ✅ CORRECT: Generic error to user, detailed log
import logging
try:
    db.connect(host, user, password)
except Exception as e:
    logging.error(f"Database connection failed: {e}", exc_info=True)
    return "An error occurred. Please try again later.", 500
```

#### 5. Dependency Management

```bash
# Check for vulnerabilities
pip-audit
npm audit

# Update dependencies
pip install -U package-name
npm update package-name

# Review security advisories
gh browse -- /security/advisories
```

### Secure Code Review Checklist

```yaml
☐ Input Validation
  ☐ All user input validated
  ☐ Whitelist validation (not blacklist)
  ☐ Length limits enforced
  ☐ Type checking performed

☐ Authentication/Authorization
  ☐ Authentication required on all endpoints
  ☐ Authorization checked (can user access this resource?)
  ☐ Session management secure
  ☐ Logout properly implemented

☐ Cryptography
  ☐ Secrets stored in Key Vault
  ☐ Strong algorithms used (AES-256, RSA-2048+)
  ☐ TLS 1.3 for all connections
  ☐ Certificates validated

☐ Error Handling
  ☐ Generic errors to users
  ☐ Detailed errors logged securely
  ☐ No stack traces in production
  ☐ No sensitive data in logs

☐ Dependencies
  ☐ No known vulnerabilities
  ☐ Dependencies up to date
  ☐ Licenses reviewed
  ☐ SBOM generated

☐ Data Protection
  ☐ Sensitive data encrypted at rest
  ☐ Sensitive data encrypted in transit
  ☐ PII handling compliant
  ☐ Data retention policies followed
```

-----

## 🐳 Container Security

### Building Secure Container Images

#### 1. Use Minimal Base Images

```dockerfile
# ❌ AVOID: Full OS image
FROM ubuntu:22.04

# ⚠️ BETTER: Slim image
FROM python:3.11-slim

# ✅ BEST: Distroless (no shell, minimal attack surface)
FROM gcr.io/distroless/python3-debian12
```

#### 2. Multi-Stage Builds

```dockerfile
# ✅ CORRECT: Multi-stage build
# Stage 1: Build
FROM node:18 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# Stage 2: Runtime (only includes built artifacts)
FROM gcr.io/distroless/nodejs18-debian12
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
USER nonroot
EXPOSE 3000
CMD ["dist/index.js"]
```

**Benefits:**

- ✅ Smaller image size
- ✅ No build tools in production image
- ✅ Reduced attack surface

#### 3. Non-Root User

```dockerfile
# ❌ WRONG: Running as root
FROM python:3.11-slim
COPY app.py .
CMD ["python", "app.py"]

# ✅ CORRECT: Non-root user
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set up app directory with correct permissions
WORKDIR /app
COPY --chown=appuser:appuser app.py .

# Switch to non-root user
USER appuser

CMD ["python", "app.py"]
```

#### 4. Security Best Practices

```dockerfile
# ✅ COMPLETE EXAMPLE: Secure Dockerfile

# Use specific version (not :latest)
FROM python:3.11.7-slim-bookworm AS builder

# Install only necessary packages
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11.7-slim-bookworm

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set up application
WORKDIR /app
COPY --chown=appuser:appuser . .

# Security: Drop all capabilities, read-only filesystem
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Expose port
EXPOSE 8000

# Run application
CMD ["python", "app.py"]
```

#### 5. .dockerignore

```
# .dockerignore - Prevent secrets from being copied

# Git
.git
.gitignore

# Secrets and credentials
*.pem
*.key
*.p12
*.pfx
.env
.env.*
secrets/
credentials/

# Development files
node_modules/
venv/
__pycache__/
*.pyc
.pytest_cache/
.coverage

# Documentation
README.md
docs/

# CI/CD
.github/
.gitlab-ci.yml
azure-pipelines.yml

# IDE
.vscode/
.idea/
*.swp
*.swo
```

### Container Scanning

**All images must pass security scanning before deployment.**

```yaml
# GitHub Actions example
name: Container Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build image
      run: docker build -t myapp:${{ github.sha }} .
    
    - name: Scan with Trivy
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: myapp:${{ github.sha }}
        severity: 'CRITICAL,HIGH'
        exit-code: '1'  # Fail build on findings
    
    - name: Scan with Snyk
      uses: snyk/actions/docker@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        image: myapp:${{ github.sha }}
        args: --severity-threshold=high
```

**Scan Results Interpretation:**

```
Severity    Action
─────────────────────────────────────────────
CRITICAL    🛑 BLOCK deployment
            Must fix before proceeding

HIGH        ⚠️  WARN and create ticket
            Fix within 7 days

MEDIUM      ℹ️  LOG
            Fix within 30 days

LOW         ℹ️  LOG
            Fix in next maintenance cycle
```

### Image Signing

**All production images must be signed.**

```bash
# Sign image with Cosign
cosign sign --key cosign.key \
  acridpprod.azurecr.io/myapp:1.0.0

# Verify signature
cosign verify --key cosign.pub \
  acridpprod.azurecr.io/myapp:1.0.0
```

**Admission Controller** enforces that only signed images can be deployed to production.

-----

## 🏗️ Infrastructure as Code Security

### Terraform Security

#### 1. State File Security

```hcl
# ✅ CORRECT: Remote state with encryption
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "sttfstateprod"
    container_name       = "tfstate"
    key                  = "production.terraform.tfstate"
    
    # Encryption enabled on storage account
    # Access via Managed Identity
  }
}
```

**State File Contains Sensitive Data:**

- Passwords (even if from Key Vault)
- Private keys
- Connection strings
- API tokens

**Protect State Files:**

- ✅ Store in encrypted Azure Storage
- ✅ Enable versioning
- ✅ Enable soft delete
- ✅ Restrict access (RBAC)
- ❌ Never commit to Git
- ❌ Never store locally long-term

#### 2. Secrets in Terraform

```hcl
# ❌ WRONG: Hardcoded secret
resource "azurerm_sql_server" "main" {
  administrator_login_password = "P@ssw0rd123!"
}

# ✅ CORRECT: From Key Vault
data "azurerm_key_vault_secret" "sql_admin_password" {
  name         = "sql-admin-password"
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_sql_server" "main" {
  administrator_login_password = data.azurerm_key_vault_secret.sql_admin_password.value
}

# ✅ ALSO CORRECT: Random password stored in Key Vault
resource "random_password" "sql_admin" {
  length  = 32
  special = true
}

resource "azurerm_key_vault_secret" "sql_admin_password" {
  name         = "sql-admin-password"
  value        = random_password.sql_admin.result
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_sql_server" "main" {
  administrator_login_password = azurerm_key_vault_secret.sql_admin_password.value
}
```

#### 3. Terraform Security Scanning

```bash
# Scan Terraform code
tfsec .

# Example output:
# Result #1 HIGH Storage account does not use latest TLS version
# ──────────────────────────────────────────────────────
#  storage.tf:15-20
# ──────────────────────────────────────────────────────
#  15   resource "azurerm_storage_account" "main" {
#  16     name                     = "mystorageaccount"
#  17     resource_group_name      = azurerm_resource_group.main.name
#  18     location                 = azurerm_resource_group.main.location
#  19     min_tls_version          = "TLS1_0"  # ❌ WRONG
#  20   }
```

**Fix:**

```hcl
resource "azurerm_storage_account" "main" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  min_tls_version          = "TLS1_3"  # ✅ CORRECT
  enable_https_traffic_only = true
  
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    virtual_network_subnet_ids = [
      azurerm_subnet.private_endpoints.id
    ]
  }
}
```

#### 4. Terraform Best Practices

```hcl
# ✅ CORRECT: Comprehensive secure configuration

resource "azurerm_key_vault" "main" {
  name                = "kv-idp-prod"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  
  # Security configurations
  sku_name                      = "premium"  # HSM-backed keys
  enabled_for_disk_encryption   = false      # Explicit
  enabled_for_deployment        = false      # Explicit
  enabled_for_template_deployment = false    # Explicit
  enable_rbac_authorization     = true       # Use RBAC not access policies
  public_network_access_enabled = false      # No public access
  purge_protection_enabled      = true       # Prevent deletion
  soft_delete_retention_days    = 90         # Retention
  
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
  
  # Tags for tracking
  tags = {
    Environment = "Production"
    CostCenter  = "Platform"
    Owner       = "security-team"
    Compliance  = "Required"
  }
}
```

-----

## 🌐 Network Security Guidelines

### Network Policies

**Default Deny Policy** is enforced in all namespaces.

```yaml
# Applied automatically to all namespaces
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
```

**To allow traffic, you must create explicit policies:**

```yaml
# Example: Allow frontend to backend
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
```

### Egress Control

**All internet-bound traffic goes through Azure Firewall.**

**Allowed Destinations (Default):**

- Azure services (management.azure.com, etc.)
- Package managers (pypi.org, npmjs.org)
- Container registries (mcr.microsoft.com, ghcr.io)
- GitHub (github.com, api.github.com)

**To Request New Destination:**

```yaml
# Create ticket with details:
Title: "Firewall Rule Request: Allow access to external-api.com"

Justification: 
  "Application needs to call third-party payment API"

Details:
  - FQDN: api.stripe.com
  - Protocol: HTTPS
  - Port: 443
  - Source: production namespace, payment-service pod
  - Business Owner: payments-team@crusoe-island.com
  - Risk Assessment: Low (established vendor, encrypted traffic)

Security Review:
  - Vendor reputation: ✓ (Stripe is PCI compliant)
  - Data sensitivity: High (payment information)
  - Alternative: None (required for business)
  - Monitoring: Enable detailed logging
```

-----

## 🔐 Data Protection

### Data Classification

**All data must be classified:**

|Classification      |Examples                  |Encryption  |Access      |Retention     |
|--------------------|--------------------------|------------|------------|--------------|
|**Highly Sensitive**|Passwords, keys, PII      |Always (CMK)|Minimal     |90 days       |
|**Confidential**    |Source code, customer data|Always (PMK)|Need-to-know|Per compliance|
|**Internal**        |Logs, metrics             |At rest     |Role-based  |90 days       |
|**Public**          |Documentation             |In transit  |Public      |Indefinite    |

### Encryption

**Encryption at Rest:**

All data is encrypted at rest by default in Azure:

- ✅ Azure Storage: AES-256
- ✅ Azure SQL: TDE (Transparent Data Encryption)
- ✅ Azure Disks: Encryption at host
- ✅ Kubernetes Secrets: etcd encryption

**Encryption in Transit:**

```yaml
# ✅ CORRECT: TLS everywhere

# Ingress (external)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - app.crusoe-island.com
    secretName: app-tls-cert

# Service (internal)
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-internal: "true"
spec:
  ports:
  - port: 443  # Use HTTPS internally too
    targetPort: 8443
```

### PII Handling

**Personal Identifiable Information (PII) requires special handling:**

```python
# ✅ CORRECT: PII handling

import hashlib
import hmac

class PIIHandler:
    def __init__(self):
        # Get encryption key from Key Vault
        self.key = get_key_vault_secret("pii-encryption-key")
    
    def encrypt_pii(self, data: str) -> str:
        """Encrypt PII before storage"""
        from cryptography.fernet import Fernet
        f = Fernet(self.key)
        return f.encrypt(data.encode()).decode()
    
    def decrypt_pii(self, encrypted: str) -> str:
        """Decrypt PII for authorized use"""
        from cryptography.fernet import Fernet
        f = Fernet(self.key)
        return f.decrypt(encrypted.encode()).decode()
    
    def hash_pii(self, data: str) -> str:
        """Hash PII for non-reversible storage (e.g., user ID lookup)"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            data.encode(),
            self.key,
            100000
        ).hex()
    
    def anonymize_for_logging(self, email: str) -> str:
        """Anonymize PII for logging"""
        # user@example.com → u***r@e***e.com
        user, domain = email.split('@')
        return f"{user[0]}***{user[-1]}@{domain[0]}***{domain.split('.')[-1]}"

# Usage
pii = PIIHandler()

# Store in database (encrypted)
encrypted_email = pii.encrypt_pii("user@example.com")
db.store(encrypted_email)

# Log (anonymized)
logger.info(f"User logged in: {pii.anonymize_for_logging('user@example.com')}")
```

**PII in Logs:**

```python
# ❌ WRONG: PII in logs
logger.info(f"User {user.email} logged in from {ip_address}")

# ✅ CORRECT: Anonymized logging
logger.info(f"User {user.hashed_id} logged in from {anonymize_ip(ip_address)}")
```

-----

## 🚀 CI/CD Pipeline Security

### Secure Pipeline Principles

1. **Least Privilege**: Pipelines should have minimum necessary permissions
1. **Secrets in Key Vault**: Never in pipeline variables
1. **Security Gates**: Automated security checks before deployment
1. **Approval Gates**: Manual approval for production
1. **Audit Trail**: Complete log of all deployments

### Azure DevOps Pipeline Security

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
    - main
    - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: 'production-secrets'  # Linked to Key Vault

stages:
- stage: SecurityScans
  jobs:
  - job: SAST
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.11'
    
    # Secret scanning
    - script: |
        pip install detect-secrets
        detect-secrets scan --baseline .secrets.baseline
      displayName: 'Secret Scan'
    
    # Dependency scanning
    - script: |
        pip install pip-audit
        pip-audit --desc -r requirements.txt
      displayName: 'Dependency Scan'
    
    # SAST with Semgrep
    - script: |
        pip install semgrep
        semgrep --config=auto --error
      displayName: 'SAST Scan'
  
  - job: ContainerScan
    steps:
    - task: Docker@2
      inputs:
        command: 'build'
        Dockerfile: 'Dockerfile'
        tags: '$(Build.BuildId)'
    
    # Trivy scan
    - script: |
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
          aquasec/trivy image --severity CRITICAL,HIGH \
          --exit-code 1 myapp:$(Build.BuildId)
      displayName: 'Container Vulnerability Scan'

- stage: Build
  dependsOn: SecurityScans
  condition: succeeded()
  jobs:
  - job: BuildAndPush
    steps:
    # Build and push to ACR
    - task: Docker@2
      inputs:
        containerRegistry: 'ACR-Production'
        repository: 'myapp'
        command: 'buildAndPush'
        Dockerfile: 'Dockerfile'
        tags: |
          $(Build.BuildId)
          latest

- stage: DeployDev
  dependsOn: Build
  condition: succeeded()
  jobs:
  - deployment: DeployDev
    environment: 'development'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: KubernetesManifest@0
            inputs:
              action: 'deploy'
              kubernetesServiceConnection: 'AKS-Dev'
              namespace: 'dev'
              manifests: 'k8s/deployment.yaml'

- stage: DeployProd
  dependsOn: DeployDev
  condition: succeeded()
  jobs:
  - deployment: DeployProd
    environment: 'production'  # Manual approval required
    strategy:
      runOnce:
        deploy:
          steps:
          # Get secrets from Key Vault
          - task: AzureKeyVault@2
            inputs:
              azureSubscription: 'Production'
              KeyVaultName: 'kv-idp-prod'
              SecretsFilter: '*'
          
          # Deploy to production
          - task: KubernetesManifest@0
            inputs:
              action: 'deploy'
              kubernetesServiceConnection: 'AKS-Prod'
              namespace: 'production'
              manifests: 'k8s/deployment.yaml'
              imagePullSecrets: 'acr-secret'
```

### GitHub Actions Security

```yaml
# .github/workflows/security.yml
name: Security Checks

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy results to GitHub Security
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
    
    - name: Run Snyk
      uses: snyk/actions/node@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        args: --severity-threshold=high
```

### Secrets in CI/CD

```yaml
# ✅ CORRECT: Secrets from Key Vault

# Azure DevOps
variables:
  - group: production-secrets  # Linked to Key Vault

# GitHub Actions
- name: Get secrets
  uses: Azure/get-keyvault-secrets@v1
  with:
    keyvault: 'kv-idp-prod'
    secrets: 'database-password, api-key'

# ❌ WRONG: Secrets in pipeline variables
# Don't do this!
```

-----

## ☸️ Kubernetes Security

### Pod Security Standards

**All pods must comply with the “restricted” Pod Security Standard.**

```yaml
# Namespace enforces restricted standard
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**Secure Pod Example:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  # Security context at pod level
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  
  serviceAccountName: app-sa  # Dedicated service account
  automountServiceAccountToken: false  # Don't auto-mount if not needed
  
  containers:
  - name: app
    image: acridpprod.azurecr.io/myapp:1.0.0
    
    # Security context at container level
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
    
    # Resource limits (prevent DoS)
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
      requests:
        memory: "256Mi"
        cpu: "250m"
    
    # Mount secrets from Key Vault
    volumeMounts:
    - name: secrets
      mountPath: "/mnt/secrets"
      readOnly: true
    - name: tmp
      mountPath: "/tmp"
    
    # Liveness and readiness probes
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
    
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
  
  volumes:
  - name: secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "app-secrets"
  - name: tmp
    emptyDir: {}
```

### Service Accounts

**Every application should have its own service account.**

```yaml
# Create dedicated service account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: production
  annotations:
    azure.workload.identity/client-id: "CLIENT_ID"

---
# Role for the service account
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]
  verbs: ["get"]

---
# Bind role to service account
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
```

### Network Policies

**Required for all deployments:**

```yaml
# Always include network policy with your deployment
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  
  # Ingress: Only from ingress controller
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  
  # Egress: DNS + database + external API
  egress:
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
  
  # Allow to database
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
  
  # Allow to external API (via firewall)
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
    ports:
    - protocol: TCP
      port: 443
```

-----

## 🚨 Incident Response

### Reporting Security Incidents

**If you discover a security issue:**

```
1. IMMEDIATELY notify security team
   
   Critical (P0): Call emergency hotline +XX-XXX-XXX-XXXX
   High (P1): Email security@crusoe-island.com + Slack #security
   Medium (P2): Email security@crusoe-island.com
   
2. Do NOT share details publicly
   
   ❌ Don't post in public Slack channels
   ❌ Don't create public GitHub issues
   ❌ Don't email entire company
   
3. Preserve evidence
   
   ✅ Don't delete logs
   ✅ Take screenshots if applicable
   ✅ Note exact time of discovery
   ✅ Document steps to reproduce
   
4. Follow security team guidance
   
   They will coordinate response
```

### Security Incident Template

```markdown
# Security Incident Report

**Severity:** [Critical/High/Medium/Low]
**Reported by:** [Your name]
**Date/Time:** [When discovered]
**Status:** [Active/Contained/Resolved]

## Summary
Brief description of the security incident.

## Details
- What happened?
- When did it happen?
- Where did it happen? (system, environment, etc.)
- Who is affected?
- What is the potential impact?

## Evidence
- Logs: [attach or link]
- Screenshots: [attach]
- Error messages: [paste here]

## Immediate Actions Taken
- [ ] Isolated affected systems
- [ ] Rotated credentials
- [ ] Notified stakeholders
- [ ] Other: [specify]

## Next Steps
[What should be done next?]
```

### Common Incident Scenarios

**Scenario 1: Credentials Leaked in Git**

```bash
# 1. IMMEDIATE: Rotate credentials
az keyvault secret set \
  --vault-name kv-idp-prod \
  --name "leaked-secret" \
  --value "NewSecureValue123!"

# 2. Contact security team
# They will:
# - Check for unauthorized access
# - Remove from Git history
# - Update secret scanning rules

# 3. Document incident
# Create incident report
```

**Scenario 2: Suspicious Activity Detected**

```
1. Check Azure Sentinel alerts
   portal.azure.com → Sentinel → Incidents

2. Review relevant logs
   - Azure AD sign-in logs
   - AKS audit logs
   - Firewall logs

3. If confirmed malicious:
   - Disable compromised account
   - Rotate accessed credentials
   - Isolate affected resources
   - Follow incident response runbook

4. Document timeline and actions
```

**Scenario 3: Vulnerability Discovered**

```
1. Assess severity (CVSS score)
   
   Critical (9.0-10.0): Immediate action
   High (7.0-8.9): Fix within 7 days
   Medium (4.0-6.9): Fix within 30 days
   Low (0.1-3.9): Next maintenance cycle

2. Check if exploited
   - Review logs for exploitation attempts
   - Check for IoCs (Indicators of Compromise)

3. Apply patch/mitigation
   - Update dependency
   - Apply workaround
   - Deploy fix

4. Verify fix
   - Rescan with vulnerability scanner
   - Test functionality
   - Monitor for issues
```

-----

## 📋 Compliance and Auditing

### Audit Logging

**All security-relevant events are logged:**

```
Azure AD:
  ✓ Sign-ins (successful and failed)
  ✓ Password changes
  ✓ Role assignments
  ✓ MFA events
  ✓ Conditional Access events

Azure Resources:
  ✓ Resource creation/deletion
  ✓ Configuration changes
  ✓ RBAC changes
  ✓ Network security group changes

AKS:
  ✓ API server requests
  ✓ Admission controller decisions
  ✓ Pod security violations
  ✓ Network policy violations

Key Vault:
  ✓ All secret access
  ✓ Key operations
  ✓ Certificate operations
  ✓ Permission changes

Firewall:
  ✓ All allowed/denied connections
  ✓ Application rule matches
  ✓ Network rule matches
  ✓ Threat intelligence hits
```

### Accessing Audit Logs

```bash
# Azure AD sign-in logs
az ad signed-in-user list-owned-objects

# Azure Activity Logs
az monitor activity-log list \
  --resource-group rg-idp-prod \
  --start-time 2024-12-20T00:00:00Z

# Key Vault audit logs
az monitor diagnostic-settings show \
  --resource /subscriptions/.../resourceGroups/.../providers/Microsoft.KeyVault/vaults/kv-idp-prod

# Query logs in Log Analytics
az monitor log-analytics query \
  --workspace WORKSPACE_ID \
  --analytics-query "AzureDiagnostics | where ResourceType == 'KEYVAULT' | take 10"
```

### Compliance Requirements

**Your responsibilities:**

```yaml
Data Protection:
  ☐ Classify data appropriately
  ☐ Encrypt sensitive data
  ☐ Follow retention policies
  ☐ Handle PII correctly
  ☐ Report data breaches within 72 hours (GDPR)

Access Control:
  ☐ Use MFA
  ☐ Follow least privilege
  ☐ Review access quarterly
  ☐ Disable accounts of leavers immediately
  ☐ No shared accounts

Security Practices:
  ☐ Keep systems patched
  ☐ Use approved tools only
  ☐ No shadow IT
  ☐ Report vulnerabilities
  ☐ Complete security training annually

Incident Response:
  ☐ Report incidents immediately
  ☐ Preserve evidence
  ☐ Follow runbooks
  ☐ Document lessons learned
```

-----

## 🔧 Security Tools Reference

### Installed Tools

```bash
# Security scanning
tfsec          # Terraform security scanner
trivy          # Container vulnerability scanner
detect-secrets # Secret scanner
semgrep        # SAST tool
pip-audit      # Python dependency scanner
npm audit      # Node.js dependency scanner

# Kubernetes tools
kubectl        # Kubernetes CLI
kubescape      # Kubernetes security scanner
helm           # Package manager

# Azure tools
az             # Azure CLI
az aks         # AKS management

# Monitoring
kubectl-trace  # Trace system calls
stern          # Multi-pod log tailing
```

### Quick Reference

```bash
# Check for secrets in code
detect-secrets scan

# Scan Terraform for security issues
tfsec .

# Scan container image
trivy image myimage:latest

# Check Python dependencies
pip-audit

# Check Node.js dependencies
npm audit

# Scan Kubernetes manifests
kubescape scan *.yaml

# Check pod security
kubectl get pod -n production -o yaml | kubescape scan -
```

-----

## ⚠️ Common Security Mistakes

### Top 10 Security Mistakes (And How to Avoid Them)

#### 1. Committing Secrets to Git

```bash
# ❌ WRONG
git add .env
git commit -m "Add configuration"

# ✅ CORRECT
# Add to .gitignore
echo ".env" >> .gitignore

# Use Key Vault
az keyvault secret set --vault-name kv-idp-prod --name "api-key" --value "secret123"
```

**Prevention:**

- ✅ Use pre-commit hooks
- ✅ Add `.env` to `.gitignore`
- ✅ Use Key Vault for all secrets
- ✅ Enable GitHub secret scanning

#### 2. Running Containers as Root

```dockerfile
# ❌ WRONG
FROM ubuntu:22.04
COPY app /app
CMD ["/app/run.sh"]

# ✅ CORRECT
FROM ubuntu:22.04
RUN useradd -r -u 1000 appuser
COPY --chown=appuser:appuser app /app
USER appuser
CMD ["/app/run.sh"]
```

#### 3. No Input Validation

```python
# ❌ WRONG
user_id = request.args.get('id')
user = db.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ CORRECT
user_id = request.args.get('id')
if not user_id.isdigit():
    abort(400, "Invalid user ID")
user = db.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
```

#### 4. Overly Permissive Network Policies

```yaml
# ❌ WRONG: Allow all egress
egress:
- to:
  - ipBlock:
      cidr: 0.0.0.0/0

# ✅ CORRECT: Explicit destinations only
egress:
- to:
  - podSelector:
      matchLabels:
        app: database
  ports:
  - protocol: TCP
    port: 5432
```

#### 5. Using `latest` Tag

```yaml
# ❌ WRONG
image: myapp:latest

# ✅ CORRECT
image: myapp:1.2.3  # Specific version
```

#### 6. No Resource Limits

```yaml
# ❌ WRONG
containers:
- name: app
  image: myapp:1.0

# ✅ CORRECT
containers:
- name: app
  image: myapp:1.0
  resources:
    limits:
      memory: "512Mi"
      cpu: "500m"
    requests:
      memory: "256Mi"
      cpu: "250m"
```

#### 7. Storing Passwords in Plain Text

```python
# ❌ WRONG
password = "mypassword"
db.insert(password)

# ✅ CORRECT
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
db.insert(hashed)
```

#### 8. No TLS Verification

```python
# ❌ WRONG
import requests
response = requests.get('https://api.example.com', verify=False)

# ✅ CORRECT
import requests
response = requests.get('https://api.example.com')  # verify=True by default
```

#### 9. Logging Sensitive Data

```python
# ❌ WRONG
logger.info(f"User {email} logged in with password {password}")

# ✅ CORRECT
logger.info(f"User {hash_id(email)} logged in successfully")
```

#### 10. No Error Handling

```python
# ❌ WRONG
try:
    db.connect()
except Exception as e:
    print(f"Error: {e}")  # Reveals internal details

# ✅ CORRECT
try:
    db.connect()
except Exception as e:
    logger.error(f"Database connection failed: {e}", exc_info=True)
    return "Service temporarily unavailable", 503
```

-----

## ✅ Security Checklist

### Pre-Deployment Checklist

```yaml
Code Security:
  ☐ No secrets in code
  ☐ Input validation implemented
  ☐ Output encoding for XSS prevention
  ☐ SQL queries parameterized
  ☐ Error handling doesn't leak information
  ☐ Logging doesn't include sensitive data
  ☐ Dependencies scanned for vulnerabilities
  ☐ SAST scan passed
  ☐ Code reviewed by peer

Container Security:
  ☐ Minimal base image used
  ☐ Multi-stage build implemented
  ☐ Running as non-root user
  ☐ Read-only root filesystem
  ☐ No secrets in Dockerfile
  ☐ .dockerignore properly configured
  ☐ Image scanned (Trivy, Snyk)
  ☐ Image signed (Cosign)
  ☐ Specific version tag (not :latest)

Kubernetes Security:
  ☐ Dedicated service account
  ☐ Pod Security Standard compliant
  ☐ Resource limits set
  ☐ Network policy defined
  ☐ Secrets from Key Vault
  ☐ Liveness/readiness probes configured
  ☐ No privileged containers
  ☐ Security context configured

Infrastructure:
  ☐ Terraform scanned (tfsec)
  ☐ No hardcoded secrets
  ☐ State file secured
  ☐ Resources tagged
  ☐ Network security groups configured
  ☐ Private endpoints used
  ☐ Encryption enabled

CI/CD:
  ☐ Security scans in pipeline
  ☐ Secrets from Key Vault
  ☐ Manual approval for production
  ☐ Deployment logs captured
  ☐ Rollback plan documented

Documentation:
  ☐ Architecture documented
  ☐ Security controls documented
  ☐ Runbooks created
  ☐ Incident response plan
  ☐ Recovery procedures
```

-----

## ❓ FAQ

### General Questions

**Q: Why do I need MFA if I have a strong password?**

A: Passwords can be phished, stolen, or cracked. MFA provides a second factor that attackers can’t easily compromise. Even if your password is leaked in a data breach, your account remains protected.

**Q: Can I use my personal laptop for work?**

A: No. Only company-managed devices can access production systems. Personal devices don’t have required security controls (encryption, endpoint protection, compliance monitoring).

**Q: How do I report a security vulnerability?**

A: Email security@crusoe-island.com or use our GitHub Security Advisories. Never post publicly. See [SECURITY.md](../SECURITY.md) for details.

### Secrets Management

**Q: Where should I store API keys?**

A: Always in Azure Key Vault. Never in code, config files, or environment variables (in Dockerfile).

**Q: How do I access secrets locally during development?**

A: Use `az login` to authenticate, then access Key Vault:

```bash
az keyvault secret show --vault-name kv-idp-dev --name "api-key" --query "value" -o tsv
```

**Q: What if I accidentally commit a secret?**

A: 1) Immediately rotate the secret, 2) Contact security team, 3) They’ll help remove it from Git history.

### Access Control

**Q: Why don’t I have admin access?**

A: We follow the principle of least privilege. Request temporary admin access via PIM only when needed.

**Q: How do I get access to production?**

A: Production access is tightly controlled. Submit request via IT ticketing system with business justification. Access may be view-only or require PIM activation.

**Q: Why can’t I access the Kubernetes API directly?**

A: The API server is private (not exposed to internet). Use VPN or Bastion to access it.

### Container Security

**Q: Why can’t I use `docker.io/ubuntu:latest`?**

A: 1) `latest` tag changes over time (not reproducible), 2) Ubuntu is a large image (use minimal base), 3) Should scan and sign all images.

**Q: My container needs to run as root. What should I do?**

A: Very few applications truly need root. Consult security team to find alternative. If absolutely necessary, requires security review and approval.

### Network Security

**Q: Why can’t my pod access the internet?**

A: Default deny egress policy. You need explicit network policy allowing egress, and destination must be allowed in Azure Firewall.

**Q: How do I request a new firewall rule?**

A: Create ticket with justification, destination FQDN, protocol, and business impact. Security team will review.

### Compliance

**Q: How long are logs retained?**

A: 90 days in hot storage, 1 year in warm storage, 7 years in cold storage (compliance).

**Q: Can I download customer data?**

A: Only if you have specific authorization and business need. Must be encrypted and handled according to data classification policies.

-----

## 📚 Additional Resources

### Internal Documentation

- [Threat Model](../architecture/threat-model.md)
- [Defense-in-Depth Architecture](../architecture/defense-in-depth.md)
- [Network Architecture](../architecture/network-architecture.md)
- [SECURITY.md](../SECURITY.md)

### Training

- Security Awareness Training (required annually)
- Secure Coding Training (developers)
- Kubernetes Security Training (platform engineers)
- Incident Response Training (all teams)

### External Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

### Tools Documentation

- [Trivy](https://aquasecurity.github.io/trivy/)
- [tfsec](https://aquasecurity.github.io/tfsec/)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [Semgrep](https://semgrep.dev/docs/)

-----

## 📞 Getting Help

### Support Channels

|Issue Type                  |Contact                   |Response Time  |
|----------------------------|--------------------------|---------------|
|Security Incident (Critical)|+XX-XXX-XXX-XXXX          |Immediate      |
|Security Question           |#security (Slack)         |4 hours        |
|Access Request              |IT Help Desk              |1 business day |
|Security Review             |security@crusoe-island.com|2 business days|

### Security Team

- **CISO**: Jane Doe (jane.doe@crusoe-island.com)
- **Security Lead**: John Smith (john.smith@crusoe-island.com)
- **Security Engineers**: #security (Slack)

-----

## 📝 Document Control

**Version History:**

|Version|Date      |Author       |Changes               |
|-------|----------|-------------|----------------------|
|1.0    |2024-12-21|Security Team|Initial security guide|

**Review Schedule:**

- **Quarterly**: Content review and updates
- **Annually**: Comprehensive audit
- **Ad-hoc**: After major security changes

**Next Review:** March 21, 2025

-----

**Document Classification:** Internal  
**Distribution:** All Employees  
**Mandatory Reading:** Yes (Security Awareness Training)

-----

*Security is not a destination, it’s a journey. This guide will be updated as threats evolve and our platform matures. Stay vigilant, stay secure!* 🔒

**Remember: When in doubt, ask the security team. It’s better to ask than to guess!** 💬
