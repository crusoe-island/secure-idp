# Contributing to Crusoe IDP

Thank you for your interest in contributing to Crusoe IDP! This document provides guidelines and instructions for contributing to this secure Internal Developer Platform.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Security Guidelines](#security-guidelines)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)
- [Community](#community)

-----

## 🤝 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of:

- Experience level
- Gender identity and expression
- Sexual orientation
- Disability
- Personal appearance
- Body size
- Race or ethnicity
- Age
- Religion
- Nationality

### Our Standards

**Examples of behavior that contributes to a positive environment:**

✅ Using welcoming and inclusive language  
✅ Being respectful of differing viewpoints and experiences  
✅ Gracefully accepting constructive criticism  
✅ Focusing on what is best for the community  
✅ Showing empathy towards other community members

**Examples of unacceptable behavior:**

❌ Trolling, insulting/derogatory comments, and personal attacks  
❌ Public or private harassment  
❌ Publishing others’ private information without permission  
❌ Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team. All complaints will be reviewed and investigated promptly and fairly.

-----

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have:

1. **Development Tools**:
- Git >= 2.40
- Docker >= 24.0
- Python >= 3.11
- Node.js >= 18
- Terraform >= 1.6
- Azure CLI >= 2.50
1. **Azure Access**:
- Azure subscription with appropriate permissions
- Ability to create service principals
1. **Knowledge**:
- Familiarity with Terraform and Infrastructure-as-Code
- Understanding of Kubernetes basics
- Knowledge of security best practices
- Experience with Python and/or TypeScript (depending on your contribution area)

### Setting Up Your Development Environment

1. **Fork the Repository**

```bash
# Fork via GitHub UI, then clone your fork
git clone https://github.com/YOUR-USERNAME/secure-idp.git
cd secure-idp

# Add upstream remote
git remote add upstream https://github.com/crusoe-island/secure-idp.git
```

1. **Install Development Dependencies**

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Install Python dependencies
pip install -r requirements-dev.txt

# Install Node.js dependencies (for Backstage)
cd backstage
yarn install
cd ..

# Install Terraform tools
brew install tfsec terraform-docs  # macOS
# or
apt-get install tfsec  # Linux
```

1. **Configure Azure Credentials**

```bash
# Login to Azure
az login

# Set subscription
az account set --subscription "your-subscription-id"

# Create service principal for development
az ad sp create-for-rbac \
  --name "sp-idp-dev-$(whoami)" \
  --role Contributor \
  --scopes /subscriptions/YOUR-SUBSCRIPTION-ID
```

1. **Verify Setup**

```bash
# Run all pre-commit checks
pre-commit run --all-files

# Run tests
pytest tests/ -v

# Verify Terraform
cd terraform/environments/dev
terraform init
terraform validate
```

-----

## 🔄 Development Workflow

### Branch Naming Convention

Use descriptive branch names following this pattern:

```
<type>/<short-description>

Types:
- feat/     : New feature
- fix/      : Bug fix
- docs/     : Documentation changes
- test/     : Adding or updating tests
- refactor/ : Code refactoring
- chore/    : Maintenance tasks
- security/ : Security improvements

Examples:
- feat/add-cost-optimization
- fix/terraform-state-lock
- docs/update-security-guide
- security/upgrade-dependencies
```

### Standard Workflow

1. **Create a Branch**

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feat/my-awesome-feature
```

1. **Make Changes**

```bash
# Make your changes
vim terraform/modules/my-module/main.tf

# Test locally
terraform fmt -recursive
terraform validate
pytest tests/

# Commit changes (pre-commit hooks will run automatically)
git add .
git commit -m "feat: add awesome feature"
```

1. **Keep Your Branch Updated**

```bash
# Regularly sync with upstream
git fetch upstream
git rebase upstream/main
```

1. **Push Changes**

```bash
git push origin feat/my-awesome-feature
```

1. **Create Pull Request**

- Go to GitHub and create a Pull Request
- Fill out the PR template completely
- Link any related issues
- Request reviews from maintainers

-----

## 📝 Coding Standards

### General Principles

1. **Security First**: Every change must maintain or improve security posture
1. **Test-Driven Development**: Write tests before implementation when possible
1. **Documentation**: Code should be self-documenting, but add comments for complex logic
1. **Simplicity**: Prefer simple, readable code over clever solutions
1. **Consistency**: Follow existing patterns in the codebase

### Terraform Standards

**File Organization**:

```
module/
├── main.tf           # Main resources
├── variables.tf      # Input variables
├── outputs.tf        # Output values
├── locals.tf         # Local values (if needed)
├── versions.tf       # Provider version constraints
├── README.md         # Module documentation
└── examples/         # Usage examples
    └── basic/
        └── main.tf
```

**Naming Conventions**:

```hcl
# Resources: type-name-environment
resource "azurerm_resource_group" "platform" {
  name     = "rg-idp-${var.environment}"
  location = var.location
}

# Variables: descriptive snake_case
variable "enable_network_policy" {
  type        = bool
  description = "Enable Kubernetes network policies"
  default     = true
}

# Use consistent tag structure
tags = merge(
  local.common_tags,
  {
    Purpose = "Internal Developer Platform"
  }
)
```

**Best Practices**:

```hcl
# ✅ DO: Use consistent formatting
resource "azurerm_kubernetes_cluster" "aks" {
  name                = "aks-idp-${var.environment}"
  location            = var.location
  resource_group_name = azurerm_resource_group.platform.name
  
  # Security settings
  private_cluster_enabled = true
  
  tags = local.common_tags
}

# ❌ DON'T: Hardcode values
resource "azurerm_kubernetes_cluster" "aks" {
  name     = "my-aks-cluster"
  location = "eastus"
}

# ✅ DO: Add validation
variable "environment" {
  type        = string
  description = "Environment name"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

# ✅ DO: Document outputs
output "aks_cluster_id" {
  description = "The Kubernetes cluster ID"
  value       = azurerm_kubernetes_cluster.aks.id
}
```

### Python Standards

**Code Style**:

```python
# Follow PEP 8, enforced by Black and Flake8
# Use type hints
from typing import List, Dict, Optional

def deploy_service(
    name: str,
    image: str,
    replicas: int = 2,
    environment: str = "dev"
) -> Dict[str, str]:
    """
    Deploy a service to Kubernetes.
    
    Args:
        name: Service name
        image: Container image
        replicas: Number of replicas (default: 2)
        environment: Target environment (default: dev)
    
    Returns:
        Dict containing deployment status and metadata
    
    Raises:
        ValueError: If service name is invalid
        DeploymentError: If deployment fails
    """
    if not name or not name.isalnum():
        raise ValueError("Service name must be alphanumeric")
    
    # Implementation here
    return {
        "status": "deployed",
        "name": name,
        "replicas": replicas
    }
```

**Security Practices**:

```python
# ✅ DO: Use environment variables for secrets
import os
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
secret_value = os.environ.get("SECRET_NAME")

# ❌ DON'T: Hardcode secrets
SECRET_KEY = "my-secret-key-12345"  # NEVER do this

# ✅ DO: Validate input
def create_resource(name: str):
    if not name.isalnum():
        raise ValueError("Name must be alphanumeric")
    # Create resource

# ✅ DO: Use secure random
import secrets
token = secrets.token_urlsafe(32)

# ❌ DON'T: Use weak random
import random
token = random.randint(1000, 9999)  # Not cryptographically secure
```

### TypeScript/JavaScript Standards

**Code Style**:

```typescript
// Use ESLint and Prettier
// Follow Airbnb style guide

// ✅ DO: Use interfaces for type safety
interface DeploymentConfig {
  serviceName: string;
  image: string;
  replicas?: number;
  environment: 'dev' | 'staging' | 'prod';
}

// ✅ DO: Use async/await
async function deployService(config: DeploymentConfig): Promise<void> {
  try {
    const result = await api.deploy(config);
    console.log('Deployment successful:', result);
  } catch (error) {
    console.error('Deployment failed:', error);
    throw error;
  }
}

// ❌ DON'T: Use any type
function processData(data: any) {  // Avoid this
  // ...
}

// ✅ DO: Use specific types
function processData(data: DeploymentConfig) {
  // ...
}
```

### Kubernetes Manifests

**Best Practices**:

```yaml
# ✅ DO: Use labels and selectors
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-service
  labels:
    app: backend
    environment: production
    managed-by: crusoe-idp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      # ✅ DO: Set security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      
      containers:
      - name: backend
        image: myapp:1.0.0
        
        # ✅ DO: Set resource limits
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        
        # ✅ DO: Use readiness/liveness probes
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
        
        # ✅ DO: Set security context
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
```

-----

## 🔒 Security Guidelines

### Critical Security Requirements

1. **Never Commit Secrets**
- Use Azure Key Vault for all secrets
- Pre-commit hooks will catch most issues, but stay vigilant
- Use `.env.example` for configuration templates
1. **Security Testing**
- All PRs must pass security scans (tfsec, Bandit, Snyk, etc.)
- Fix HIGH and CRITICAL vulnerabilities before merging
- Document any security exceptions
1. **Dependency Management**
- Keep dependencies up to date
- Review security advisories regularly
- Use Dependabot for automated updates
1. **Code Review**
- Security-critical changes require approval from security team
- All Terraform changes require infrastructure team review

### Security Checklist for Pull Requests

- [ ] No hardcoded secrets or credentials
- [ ] All secrets stored in Azure Key Vault
- [ ] Security scanning passes (no HIGH/CRITICAL issues)
- [ ] Input validation implemented
- [ ] Error messages don’t leak sensitive information
- [ ] Authentication and authorization properly implemented
- [ ] Logging doesn’t include sensitive data
- [ ] Dependencies are up to date and secure
- [ ] Security tests added for new features
- [ ] Documentation updated with security considerations

-----

## 🧪 Testing Requirements

### Test Categories

1. **Unit Tests**: Test individual functions/modules
1. **Integration Tests**: Test component interactions
1. **Security Tests**: Validate security controls
1. **Infrastructure Tests**: Test Terraform modules

### Testing Standards

**Python Tests** (pytest):

```python
# tests/test_deployment.py
import pytest
from deployment import deploy_service

def test_deploy_service_success():
    """Test successful service deployment."""
    result = deploy_service(
        name="test-service",
        image="nginx:latest",
        replicas=2
    )
    
    assert result["status"] == "deployed"
    assert result["replicas"] == 2

def test_deploy_service_invalid_name():
    """Test deployment with invalid service name."""
    with pytest.raises(ValueError):
        deploy_service(
            name="invalid name with spaces",
            image="nginx:latest"
        )

@pytest.mark.integration
def test_deploy_to_aks():
    """Integration test: deploy to actual AKS cluster."""
    # This runs in CI only, not locally
    pass
```

**Terraform Tests** (Terratest):

```go
// tests/terraform_test.go
package test

import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/stretchr/testify/assert"
)

func TestAKSModule(t *testing.T) {
    t.Parallel()
    
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../terraform/modules/aks",
        Vars: map[string]interface{}{
            "environment": "dev",
        },
    })
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    // Validate outputs
    clusterName := terraform.Output(t, terraformOptions, "cluster_name")
    assert.Equal(t, "aks-idp-dev", clusterName)
}
```

### Running Tests

```bash
# Run all Python tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test file
pytest tests/test_deployment.py -v

# Run tests by marker
pytest tests/ -m security -v

# Run Terraform tests
cd terraform/tests
go test -v -timeout 30m

# Run integration tests (requires Azure access)
pytest tests/integration/ -v
```

### Test Coverage Requirements

- **Minimum coverage**: 80% overall
- **Critical paths**: 95% coverage required
- **Security functions**: 100% coverage required
- **New features**: Must include tests

-----

## 📥 Pull Request Process

### Before Submitting

1. **Self Review**
- [ ] Code follows project standards
- [ ] All tests pass locally
- [ ] Pre-commit hooks pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)
1. **Commit Messages**

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

<longer description if needed>

<footer with issue references>
```

**Types**:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks
- `security`: Security improvements

**Examples**:

```
feat(terraform): add network policy module

Implements Calico network policies for AKS cluster with
default-deny stance and explicit allow rules.

Closes #123
```

```
fix(backstage): resolve authentication redirect loop

The OAuth callback was not properly handling state parameter,
causing infinite redirects. Added state validation.

Fixes #456
```

### Pull Request Template

When creating a PR, use this template:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security improvement

## Related Issues
Closes #(issue number)

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
Describe testing performed:
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Security Impact
Describe any security implications:
- [ ] No security impact
- [ ] Security improvement
- [ ] Requires security review

## Documentation
- [ ] README updated
- [ ] API documentation updated
- [ ] Architecture documentation updated
- [ ] CHANGELOG updated

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Tests added and passing
- [ ] No new warnings generated
- [ ] Dependent changes merged
```

### Review Process

1. **Automated Checks**
- CI/CD pipeline must pass
- Security scans must pass
- Test coverage maintained or improved
1. **Code Review**
- At least one approval required
- Security changes require security team approval
- Infrastructure changes require infrastructure team approval
1. **Merge Requirements**
- All conversations resolved
- All checks passing
- Approved by required reviewers
- Branch up to date with main

-----

## 📚 Documentation

### Documentation Requirements

All contributions should include appropriate documentation:

1. **Code Documentation**
- Docstrings for all public functions/classes
- Comments for complex logic
- Type hints (Python) or interfaces (TypeScript)
1. **Module Documentation**
- README.md for each Terraform module
- Usage examples
- Input/output documentation
1. **Architecture Documentation**
- Update architecture diagrams if structure changes
- Document design decisions in ADRs
- Update threat model if security surface changes

### Writing Documentation

**Good Documentation Example**:

```markdown
# AKS Cluster Module

This module creates a secure, production-ready Azure Kubernetes Service cluster
with private networking, network policies, and RBAC enabled.

## Features

- Private cluster (no public API endpoint)
- Azure AD integration for RBAC
- Calico network policies
- Azure Policy enforcement
- Defender for Containers enabled

## Usage

```hcl
module "aks" {
  source = "../../modules/aks"
  
  environment         = "prod"
  location           = "westeurope"
  resource_group_name = "rg-idp-prod"
  
  node_count = 3
  vm_size    = "Standard_D4s_v3"
  
  enable_network_policy = true
  enable_azure_policy   = true
}
```

## Requirements

|Name     |Version|
|---------|-------|
|terraform|>= 1.6 |
|azurerm  |~> 3.80|

## Security Considerations

This module implements several security best practices:

- Private cluster configuration prevents internet exposure
- Azure AD integration enforces identity-based access
- Network policies provide pod-to-pod security

```
---

## 🌍 Community

### Getting Help

- **Documentation**: Check [docs/](docs/) directory first
- **Discussions**: Use [GitHub Discussions](https://github.com/crusoe-island/secure-idp/discussions)
- **Issues**: Report bugs via [GitHub Issues](https://github.com/crusoe-island/secure-idp/issues)
- **Security**: Report security issues privately (see [SECURITY.md](.github/SECURITY.md))

### Ways to Contribute

Not all contributions are code! Here are other ways to help:

- 📖 Improve documentation
- 🐛 Report bugs
- 💡 Suggest features
- 🧪 Write tests
- 🎨 Improve UI/UX
- 🔍 Review pull requests
- 💬 Answer questions in discussions
- 📝 Write blog posts or tutorials

### Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- GitHub contributors page

---

## 📄 License

By contributing to Crusoe IDP, you agree that your contributions will be licensed under the MIT License.

---

## 🙏 Thank You

Thank you for contributing to Crusoe IDP! Your efforts help make secure platform engineering accessible to everyone.

**Remember**: Security is not a feature, it's a foundation. Every contribution should maintain or improve our security posture.

---

## 📞 Contact

- **Project Lead**: Willem van Heemstra
- **Security Team**: security@crusoe-island.com
- **General Questions**: Use GitHub Discussions

---

*Last Updated: December 2024*

*"Building secure platforms, one contribution at a time."* 🏝️ 🔒
```
