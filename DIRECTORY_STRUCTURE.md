# Directory Structure

```
secure-idp/
├── .github/
│   ├── workflows/
│   │   ├── terraform-security-scan.yml
│   │   ├── container-security-scan.yml
│   │   ├── dependency-scan.yml
│   │   └── security-audit.yml
│   └── SECURITY.md
├── docs/
│   ├── architecture/
│   │   ├── threat-model.md
│   │   ├── defense-in-depth.md
│   │   └── network-architecture.md
│   ├── security/
│   │   ├── security-guide.md
│   │   ├── incident-response-part1.md
│   │   ├── incident-response-part2.md
│   │   ├── incident-response-part3.md
│   │   └── compliance.md
│   ├── developer-guide/
│   │   ├── getting-started.md
│   │   ├── deployment-guide.md
│   │   └── troubleshooting.md
│   └── ADRs/  # Architecture Decision Records
│       └── 001-zero-trust-architecture.md
├── terraform/
│   ├── modules/
│   │   ├── network/
│   │   ├── aks/
│   │   ├── key-vault/
│   │   ├── monitoring/
│   │   └── security-baseline/
│   ├── environments/
│   │   ├── dev/
│   │   ├── staging/
│   │   └── prod/
│   └── tests/
├── kubernetes/
│   ├── base/
│   ├── overlays/
│   ├── policies/
│   │   ├── network-policies/
│   │   ├── pod-security-policies/
│   │   └── rbac/
│   └── security/
├── backstage/
│   ├── packages/
│   ├── plugins/
│   └── app-config.yaml
├── scripts/
│   ├── security/
│   │   ├── security_validation.py
│   │   └── vulnerability_scanner.sh
│   └── automation/
├── tests/
│   ├── security/
│   ├── integration/
│   └── e2e/
├── .gitignore
├── .pre-commit-config.yaml
├── README.md
├── CONTRIBUTING.md
└── LICENSE
```
