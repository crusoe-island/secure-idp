# Deployment Guide - Crusoe IDP

**Version:** 1.0  
**Last Updated:** December 21, 2024  
**Audience:** Developers, DevOps Engineers  
**Prerequisites:** Complete [Getting Started Guide](getting-started.md)

This guide covers everything you need to know about deploying applications on the Crusoe Internal Developer Platform, from simple deployments to advanced strategies.

-----

## 📋 Table of Contents

- [Deployment Overview](#deployment-overview)
- [Deployment Strategies](#deployment-strategies)
- [Environment Progression](#environment-progression)
- [CI/CD Pipeline Configuration](#cicd-pipeline-configuration)
- [GitOps Workflow](#gitops-workflow)
- [Kubernetes Deployment Patterns](#kubernetes-deployment-patterns)
- [Configuration Management](#configuration-management)
- [Rollback Procedures](#rollback-procedures)
- [Monitoring Deployments](#monitoring-deployments)
- [Advanced Deployment Patterns](#advanced-deployment-patterns)
- [Troubleshooting Deployments](#troubleshooting-deployments)
- [Best Practices](#best-practices)

-----

## 🎯 Deployment Overview

### What is a Deployment?

```yaml
Deployment Definition:
  A deployment is the process of releasing a new version of your
  application to a target environment in a controlled, repeatable way.

Key Components:
  1. Source Code:
     - Application code
     - Configuration files
     - Infrastructure definitions
  
  2. Build Artifacts:
     - Docker container images
     - Tagged and versioned
     - Stored in Azure Container Registry
  
  3. Deployment Configuration:
     - Kubernetes manifests
     - Kustomize overlays
     - Helm charts (optional)
  
  4. Target Environment:
     - Development (dev-<namespace>)
     - Staging (staging)
     - Production (production)
```

### Deployment Flow on Crusoe IDP

```
┌─────────────────────────────────────────────────────────────┐
│                    Deployment Flow                           │
└─────────────────────────────────────────────────────────────┘

Developer Workflow:
  1. Code Changes
     ↓
  2. Git Commit & Push
     ↓
  3. Pull Request (optional)
     ↓
  4. Merge to Branch
     ↓

Automated CI/CD:
  5. GitHub Actions Triggered
     ↓
  6. Security Scans (secrets, vulnerabilities)
     ↓
  7. Build Docker Image
     ↓
  8. Push to ACR
     ↓
  9. Update Kubernetes Manifests
     ↓
  10. Deploy to Target Environment
     ↓
  11. Health Checks
     ↓
  12. Deployment Complete ✓

Rollback if needed:
  ↓
  Git Revert → Redeploy
```

### Deployment Types

```yaml
Type 1: Developer Deployment (Dev Environment)
  Trigger: Push to dev branch
  Target: dev-<yourname> namespace
  Approval: None required
  Rollback: Automatic on failure
  Use Case: Feature development, testing
  
Type 2: Staging Deployment
  Trigger: Push to staging branch
  Target: staging namespace
  Approval: Automatic (after CI passes)
  Rollback: Automatic on failure
  Use Case: Integration testing, QA
  
Type 3: Production Deployment
  Trigger: Push to main branch + manual trigger
  Target: production namespace
  Approval: Required (Platform Team)
  Rollback: Manual (with approval)
  Use Case: Customer-facing releases
  
Type 4: Hotfix Deployment
  Trigger: Push to hotfix/* branch
  Target: All environments (fast-tracked)
  Approval: Expedited review
  Rollback: Automatic on failure
  Use Case: Critical bugs, security patches
```

-----

## 🎲 Deployment Strategies

### Rolling Deployment (Default)

**How it works:** Gradually replaces old pods with new ones.

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 6
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 2          # Max 2 extra pods during update
      maxUnavailable: 1     # Max 1 pod down during update
  template:
    spec:
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:v2.0.0
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

**Flow:**

```
Initial State:  [v1.0] [v1.0] [v1.0] [v1.0] [v1.0] [v1.0]
                  ↓
Step 1:        [v1.0] [v1.0] [v1.0] [v1.0] [v1.0] [v1.0] [v2.0] [v2.0]
                  ↓
Step 2:        [v1.0] [v1.0] [v1.0] [v1.0] [v2.0] [v2.0] [v2.0] [v2.0]
                  ↓
Step 3:        [v1.0] [v1.0] [v2.0] [v2.0] [v2.0] [v2.0] [v2.0] [v2.0]
                  ↓
Final:         [v2.0] [v2.0] [v2.0] [v2.0] [v2.0] [v2.0]
```

**Pros:**

- ✓ Zero downtime
- ✓ Gradual rollout
- ✓ Easy rollback
- ✓ Default Kubernetes strategy

**Cons:**

- ✗ Both versions run simultaneously
- ✗ Longer deployment time
- ✗ May cause issues if versions incompatible

**Use Case:** Most applications, standard deployments

**Monitoring:**

```bash
# Watch rollout progress
kubectl rollout status deployment/my-app

# Check rollout history
kubectl rollout history deployment/my-app

# Pause rollout if issues detected
kubectl rollout pause deployment/my-app

# Resume when ready
kubectl rollout resume deployment/my-app
```

-----

### Recreate Deployment

**How it works:** Stops all old pods before starting new ones.

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 6
  strategy:
    type: Recreate
  template:
    spec:
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:v2.0.0
```

**Flow:**

```
Initial State:  [v1.0] [v1.0] [v1.0] [v1.0] [v1.0] [v1.0]
                  ↓
Terminate:      [ ... terminating all pods ... ]
                  ↓
Downtime:       [     no pods running     ]
                  ↓
Start New:      [v2.0] [v2.0] [v2.0] [v2.0] [v2.0] [v2.0]
```

**Pros:**

- ✓ Simple and straightforward
- ✓ No version mixing
- ✓ Clean state transition

**Cons:**

- ✗ Downtime during deployment
- ✗ Not suitable for production

**Use Case:**

- Development environments
- Stateful applications requiring clean shutdown
- Database schema migrations

-----

### Blue-Green Deployment

**How it works:** Maintain two identical environments, switch traffic between them.

```yaml
# Blue deployment (current)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-blue
  labels:
    version: blue
spec:
  replicas: 6
  selector:
    matchLabels:
      app: my-app
      version: blue
  template:
    metadata:
      labels:
        app: my-app
        version: blue
    spec:
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:v1.0.0

---
# Green deployment (new)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-green
  labels:
    version: green
spec:
  replicas: 6
  selector:
    matchLabels:
      app: my-app
      version: green
  template:
    metadata:
      labels:
        app: my-app
        version: green
    spec:
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:v2.0.0

---
# Service (switch between blue and green)
apiVersion: v1
kind: Service
metadata:
  name: my-app
spec:
  selector:
    app: my-app
    version: blue  # Change to 'green' to switch
  ports:
  - port: 80
    targetPort: 8080
```

**Deployment Process:**

```bash
# 1. Deploy green version
kubectl apply -f deployment-green.yaml

# 2. Wait for green to be healthy
kubectl wait --for=condition=available deployment/my-app-green --timeout=300s

# 3. Test green version
kubectl port-forward deployment/my-app-green 8080:8080
# Manual testing...

# 4. Switch traffic to green
kubectl patch service my-app -p '{"spec":{"selector":{"version":"green"}}}'

# 5. Monitor for issues
# If problems, switch back to blue immediately

# 6. After confidence period, delete blue
kubectl delete deployment my-app-blue
```

**Pros:**

- ✓ Instant rollback (just switch back)
- ✓ Full testing before switch
- ✓ Zero downtime
- ✓ Simple to understand

**Cons:**

- ✗ Requires 2x resources during deployment
- ✗ Database migrations tricky
- ✗ More complex configuration

**Use Case:**

- Production deployments with high risk
- Major version upgrades
- When instant rollback critical

-----

### Canary Deployment

**How it works:** Gradually shift traffic to new version while monitoring.

```yaml
# Using multiple Services and Ingress weights

# Stable version
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-stable
spec:
  replicas: 9  # 90% of traffic
  selector:
    matchLabels:
      app: my-app
      track: stable
  template:
    metadata:
      labels:
        app: my-app
        track: stable
    spec:
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:v1.0.0

---
# Canary version
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-canary
spec:
  replicas: 1  # 10% of traffic
  selector:
    matchLabels:
      app: my-app
      track: canary
  template:
    metadata:
      labels:
        app: my-app
        track: canary
    spec:
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:v2.0.0

---
# Service for stable
apiVersion: v1
kind: Service
metadata:
  name: my-app-stable
spec:
  selector:
    app: my-app
    track: stable
  ports:
  - port: 80
    targetPort: 8080

---
# Service for canary
apiVersion: v1
kind: Service
metadata:
  name: my-app-canary
spec:
  selector:
    app: my-app
    track: canary
  ports:
  - port: 80
    targetPort: 8080

---
# Ingress with traffic splitting
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  annotations:
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-weight: "10"  # 10% to canary
spec:
  rules:
  - host: my-app.crusoe-island.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-app-canary
            port:
              number: 80
```

**Deployment Process:**

```bash
# Stage 1: Deploy canary with 10% traffic
kubectl apply -f deployment-canary.yaml

# Monitor error rates, latency, etc.
# If metrics good, increase canary traffic

# Stage 2: Increase to 25%
kubectl patch ingress my-app \
  -p '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/canary-weight":"25"}}}'

# Continue monitoring...

# Stage 3: Increase to 50%
kubectl patch ingress my-app \
  -p '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/canary-weight":"50"}}}'

# Stage 4: Full rollout (100%)
kubectl patch ingress my-app \
  -p '{"metadata":{"annotations":{"nginx.ingress.kubernetes.io/canary-weight":"100"}}}'

# Stage 5: Delete stable deployment
kubectl delete deployment my-app-stable
```

**Traffic Progression:**

```
Stage 1: [v1.0: 90%] [v2.0: 10%]  ← Initial canary
         ↓
Stage 2: [v1.0: 75%] [v2.0: 25%]  ← Increased confidence
         ↓
Stage 3: [v1.0: 50%] [v2.0: 50%]  ← Half traffic
         ↓
Stage 4: [v1.0:  0%] [v2.0: 100%] ← Full rollout
```

**Automated Canary with Flagger:**

```yaml
# flagger-canary.yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: my-app
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-app
  progressDeadlineSeconds: 600
  service:
    port: 80
  analysis:
    interval: 1m
    threshold: 5
    maxWeight: 50
    stepWeight: 10
    metrics:
    - name: request-success-rate
      thresholdRange:
        min: 99
      interval: 1m
    - name: request-duration
      thresholdRange:
        max: 500
      interval: 1m
  webhooks:
  - name: load-test
    url: http://flagger-loadtester/
    metadata:
      cmd: "hey -z 1m -q 10 -c 2 http://my-app/"
```

**Pros:**

- ✓ Risk mitigation (limited blast radius)
- ✓ Real user testing
- ✓ Gradual rollout
- ✓ Can automate based on metrics

**Cons:**

- ✗ Complex setup
- ✗ Requires good monitoring
- ✗ Longer deployment time
- ✗ Multiple versions in production

**Use Case:**

- High-risk production deployments
- Major feature releases
- Performance-sensitive applications
- A/B testing

-----

### A/B Testing Deployment

**How it works:** Route specific users/requests to different versions.

```yaml
# Using Ingress rules for A/B testing

# Version A (control)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-a
spec:
  replicas: 5
  selector:
    matchLabels:
      app: my-app
      version: a
  template:
    metadata:
      labels:
        app: my-app
        version: a
    spec:
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:v1.0.0

---
# Version B (experiment)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-b
spec:
  replicas: 5
  selector:
    matchLabels:
      app: my-app
      version: b
  template:
    metadata:
      labels:
        app: my-app
        version: b
    spec:
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:v2.0.0

---
# Ingress with header-based routing
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app-ab
  annotations:
    # Route based on cookie
    nginx.ingress.kubernetes.io/canary: "true"
    nginx.ingress.kubernetes.io/canary-by-cookie: "ab-test-group"
    nginx.ingress.kubernetes.io/canary-by-cookie-value: "version-b"
spec:
  rules:
  - host: my-app.crusoe-island.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-app-b
            port:
              number: 80
```

**Routing Options:**

```yaml
# Option 1: Cookie-based
nginx.ingress.kubernetes.io/canary-by-cookie: "user-group"
nginx.ingress.kubernetes.io/canary-by-cookie-value: "beta-testers"

# Option 2: Header-based
nginx.ingress.kubernetes.io/canary-by-header: "X-Version"
nginx.ingress.kubernetes.io/canary-by-header-value: "v2"

# Option 3: Geographic
nginx.ingress.kubernetes.io/canary-by-header: "X-Country"
nginx.ingress.kubernetes.io/canary-by-header-value: "US|CA"

# Option 4: User ID-based (application logic)
# Implement in application code based on user ID hash
```

**Pros:**

- ✓ Test features with specific users
- ✓ Measure business metrics
- ✓ Gradual feature rollout
- ✓ Easy to target specific segments

**Cons:**

- ✗ Complex routing logic
- ✗ Requires analytics integration
- ✗ May need sticky sessions
- ✗ Multiple versions in production

**Use Case:**

- Feature flags / gradual feature rollout
- Testing UI/UX changes
- Business metric optimization
- Regional rollouts

-----

## 🔄 Environment Progression

### Development Environment

```yaml
Environment: Development (dev-<yourname>)
Purpose: Personal sandbox for feature development
Cluster: aks-idp-dev
Region: West Europe

Deployment Trigger:
  - Manual: kubectl apply
  - Automatic: Push to dev branch
  
Characteristics:
  - Personal namespace per developer
  - Isolated from other developers
  - Relaxed resource limits
  - Fast iteration
  - No approval required
  
Resource Limits:
  CPU: 8 cores total
  Memory: 16 GB total
  Storage: 50 GB total
  Pods: 50 max
  
Access:
  - Full access to own namespace
  - Read-only to shared resources
  - No access to staging/production
  
Data:
  - Mock data or anonymized copies
  - Test databases (separate from staging/prod)
  - External API mocks when possible
```

**Development Workflow:**

```bash
# 1. Create feature branch
git checkout -b feature/new-api

# 2. Make changes and test locally
docker build -t my-app:local .
docker run -p 8080:8080 my-app:local

# 3. Push image to ACR
docker tag my-app:local acridpdev.azurecr.io/my-app:dev-$(whoami)
docker push acridpdev.azurecr.io/my-app:dev-$(whoami)

# 4. Deploy to your dev namespace
cat > k8s/overlays/dev-$(whoami)/kustomization.yaml << EOF
namespace: dev-$(whoami)
bases:
- ../../base
images:
- name: acridpdev.azurecr.io/my-app
  newTag: dev-$(whoami)
EOF

kubectl apply -k k8s/overlays/dev-$(whoami)/

# 5. Test in Kubernetes
kubectl port-forward service/my-app 8080:80

# 6. When satisfied, push to GitHub
git add .
git commit -m "feat: add new API endpoint"
git push origin feature/new-api

# 7. Create PR for staging
```

-----

### Staging Environment

```yaml
Environment: Staging
Purpose: Pre-production testing and QA
Cluster: aks-idp-staging
Region: West Europe

Deployment Trigger:
  - Automatic: Merge to staging branch
  - Manual: Promote from dev
  
Characteristics:
  - Shared environment for all developers
  - Production-like configuration
  - Integrated with other services
  - Performance testing
  - QA validation
  
Resource Limits:
  CPU: Same as production
  Memory: Same as production
  Storage: Same as production
  
Access:
  - All developers: Read access
  - Platform team: Write access
  - QA team: Full testing access
  
Data:
  - Staging database (separate from prod)
  - Realistic data volumes
  - May use production data snapshots (anonymized)
  - External API staging endpoints
```

**Staging Deployment Process:**

```bash
# Option 1: Automatic via GitHub Actions
# Merge PR to staging branch
git checkout staging
git merge feature/new-api
git push origin staging
# GitHub Actions automatically deploys

# Option 2: Manual deployment
# Get staging cluster credentials
az aks get-credentials \
  --resource-group rg-idp-staging \
  --name aks-idp-staging

# Deploy
kubectl apply -k k8s/overlays/staging/

# Verify deployment
kubectl get pods -n staging
kubectl logs -n staging -l app=my-app

# Run smoke tests
./scripts/smoke-test.sh https://staging.crusoe-island.com

# Notify QA team
# Slack: #qa-team
# Message: "v1.2.3 deployed to staging, ready for testing"
```

**Staging Gates:**

```yaml
Before Promoting to Production:

1. Automated Tests Pass:
   ☐ Unit tests (100% pass)
   ☐ Integration tests (100% pass)
   ☐ E2E tests (100% pass)
   ☐ Performance tests (within SLA)
   ☐ Security scans (no CRITICAL issues)

2. QA Validation:
   ☐ Functional testing complete
   ☐ Regression testing complete
   ☐ Smoke testing pass
   ☐ Load testing (if applicable)
   ☐ QA sign-off obtained

3. Stability Requirements:
   ☐ Running in staging for 24+ hours
   ☐ No critical errors in logs
   ☐ No memory leaks detected
   ☐ Resource usage within limits
   ☐ All health checks passing

4. Documentation:
   ☐ Release notes prepared
   ☐ Rollback plan documented
   ☐ Deployment runbook updated
   ☐ Customer communication drafted (if needed)
```

-----

### Production Environment

```yaml
Environment: Production
Purpose: Live customer-facing services
Cluster: aks-idp-prod
Region: West Europe + North Europe (DR)

Deployment Trigger:
  - Manual only with approval
  - Scheduled deployment windows
  
Characteristics:
  - Highly available (multi-zone)
  - Disaster recovery configured
  - Strict change control
  - Full monitoring and alerting
  - Incident response procedures
  
Resource Limits:
  CPU: Auto-scaling (10-100 cores)
  Memory: Auto-scaling (20-200 GB)
  Storage: 500 GB+ with replication
  
Access:
  - Platform team: Write access (with approval)
  - Developers: Read-only access
  - On-call team: Emergency access
  
Data:
  - Live customer data
  - GDPR compliance required
  - Regular backups (hourly)
  - Point-in-time recovery available
```

**Production Deployment Process:**

```bash
# 1. Create production deployment ticket
# Jira: IDP-DEPLOY-XXX
# Include: version, changes, rollback plan, testing evidence

# 2. Schedule deployment (deployment windows)
# Mon-Thu: 10:00-16:00 CET (non-peak hours)
# Fri-Sun: Emergency only

# 3. Pre-deployment checklist
./scripts/pre-deployment-check.sh v1.2.3
# Verifies:
# - Staging successful
# - All tests passed
# - Security scans clean
# - Approval obtained
# - Rollback plan ready

# 4. Create change request
az repos pr create \
  --title "Production deployment: v1.2.3" \
  --description "See DEPLOY-XXX for details" \
  --source-branch staging \
  --target-branch main \
  --reviewers platform-team

# 5. Get approval (required reviewers)
# - Platform Lead
# - Security Team (if security-related)
# - Product Owner (if customer-facing)

# 6. Merge to main (triggers approval gate)
git checkout main
git merge staging
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin main --tags

# 7. Manual approval in GitHub Actions
# Visit: https://github.com/org/repo/actions
# Click: "Review deployment"
# Approve: Enter justification

# 8. Monitor deployment
kubectl rollout status deployment/my-app -n production

# 9. Verify health
./scripts/production-health-check.sh

# 10. Monitor for 1 hour (watch dashboards)
# Grafana: https://grafana.crusoe-island.com
# Watch for:
# - Error rate < 0.1%
# - Response time < 200ms p95
# - No failed health checks
# - No increase in alerts

# 11. Update deployment ticket (success/failure)
```

**Production Deployment Windows:**

```yaml
Preferred Windows:
  Monday-Thursday: 10:00-16:00 CET
  - Low traffic period
  - Full team available
  - Time to monitor and react

Restricted Windows:
  Friday-Sunday: Emergency only
  - Weekend on-call coverage
  - Reduced team availability
  - Customer support limited

Blackout Windows:
  - Public holidays
  - Major marketing campaigns
  - End of month/quarter
  - Known high-traffic events
  
Emergency Deployments:
  - Security patches
  - Critical production bugs
  - Service outages
  - Data loss prevention
  - Approval: CISO or CTO
```

-----

## 🔧 CI/CD Pipeline Configuration

### GitHub Actions Workflow

Complete production-ready workflow:

```yaml
# .github/workflows/deploy.yml
name: Build and Deploy

on:
  push:
    branches:
      - dev
      - staging
      - main
  pull_request:
    branches:
      - staging
      - main

env:
  ACR_NAME: acridpprod
  IMAGE_NAME: my-app
  AZURE_CREDENTIALS: ${{ secrets.AZURE_CREDENTIALS }}

jobs:
  # ============================================================
  # Stage 1: Security Scanning
  # ============================================================
  security-scan:
    name: Security Scans
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis
      
      - name: Run secret detection
        run: |
          pip install detect-secrets
          detect-secrets scan --all-files \
            --exclude-files '\.git/.*' \
            --exclude-files 'node_modules/.*' > scan-results.json
          
          # Fail if secrets found
          if [ $(jq '.results | length' scan-results.json) -gt 0 ]; then
            echo "🚨 Secrets detected in code!"
            jq '.results' scan-results.json
            exit 1
          fi
      
      - name: Run Trivy filesystem scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'  # Fail on critical/high
      
      - name: Run Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten
      
      - name: Dependency scan (npm)
        if: hashFiles('package.json') != ''
        run: |
          npm audit --audit-level=high
      
      - name: Dependency scan (pip)
        if: hashFiles('requirements.txt') != ''
        run: |
          pip install pip-audit
          pip-audit --require-hashes --disable-pip

  # ============================================================
  # Stage 2: Build and Test
  # ============================================================
  build-and-test:
    name: Build and Test
    runs-on: ubuntu-latest
    needs: security-scan
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Build Docker image (for testing)
        uses: docker/build-push-action@v5
        with:
          context: .
          push: false
          load: true
          tags: ${{ env.IMAGE_NAME }}:test
          cache-from: type=gha
          cache-to: type=gha,mode=max
      
      - name: Run container structure tests
        run: |
          curl -LO https://storage.googleapis.com/container-structure-test/latest/container-structure-test-linux-amd64
          chmod +x container-structure-test-linux-amd64
          ./container-structure-test-linux-amd64 test \
            --image ${{ env.IMAGE_NAME }}:test \
            --config tests/container-structure-test.yaml
      
      - name: Scan image for vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.IMAGE_NAME }}:test
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      
      - name: Run unit tests
        run: |
          docker run --rm ${{ env.IMAGE_NAME }}:test npm test
      
      - name: Run integration tests
        run: |
          docker-compose -f docker-compose.test.yml up --abort-on-container-exit
          docker-compose -f docker-compose.test.yml down

  # ============================================================
  # Stage 3: Build and Push
  # ============================================================
  build-and-push:
    name: Build and Push to ACR
    runs-on: ubuntu-latest
    needs: build-and-test
    if: github.event_name == 'push'
    
    outputs:
      image-tag: ${{ steps.meta.outputs.version }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Docker metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=sha,prefix={{branch}}-
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
      
      - name: Login to Azure
        uses: azure/login@v1
        with:
          creds: ${{ env.AZURE_CREDENTIALS }}
      
      - name: Login to ACR
        run: az acr login --name ${{ env.ACR_NAME }}
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
      
      - name: Sign image with Cosign
        run: |
          cosign sign --yes \
            ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}@${{ steps.build-push.outputs.digest }}
      
      - name: Generate SBOM
        run: |
          syft ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:${{ steps.meta.outputs.version }} \
            -o spdx-json > sbom.spdx.json
      
      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.spdx.json

  # ============================================================
  # Stage 4: Deploy to Dev
  # ============================================================
  deploy-dev:
    name: Deploy to Development
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == 'refs/heads/dev'
    environment:
      name: development
      url: https://dev-${{ github.actor }}.crusoe-island.com
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Login to Azure
        uses: azure/login@v1
        with:
          creds: ${{ env.AZURE_CREDENTIALS }}
      
      - name: Get AKS credentials
        run: |
          az aks get-credentials \
            --resource-group rg-idp-dev \
            --name aks-idp-dev \
            --overwrite-existing
      
      - name: Deploy to dev namespace
        run: |
          kubectl set image deployment/${{ env.IMAGE_NAME }} \
            ${{ env.IMAGE_NAME }}=${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:${{ needs.build-and-push.outputs.image-tag }} \
            -n dev-${{ github.actor }}
          
          kubectl rollout status deployment/${{ env.IMAGE_NAME }} \
            -n dev-${{ github.actor }} \
            --timeout=5m
      
      - name: Run smoke tests
        run: |
          ./scripts/smoke-test.sh dev-${{ github.actor }}

  # ============================================================
  # Stage 5: Deploy to Staging
  # ============================================================
  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == 'refs/heads/staging'
    environment:
      name: staging
      url: https://staging.crusoe-island.com
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Login to Azure
        uses: azure/login@v1
        with:
          creds: ${{ env.AZURE_CREDENTIALS }}
      
      - name: Get AKS credentials
        run: |
          az aks get-credentials \
            --resource-group rg-idp-staging \
            --name aks-idp-staging \
            --overwrite-existing
      
      - name: Update manifests
        run: |
          cd k8s/overlays/staging
          kustomize edit set image \
            ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}=${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:${{ needs.build-and-push.outputs.image-tag }}
      
      - name: Deploy to staging
        run: |
          kubectl apply -k k8s/overlays/staging/
          kubectl rollout status deployment/${{ env.IMAGE_NAME }} \
            -n staging \
            --timeout=10m
      
      - name: Run smoke tests
        run: |
          ./scripts/smoke-test.sh staging
      
      - name: Run E2E tests
        run: |
          ./scripts/e2e-test.sh staging
      
      - name: Notify QA team
        if: success()
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
            -H 'Content-Type: application/json' \
            -d '{
              "channel": "#qa-team",
              "text": "🚀 New deployment to staging: ${{ env.IMAGE_NAME }}:${{ needs.build-and-push.outputs.image-tag }}\nReady for testing!"
            }'

  # ============================================================
  # Stage 6: Deploy to Production
  # ============================================================
  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://crusoe-island.com
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Pre-deployment checks
        run: |
          ./scripts/pre-deployment-check.sh ${{ needs.build-and-push.outputs.image-tag }}
      
      - name: Login to Azure
        uses: azure/login@v1
        with:
          creds: ${{ env.AZURE_CREDENTIALS }}
      
      - name: Get AKS credentials
        run: |
          az aks get-credentials \
            --resource-group rg-idp-prod \
            --name aks-idp-prod \
            --overwrite-existing
      
      - name: Create deployment annotation
        run: |
          kubectl annotate deployment/${{ env.IMAGE_NAME }} \
            kubernetes.io/change-cause="Deploy ${{ needs.build-and-push.outputs.image-tag }} by ${{ github.actor }}" \
            -n production
      
      - name: Update manifests
        run: |
          cd k8s/overlays/production
          kustomize edit set image \
            ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}=${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:${{ needs.build-and-push.outputs.image-tag }}
      
      - name: Deploy to production
        run: |
          kubectl apply -k k8s/overlays/production/
          kubectl rollout status deployment/${{ env.IMAGE_NAME }} \
            -n production \
            --timeout=15m
      
      - name: Run smoke tests
        run: |
          ./scripts/smoke-test.sh production
      
      - name: Monitor deployment
        run: |
          ./scripts/monitor-deployment.sh 15  # Monitor for 15 minutes
      
      - name: Notify on success
        if: success()
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
            -H 'Content-Type: application/json' \
            -d '{
              "channel": "#deployments",
              "text": "✅ Production deployment successful: ${{ env.IMAGE_NAME }}:${{ needs.build-and-push.outputs.image-tag }}"
            }'
      
      - name: Rollback on failure
        if: failure()
        run: |
          kubectl rollout undo deployment/${{ env.IMAGE_NAME }} -n production
          curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
            -H 'Content-Type: application/json' \
            -d '{
              "channel": "#incidents",
              "text": "🚨 Production deployment failed and rolled back: ${{ env.IMAGE_NAME }}:${{ needs.build-and-push.outputs.image-tag }}"
            }'
```

### Pipeline Secrets Configuration

```bash
# Required secrets in GitHub repository settings
# Settings → Secrets and variables → Actions

# AZURE_CREDENTIALS
# Azure service principal credentials (JSON format)
az ad sp create-for-rbac \
  --name "github-actions-${{ env.IMAGE_NAME }}" \
  --role contributor \
  --scopes /subscriptions/{subscription-id}/resourceGroups/rg-idp-prod \
  --sdk-auth

# Output (save as secret):
{
  "clientId": "...",
  "clientSecret": "...",
  "subscriptionId": "...",
  "tenantId": "...",
  "activeDirectoryEndpointUrl": "...",
  "resourceManagerEndpointUrl": "...",
  "activeDirectoryGraphResourceId": "...",
  "sqlManagementEndpointUrl": "...",
  "galleryEndpointUrl": "...",
  "managementEndpointUrl": "..."
}

# SLACK_WEBHOOK_URL
# Slack incoming webhook for notifications
# Get from: https://api.slack.com/messaging/webhooks

# COSIGN_KEY (optional, for image signing)
# Cosign private key
cosign generate-key-pair
# Save cosign.key contents as secret
```

-----

## 📝 GitOps Workflow

### What is GitOps?

```yaml
GitOps Principles:
  1. Declarative:
     - Entire system described declaratively
     - Git as single source of truth
     
  2. Versioned and Immutable:
     - Git history provides audit trail
     - Easy rollback to any previous state
     
  3. Pulled Automatically:
     - Software agents pull desired state from Git
     - System self-heals to match Git
     
  4. Continuously Reconciled:
     - Software agents ensure actual matches desired
     - Drift detection and correction

On Crusoe IDP:
  Git Repository → GitHub Actions → Kubernetes
  
  Changes:
  - All changes via Git commits
  - No kubectl apply from laptops (dev only)
  - Pull requests for review
  - Automatic deployment on merge
```

### Repository Structure for GitOps

```
my-app/
├── src/                          # Application source code
├── Dockerfile                     # Container definition
├── k8s/
│   ├── base/                      # Base Kubernetes resources
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   ├── serviceaccount.yaml
│   │   ├── configmap.yaml
│   │   └── kustomization.yaml
│   │
│   └── overlays/                  # Environment-specific overrides
│       ├── dev/
│       │   ├── kustomization.yaml
│       │   ├── patch-replicas.yaml
│       │   └── patch-resources.yaml
│       │
│       ├── staging/
│       │   ├── kustomization.yaml
│       │   ├── patch-replicas.yaml
│       │   └── patch-ingress.yaml
│       │
│       └── production/
│           ├── kustomization.yaml
│           ├── patch-replicas.yaml
│           ├── patch-resources.yaml
│           ├── patch-ingress.yaml
│           └── hpa.yaml
│
├── .github/
│   └── workflows/
│       └── deploy.yml             # CI/CD pipeline
│
└── scripts/
    ├── smoke-test.sh
    ├── e2e-test.sh
    └── pre-deployment-check.sh
```

### Kustomize Configuration

**Base configuration:**

```yaml
# k8s/base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- deployment.yaml
- service.yaml
- serviceaccount.yaml
- configmap.yaml

commonLabels:
  app: my-app
  managed-by: kustomize

commonAnnotations:
  contact: team@crusoe-island.com
  documentation: https://wiki.crusoe-island.com/my-app
```

**Development overlay:**

```yaml
# k8s/overlays/dev/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: dev-developer

bases:
- ../../base

images:
- name: acridpdev.azurecr.io/my-app
  newTag: dev  # Updated by CI/CD

replicas:
- name: my-app
  count: 1

patches:
- path: patch-resources.yaml
- path: patch-env.yaml

configMapGenerator:
- name: my-app-config
  behavior: merge
  literals:
  - LOG_LEVEL=debug
  - ENVIRONMENT=development
```

**Production overlay:**

```yaml
# k8s/overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: production

bases:
- ../../base

images:
- name: acridpdev.azurecr.io/my-app
  newTag: v1.2.3  # Updated by CI/CD

replicas:
- name: my-app
  count: 6

patches:
- path: patch-resources.yaml
- path: patch-env.yaml
- path: patch-security.yaml

resources:
- hpa.yaml  # Horizontal Pod Autoscaler
- pdb.yaml  # Pod Disruption Budget

configMapGenerator:
- name: my-app-config
  behavior: merge
  literals:
  - LOG_LEVEL=info
  - ENVIRONMENT=production

secretGenerator:
- name: my-app-secrets
  behavior: replace
  files:
  - .secret-placeholder  # Actual secrets from Key Vault
```

### GitOps Workflow Steps

```bash
# 1. Developer makes changes
git checkout -b feature/improve-performance
# Make code changes...
git add .
git commit -m "perf: optimize database queries"
git push origin feature/improve-performance

# 2. Create pull request
# GitHub UI: Create pull request from feature branch to staging

# 3. Automated checks run
# - Security scans
# - Unit tests
# - Build container
# - Integration tests

# 4. Code review
# Team members review changes

# 5. Merge to staging
# After approval, merge PR
# GitHub Actions automatically deploys to staging

# 6. QA testing in staging
# QA team validates changes

# 7. Create production PR
git checkout main
git merge staging
git push origin main

# 8. Production approval
# Platform team approves production deployment
# GitHub Actions deploys with manual approval gate

# 9. Monitor production
# Watch dashboards for 1 hour
# Verify metrics within SLA

# 10. Tag release
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

### Drift Detection and Reconciliation

```bash
# Detect configuration drift
# (When cluster state doesn't match Git)

# Check what's currently deployed
kubectl get deployment my-app -n production -o yaml > /tmp/deployed.yaml

# Check what Git says should be deployed
kubectl kustomize k8s/overlays/production/ > /tmp/desired.yaml

# Compare
diff /tmp/deployed.yaml /tmp/desired.yaml

# If drift detected, reconcile:
kubectl apply -k k8s/overlays/production/

# Automated drift detection (in CI/CD)
# Run every hour:
- name: Drift detection
  schedule:
    - cron: '0 * * * *'  # Every hour
  steps:
    - name: Check for drift
      run: |
        kubectl diff -k k8s/overlays/production/
        if [ $? -ne 0 ]; then
          echo "⚠️ Configuration drift detected!"
          # Send alert
        fi
```

-----

## 🎨 Kubernetes Deployment Patterns

### Multi-Container Pods

**Sidecar pattern:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-with-sidecar
spec:
  replicas: 3
  template:
    spec:
      containers:
      # Main application container
      - name: app
        image: acridpdev.azurecr.io/my-app:v1.0.0
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: shared-logs
          mountPath: /var/log/app
      
      # Sidecar: Log shipper
      - name: log-shipper
        image: fluent/fluent-bit:latest
        volumeMounts:
        - name: shared-logs
          mountPath: /var/log/app
          readOnly: true
        - name: fluent-bit-config
          mountPath: /fluent-bit/etc/
      
      volumes:
      - name: shared-logs
        emptyDir: {}
      - name: fluent-bit-config
        configMap:
          name: fluent-bit-config
```

**Init container pattern:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-with-init
spec:
  template:
    spec:
      initContainers:
      # Init container: Database migrations
      - name: db-migrate
        image: acridpdev.azurecr.io/my-app:v1.0.0
        command: ['npm', 'run', 'migrate']
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: url
      
      # Init container: Wait for dependencies
      - name: wait-for-db
        image: busybox:latest
        command: ['sh', '-c']
        args:
        - |
          until nc -z postgres-service 5432; do
            echo "Waiting for database..."
            sleep 2
          done
          echo "Database is ready!"
      
      containers:
      - name: app
        image: acridpdev.azurecr.io/my-app:v1.0.0
```

### StatefulSet for Stateful Applications

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: my-stateful-app
spec:
  serviceName: my-stateful-app
  replicas: 3
  selector:
    matchLabels:
      app: my-stateful-app
  template:
    metadata:
      labels:
        app: my-stateful-app
    spec:
      containers:
      - name: app
        image: acridpdev.azurecr.io/my-stateful-app:v1.0.0
        ports:
        - containerPort: 8080
          name: web
        volumeMounts:
        - name: data
          mountPath: /data
  
  # Persistent volume claim template
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: managed-premium
      resources:
        requests:
          storage: 10Gi

---
# Headless service for StatefulSet
apiVersion: v1
kind: Service
metadata:
  name: my-stateful-app
spec:
  clusterIP: None  # Headless
  selector:
    app: my-stateful-app
  ports:
  - port: 8080
    name: web
```

**Accessing StatefulSet pods:**

```bash
# Pods have stable names:
# my-stateful-app-0
# my-stateful-app-1
# my-stateful-app-2

# Stable DNS names:
# my-stateful-app-0.my-stateful-app.namespace.svc.cluster.local
# my-stateful-app-1.my-stateful-app.namespace.svc.cluster.local
# my-stateful-app-2.my-stateful-app.namespace.svc.cluster.local

# Connect to specific pod
kubectl exec -it my-stateful-app-0 -- /bin/sh
```

### DaemonSet for Node-Level Services

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-monitor
spec:
  selector:
    matchLabels:
      app: node-monitor
  template:
    metadata:
      labels:
        app: node-monitor
    spec:
      hostNetwork: true  # Use host network
      hostPID: true      # Access host processes
      containers:
      - name: monitor
        image: acridpdev.azurecr.io/node-monitor:v1.0.0
        securityContext:
          privileged: true  # Required for node-level access
        volumeMounts:
        - name: host-root
          mountPath: /host
          readOnly: true
      volumes:
      - name: host-root
        hostPath:
          path: /
```

### Jobs and CronJobs

**One-time job:**

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: data-migration
spec:
  template:
    spec:
      containers:
      - name: migrate
        image: acridpdev.azurecr.io/my-app:v1.0.0
        command: ['npm', 'run', 'migrate']
      restartPolicy: Never
  backoffLimit: 3  # Retry 3 times on failure
```

**Scheduled CronJob:**

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-backup
spec:
  schedule: "0 2 * * *"  # Every day at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: acridpdev.azurecr.io/backup-tool:v1.0.0
            command: ['/scripts/backup.sh']
            env:
            - name: BACKUP_DESTINATION
              value: "azure://backups/"
          restartPolicy: OnFailure
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
```

**Run job manually:**

```bash
# Create job from CronJob
kubectl create job --from=cronjob/nightly-backup manual-backup-$(date +%s)

# Watch job progress
kubectl get jobs -w

# View job logs
kubectl logs job/manual-backup-1234567890
```

-----

## ⚙️ Configuration Management

### ConfigMaps

**Create ConfigMap:**

```yaml
# From literal values
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-app-config
data:
  LOG_LEVEL: "info"
  MAX_CONNECTIONS: "100"
  FEATURE_FLAGS: "feature-a,feature-b"
  app.properties: |
    server.port=8080
    server.timeout=30s
    cache.enabled=true
```

```bash
# From file
kubectl create configmap my-app-config \
  --from-file=config.json \
  --from-file=app.properties

# From env file
kubectl create configmap my-app-env \
  --from-env-file=.env.production
```

**Use ConfigMap in Pod:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
  - name: app
    image: acridpdev.azurecr.io/my-app:v1.0.0
    
    # Option 1: All keys as environment variables
    envFrom:
    - configMapRef:
        name: my-app-config
    
    # Option 2: Specific keys as environment variables
    env:
    - name: LOG_LEVEL
      valueFrom:
        configMapKeyRef:
          name: my-app-config
          key: LOG_LEVEL
    
    # Option 3: Mount as files
    volumeMounts:
    - name: config
      mountPath: /config
      readOnly: true
  
  volumes:
  - name: config
    configMap:
      name: my-app-config
```

### Secrets (from Azure Key Vault)

**SecretProviderClass (managed by platform team):**

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: my-app-secrets
  namespace: production
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    userAssignedIdentityID: "client-id-of-managed-identity"
    keyvaultName: "kv-idp-prod"
    cloudName: ""
    objects: |
      array:
        - |
          objectName: database-password
          objectType: secret
          objectVersion: ""
        - |
          objectName: api-key
          objectType: secret
          objectVersion: ""
    tenantId: "your-tenant-id"
```

**Use secrets in Pod:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  serviceAccountName: my-app  # With workload identity
  containers:
  - name: app
    image: acridpdev.azurecr.io/my-app:v1.0.0
    
    # Secrets mounted as files
    volumeMounts:
    - name: secrets-store
      mountPath: "/mnt/secrets"
      readOnly: true
    
    # Read secrets in application:
    # const dbPassword = fs.readFileSync('/mnt/secrets/database-password', 'utf8');
  
  volumes:
  - name: secrets-store
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "my-app-secrets"
```

**Request secrets from platform team:**

```markdown
Slack: #platform-support

Subject: Request Azure Key Vault secrets for my-app

Application: my-app
Environment: production
Namespace: production

Secrets needed:
1. database-password
   - Description: PostgreSQL database password
   - Justification: Application needs to connect to database
   
2. stripe-api-key
   - Description: Stripe payment API key
   - Justification: Process payments

Service Account: my-app (already exists in production namespace)

Business Owner: @john.smith
Technical Owner: @jane.doe
```

### Environment-Specific Configuration

**Using Kustomize patches:**

```yaml
# k8s/overlays/production/patch-env.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: NODE_ENV
          value: "production"
        - name: LOG_LEVEL
          value: "warn"
        - name: ENABLE_DEBUG
          value: "false"
        - name: MAX_CONNECTIONS
          value: "1000"
```

**ConfigMap per environment:**

```bash
# Development
kubectl create configmap my-app-config \
  --from-literal=LOG_LEVEL=debug \
  --from-literal=ENABLE_DEBUG=true \
  -n development

# Staging
kubectl create configmap my-app-config \
  --from-literal=LOG_LEVEL=info \
  --from-literal=ENABLE_DEBUG=true \
  -n staging

# Production
kubectl create configmap my-app-config \
  --from-literal=LOG_LEVEL=warn \
  --from-literal=ENABLE_DEBUG=false \
  -n production
```

-----

## ⏪ Rollback Procedures

### Automatic Rollback on Failure

**Configured in deployment:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  progressDeadlineSeconds: 600  # 10 minutes timeout
  minReadySeconds: 30           # Wait 30s before considering ready
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0  # Zero downtime
  template:
    spec:
      containers:
      - name: app
        image: acridpdev.azurecr.io/my-app:v2.0.0
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3  # Fail after 3 attempts
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          failureThreshold: 3
```

**GitHub Actions automatic rollback:**

```yaml
- name: Deploy to production
  run: |
    kubectl apply -k k8s/overlays/production/
    kubectl rollout status deployment/my-app -n production --timeout=10m
  
- name: Rollback on failure
  if: failure()
  run: |
    echo "🚨 Deployment failed, rolling back..."
    kubectl rollout undo deployment/my-app -n production
    kubectl rollout status deployment/my-app -n production --timeout=5m
    
    # Notify team
    curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
      -d '{"text":"🚨 Production deployment failed and rolled back"}'
```

### Manual Rollback

**View rollout history:**

```bash
# List all revisions
kubectl rollout history deployment/my-app -n production

# Output:
# REVISION  CHANGE-CAUSE
# 1         Deploy v1.0.0
# 2         Deploy v1.1.0
# 3         Deploy v1.2.0 (current)
# 4         Deploy v1.3.0 (failed)

# View specific revision details
kubectl rollout history deployment/my-app --revision=3 -n production
```

**Rollback to previous version:**

```bash
# Rollback to immediately previous version
kubectl rollout undo deployment/my-app -n production

# Check rollback status
kubectl rollout status deployment/my-app -n production

# Verify pods are running
kubectl get pods -n production -l app=my-app
```

**Rollback to specific revision:**

```bash
# Rollback to revision 2
kubectl rollout undo deployment/my-app --to-revision=2 -n production

# Verify
kubectl rollout history deployment/my-app -n production
```

### Git-Based Rollback (Preferred)

**Revert commit:**

```bash
# Find the problematic commit
git log --oneline

# Revert the commit
git revert abc1234

# Push to trigger redeploy
git push origin main

# CI/CD will automatically deploy the reverted state
```

**Rollback to previous tag:**

```bash
# List tags
git tag

# Checkout previous version
git checkout v1.2.0

# Create hotfix branch
git checkout -b hotfix/rollback-to-v1.2.0

# Update image tag in kustomization
cd k8s/overlays/production
kustomize edit set image acridpdev.azurecr.io/my-app:v1.2.0

# Commit and push
git add .
git commit -m "hotfix: rollback to v1.2.0"
git push origin hotfix/rollback-to-v1.2.0

# Create PR with "URGENT" label
# After approval, CI/CD deploys
```

### Emergency Rollback Procedure

```yaml
EMERGENCY ROLLBACK PROCEDURE

When to Use:
  - Production outage caused by deployment
  - Critical bugs affecting customers
  - Security vulnerability introduced
  - Data integrity issues

Steps:

1. Immediate Action (0-5 min):
   ☐ Notify team (#incidents channel)
   ☐ Start incident timeline
   ☐ Identify last known good version

2. Execute Rollback (5-10 min):
   ```bash
   # Quick kubectl rollback
   kubectl rollout undo deployment/my-app -n production
   
   # Or specific version
   kubectl set image deployment/my-app \
     my-app=acridpdev.azurecr.io/my-app:v1.2.0 \
     -n production
```

1. Verify Rollback (10-15 min):
   ☐ Check pods are running
   ☐ Run smoke tests
   ☐ Verify metrics return to normal
   ☐ Check error rates
1. Communicate (15-20 min):
   ☐ Update status page
   ☐ Notify affected customers
   ☐ Internal team update
1. Post-Rollback (20-60 min):
   ☐ Update Git to match production
   ☐ Document incident
   ☐ Plan fix for issue
   ☐ Schedule post-mortem

```
---

## 📊 Monitoring Deployments

### Key Metrics to Watch

```yaml
During Deployment (0-30 min):

1. Deployment Progress:
   - Pods: Desired vs Ready vs Available
   - Rollout status
   - Time to healthy

2. Error Rate:
   - HTTP 5xx responses
   - Application exceptions
   - Failed requests
   Target: < 0.1% (99.9% success)

3. Response Time:
   - p50, p95, p99 latency
   - Database query time
   - External API calls
   Target: p95 < 200ms

4. Resource Usage:
   - CPU utilization
   - Memory usage
   - Network throughput
   Target: < 70% of limits

5. Health Checks:
   - Liveness probe failures
   - Readiness probe failures
   Target: 0 failures

Post-Deployment (30-60 min):

6. Business Metrics:
   - User sign-ups
   - Transaction volume
   - Conversion rate
   Target: Within 5% of baseline

7. Dependencies:
   - Database connections
   - Cache hit rate
   - Message queue depth
   Target: Normal ranges

8. Logs:
   - Error log volume
   - Warning patterns
   - New error types
   Target: No new errors
```

### Monitoring Commands

```bash
# Watch deployment progress
kubectl rollout status deployment/my-app -n production -w

# Watch pods
kubectl get pods -n production -l app=my-app -w

# Check pod events
kubectl get events -n production --sort-by='.lastTimestamp' | grep my-app

# View logs from all pods
kubectl logs -n production -l app=my-app --tail=100 -f

# Check resource usage
kubectl top pods -n production -l app=my-app

# Check endpoints
kubectl get endpoints my-app -n production

# Describe deployment
kubectl describe deployment my-app -n production
```

### Grafana Dashboards

**Deployment Dashboard URL:**

```
https://grafana.crusoe-island.com/d/deployment-monitoring
```

**Key Panels:**

1. Deployment Timeline
1. Error Rate (last 1h)
1. Response Time (p50, p95, p99)
1. Request Rate
1. Pod Count
1. CPU/Memory Usage
1. HTTP Status Codes
1. Database Query Time

### Alerting Rules

**Critical alerts (PagerDuty):**

```yaml
- alert: HighErrorRate
  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.01
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "High error rate detected"
    description: "Error rate is {{ $value }} (threshold: 0.01)"

- alert: DeploymentFailed
  expr: kube_deployment_status_replicas_unavailable > 0
  for: 10m
  labels:
    severity: critical
  annotations:
    summary: "Deployment has unavailable replicas"

- alert: PodCrashLooping
  expr: rate(kube_pod_container_status_restarts_total[15m]) > 0
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Pod is crash looping"
```

**Warning alerts (Slack):**

```yaml
- alert: HighResponseTime
  expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "High response time detected"
    description: "P95 latency is {{ $value }}s (threshold: 0.5s)"

- alert: HighCPUUsage
  expr: rate(container_cpu_usage_seconds_total[5m]) > 0.8
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "High CPU usage"
```

### Health Check Endpoints

**Implement in your application:**

```javascript
// Node.js example
const express = require('express');
const app = express();

// Liveness probe - Is the app alive?
app.get('/health', (req, res) => {
  // Basic health check
  res.status(200).json({ status: 'healthy' });
});

// Readiness probe - Is the app ready to serve traffic?
app.get('/ready', async (req, res) => {
  try {
    // Check database connection
    await db.ping();
    
    // Check cache connection
    await cache.ping();
    
    // Check external dependencies
    await checkDependencies();
    
    res.status(200).json({ 
      status: 'ready',
      checks: {
        database: 'ok',
        cache: 'ok',
        dependencies: 'ok'
      }
    });
  } catch (error) {
    res.status(503).json({ 
      status: 'not ready',
      error: error.message 
    });
  }
});

// Startup probe - Has the app finished starting?
app.get('/startup', (req, res) => {
  if (appFullyStarted) {
    res.status(200).json({ status: 'started' });
  } else {
    res.status(503).json({ status: 'starting' });
  }
});
```

-----

## 🚀 Advanced Deployment Patterns

### Progressive Delivery with Flagger

**Install Flagger (platform team):**

```bash
kubectl apply -k github.com/fluxcd/flagger//kustomize/kubernetes
```

**Canary deployment with Flagger:**

```yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: my-app
  namespace: production
spec:
  # Deployment reference
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: my-app
  
  # Service mesh provider (nginx)
  provider: nginx
  
  # Deployment strategy
  progressDeadlineSeconds: 600
  
  service:
    port: 80
    targetPort: 8080
  
  # Automated canary analysis
  analysis:
    # Schedule interval
    interval: 1m
    
    # Max number of failed metric checks
    threshold: 5
    
    # Max traffic percentage routed to canary
    maxWeight: 50
    
    # Traffic increment step
    stepWeight: 10
    
    # Prometheus metrics
    metrics:
    - name: request-success-rate
      thresholdRange:
        min: 99
      interval: 1m
    
    - name: request-duration
      thresholdRange:
        max: 500
      interval: 1m
    
    # Load testing webhook
    webhooks:
    - name: acceptance-test
      type: pre-rollout
      url: http://flagger-loadtester/
      timeout: 30s
      metadata:
        type: bash
        cmd: "curl http://my-app-canary:80/ | grep OK"
    
    - name: load-test
      url: http://flagger-loadtester/
      timeout: 5s
      metadata:
        cmd: "hey -z 1m -q 10 -c 2 http://my-app-canary:80/"
```

**Flagger canary progression:**

```
1. Detect new deployment
   ↓
2. Scale canary (wait for readiness)
   ↓
3. Run acceptance tests
   ↓
4. Route 10% traffic to canary
   ↓
5. Run load tests, check metrics
   ↓
6. If metrics good: increase to 20%
7. If metrics bad: rollback
   ↓
8. Continue incrementing by 10%
   ↓
9. Reach 50% (maxWeight)
   ↓
10. If all checks pass: promote canary
11. Route 100% to canary
12. Scale down primary
```

### Feature Flags

**Using LaunchDarkly (example):**

```javascript
// Initialize LaunchDarkly client
const LaunchDarkly = require('launchdarkly-node-server-sdk');
const client = LaunchDarkly.init(process.env.LAUNCHDARKLY_SDK_KEY);

await client.waitForInitialization();

// Check feature flag
app.get('/api/users', async (req, res) => {
  const user = {
    key: req.user.id,
    email: req.user.email,
    custom: {
      groups: req.user.groups
    }
  };
  
  // Check if new API version enabled for this user
  const useNewAPI = await client.variation('new-user-api', user, false);
  
  if (useNewAPI) {
    // New implementation
    return res.json(await getUsersV2());
  } else {
    // Old implementation
    return res.json(await getUsersV1());
  }
});
```

**Deployment with feature flags:**

```yaml
Strategy:
  1. Deploy new code (behind feature flag, disabled)
  2. Enable for internal users (10%)
  3. Enable for beta users (25%)
  4. Gradual rollout (50%, 75%, 100%)
  5. Remove flag after stable

Benefits:
  - Deploy without risk
  - Test in production safely
  - Instant rollback (just disable flag)
  - A/B testing
  - Gradual feature rollout
```

### Multi-Region Deployment

**Geo-distributed deployment:**

```yaml
Regions:
  Primary: West Europe (prod cluster)
  Secondary: North Europe (DR cluster)
  
Traffic Routing:
  - Azure Traffic Manager
  - Geographic routing
  - Automatic failover
  
Deployment Process:
  1. Deploy to West Europe
  2. Monitor for 1 hour
  3. If stable, deploy to North Europe
  4. Enable traffic to both regions
  5. Monitor global metrics
```

**Multi-region deployment script:**

```bash
#!/bin/bash
# deploy-multi-region.sh

REGIONS=("westeurope" "northeurope")
VERSION=$1

for region in "${REGIONS[@]}"; do
  echo "🚀 Deploying to $region..."
  
  # Get cluster credentials
  az aks get-credentials \
    --resource-group rg-idp-prod-$region \
    --name aks-idp-prod-$region \
    --overwrite-existing
  
  # Deploy
  kubectl set image deployment/my-app \
    my-app=acridpdev.azurecr.io/my-app:$VERSION \
    -n production
  
  # Wait for rollout
  kubectl rollout status deployment/my-app -n production --timeout=10m
  
  # Health check
  ./scripts/health-check.sh $region
  
  if [ $? -ne 0 ]; then
    echo "❌ Deployment failed in $region"
    exit 1
  fi
  
  echo "✅ Deployment successful in $region"
  
  # Wait between regions
  if [ "$region" != "${REGIONS[-1]}" ]; then
    echo "Waiting 30 minutes before next region..."
    sleep 1800
  fi
done

echo "🎉 Multi-region deployment complete!"
```

-----

**Continue to [Troubleshooting](#troubleshooting-deployments) section…**

-----

## 🔧 Troubleshooting Deployments

### Common Deployment Issues

#### Issue 1: ImagePullBackOff

**Symptoms:**

```bash
kubectl get pods
# NAME                     READY   STATUS             RESTARTS   AGE
# my-app-7d4b8f6c9d-abcde  0/1     ImagePullBackOff   0          2m
```

**Diagnosis:**

```bash
# Describe pod
kubectl describe pod my-app-7d4b8f6c9d-abcde

# Look for:
# Failed to pull image "acridpdev.azurecr.io/my-app:v1.0.0": 
# Error: authentication required
```

**Solutions:**

```bash
# 1. Check image exists
az acr repository show-tags --name acridpdev --repository my-app

# 2. Verify image name and tag
kubectl get deployment my-app -o yaml | grep image:

# 3. Check ACR credentials
kubectl get secret acr-secret -o yaml

# 4. Manually pull to test
docker pull acridpdev.azurecr.io/my-app:v1.0.0

# 5. If credentials issue, recreate secret
kubectl create secret docker-registry acr-secret \
  --docker-server=acridpdev.azurecr.io \
  --docker-username=$ACR_USERNAME \
  --docker-password=$ACR_PASSWORD
```

#### Issue 2: CrashLoopBackOff

**Symptoms:**

```bash
kubectl get pods
# NAME                     READY   STATUS             RESTARTS   AGE
# my-app-7d4b8f6c9d-abcde  0/1     CrashLoopBackOff   5          5m
```

**Diagnosis:**

```bash
# View current logs
kubectl logs my-app-7d4b8f6c9d-abcde

# View previous container logs
kubectl logs my-app-7d4b8f6c9d-abcde --previous

# Common causes:
# - Application error on startup
# - Missing environment variable
# - Cannot connect to database
# - Port already in use
# - Insufficient permissions
```

**Solutions:**

```bash
# 1. Check logs for error message
kubectl logs my-app-7d4b8f6c9d-abcde --previous | tail -50

# 2. Check environment variables
kubectl exec my-app-7d4b8f6c9d-abcde -- env

# 3. Check if dependencies are ready
kubectl get pods -l app=database

# 4. Exec into container (if stays up long enough)
kubectl exec -it my-app-7d4b8f6c9d-abcde -- /bin/sh

# 5. Test locally with same environment
docker run -it --env-file .env acridpdev.azurecr.io/my-app:v1.0.0
```

#### Issue 3: Deployment Stuck in Progress

**Symptoms:**

```bash
kubectl get deployment my-app
# NAME     READY   UP-TO-DATE   AVAILABLE   AGE
# my-app   3/6     3            3           10m
```

**Diagnosis:**

```bash
# Check deployment status
kubectl rollout status deployment/my-app

# Check pods
kubectl get pods -l app=my-app

# Check events
kubectl get events --sort-by='.lastTimestamp' | grep my-app

# Check replica sets
kubectl get rs -l app=my-app
```

**Common causes:**

- New pods failing readiness probes
- Insufficient resources
- Image pull errors
- Node issues

**Solutions:**

```bash
# 1. Check pod status in detail
kubectl describe pod <pod-name>

# 2. If resource issues
kubectl describe nodes

# 3. If probe issues, check probe configuration
kubectl get deployment my-app -o yaml | grep -A 10 readinessProbe

# 4. Pause deployment to investigate
kubectl rollout pause deployment/my-app

# 5. After fixing, resume
kubectl rollout resume deployment/my-app

# 6. Or rollback if needed
kubectl rollout undo deployment/my-app
```

#### Issue 4: Service Not Accessible

**Symptoms:**

```bash
# Service exists but can't connect
kubectl get svc my-app
# NAME     TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)   AGE
# my-app   ClusterIP   10.0.100.123   <none>        80/TCP    5m

# But connection fails
kubectl run -it --rm debug --image=busybox --restart=Never -- wget -O- http://my-app
# Connection refused
```

**Diagnosis:**

```bash
# 1. Check service endpoints
kubectl get endpoints my-app

# If no endpoints, pods don't match selector

# 2. Check service selector matches pod labels
kubectl get svc my-app -o yaml | grep selector: -A 5
kubectl get pods --show-labels | grep my-app

# 3. Check if pods are ready
kubectl get pods -l app=my-app

# 4. Check pod port matches service targetPort
kubectl get svc my-app -o yaml | grep targetPort:
kubectl get pod <pod-name> -o yaml | grep containerPort: -A 2
```

**Solutions:**

```bash
# 1. Fix selector mismatch
kubectl edit svc my-app
# Update selector to match pod labels

# 2. Fix port mismatch
kubectl edit svc my-app
# Update targetPort to match container port

# 3. If pods not ready, check readiness probes
kubectl logs <pod-name>
kubectl describe pod <pod-name>

# 4. Test pod directly (bypass service)
kubectl port-forward <pod-name> 8080:8080
curl http://localhost:8080
```

#### Issue 5: Ingress/External Access Not Working

**Symptoms:**

```bash
# Ingress exists
kubectl get ingress my-app
# NAME     CLASS   HOSTS                    ADDRESS   PORTS   AGE
# my-app   nginx   my-app.crusoe-island.com           80      5m

# But accessing URL gives 404 or 503
```

**Diagnosis:**

```bash
# 1. Check ingress configuration
kubectl describe ingress my-app

# 2. Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx

# 3. Check DNS resolution
nslookup my-app.crusoe-island.com

# 4. Check if backend service exists
kubectl get svc my-app

# 5. Check ingress annotations
kubectl get ingress my-app -o yaml | grep annotations: -A 10
```

**Solutions:**

```bash
# 1. Verify ingress backend
kubectl get ingress my-app -o yaml | grep backend: -A 5

# 2. Check service name matches
kubectl get svc | grep my-app

# 3. Test service directly first
kubectl port-forward svc/my-app 8080:80
curl http://localhost:8080

# 4. Check ingress class
kubectl get ingressclass

# 5. Check TLS secret (if using HTTPS)
kubectl get secret tls-secret -o yaml
```

#### Issue 6: ConfigMap/Secret Not Updating

**Symptoms:**

- Updated ConfigMap but pods still use old values
- Secret rotated but application sees old value

**Explanation:**
ConfigMaps and Secrets are not automatically reloaded in running pods.

**Solutions:**

```bash
# Option 1: Restart deployment (recommended)
kubectl rollout restart deployment/my-app

# Option 2: Use immutable ConfigMaps (change name on update)
# k8s/overlays/production/kustomization.yaml
configMapGenerator:
- name: my-app-config
  behavior: create  # Creates new ConfigMap with hash suffix
  literals:
  - LOG_LEVEL=info

# Option 3: Use a tool like Reloader
# https://github.com/stakater/Reloader
# Automatically restarts pods when ConfigMap/Secret changes

# Option 4: Mount as files and watch for changes
# (requires application support)
```

### Deployment Rollback Decision Tree

```
Deployment Issue Detected
│
├─ Pods starting successfully?
│  ├─ NO → Check ImagePullBackOff / CrashLoopBackOff fixes
│  └─ YES → Continue
│
├─ Health checks passing?
│  ├─ NO → Check readiness/liveness probe configuration
│  └─ YES → Continue
│
├─ Service accessible?
│  ├─ NO → Check Service/Ingress configuration
│  └─ YES → Continue
│
├─ Error rate normal?
│  ├─ NO → Is it > 1%?
│  │  ├─ YES → ROLLBACK IMMEDIATELY
│  │  └─ NO → Monitor closely, prepare rollback
│  └─ YES → Continue
│
├─ Response time normal?
│  ├─ NO → Is it > 2x baseline?
│  │  ├─ YES → ROLLBACK
│  │  └─ NO → Monitor, investigate
│  └─ YES → Continue
│
└─ Deployment SUCCESSFUL ✓
```

-----

## ✅ Best Practices

### Deployment Best Practices

```yaml
1. Always Use Version Tags:
   ✓ DO: acridpdev.azurecr.io/my-app:v1.2.3
   ✗ DON'T: acridpdev.azurecr.io/my-app:latest

2. Implement Health Checks:
   ✓ Liveness probe (is app alive?)
   ✓ Readiness probe (is app ready?)
   ✓ Startup probe (has app started?)

3. Set Resource Limits:
   ✓ requests (minimum needed)
   ✓ limits (maximum allowed)
   ✓ Prevent resource exhaustion

4. Use Rolling Updates:
   ✓ Zero downtime
   ✓ Gradual rollout
   ✓ Easy rollback

5. Monitor Deployments:
   ✓ Watch during deployment
   ✓ Monitor for 1 hour after
   ✓ Have rollback plan ready

6. Test Before Production:
   ✓ Test in development
   ✓ Validate in staging
   ✓ QA sign-off
   ✓ Then production

7. Automate Everything:
   ✓ CI/CD pipeline
   ✓ Security scans
   ✓ Automated tests
   ✓ Automated rollback

8. Use GitOps:
   ✓ Git as source of truth
   ✓ All changes via PR
   ✓ Audit trail
   ✓ Easy rollback

9. Gradual Rollout:
   ✓ Dev → Staging → Production
   ✓ Or canary deployment
   ✓ Monitor at each stage
   ✓ Rollback if issues

10. Document Everything:
    ✓ Deployment runbooks
    ✓ Rollback procedures
    ✓ Incident response
    ✓ Configuration docs
```

### Security Best Practices

```yaml
1. Never Commit Secrets:
   ✓ Use Azure Key Vault
   ✓ Mount secrets at runtime
   ✓ Rotate regularly
   ✗ Never in Git, environment variables, or ConfigMaps

2. Scan Everything:
   ✓ Secret scanning (detect-secrets)
   ✓ Dependency scanning (npm audit, pip-audit)
   ✓ Container scanning (Trivy)
   ✓ SAST scanning (Semgrep)

3. Run as Non-Root:
   ✓ Create dedicated user in Dockerfile
   ✓ Set securityContext in pod spec
   ✓ Drop all capabilities

4. Use Minimal Images:
   ✓ Distroless or Alpine base
   ✓ Multi-stage builds
   ✓ No unnecessary packages

5. Sign Images:
   ✓ Sign with Cosign
   ✓ Verify signatures
   ✓ Policy enforcement

6. Network Policies:
   ✓ Default deny
   ✓ Explicit allow rules
   ✓ Limit egress

7. RBAC:
   ✓ Least privilege
   ✓ Dedicated service accounts
   ✓ No admin access
```

### Performance Best Practices

```yaml
1. Right-Size Resources:
   ✓ Profile application
   ✓ Set appropriate requests/limits
   ✓ Use HPA for scaling

2. Optimize Images:
   ✓ Layer caching
   ✓ .dockerignore
   ✓ Minimize image size

3. Efficient Probes:
   ✓ Lightweight health checks
   ✓ Appropriate timeouts
   ✓ Don't check external dependencies in liveness

4. Connection Pooling:
   ✓ Database connection pools
   ✓ HTTP keep-alive
   ✓ Redis connection pooling

5. Caching:
   ✓ Redis for session/data caching
   ✓ CDN for static assets
   ✓ HTTP caching headers

6. Graceful Shutdown:
   ✓ Handle SIGTERM
   ✓ Drain connections
   ✓ Complete in-flight requests
```

-----

## 📚 Additional Resources

### Internal Documentation

- [Getting Started Guide](getting-started.md)
- [Security Guide](../security/security-guide.md)
- [Troubleshooting Guide](troubleshooting-guide.md)
- [Runbooks](../runbooks/)

### External Resources

- [Kubernetes Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Kustomize](https://kustomize.io/)
- [GitHub Actions](https://docs.github.com/en/actions)
- [Flagger](https://flagger.app/)
- [Azure AKS](https://docs.microsoft.com/azure/aks/)

### Support

- Slack: #platform-support
- Office Hours: Wednesdays 2-3 PM
- Email: platform-team@crusoe-island.com
- On-call: +XX-XXX-XXX-XXXX (emergencies only)

-----

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Maintained by:** Platform Engineering Team

-----

*Happy deploying! 🚀*
