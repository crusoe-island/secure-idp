# Getting Started with Crusoe IDP

**Version:** 1.0  
**Last Updated:** December 21, 2024  
**Audience:** Developers  
**Time to Complete:** 30-60 minutes

Welcome to the Crusoe Internal Developer Platform (IDP)! This guide will walk you through everything you need to get started, from initial setup to deploying your first application.

-----

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Day 1 Setup](#day-1-setup)
- [Understanding the Platform](#understanding-the-platform)
- [Your First Deployment](#your-first-deployment)
- [Common Development Workflows](#common-development-workflows)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Getting Help](#getting-help)
- [Next Steps](#next-steps)

-----

## ✅ Prerequisites

Before you begin, make sure you have:

### Required Access

```yaml
Access You Need:
  ☐ Azure AD account with MFA enabled
  ☐ Member of Azure AD group: IDP-Developers
  ☐ VPN access (if working remotely)
  ☐ Slack access (#developers, #platform-support)
  ☐ GitHub organization access (crusoe-island)

Request Access:
  - Contact: it-helpdesk@crusoe-island.com
  - Slack: #it-support
  - Expected time: 1 business day
```

### Your Workstation

```yaml
Supported Operating Systems:
  ✓ macOS 12+ (Monterey or later)
  ✓ Windows 10/11 with WSL2
  ✓ Linux (Ubuntu 22.04+ or equivalent)

Minimum Hardware:
  - CPU: 4 cores
  - RAM: 8GB (16GB recommended)
  - Disk: 50GB free space
  - Network: Stable internet connection
```

### Knowledge Prerequisites

```yaml
You Should Know:
  Essential:
    - Basic command line usage
    - Git fundamentals (clone, commit, push)
    - Basic understanding of containers (Docker)
    - YAML syntax
  
  Helpful but Not Required:
    - Kubernetes basics
    - CI/CD concepts
    - Azure fundamentals
    - Terraform basics
```

-----

## 🚀 Day 1 Setup

Let’s get your development environment ready! Follow these steps in order.

### Step 1: Install Required Tools

#### macOS Setup

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install essential tools
brew install \
  azure-cli \
  kubectl \
  helm \
  terraform \
  git \
  jq \
  yq

# Install Docker Desktop
brew install --cask docker

# Verify installations
az --version
kubectl version --client
helm version
terraform --version
docker --version
```

#### Windows (WSL2) Setup

```bash
# Run in WSL2 terminal

# Update package lists
sudo apt update

# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install Terraform
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform

# Install jq and yq
sudo apt install jq
sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod a+x /usr/local/bin/yq

# Install Docker Desktop for Windows, then enable WSL2 integration
```

#### Linux (Ubuntu) Setup

```bash
# Update package lists
sudo apt update

# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install Terraform
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform

# Install Docker
sudo apt install docker.io
sudo usermod -aG docker $USER
newgrp docker

# Install jq and yq
sudo apt install jq
sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
sudo chmod a+x /usr/local/bin/yq
```

### Step 2: Configure Azure CLI

```bash
# Login to Azure (this will open a browser)
az login

# Set default subscription
az account set --subscription "IDP-Production"

# Verify your identity
az account show

# Expected output:
# {
#   "name": "IDP-Production",
#   "user": {
#     "name": "your.name@crusoe-island.com",
#     "type": "user"
#   }
# }
```

### Step 3: Connect to Kubernetes Cluster

```bash
# Get AKS credentials (choose your environment)
# For development:
az aks get-credentials \
  --resource-group rg-idp-dev \
  --name aks-idp-dev \
  --overwrite-existing

# For staging:
az aks get-credentials \
  --resource-group rg-idp-staging \
  --name aks-idp-staging \
  --overwrite-existing

# Verify connection
kubectl cluster-info

# Check your access
kubectl auth can-i create deployments -n development

# Expected output: yes
```

### Step 4: Set Up Git and GitHub

```bash
# Configure Git with your work identity
git config --global user.name "Your Name"
git config --global user.email "your.name@crusoe-island.com"

# Set up SSH key for GitHub (if not already done)
ssh-keygen -t ed25519 -C "your.name@crusoe-island.com"

# Add SSH key to ssh-agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Display your public key (add this to GitHub)
cat ~/.ssh/id_ed25519.pub

# Test GitHub connection
ssh -T git@github.com

# Expected output: Hi username! You've successfully authenticated...
```

**Add SSH Key to GitHub:**

1. Go to: https://github.com/settings/keys
1. Click “New SSH key”
1. Paste your public key
1. Click “Add SSH key”

### Step 5: Clone Platform Repositories

```bash
# Create workspace directory
mkdir -p ~/crusoe-workspace
cd ~/crusoe-workspace

# Clone the platform configuration repository
git clone git@github.com:crusoe-island/idp-platform.git

# Clone your team's application repository (example)
git clone git@github.com:crusoe-island/sample-app.git

# Verify
ls -la
# Expected: idp-platform/ sample-app/
```

### Step 6: Install Security Tools

```bash
# Install pre-commit hooks framework
pip3 install pre-commit --break-system-packages

# Install detect-secrets (secret scanning)
pip3 install detect-secrets --break-system-packages

# Install tfsec (Terraform security scanner)
brew install tfsec  # macOS
# OR
curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash  # Linux

# Install trivy (container scanner)
brew install aquasecurity/trivy/trivy  # macOS
# OR
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy  # Linux

# Set up pre-commit hooks in your repository
cd ~/crusoe-workspace/sample-app
pre-commit install

# Test pre-commit hooks
pre-commit run --all-files
```

### Step 7: Configure Development Namespace

```bash
# Each developer gets a personal namespace
# Format: dev-<your-firstname>

# Set your namespace as default
kubectl config set-context --current --namespace=dev-$(whoami)

# Verify your namespace exists
kubectl get namespace dev-$(whoami)

# If it doesn't exist, request one via Slack #platform-support

# Create a handy alias
echo "alias k='kubectl'" >> ~/.bashrc  # or ~/.zshrc for macOS
source ~/.bashrc  # or ~/.zshrc
```

### Step 8: Set Up Azure Container Registry Access

```bash
# Login to Azure Container Registry
az acr login --name acridpdev

# Verify access
az acr repository list --name acridpdev --output table

# Expected: List of repositories you have access to
```

### Step 9: Verify Everything Works

Run this comprehensive verification script:

```bash
#!/bin/bash
# save as: verify-setup.sh

echo "🔍 Verifying Crusoe IDP Setup..."
echo ""

# Check Azure CLI
echo "✓ Checking Azure CLI..."
az account show --query name -o tsv || echo "❌ Azure CLI not configured"

# Check kubectl
echo "✓ Checking kubectl..."
kubectl cluster-info | grep -q "is running" && echo "  ✓ Connected to cluster" || echo "❌ Not connected to cluster"

# Check namespace access
echo "✓ Checking namespace access..."
kubectl auth can-i create deployments && echo "  ✓ Can create deployments" || echo "❌ Cannot create deployments"

# Check Azure Container Registry
echo "✓ Checking ACR access..."
az acr repository list --name acridpdev --output table &>/dev/null && echo "  ✓ ACR access working" || echo "❌ ACR access failed"

# Check security tools
echo "✓ Checking security tools..."
command -v detect-secrets &>/dev/null && echo "  ✓ detect-secrets installed" || echo "⚠ detect-secrets not installed"
command -v tfsec &>/dev/null && echo "  ✓ tfsec installed" || echo "⚠ tfsec not installed"
command -v trivy &>/dev/null && echo "  ✓ trivy installed" || echo "⚠ trivy not installed"

echo ""
echo "✅ Setup verification complete!"
```

```bash
# Make it executable and run
chmod +x verify-setup.sh
./verify-setup.sh
```

**Expected Output:**

```
🔍 Verifying Crusoe IDP Setup...

✓ Checking Azure CLI...
  ✓ Connected to Azure
✓ Checking kubectl...
  ✓ Connected to cluster
✓ Checking namespace access...
  ✓ Can create deployments
✓ Checking ACR access...
  ✓ ACR access working
✓ Checking security tools...
  ✓ detect-secrets installed
  ✓ tfsec installed
  ✓ trivy installed

✅ Setup verification complete!
```

-----

## 🎯 Understanding the Platform

Before deploying, let’s understand what you’re working with.

### Platform Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Crusoe IDP Architecture                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────┐
│   Developers    │
│  (You are here) │
└────────┬────────┘
         │
         ├─ git push ─→ GitHub
         │                │
         │                ├─→ GitHub Actions (CI/CD)
         │                │    ├─ Security scans
         │                │    ├─ Build Docker image
         │                │    ├─ Push to ACR
         │                │    └─ Deploy to AKS
         │                │
         └─ kubectl ───→ Azure Kubernetes Service (AKS)
                           │
                           ├─→ Development (dev-<yourname>)
                           ├─→ Staging (staging namespace)
                           └─→ Production (production namespace)
```

### Environments

```yaml
Development:
  Cluster: aks-idp-dev
  Your Namespace: dev-<yourname>
  Purpose: Personal sandbox for testing
  Auto-Deploy: Yes (on push to dev branch)
  Resources: Moderate limits
  Access: All developers (own namespace only)
  
Staging:
  Cluster: aks-idp-staging
  Namespace: staging
  Purpose: Pre-production testing
  Auto-Deploy: Yes (on push to staging branch)
  Resources: Production-like
  Access: All developers (read), Platform team (write)
  
Production:
  Cluster: aks-idp-prod
  Namespace: production
  Purpose: Live customer-facing services
  Auto-Deploy: Manual approval required
  Resources: Full production
  Access: Platform team + approved deployers
```

### Repository Structure

```
sample-app/                    # Your application repository
├── .github/
│   └── workflows/
│       ├── ci.yml            # Build and test
│       └── cd.yml            # Deploy pipeline
├── src/                       # Application source code
├── Dockerfile                 # Container definition
├── k8s/                       # Kubernetes manifests
│   ├── base/                  # Base configuration
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── kustomization.yaml
│   └── overlays/              # Environment-specific
│       ├── dev/
│       ├── staging/
│       └── production/
├── .pre-commit-config.yaml   # Pre-commit hooks
├── .dockerignore             # Files to exclude from image
└── README.md

idp-platform/                  # Platform configuration (read-only for most)
├── terraform/                 # Infrastructure as Code
├── kubernetes/                # Cluster-wide resources
└── docs/                      # Platform documentation
```

### Key Concepts

#### 1. GitOps Workflow

```yaml
GitOps Principles:
  - Git is the single source of truth
  - All changes via pull requests
  - Automatic deployment on merge
  - Rollback = revert commit
  
Your Workflow:
  1. Create feature branch
  2. Make changes locally
  3. Push to GitHub
  4. Create Pull Request
  5. Automated checks run
  6. Code review
  7. Merge → Auto-deploy
```

#### 2. Namespaces

```yaml
What is a Namespace?
  - Virtual cluster within AKS
  - Isolation boundary for resources
  - Each developer has their own
  - Separate quotas and policies

Your Personal Namespace:
  Name: dev-<yourname>
  Resources Available:
    - Deployments: 10
    - Pods: 50
    - CPU: 8 cores
    - Memory: 16 GB
    - Storage: 50 GB
  
  Can Create:
    ✓ Deployments
    ✓ Services
    ✓ ConfigMaps
    ✓ Secrets (from Key Vault only)
    ✓ Ingresses
  
  Cannot Create:
    ✗ Namespaces
    ✗ ClusterRoles
    ✗ PersistentVolumes
    ✗ NetworkPolicies (managed by platform)
```

#### 3. Container Registry

```yaml
Azure Container Registry (ACR):
  Name: acridpdev.azurecr.io
  
  Image Naming:
    Format: acridpdev.azurecr.io/<app-name>:<tag>
    Example: acridpdev.azurecr.io/sample-app:v1.2.3
    
  Tagging Strategy:
    - Git SHA: sha-<commit-hash> (automatic)
    - Semantic: v1.2.3 (manual tags)
    - Branch: dev, staging (updated on push)
    - latest: Production current
  
  Scanning:
    - Automatic Trivy scan on push
    - Block deployment if CRITICAL vulnerabilities
    - View results in GitHub Actions
```

#### 4. Secrets Management

```yaml
Azure Key Vault Integration:
  
  How It Works:
    1. Secrets stored in Azure Key Vault
    2. Kubernetes Secrets Provider pulls them
    3. Mounted as files in your pods
    4. Never in Git, never in code
  
  Accessing Secrets:
    # In your deployment.yaml:
    volumeMounts:
      - name: secrets-store
        mountPath: "/mnt/secrets"
        readOnly: true
    
    volumes:
      - name: secrets-store
        csi:
          driver: secrets-store.csi.k8s.io
          readOnly: true
          volumeAttributes:
            secretProviderClass: "app-secrets"
  
  Requesting Secrets:
    - Slack: #platform-support
    - Provide: app name, secret name, justification
    - Platform team creates SecretProviderClass
    - You reference it in your deployment
```

-----

## 🎬 Your First Deployment

Let’s deploy a simple application to your development namespace!

### Option 1: Deploy the Sample App (Recommended for First Time)

```bash
# 1. Clone the sample app
cd ~/crusoe-workspace
git clone git@github.com:crusoe-island/sample-app.git
cd sample-app

# 2. Review the application
cat README.md
ls -la

# 3. Build Docker image locally (optional, to test)
docker build -t sample-app:local .
docker run -p 8080:8080 sample-app:local
# Visit http://localhost:8080
# Press Ctrl+C to stop

# 4. Deploy to your dev namespace
kubectl apply -k k8s/overlays/dev/

# 5. Wait for deployment to be ready
kubectl wait --for=condition=available --timeout=300s deployment/sample-app

# 6. Check the deployment
kubectl get pods
kubectl get service sample-app

# Expected output:
# NAME                          READY   STATUS    RESTARTS   AGE
# sample-app-7d4b8f6c9d-abcde   1/1     Running   0          30s

# 7. Access your application
kubectl port-forward service/sample-app 8080:80

# Visit http://localhost:8080 in your browser
# You should see: "Hello from Crusoe IDP!"
```

### Option 2: Deploy Your Own Application

Let’s containerize and deploy your own application.

#### Step 1: Create a Dockerfile

```dockerfile
# Example: Node.js application
# Save as: Dockerfile

FROM node:20-alpine AS build

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Build (if needed)
RUN npm run build

# Runtime stage
FROM node:20-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy from build stage
COPY --from=build --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=nodejs:nodejs /app/dist ./dist
COPY --from=build --chown=nodejs:nodejs /app/package*.json ./

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD node healthcheck.js

# Start application
CMD ["node", "dist/index.js"]
```

#### Step 2: Create .dockerignore

```bash
# Save as: .dockerignore

node_modules
npm-debug.log
.git
.gitignore
.env
.env.local
*.md
.DS_Store
coverage/
.vscode/
.idea/
dist/  # Remove this line if you build outside Docker
```

#### Step 3: Build and Test Locally

```bash
# Build image
docker build -t my-app:local .

# Test locally
docker run -p 3000:3000 my-app:local

# In another terminal, test
curl http://localhost:3000/health
# Expected: {"status":"healthy"}

# Stop container
docker stop $(docker ps -q --filter ancestor=my-app:local)
```

#### Step 4: Create Kubernetes Manifests

```bash
# Create directory structure
mkdir -p k8s/base k8s/overlays/dev

# Create base deployment
cat > k8s/base/deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  labels:
    app: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      serviceAccountName: my-app
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
      containers:
      - name: my-app
        image: acridpdev.azurecr.io/my-app:latest
        ports:
        - containerPort: 3000
          name: http
        env:
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "3000"
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1001
          capabilities:
            drop:
            - ALL
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
EOF

# Create base service
cat > k8s/base/service.yaml << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: my-app
  labels:
    app: my-app
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app: my-app
EOF

# Create base service account
cat > k8s/base/serviceaccount.yaml << 'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  labels:
    app: my-app
EOF

# Create base kustomization
cat > k8s/base/kustomization.yaml << 'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
- deployment.yaml
- service.yaml
- serviceaccount.yaml

commonLabels:
  app: my-app
  managed-by: kustomize
EOF

# Create dev overlay
cat > k8s/overlays/dev/kustomization.yaml << 'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: dev-yourname  # Replace with your namespace

bases:
- ../../base

images:
- name: acridpdev.azurecr.io/my-app
  newTag: dev

replicas:
- name: my-app
  count: 1

patches:
- target:
    kind: Deployment
    name: my-app
  patch: |-
    - op: add
      path: /spec/template/spec/containers/0/env/-
      value:
        name: ENVIRONMENT
        value: development
EOF
```

#### Step 5: Push Image to ACR

```bash
# Build and tag for ACR
docker build -t acridpdev.azurecr.io/my-app:dev .

# Push to ACR
docker push acridpdev.azurecr.io/my-app:dev

# Verify
az acr repository show-tags \
  --name acridpdev \
  --repository my-app \
  --output table
```

#### Step 6: Deploy to Kubernetes

```bash
# Update the namespace in dev overlay
sed -i '' 's/dev-yourname/dev-'$(whoami)'/' k8s/overlays/dev/kustomization.yaml

# Preview what will be deployed
kubectl kustomize k8s/overlays/dev/

# Deploy
kubectl apply -k k8s/overlays/dev/

# Watch deployment progress
kubectl get pods -w

# Once running, check logs
kubectl logs -l app=my-app

# Test the service
kubectl port-forward service/my-app 3000:80

# Visit http://localhost:3000
```

#### Step 7: Set Up CI/CD Pipeline

```bash
# Create GitHub Actions workflow
mkdir -p .github/workflows

cat > .github/workflows/ci-cd.yaml << 'EOF'
name: CI/CD

on:
  push:
    branches:
      - main
      - dev
  pull_request:
    branches:
      - main

env:
  ACR_NAME: acridpdev
  IMAGE_NAME: my-app

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run secret scan
        run: |
          pip install detect-secrets
          detect-secrets scan --baseline .secrets.baseline
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'

  build-and-push:
    runs-on: ubuntu-latest
    needs: security-scan
    if: github.event_name == 'push'
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Login to Azure
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      
      - name: Login to ACR
        run: az acr login --name ${{ env.ACR_NAME }}
      
      - name: Build and push
        run: |
          TAG=${GITHUB_REF##*/}-${GITHUB_SHA::7}
          docker build -t ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:$TAG .
          docker push ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:$TAG
          
          # Also tag as branch name
          docker tag ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:$TAG \
                     ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:${GITHUB_REF##*/}
          docker push ${{ env.ACR_NAME }}.azurecr.io/${{ env.IMAGE_NAME }}:${GITHUB_REF##*/}

  deploy-dev:
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == 'refs/heads/dev'
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Login to Azure
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      
      - name: Get AKS credentials
        run: |
          az aks get-credentials \
            --resource-group rg-idp-dev \
            --name aks-idp-dev
      
      - name: Deploy to dev
        run: |
          kubectl apply -k k8s/overlays/dev/
          kubectl rollout status deployment/my-app -n dev-${GITHUB_ACTOR}
EOF
```

#### Step 8: Commit and Push

```bash
# Initialize secrets baseline
detect-secrets scan > .secrets.baseline

# Add all files
git add .

# Commit (pre-commit hooks will run)
git commit -m "Initial deployment configuration"

# Push to GitHub
git push origin main

# Check GitHub Actions
# Visit: https://github.com/crusoe-island/my-app/actions
```

-----

## 🔄 Common Development Workflows

### Workflow 1: Feature Development

```bash
# 1. Create feature branch
git checkout -b feature/add-user-api

# 2. Make your changes
# Edit src/api/users.js
# Add tests

# 3. Test locally
npm test
npm run lint

# 4. Build and test container locally
docker build -t my-app:feature .
docker run -p 3000:3000 my-app:feature

# 5. Commit changes (pre-commit hooks run automatically)
git add .
git commit -m "feat: add user API endpoint"

# 6. Push to GitHub
git push origin feature/add-user-api

# 7. Create Pull Request
# Visit GitHub and click "Create Pull Request"
# Automated checks will run

# 8. After review and approval, merge
# The app will auto-deploy to dev environment

# 9. Clean up
git checkout main
git pull
git branch -d feature/add-user-api
```

### Workflow 2: Debugging a Pod

```bash
# List your pods
kubectl get pods

# View logs
kubectl logs <pod-name>

# Follow logs in real-time
kubectl logs -f <pod-name>

# Get previous logs (if pod restarted)
kubectl logs <pod-name> --previous

# Execute commands in pod
kubectl exec -it <pod-name> -- /bin/sh

# Inside the pod:
ls /app
env | grep APP_
ps aux
exit

# Describe pod (shows events and status)
kubectl describe pod <pod-name>

# Check pod resource usage
kubectl top pod <pod-name>
```

### Workflow 3: Updating Configuration

```bash
# Option A: ConfigMap for non-sensitive data
cat > k8s/base/configmap.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-app-config
data:
  LOG_LEVEL: "info"
  MAX_CONNECTIONS: "100"
  FEATURE_FLAGS: "feature-a,feature-b"
EOF

# Add to kustomization.yaml
echo "- configmap.yaml" >> k8s/base/kustomization.yaml

# Reference in deployment.yaml
# Add under spec.template.spec.containers[0]:
#   envFrom:
#   - configMapRef:
#       name: my-app-config

# Apply changes
kubectl apply -k k8s/overlays/dev/

# Option B: Secrets from Key Vault (request from platform team)
# They will provide a SecretProviderClass
# You reference it as shown in "Key Concepts" section

# Restart pods to pick up new config
kubectl rollout restart deployment/my-app
```

### Workflow 4: Scaling Your Application

```bash
# Scale to 3 replicas
kubectl scale deployment/my-app --replicas=3

# Verify
kubectl get pods -l app=my-app

# To make permanent, update kustomization.yaml:
# replicas:
# - name: my-app
#   count: 3

# Watch autoscaling (if HPA is configured)
kubectl get hpa my-app -w
```

### Workflow 5: Rolling Back a Deployment

```bash
# View rollout history
kubectl rollout history deployment/my-app

# Rollback to previous version
kubectl rollout undo deployment/my-app

# Rollback to specific revision
kubectl rollout undo deployment/my-app --to-revision=2

# Check status
kubectl rollout status deployment/my-app

# Git method (preferred for production):
git revert <bad-commit-hash>
git push origin main
# CI/CD will deploy the reverted state
```

### Workflow 6: Accessing External Services

```bash
# Your pod can access:
# ✓ Other services in your namespace
# ✓ Azure services (via managed identity)
# ✓ Approved external APIs (via firewall)

# Access another service in your namespace:
curl http://other-service.dev-yourname.svc.cluster.local

# Access Azure Key Vault (using DefaultAzureCredential):
# Your code:
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
client = SecretClient(
    vault_url="https://kv-idp-dev.vault.azure.net",
    credential=credential
)
secret = client.get_secret("my-secret")

# Request external API access:
# Slack: #platform-support
# Provide: URL, justification, required ports
# Platform team will update firewall rules
```

-----

## ✨ Best Practices

### Container Best Practices

```yaml
DO:
  ✓ Use official base images
  ✓ Use multi-stage builds
  ✓ Run as non-root user
  ✓ Use specific image tags (not :latest)
  ✓ Scan images for vulnerabilities
  ✓ Keep images small (<500MB ideally)
  ✓ Use .dockerignore
  ✓ Add health checks

DON'T:
  ✗ Store secrets in images
  ✗ Run as root
  ✗ Use :latest tag in production
  ✗ Include unnecessary files
  ✗ Skip vulnerability scans
  ✗ Make images unnecessarily large
```

### Kubernetes Best Practices

```yaml
DO:
  ✓ Set resource requests and limits
  ✓ Use liveness and readiness probes
  ✓ Use namespaces for isolation
  ✓ Label everything consistently
  ✓ Use ConfigMaps for configuration
  ✓ Use Secrets for sensitive data
  ✓ Implement graceful shutdown
  ✓ Use rolling updates

DON'T:
  ✗ Run privileged containers
  ✗ Use hostNetwork or hostPath
  ✗ Skip resource limits
  ✗ Ignore security contexts
  ✗ Deploy without health checks
```

### Git Best Practices

```yaml
DO:
  ✓ Write clear commit messages
  ✓ Keep commits focused and atomic
  ✓ Create feature branches
  ✓ Use pull requests for code review
  ✓ Run tests before committing
  ✓ Keep branches up to date with main
  ✓ Delete merged branches

DON'T:
  ✗ Commit secrets or credentials
  ✗ Commit directly to main
  ✗ Use generic commit messages ("fix bug")
  ✗ Have large, unfocused commits
  ✗ Leave stale branches
```

### Security Best Practices

```yaml
DO:
  ✓ Use MFA everywhere
  ✓ Rotate credentials regularly
  ✓ Scan for secrets before committing
  ✓ Keep dependencies up to date
  ✓ Use HTTPS for all connections
  ✓ Follow principle of least privilege
  ✓ Enable audit logging
  ✓ Report security issues immediately

DON'T:
  ✗ Commit secrets to Git
  ✗ Share credentials
  ✗ Disable security scans
  ✗ Use weak passwords
  ✗ Click suspicious links
  ✗ Ignore security alerts
```

-----

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Issue 1: Pod Won’t Start

```bash
# Check pod status
kubectl get pods

# Common statuses:
# - ImagePullBackOff: Can't pull image
# - CrashLoopBackOff: Container keeps crashing
# - Pending: Can't schedule pod

# For ImagePullBackOff:
kubectl describe pod <pod-name>
# Check: image name, ACR access
# Fix: Verify image exists, check credentials

# For CrashLoopBackOff:
kubectl logs <pod-name>
kubectl logs <pod-name> --previous
# Check: application errors, missing environment variables

# For Pending:
kubectl describe pod <pod-name>
# Check: resource requests, node capacity
# Fix: Reduce requests or contact platform team
```

#### Issue 2: Can’t Access Service

```bash
# Check service exists
kubectl get service my-app

# Check endpoints
kubectl get endpoints my-app

# If no endpoints, pods aren't ready
kubectl get pods -l app=my-app
kubectl describe pod <pod-name>

# Test from another pod
kubectl run -it --rm debug --image=busybox --restart=Never -- sh
wget -O- http://my-app.dev-yourname.svc.cluster.local
exit

# Check network policies
kubectl get networkpolicies
```

#### Issue 3: Authentication Errors

```bash
# Re-login to Azure
az login
az account set --subscription "IDP-Production"

# Refresh AKS credentials
az aks get-credentials \
  --resource-group rg-idp-dev \
  --name aks-idp-dev \
  --overwrite-existing

# Test access
kubectl auth can-i create deployments

# If still issues, check with platform team
```

#### Issue 4: CI/CD Pipeline Fails

```bash
# Check GitHub Actions logs
# Visit: https://github.com/<org>/<repo>/actions

# Common failures:

# Security scan failed:
# - Secret detected: Review and remove from Git
# - Vulnerability found: Update dependency

# Build failed:
# - Syntax error: Check your code
# - Missing dependency: Update package.json

# Deploy failed:
# - Invalid YAML: Run 'kubectl apply --dry-run'
# - Insufficient permissions: Contact platform team
```

#### Issue 5: Secret Not Available in Pod

```bash
# Check if SecretProviderClass exists
kubectl get secretproviderclass

# Check pod events
kubectl describe pod <pod-name>

# Verify volume mount
kubectl exec <pod-name> -- ls -la /mnt/secrets

# If empty or missing:
# 1. Verify SecretProviderClass name matches
# 2. Check Azure Key Vault has the secret
# 3. Verify managed identity has access
# 4. Contact platform team if still issues
```

### Getting Help

```yaml
Self-Service Resources:
  1. Platform Documentation:
     - Internal wiki: https://wiki.crusoe-island.com/idp
     - This guide: docs/developer-guide/
     - Security guide: docs/security/security-guide.md
  
  2. Check Runbooks:
     - docs/runbooks/common-issues.md
     - docs/runbooks/debugging-guide.md
  
  3. Search Slack History:
     - #platform-support
     - #developers

Getting Help from Platform Team:
  
  Level 1 - Questions:
    Channel: #platform-support
    Response Time: 4 hours (business hours)
    Example: "How do I access Azure Key Vault?"
  
  Level 2 - Issues:
    Create Jira ticket: IDP project
    Response Time: 1 business day
    Include:
      - What you're trying to do
      - What you've tried
      - Error messages
      - kubectl describe output
  
  Level 3 - Incidents:
    Slack: #platform-incidents
    Response Time: Immediate
    For: Production outages, security issues
    Include: Impact, affected services

Office Hours:
  When: Wednesdays 2-3 PM
  Where: Zoom (link in #platform-support topic)
  Format: Drop-in, ask anything
```

-----

## 🎓 Next Steps

### Week 1: Master the Basics

```yaml
Day 1-2: Setup (Done!)
  ☐ Complete this getting started guide
  ☐ Deploy sample app successfully
  ☐ Understand platform architecture

Day 3-4: Deploy Your App
  ☐ Containerize your application
  ☐ Create Kubernetes manifests
  ☐ Deploy to dev namespace
  ☐ Set up CI/CD pipeline

Day 5: Learn and Explore
  ☐ Read security-guide.md
  ☐ Experiment with kubectl commands
  ☐ Join office hours
  ☐ Ask questions in Slack
```

### Week 2: Advanced Topics

```yaml
Topics to Explore:
  ☐ Advanced Kubernetes (StatefulSets, Jobs, CronJobs)
  ☐ Monitoring and observability (Prometheus, Grafana)
  ☐ Service mesh (if applicable)
  ☐ Database integration
  ☐ Message queues (if applicable)
  ☐ API Gateway patterns
```

### Month 1: Become Proficient

```yaml
Goals:
  ☐ Successfully deploy and maintain your app
  ☐ Understand all environments (dev, staging, prod)
  ☐ Comfortable with troubleshooting
  ☐ Contributing to platform improvements
  ☐ Helping onboard new developers
```

### Additional Resources

```yaml
Documentation:
  - Kubernetes Basics: https://kubernetes.io/docs/tutorials/kubernetes-basics/
  - Docker Best Practices: https://docs.docker.com/develop/dev-best-practices/
  - Azure AKS: https://docs.microsoft.com/azure/aks/
  - GitOps: https://www.gitops.tech/

Internal Resources:
  - Platform Wiki: https://wiki.crusoe-island.com/idp
  - Architecture Diagrams: docs/architecture/
  - API Documentation: docs/api/
  - Runbooks: docs/runbooks/

Community:
  - Slack: #developers, #platform-support
  - Office Hours: Wednesdays 2-3 PM
  - Monthly Platform Updates: First Friday of month
```

-----

## 📚 Appendix

### Useful Commands Cheat Sheet

```bash
# Kubernetes
kubectl get pods                              # List pods
kubectl get pods -w                           # Watch pods
kubectl get all                               # List all resources
kubectl logs <pod>                            # View logs
kubectl logs -f <pod>                         # Follow logs
kubectl exec -it <pod> -- /bin/sh            # Shell into pod
kubectl describe pod <pod>                    # Detailed pod info
kubectl delete pod <pod>                      # Delete pod
kubectl port-forward svc/<svc> 8080:80       # Port forward
kubectl top pod <pod>                         # Resource usage
kubectl get events --sort-by=.metadata.creationTimestamp  # Recent events

# Azure CLI
az login                                      # Login to Azure
az account show                               # Show current account
az acr login --name acridpdev                # Login to ACR
az aks get-credentials --resource-group rg-idp-dev --name aks-idp-dev  # Get AKS creds

# Docker
docker build -t image:tag .                   # Build image
docker run -p 8080:80 image:tag              # Run container
docker ps                                     # List containers
docker logs <container>                       # View logs
docker exec -it <container> /bin/sh          # Shell into container
docker stop <container>                       # Stop container

# Git
git status                                    # Check status
git add .                                     # Stage all changes
git commit -m "message"                       # Commit
git push                                      # Push to remote
git pull                                      # Pull from remote
git checkout -b branch-name                   # Create branch
git branch -d branch-name                     # Delete branch
```

### Environment Variables Reference

```yaml
Common Environment Variables:

Application:
  NODE_ENV: production|development|staging
  PORT: 3000
  LOG_LEVEL: debug|info|warn|error

Azure:
  AZURE_CLIENT_ID: Managed identity client ID
  AZURE_TENANT_ID: Azure tenant ID

Kubernetes:
  KUBERNETES_SERVICE_HOST: Kubernetes API host
  KUBERNETES_SERVICE_PORT: Kubernetes API port
  POD_NAME: Current pod name
  POD_NAMESPACE: Current namespace
  POD_IP: Pod IP address
```

### Resource Limits Reference

```yaml
CPU Units:
  1 CPU = 1000m (millicores)
  Examples:
    100m = 0.1 CPU (10% of one core)
    500m = 0.5 CPU (50% of one core)
    2000m = 2 CPU (two full cores)

Memory Units:
  Ki = Kibibyte (1024 bytes)
  Mi = Mebibyte (1024 Ki)
  Gi = Gibibyte (1024 Mi)
  Examples:
    128Mi = 128 mebibytes
    1Gi = 1 gibibyte
    512Mi = 512 mebibytes

Typical Application Ranges:
  Small (API, microservice):
    requests: cpu: 100m, memory: 128Mi
    limits: cpu: 500m, memory: 512Mi
  
  Medium (Web app):
    requests: cpu: 250m, memory: 256Mi
    limits: cpu: 1000m, memory: 1Gi
  
  Large (Data processing):
    requests: cpu: 500m, memory: 512Mi
    limits: cpu: 2000m, memory: 4Gi
```

-----

## 🎉 Congratulations!

You’ve completed the getting started guide! You now know how to:

✅ Set up your development environment  
✅ Connect to the Crusoe IDP platform  
✅ Deploy applications to Kubernetes  
✅ Use CI/CD pipelines  
✅ Troubleshoot common issues  
✅ Follow security best practices

**You’re ready to start building on the Crusoe IDP!**

-----

## 📝 Feedback

This guide is continuously improved based on developer feedback.

**Found an issue or have a suggestion?**

- Create an issue: https://github.com/crusoe-island/idp-platform/issues
- Slack: #platform-support
- Email: platform-team@crusoe-island.com

**Questions about this guide?**

- Slack: #platform-support
- Office Hours: Wednesdays 2-3 PM

-----

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Maintained by:** Platform Engineering Team  
**License:** Internal Use Only - Confidential

-----

*Happy coding! 🚀*
