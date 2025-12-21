# Network Architecture - Crusoe IDP

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Owner:** Platform Engineering Team  
**Status:** Active

-----

## 📋 Table of Contents

- [Overview](#overview)
- [Network Design Principles](#network-design-principles)
- [Network Topology](#network-topology)
- [IP Address Plan](#ip-address-plan)
- [Security Zones](#security-zones)
- [Traffic Flows](#traffic-flows)
- [Azure Network Services](#azure-network-services)
- [Kubernetes Networking](#kubernetes-networking)
- [DNS Architecture](#dns-architecture)
- [Load Balancing](#load-balancing)
- [Network Security](#network-security)
- [Egress Control](#egress-control)
- [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)
- [Disaster Recovery](#disaster-recovery)
- [Performance Optimization](#performance-optimization)
- [Configuration Examples](#configuration-examples)
- [Network Policies Reference](#network-policies-reference)

-----

## 🌐 Overview

### Purpose

This document describes the network architecture for the Crusoe Internal Developer Platform (IDP). The design implements a secure, scalable, and highly available network infrastructure that supports:

- Zero-trust security model
- Defense-in-depth network segmentation
- Private-only connectivity for sensitive services
- High availability and disaster recovery
- Compliance with security best practices

### Scope

This architecture covers:

- **Azure Virtual Networks**: VNet design and subnets
- **Network Security**: Firewalls, NSGs, private endpoints
- **AKS Networking**: CNI, network policies, service mesh
- **Connectivity**: VPN, ExpressRoute (future), peering
- **DNS**: Public and private DNS zones
- **Load Balancing**: Internal and external load balancers
- **Egress Control**: Internet-bound traffic filtering

### Key Characteristics

```
Characteristic         Value
─────────────────────────────────────────
Network Model         Hub-and-Spoke
Address Space         10.0.0.0/16 (primary)
Availability Zones    3 (for production)
Internet Exposure     Minimal (WAF + public LB only)
Private Endpoints     All PaaS services
Network Plugin        Azure CNI
Network Policies      Calico
Service Mesh          Istio (future)
```

-----

## 🎯 Network Design Principles

### 1. Zero Trust Network

**Principle:** Never trust, always verify

```
Traditional Network          Zero Trust Network
─────────────────────────────────────────────────
Trust inside perimeter      No implicit trust
Castle-and-moat            Micro-segmentation
Network = security zone    Identity = security perimeter
VPN = trusted              Verify every connection
```

**Implementation:**

- No automatic trust between subnets
- Explicit allow rules for all traffic
- Identity-based access (not IP-based)
- Encryption everywhere (TLS)

### 2. Defense-in-Depth

**Principle:** Multiple layers of network security

```
┌─────────────────────────────────────────────┐
│ Layer 7: Application (WAF)                  │
├─────────────────────────────────────────────┤
│ Layer 4-7: Azure Firewall                   │
├─────────────────────────────────────────────┤
│ Layer 4: Load Balancer                      │
├─────────────────────────────────────────────┤
│ Layer 3-4: Network Security Groups          │
├─────────────────────────────────────────────┤
│ Layer 3: Virtual Network                    │
├─────────────────────────────────────────────┤
│ Layer 3: Kubernetes Network Policies        │
├─────────────────────────────────────────────┤
│ Layer 2-3: Azure CNI                        │
└─────────────────────────────────────────────┘
```

### 3. Least Privilege Network Access

**Principle:** Only allow necessary connectivity

- Default deny all traffic
- Explicit allow for required flows
- Minimal port exposure
- Time-bound access where possible

### 4. Segmentation and Isolation

**Principle:** Separate network zones by trust level

```
Zone              Trust Level    Connectivity
───────────────────────────────────────────────
Internet          Untrusted      Ingress only
DMZ               Low            Controlled
Application       Medium         Restricted
Platform          High           Limited
Management        Highest        Minimal
Data              Highest        Private only
```

### 5. High Availability

**Principle:** No single point of failure

- Zone-redundant services (3 AZs)
- Multiple paths for critical traffic
- Automatic failover
- Geographic redundancy (future: multi-region)

### 6. Observability

**Principle:** You can’t secure what you can’t see

- Flow logs on all NSGs
- Firewall diagnostic logs
- Network Watcher enabled
- Traffic Analytics
- Connection monitoring

-----

## 🏗️ Network Topology

### Hub-and-Spoke Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                              INTERNET                               │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │ Azure Front Door│
                    │    + WAF        │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼─────┐      ┌──────▼──────┐     ┌─────▼────┐
    │   Dev    │      │  Staging    │     │   Prod   │
    │  Region  │      │   Region    │     │  Region  │
    └────┬─────┘      └──────┬──────┘     └─────┬────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
                  ┌──────────▼──────────┐
                  │    HUB VNET         │
                  │  (Shared Services)  │
                  │                     │
                  │ ┌─────────────────┐ │
                  │ │ Azure Firewall  │ │
                  │ │ (Egress Control)│ │
                  │ └─────────────────┘ │
                  │                     │
                  │ ┌─────────────────┐ │
                  │ │ VPN Gateway     │ │
                  │ │ (Admin Access)  │ │
                  │ └─────────────────┘ │
                  │                     │
                  │ ┌─────────────────┐ │
                  │ │ Bastion Host    │ │
                  │ └─────────────────┘ │
                  └──────────┬──────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │ VNet Peering      │      VNet Peering │
         │                   │                   │
    ┌────▼─────────┐  ┌──────▼────────┐  ┌──────▼────────┐
    │  SPOKE VNET  │  │  SPOKE VNET   │  │  SPOKE VNET   │
    │     DEV      │  │   STAGING     │  │     PROD      │
    │              │  │               │  │               │
    │ 10.10.0.0/16 │  │ 10.20.0.0/16  │  │ 10.0.0.0/16   │
    └──────────────┘  └───────────────┘  └───────────────┘
```

### Production VNet Architecture (Detailed)

```
┌───────────────────────────────────────────────────────────────────────┐
│                    PRODUCTION VNET (10.0.0.0/16)                      │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Azure Firewall Subnet (10.0.0.0/24)                         │    │
│  │ ┌─────────────────────────────────────────────────────┐     │    │
│  │ │ Azure Firewall (Zone-redundant)                     │     │    │
│  │ │ - Threat Intelligence                                │     │    │
│  │ │ - Application rules (FQDN filtering)                │     │    │
│  │ │ - Network rules (IP/port filtering)                 │     │    │
│  │ └─────────────────────────────────────────────────────┘     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ AKS System Node Subnet (10.0.1.0/24)                        │    │
│  │ NSG: aks-system-nsg                                          │    │
│  │ ┌──────────┐  ┌──────────┐  ┌──────────┐                    │    │
│  │ │System    │  │System    │  │System    │                    │    │
│  │ │Node (AZ1)│  │Node (AZ2)│  │Node (AZ3)│                    │    │
│  │ └──────────┘  └──────────┘  └──────────┘                    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ AKS User Node Subnet (10.0.2.0/23)                          │    │
│  │ NSG: aks-workload-nsg                                        │    │
│  │ ┌──────────┐  ┌──────────┐  ┌──────────┐                    │    │
│  │ │Workload  │  │Workload  │  │Workload  │                    │    │
│  │ │Node (AZ1)│  │Node (AZ2)│  │Node (AZ3)│  ... (scalable)    │    │
│  │ └──────────┘  └──────────┘  └──────────┘                    │    │
│  │                                                               │    │
│  │ Pod CIDR: 10.244.0.0/16 (Azure CNI)                          │    │
│  │ Service CIDR: 10.245.0.0/16                                  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Private Endpoints Subnet (10.0.4.0/24)                      │    │
│  │ NSG: private-endpoints-nsg                                   │    │
│  │ ┌────────────┐ ┌────────────┐ ┌────────────┐               │    │
│  │ │ Key Vault  │ │    ACR     │ │  Storage   │               │    │
│  │ │ Private EP │ │ Private EP │ │ Private EP │               │    │
│  │ └────────────┘ └────────────┘ └────────────┘               │    │
│  │                                                               │    │
│  │ Private DNS Integration: ✓                                   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Application Gateway Subnet (10.0.5.0/24)                    │    │
│  │ NSG: appgw-nsg                                               │    │
│  │ ┌─────────────────────────────────────────────────────┐     │    │
│  │ │ Application Gateway (WAF v2)                        │     │    │
│  │ │ - Zone-redundant (AZ1, AZ2, AZ3)                   │     │    │
│  │ │ - OWASP 3.2 rules                                   │     │    │
│  │ │ - TLS termination                                   │     │    │
│  │ └─────────────────────────────────────────────────────┘     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Bastion Subnet (10.0.6.0/27)                                │    │
│  │ NSG: AzureBastionSubnet-nsg (Azure-managed)                 │    │
│  │ ┌─────────────────────────────────────────────────────┐     │    │
│  │ │ Azure Bastion (Standard SKU)                        │     │    │
│  │ │ - Secure RDP/SSH access                             │     │    │
│  │ │ - No public IPs on VMs                              │     │    │
│  │ └─────────────────────────────────────────────────────┘     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Management Subnet (10.0.7.0/24)                             │    │
│  │ NSG: management-nsg                                          │    │
│  │ ┌────────────┐ ┌────────────┐ ┌────────────┐               │    │
│  │ │ Jump Box   │ │   Build    │ │  Logging   │               │    │
│  │ │   (VM)     │ │   Agent    │ │   VM       │               │    │
│  │ └────────────┘ └────────────┘ └────────────┘               │    │
│  └─────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────────────┘

Route Table: All subnets → Azure Firewall (0.0.0.0/0 → 10.0.0.4)
```

-----

## 📊 IP Address Plan

### Address Space Allocation

```yaml
Environment: Production
Region: West Europe
VNet CIDR: 10.0.0.0/16
Total Addresses: 65,536

Subnet Allocation:

# Infrastructure Subnets
AzureFirewallSubnet:        10.0.0.0/24    (256 addresses)
  - Reserved for Azure Firewall
  - Must be /26 minimum, /24 recommended

GatewaySubnet:              10.0.0.128/27  (32 addresses)  # Future
  - Reserved for VPN/ExpressRoute Gateway
  - Must be /27 minimum

# AKS Subnets
AKS-System-Subnet:          10.0.1.0/24    (256 addresses)
  - System node pools
  - Core services (CoreDNS, metrics-server)
  
AKS-Workload-Subnet:        10.0.2.0/23    (512 addresses)
  - User workload node pools
  - Application pods
  - Can expand to /22 if needed (1024 addresses)

# Service Subnets
PrivateEndpoints-Subnet:    10.0.4.0/24    (256 addresses)
  - Key Vault private endpoint
  - ACR private endpoint
  - Storage private endpoint
  - SQL private endpoint

AppGateway-Subnet:          10.0.5.0/24    (256 addresses)
  - Application Gateway (WAF)
  - Requires /24 minimum

AzureBastionSubnet:         10.0.6.0/27    (32 addresses)
  - Azure Bastion
  - Must be /27 minimum, named exactly "AzureBastionSubnet"

Management-Subnet:          10.0.7.0/24    (256 addresses)
  - Jump boxes
  - Build agents
  - Management VMs

# Reserved for Future Use
Reserved:                   10.0.8.0/21    (2048 addresses)
  - Future expansion
  - Additional services

# AKS Pod and Service CIDRs (not VNet subnets)
Pod-CIDR:                   10.244.0.0/16  (65,536 addresses)
  - Assigned to pods via Azure CNI
  - Not part of VNet address space

Service-CIDR:               10.245.0.0/16  (65,536 addresses)
  - Kubernetes service IPs
  - Not part of VNet address space
  - Must not overlap with VNet, pod, or on-prem ranges
```

### Multi-Environment Address Plan

```yaml
Global Address Space: 10.0.0.0/8

Production:      10.0.0.0/16    (West Europe)
Staging:         10.20.0.0/16   (West Europe)
Development:     10.10.0.0/16   (West Europe)

DR/Secondary:    10.1.0.0/16    (North Europe) # Future

Hub (Shared):    10.100.0.0/16  (West Europe)
  - Azure Firewall: 10.100.0.0/24
  - VPN Gateway:    10.100.1.0/24
  - DNS:            10.100.2.0/24
  - Monitoring:     10.100.3.0/24

On-Premises:     172.16.0.0/12  (Reserved, non-overlapping)
```

### IP Address Reservations

```yaml
Static IP Assignments:

Azure Firewall:
  - Primary IP: 10.0.0.4 (auto-assigned)
  
Application Gateway:
  - Frontend IP: 10.0.5.10
  - Backend pool: Dynamic

Private Endpoints:
  - Key Vault:   10.0.4.10
  - ACR:         10.0.4.11
  - Storage:     10.0.4.12
  - SQL DB:      10.0.4.13

Management:
  - Jump Box:    10.0.7.10
  - Build Agent: 10.0.7.11

AKS:
  - API Server:  Private (dynamic in 10.0.1.0/24)
  - Nodes:       Dynamic (DHCP from subnet)
  - Pods:        Dynamic (from 10.244.0.0/16)
```

-----

## 🔒 Security Zones

### Zone Classification

```
┌─────────────────────────────────────────────────────────────────┐
│                         Security Zones                          │
└─────────────────────────────────────────────────────────────────┘

Zone 1: Internet (Untrusted)
  ├─ Access: Public
  ├─ Trust: None
  ├─ Components: Azure Front Door, Public IPs
  └─ Controls: DDoS Protection, WAF, Rate Limiting

Zone 2: DMZ (Low Trust)
  ├─ Access: Controlled ingress
  ├─ Trust: Low
  ├─ Components: Application Gateway, Public Load Balancer
  └─ Controls: WAF, TLS inspection, IDS/IPS

Zone 3: Application (Medium Trust)
  ├─ Access: Authenticated users
  ├─ Trust: Medium
  ├─ Components: AKS workload nodes, applications
  └─ Controls: Network policies, pod security, RBAC

Zone 4: Platform (High Trust)
  ├─ Access: Platform services
  ├─ Trust: High
  ├─ Components: AKS system nodes, control plane
  └─ Controls: Private cluster, limited access, monitoring

Zone 5: Data (Highest Trust)
  ├─ Access: Private endpoints only
  ├─ Trust: Highest
  ├─ Components: Key Vault, databases, storage
  └─ Controls: Private endpoints, encryption, access policies

Zone 6: Management (Highest Trust)
  ├─ Access: Admins only (MFA + PIM)
  ├─ Trust: Highest
  ├─ Components: Bastion, jump boxes, admin tools
  └─ Controls: JIT access, MFA, audit logging
```

### Zone Connectivity Matrix

```
Allow Traffic Between Zones:

From ↓ / To →   │ Internet │  DMZ  │  App  │ Platform │ Data │ Mgmt
────────────────┼──────────┼───────┼───────┼──────────┼──────┼──────
Internet        │    -     │  Yes  │  No   │    No    │  No  │  No
DMZ             │   Yes*   │  No   │  Yes  │    No    │  No  │  No
Application     │   Yes*   │  No   │  Yes  │   Yes    │ Yes  │  No
Platform        │   Yes*   │  No   │  Yes  │   Yes    │ Yes  │  No
Data            │    No    │  No   │  No   │    No    │  No  │  No
Management      │   Yes*   │  Yes  │  Yes  │   Yes    │ Yes  │ Yes

* Via Azure Firewall only (egress control)
```

### Zone Transition Points

```
Internet → DMZ:
  ├─ Entry Point: Azure Front Door
  ├─ Controls: DDoS Protection, WAF
  └─ Inspection: Layer 7 (HTTP/HTTPS)

DMZ → Application:
  ├─ Entry Point: Application Gateway → AKS Ingress
  ├─ Controls: TLS termination, authentication
  └─ Inspection: mTLS (future: service mesh)

Application → Data:
  ├─ Entry Point: Private Endpoints
  ├─ Controls: Managed Identity, RBAC
  └─ Inspection: Azure Private Link

Any Zone → Internet:
  ├─ Entry Point: Azure Firewall
  ├─ Controls: FQDN filtering, threat intelligence
  └─ Inspection: Layer 4-7 (application rules)

Management → Any:
  ├─ Entry Point: Azure Bastion / Jump Box
  ├─ Controls: MFA, PIM, conditional access
  └─ Inspection: Session recording, audit logs
```

-----

## 🔄 Traffic Flows

### User Access Flow (Inbound)

```
┌──────────────────────────────────────────────────────────────────┐
│                    User Access to Application                    │
└──────────────────────────────────────────────────────────────────┘

Step 1: Internet → Azure Front Door
  ┌────────────────────────────────────────────────────────┐
  │ User (Internet)                                        │
  │   ↓ HTTPS (443)                                        │
  │ Azure Front Door (Global)                              │
  │   • DDoS Protection                                    │
  │   • WAF (OWASP 3.2)                                   │
  │   • TLS termination (TLS 1.3)                         │
  │   • Rate limiting (100 req/min per IP)                │
  │   • Geo-filtering (block high-risk countries)         │
  │   ✓ Decision: Allow                                    │
  └────────────────────────────────────────────────────────┘

Step 2: Azure Front Door → Application Gateway
  ┌────────────────────────────────────────────────────────┐
  │ Azure Front Door                                       │
  │   ↓ HTTPS (443) over Azure backbone                   │
  │ Application Gateway (10.0.5.10)                        │
  │   • WAF (additional layer)                             │
  │   • TLS re-encryption                                  │
  │   • Backend health probes                              │
  │   ✓ Decision: Route to backend pool                    │
  └────────────────────────────────────────────────────────┘

Step 3: Application Gateway → AKS Ingress
  ┌────────────────────────────────────────────────────────┐
  │ Application Gateway                                    │
  │   ↓ HTTPS (443) to private IP                         │
  │ NSG: appgw-nsg                                         │
  │   • Allow 443 from AppGW to AKS subnet                │
  │   ✓ Decision: Allow                                    │
  │   ↓                                                    │
  │ AKS Ingress Controller (NGINX)                         │
  │   • TLS termination (cert from cert-manager)          │
  │   • Path-based routing                                 │
  │   • Authentication (OAuth2-proxy)                      │
  │   ✓ Decision: Route to service                         │
  └────────────────────────────────────────────────────────┘

Step 4: Ingress → Application Service
  ┌────────────────────────────────────────────────────────┐
  │ Ingress Controller                                     │
  │   ↓ HTTP (8080) within cluster                        │
  │ Network Policy                                         │
  │   • Check: ingress → app allowed?                     │
  │   ✓ Decision: Allow                                    │
  │   ↓                                                    │
  │ Kubernetes Service (ClusterIP)                         │
  │   • Load balance across pods                           │
  │   ↓                                                    │
  │ Application Pod                                        │
  │   • Process request                                    │
  │   • Return response                                    │
  └────────────────────────────────────────────────────────┘

Total Latency: ~50-100ms (optimized)
Security Layers: 6 (Front Door WAF, AppGW WAF, NSG, Network Policy, 
                     Pod Security, Application Auth)
```

### Application to Data Flow (Internal)

```
┌──────────────────────────────────────────────────────────────────┐
│              Application → Database/Key Vault                    │
└──────────────────────────────────────────────────────────────────┘

Scenario A: Application Pod → Azure Key Vault

Step 1: Pod initiates request
  ┌────────────────────────────────────────────────────────┐
  │ Application Pod (10.244.x.x)                           │
  │   • Needs secret from Key Vault                        │
  │   • Uses Managed Identity (no credentials in code)     │
  │   ↓ HTTPS (443) to private endpoint                    │
  └────────────────────────────────────────────────────────┘

Step 2: Network Policy Check
  ┌────────────────────────────────────────────────────────┐
  │ Network Policy                                         │
  │   • Check: app pod → private endpoints subnet?        │
  │   • Policy: Allow egress to 10.0.4.0/24 on port 443   │
  │   ✓ Decision: Allow                                    │
  └────────────────────────────────────────────────────────┘

Step 3: Route through Azure CNI
  ┌────────────────────────────────────────────────────────┐
  │ Azure CNI                                              │
  │   • Route lookup: 10.0.4.10 (Key Vault PE)           │
  │   • Destination: Same VNet, different subnet          │
  │   • NSG check: aks-workload-nsg (outbound)            │
  │   ✓ Decision: Allow                                    │
  └────────────────────────────────────────────────────────┘

Step 4: Private Endpoint receives request
  ┌────────────────────────────────────────────────────────┐
  │ Private Endpoint (10.0.4.10)                           │
  │   • NSG check: private-endpoints-nsg (inbound)        │
  │   • Allow from AKS subnet                              │
  │   ✓ Decision: Forward to Key Vault                     │
  │   ↓                                                    │
  │ Azure Key Vault                                        │
  │   • Verify Managed Identity                            │
  │   • Check RBAC: Does app have "Get Secret" permission?│
  │   ✓ Decision: Allow, return secret                     │
  └────────────────────────────────────────────────────────┘

Step 5: Response returns to pod
  ┌────────────────────────────────────────────────────────┐
  │ Key Vault → Private Endpoint → Pod                     │
  │   • Same path in reverse                               │
  │   • Secret injected into pod as volume/env var         │
  │   • Logged in Key Vault audit logs                     │
  └────────────────────────────────────────────────────────┘

Security Layers: 5 (Network Policy, NSG x2, Private Endpoint, RBAC)
Authentication: Managed Identity (passwordless)
Encryption: TLS 1.3 end-to-end
```

### Egress Flow (Outbound to Internet)

```
┌──────────────────────────────────────────────────────────────────┐
│           Application Pod → Internet (via Firewall)              │
└──────────────────────────────────────────────────────────────────┘

Example: Pod needs to pull container image from docker.io

Step 1: Pod initiates outbound request
  ┌────────────────────────────────────────────────────────┐
  │ Application Pod (10.244.x.x)                           │
  │   • Needs to pull image: docker.io/library/nginx:latest│
  │   ↓ HTTPS (443) to docker.io                           │
  └────────────────────────────────────────────────────────┘

Step 2: Network Policy Check
  ┌────────────────────────────────────────────────────────┐
  │ Network Policy                                         │
  │   • Check: pod → internet allowed?                     │
  │   • Default: Deny egress                               │
  │   • Exception: Allow DNS (53/UDP)                      │
  │   • Exception: Allow to firewall subnet                │
  │   ✓ Decision: Allow to 0.0.0.0/0 (will hit firewall)  │
  └────────────────────────────────────────────────────────┘

Step 3: Route Table forces traffic to Firewall
  ┌────────────────────────────────────────────────────────┐
  │ User Defined Route (UDR)                               │
  │   • Route: 0.0.0.0/0 → 10.0.0.4 (Azure Firewall)     │
  │   • All internet traffic must go through firewall      │
  │   ↓                                                    │
  │ NSG: aks-workload-nsg (outbound)                       │
  │   • Allow to firewall subnet                           │
  │   ✓ Decision: Allow                                    │
  └────────────────────────────────────────────────────────┘

Step 4: Azure Firewall inspects and filters
  ┌────────────────────────────────────────────────────────┐
  │ Azure Firewall (10.0.0.4)                              │
  │                                                        │
  │ Application Rule Processing:                           │
  │   • Target FQDN: docker.io                            │
  │   • Protocol: HTTPS                                    │
  │   • Port: 443                                          │
  │                                                        │
  │ Rule Match:                                            │
  │   Priority 200: Allow Container Registries             │
  │   - docker.io                                          │
  │   - ghcr.io                                            │
  │   - gcr.io                                             │
  │   ✓ Decision: Allow                                    │
  │                                                        │
  │ Threat Intelligence Check:                             │
  │   • Is docker.io a known malicious domain?            │
  │   ✓ No, allow                                          │
  │                                                        │
  │ SNAT: 10.244.x.x → Firewall Public IP                 │
  └────────────────────────────────────────────────────────┘

Step 5: Traffic exits to Internet
  ┌────────────────────────────────────────────────────────┐
  │ Azure Firewall → Internet                              │
  │   • Source: Firewall public IP (x.x.x.x)              │
  │   • Destination: docker.io (resolved IP)               │
  │   • Connection established                             │
  │   • Image pulled                                       │
  │   • Logged in Firewall diagnostics                     │
  └────────────────────────────────────────────────────────┘

Security Layers: 4 (Network Policy, NSG, Firewall Rules, 
                     Threat Intelligence)
Logging: Full connection logs, DNS queries, URLs accessed
Blocked by default: Any FQDN not explicitly allowed
```

### Admin Access Flow (Management)

```
┌──────────────────────────────────────────────────────────────────┐
│              Administrator → AKS Cluster (kubectl)               │
└──────────────────────────────────────────────────────────────────┘

Step 1: Admin authenticates
  ┌────────────────────────────────────────────────────────┐
  │ Administrator Workstation                              │
  │   • User: admin@crusoe-island.com                      │
  │   ↓                                                    │
  │ Azure AD Login (az login)                              │
  │   • MFA required (Microsoft Authenticator)            │
  │   • Conditional Access evaluated                       │
  │   • Device compliance checked                          │
  │   ✓ Decision: Authenticated                            │
  └────────────────────────────────────────────────────────┘

Step 2: PIM elevation (if needed)
  ┌────────────────────────────────────────────────────────┐
  │ Azure AD Privileged Identity Management                │
  │   • Request: "AKS Cluster Admin" role                 │
  │   • Justification: "Incident response - ticket #1234" │
  │   • Approval: Security team (auto-approved for P0)     │
  │   • Duration: 4 hours (max)                            │
  │   ✓ Role activated                                     │
  └────────────────────────────────────────────────────────┘

Step 3: Connect via VPN or Bastion
  ┌────────────────────────────────────────────────────────┐
  │ Option A: VPN                                          │
  │   • Connect to VPN Gateway                             │
  │   • P2S VPN with certificate auth                      │
  │   • Assigned IP from VPN pool (10.100.10.0/24)        │
  │                                                        │
  │ Option B: Azure Bastion (Preferred)                    │
  │   • Connect to Jump Box via Bastion                    │
  │   • No public IP on Jump Box                           │
  │   • HTML5 browser-based (RDP/SSH)                      │
  │   • Session recorded for audit                         │
  │   ✓ Connected to Jump Box (10.0.7.10)                 │
  └────────────────────────────────────────────────────────┘

Step 4: Access AKS API Server
  ┌────────────────────────────────────────────────────────┐
  │ Jump Box (10.0.7.10)                                   │
  │   ↓ kubectl get pods                                   │
  │ NSG: management-nsg                                    │
  │   • Allow to AKS subnet                                │
  │   ✓ Decision: Allow                                    │
  │   ↓                                                    │
  │ AKS API Server (private endpoint)                     │
  │   • Verify Azure AD token                              │
  │   • Check Kubernetes RBAC                              │
  │   • User has cluster-admin role?                       │
  │   ✓ Decision: Allow                                    │
  │   • Command executed                                   │
  │   • Logged to AKS diagnostics + Sentinel               │
  └────────────────────────────────────────────────────────┘

Security Layers: 6 (MFA, Conditional Access, PIM, NSG, 
                     Kubernetes RBAC, Audit Logging)
Time-limited: PIM role expires after 4 hours
Audit Trail: Complete from login to kubectl command
```

-----

## 🛠️ Azure Network Services

### Azure Firewall

**Purpose:** Centralized network security for outbound traffic filtering

```hcl
resource "azurerm_firewall" "main" {
  name                = "fw-idp-prod"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"  # Premium for TLS inspection
  
  firewall_policy_id = azurerm_firewall_policy.main.id
  
  ip_configuration {
    name                 = "fw-ipconfig"
    subnet_id            = azurerm_subnet.firewall.id
    public_ip_address_id = azurerm_public_ip.firewall.id
  }
  
  zones = ["1", "2", "3"]  # Zone-redundant
}

resource "azurerm_firewall_policy" "main" {
  name                = "fwpolicy-idp-prod"
  resource_group_name = azurerm_resource_group.network.name
  location            = azurerm_resource_group.network.location
  
  dns {
    proxy_enabled = true  # DNS proxy for FQDN filtering
  }
  
  threat_intelligence_mode = "Alert"  # Alert or Deny
  
  threat_intelligence_allowlist {
    fqdns        = []  # Allowlist specific FQDNs if needed
    ip_addresses = []
  }
}

# Application Rules (FQDN-based)
resource "azurerm_firewall_policy_rule_collection_group" "app_rules" {
  name               = "app-rules"
  firewall_policy_id = azurerm_firewall_policy.main.id
  priority           = 200
  
  application_rule_collection {
    name     = "allow-container-registries"
    priority = 200
    action   = "Allow"
    
    rule {
      name = "docker-hub"
      source_addresses = ["10.0.0.0/16"]  # From entire VNet
      destination_fqdns = [
        "docker.io",
        "*.docker.io",
        "registry-1.docker.io",
        "*.docker.com"
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
    
    rule {
      name = "github-container-registry"
      source_addresses = ["10.0.0.0/16"]
      destination_fqdns = [
        "ghcr.io",
        "*.ghcr.io"
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
    
    rule {
      name = "microsoft-container-registry"
      source_addresses = ["10.0.0.0/16"]
      destination_fqdns = [
        "mcr.microsoft.com",
        "*.data.mcr.microsoft.com"
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
  }
  
  application_rule_collection {
    name     = "allow-package-managers"
    priority = 300
    action   = "Allow"
    
    rule {
      name = "python-packages"
      source_addresses = ["10.0.0.0/16"]
      destination_fqdns = [
        "pypi.org",
        "*.pypi.org",
        "files.pythonhosted.org"
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
    
    rule {
      name = "npm-packages"
      source_addresses = ["10.0.0.0/16"]
      destination_fqdns = [
        "registry.npmjs.org",
        "*.npmjs.org"
      ]
      protocols {
        type = "Https"
        port = 443
      }
    }
  }
}

# Network Rules (IP/Port-based)
resource "azurerm_firewall_policy_rule_collection_group" "network_rules" {
  name               = "network-rules"
  firewall_policy_id = azurerm_firewall_policy.main.id
  priority           = 100
  
  network_rule_collection {
    name     = "allow-ntp"
    priority = 100
    action   = "Allow"
    
    rule {
      name                  = "ntp"
      source_addresses      = ["10.0.0.0/16"]
      destination_addresses = ["*"]
      destination_ports     = ["123"]
      protocols             = ["UDP"]
    }
  }
  
  network_rule_collection {
    name     = "allow-dns"
    priority = 110
    action   = "Allow"
    
    rule {
      name                  = "dns"
      source_addresses      = ["10.0.0.0/16"]
      destination_addresses = ["*"]
      destination_ports     = ["53"]
      protocols             = ["TCP", "UDP"]
    }
  }
}
```

**Key Features:**

- ✅ Zone-redundant (3 availability zones)
- ✅ FQDN-based filtering (application rules)
- ✅ Threat intelligence (Microsoft’s threat feed)
- ✅ DNS proxy (enables FQDN in network rules)
- ✅ Diagnostic logging to Log Analytics

### Network Security Groups (NSGs)

**Purpose:** Subnet-level firewall rules

```hcl
# AKS System Node Subnet NSG
resource "azurerm_network_security_group" "aks_system" {
  name                = "nsg-aks-system"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  
  # Inbound: Default Deny
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  
  # Inbound: Allow from Load Balancer
  security_rule {
    name                       = "AllowAzureLoadBalancerInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
  }
  
  # Inbound: Allow from Management
  security_rule {
    name                       = "AllowManagementInbound"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["22", "443"]
    source_address_prefix      = "10.0.7.0/24"  # Management subnet
    destination_address_prefix = "*"
  }
  
  # Outbound: Default Allow (will be filtered by Firewall)
  security_rule {
    name                       = "AllowAllOutbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Associate NSG with subnet
resource "azurerm_subnet_network_security_group_association" "aks_system" {
  subnet_id                 = azurerm_subnet.aks_system.id
  network_security_group_id = azurerm_network_security_group.aks_system.id
}
```

**NSG Flow Logs:**

```hcl
resource "azurerm_network_watcher_flow_log" "aks_system" {
  network_watcher_name = azurerm_network_watcher.main.name
  resource_group_name  = azurerm_resource_group.network.name
  
  network_security_group_id = azurerm_network_security_group.aks_system.id
  storage_account_id        = azurerm_storage_account.flowlogs.id
  enabled                   = true
  version                   = 2
  
  retention_policy {
    enabled = true
    days    = 90
  }
  
  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.main.location
    workspace_resource_id = azurerm_log_analytics_workspace.main.id
    interval_in_minutes   = 10
  }
}
```

### Private Endpoints

**Purpose:** Private connectivity to Azure PaaS services

```hcl
# Private Endpoint for Key Vault
resource "azurerm_private_endpoint" "keyvault" {
  name                = "pe-kv-idp-prod"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  subnet_id           = azurerm_subnet.private_endpoints.id
  
  private_service_connection {
    name                           = "psc-keyvault"
    private_connection_resource_id = azurerm_key_vault.main.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }
  
  private_dns_zone_group {
    name                 = "pdns-group-keyvault"
    private_dns_zone_ids = [azurerm_private_dns_zone.keyvault.id]
  }
}

# Private DNS Zone for Key Vault
resource "azurerm_private_dns_zone" "keyvault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.network.name
}

# Link DNS Zone to VNet
resource "azurerm_private_dns_zone_virtual_network_link" "keyvault" {
  name                  = "pdns-link-keyvault"
  resource_group_name   = azurerm_resource_group.network.name
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
}

# Disable public access on Key Vault
resource "azurerm_key_vault" "main" {
  name                        = "kv-idp-prod"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "premium"
  
  # CRITICAL: Disable public access
  public_network_access_enabled = false
  
  # Network ACLs (only applies if public access enabled)
  network_acls {
    bypass                     = "AzureServices"
    default_action             = "Deny"
    ip_rules                   = []
    virtual_network_subnet_ids = []
  }
}
```

-----

## ☸️ Kubernetes Networking

### Azure CNI Configuration

**Purpose:** Native Azure networking for Kubernetes pods

```hcl
resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-idp-prod"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "aks-idp-prod"
  
  # Private cluster - no public API server
  private_cluster_enabled = true
  
  network_profile {
    network_plugin     = "azure"  # Azure CNI
    network_policy     = "calico" # Calico for network policies
    
    # IP address ranges
    service_cidr       = "10.245.0.0/16"   # Kubernetes services
    dns_service_ip     = "10.245.0.10"     # CoreDNS
    docker_bridge_cidr = "172.17.0.1/16"   # Docker bridge (deprecated but required)
    
    # Load balancer
    load_balancer_sku  = "standard"
    outbound_type      = "userDefinedRouting"  # Force through firewall
  }
  
  default_node_pool {
    name                = "system"
    node_count          = 3
    vm_size             = "Standard_D4s_v5"
    vnet_subnet_id      = azurerm_subnet.aks_system.id
    availability_zones  = ["1", "2", "3"]
    enable_auto_scaling = true
    min_count           = 3
    max_count           = 6
    
    # Pod subnet (for Azure CNI Overlay - future)
    # pod_subnet_id = azurerm_subnet.aks_pods.id
  }
}

# User node pool
resource "azurerm_kubernetes_cluster_node_pool" "workload" {
  name                  = "workload"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_D8s_v5"
  node_count            = 3
  vnet_subnet_id        = azurerm_subnet.aks_workload.id
  availability_zones    = ["1", "2", "3"]
  enable_auto_scaling   = true
  min_count             = 3
  max_count             = 20
  
  node_labels = {
    "workload" = "application"
  }
  
  node_taints = []  # No taints, general purpose
}
```

**Azure CNI Benefits:**

- ✅ Pods get IPs from VNet (can communicate with other Azure resources directly)
- ✅ No NAT required for pod-to-Azure service communication
- ✅ Better performance (no overlay network)
- ✅ Simpler troubleshooting (standard Azure networking)

**Azure CNI Considerations:**

- ⚠️ Requires larger subnet (one IP per pod)
- ⚠️ IP address planning is critical

### Calico Network Policies

**Purpose:** Microsegmentation within Kubernetes

**Default Deny Policy:**

```yaml
# Apply to all namespaces except kube-system
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

**Allow DNS:**

```yaml
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

**Frontend → Backend Communication:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
      tier: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
          tier: web
    ports:
    - protocol: TCP
      port: 8080
```

**Allow Egress to Azure Services:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-azure-services
  namespace: production
spec:
  podSelector:
    matchLabels:
      needs-azure-access: "true"
  policyTypes:
  - Egress
  egress:
  # Allow to Private Endpoints subnet
  - to:
    - ipBlock:
        cidr: 10.0.4.0/24
    ports:
    - protocol: TCP
      port: 443
  
  # Allow to firewall (for internet egress)
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24  # Firewall subnet
```

-----

## 🌍 DNS Architecture

### DNS Strategy

```
┌────────────────────────────────────────────────────────────────┐
│                         DNS Architecture                       │
└────────────────────────────────────────────────────────────────┘

Public DNS (Azure DNS or External)
  ├─ idp.crusoe-island.com          → Azure Front Door
  ├─ *.idp.crusoe-island.com        → Azure Front Door
  └─ api.crusoe-island.com          → Application Gateway Public IP

Private DNS (Azure Private DNS Zones)
  ├─ privatelink.vaultcore.azure.net
  │    └─ kv-idp-prod.vault.azure.net → 10.0.4.10
  │
  ├─ privatelink.azurecr.io
  │    └─ acridpprod.azurecr.io → 10.0.4.11
  │
  ├─ privatelink.blob.core.windows.net
  │    └─ stidpprod.blob.core.windows.net → 10.0.4.12
  │
  └─ aks-private-dns-zone
       └─ aks-api-server → 10.0.1.x (private)

Kubernetes DNS (CoreDNS)
  ├─ *.svc.cluster.local            → Service discovery
  ├─ *.production.svc.cluster.local → Namespace-specific
  └─ Forward to Azure DNS (168.63.129.16)
```

### Private DNS Configuration

```hcl
# Private DNS Zones
resource "azurerm_private_dns_zone" "keyvault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.network.name
}

resource "azurerm_private_dns_zone" "acr" {
  name                = "privatelink.azurecr.io"
  resource_group_name = azurerm_resource_group.network.name
}

resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.network.name
}

# Link all private DNS zones to VNet
resource "azurerm_private_dns_zone_virtual_network_link" "keyvault" {
  name                  = "pdns-link-kv"
  resource_group_name   = azurerm_resource_group.network.name
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false  # Manual registration via private endpoints
}

# Repeat for other zones...
```

### CoreDNS Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-custom
  namespace: kube-system
data:
  crusoe.server: |
    # Custom DNS for internal domains
    crusoe-island.com:53 {
        errors
        cache 30
        forward . 10.0.4.100  # Internal DNS server (if any)
    }
  
  log.override: |
    log
```

-----

## ⚖️ Load Balancing

### Azure Load Balancer (Internal)

**Purpose:** Load balance Kubernetes services internally

```yaml
apiVersion: v1
kind: Service
metadata:
  name: internal-app
  namespace: production
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-internal: "true"
    service.beta.kubernetes.io/azure-load-balancer-internal-subnet: "aks-workload-subnet"
spec:
  type: LoadBalancer
  selector:
    app: internal-app
  ports:
  - port: 443
    targetPort: 8443
    protocol: TCP
```

**Result:**

- Internal Load Balancer created
- IP assigned from AKS workload subnet
- Only accessible within VNet

### Application Gateway (External)

**Purpose:** External load balancing with WAF

```hcl
resource "azurerm_application_gateway" "main" {
  name                = "appgw-idp-prod"
  resource_group_name = azurerm_resource_group.network.name
  location            = azurerm_resource_group.network.location
  
  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = 2  # Or use autoscaling
  }
  
  gateway_ip_configuration {
    name      = "appgw-ip-config"
    subnet_id = azurerm_subnet.appgw.id
  }
  
  frontend_port {
    name = "https-port"
    port = 443
  }
  
  frontend_ip_configuration {
    name                 = "appgw-frontend-ip"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }
  
  backend_address_pool {
    name = "aks-backend-pool"
    # Populated by AKS ingress controller
  }
  
  backend_http_settings {
    name                  = "https-settings"
    cookie_based_affinity = "Disabled"
    port                  = 443
    protocol              = "Https"
    request_timeout       = 30
    
    probe_name = "health-probe"
  }
  
  http_listener {
    name                           = "https-listener"
    frontend_ip_configuration_name = "appgw-frontend-ip"
    frontend_port_name             = "https-port"
    protocol                       = "Https"
    ssl_certificate_name           = "appgw-ssl-cert"
  }
  
  request_routing_rule {
    name                       = "rule1"
    rule_type                  = "Basic"
    http_listener_name         = "https-listener"
    backend_address_pool_name  = "aks-backend-pool"
    backend_http_settings_name = "https-settings"
    priority                   = 100
  }
  
  probe {
    name                = "health-probe"
    protocol            = "Https"
    path                = "/healthz"
    interval            = 30
    timeout             = 30
    unhealthy_threshold = 3
    host                = "idp.crusoe-island.com"
  }
  
  waf_configuration {
    enabled          = true
    firewall_mode    = "Prevention"
    rule_set_type    = "OWASP"
    rule_set_version = "3.2"
  }
  
  zones = ["1", "2", "3"]  # Zone-redundant
}
```

-----

## 🔐 Network Security

### Defense-in-Depth Summary

```
Layer                     Control                           Status
─────────────────────────────────────────────────────────────────────
7 - Application          WAF (OWASP 3.2)                   ✓ Enabled
6 - Presentation         TLS 1.3                           ✓ Enforced
5 - Session              Session management                ✓ Configured
4-7 - Application        Azure Firewall                    ✓ Enabled
4 - Transport            Load Balancer                     ✓ Configured
3-4 - Network            Network Security Groups           ✓ Configured
3 - Network              Network Policies (Calico)         ✓ Enforced
3 - Network              Private Endpoints                 ✓ All PaaS
2 - Data Link            VNet Isolation                    ✓ Segmented
1 - Physical             Azure Infrastructure              ✓ Managed
```

### Security Best Practices

**1. No Public IPs on Resources**

- AKS nodes: No public IPs
- VMs: No public IPs (use Bastion)
- Databases: Private endpoints only

**2. Default Deny**

- NSGs: Deny all by default, explicit allow
- Network Policies: Deny all, explicit allow
- Firewall: Deny all, explicit allow

**3. Least Privilege**

- Minimum ports open
- Minimum CIDR ranges
- Time-limited access (PIM)

**4. Encryption in Transit**

- TLS 1.3 for all external traffic
- mTLS for pod-to-pod (future: service mesh)
- IPsec for VPN

**5. Logging and Monitoring**

- NSG flow logs: Enabled
- Firewall diagnostics: Enabled
- Network Watcher: Enabled
- Connection Monitor: Configured

-----

## 🚪 Egress Control

### Firewall Rules Summary

```yaml
Priority  Type         Name                  Action  Targets
────────────────────────────────────────────────────────────────
100       Network      Allow-NTP             Allow   *.ntp.org
110       Network      Allow-DNS             Allow   *:53
200       Application  Container-Registries  Allow   docker.io, ghcr.io, mcr.microsoft.com
300       Application  Package-Managers      Allow   pypi.org, npmjs.org
400       Application  Azure-Services        Allow   *.azure.com, management.azure.com
500       Application  GitHub                Allow   github.com, api.github.com
1000      Network      Allow-HTTPS           Allow   *:443 (fallback, logged)
4096      Network      Deny-All              Deny    *
```

### Egress Monitoring

```kusto
// Azure Firewall - Top Denied Destinations
AzureDiagnostics
| where Category == "AzureFirewallApplicationRule"
| where msg_s contains "Deny"
| summarize Count=count() by DestinationFqdn=extract("FQDN: ([^.]+\\.[^.]+)", 1, msg_s)
| top 20 by Count desc

// Azure Firewall - Outbound Traffic by Application
AzureDiagnostics
| where Category == "AzureFirewallApplicationRule"
| where msg_s contains "Allow"
| extend Fqdn = extract("FQDN: ([^.]+\\.[^.]+)", 1, msg_s)
| summarize TotalBytes=sum(toint(msg_s)) by Fqdn
| top 20 by TotalBytes desc
```

-----

## 📊 Monitoring and Troubleshooting

### Network Watcher

**Tools Available:**

- IP Flow Verify: Test if traffic allowed/denied
- Next Hop: Determine next hop for a packet
- Connection Troubleshoot: Diagnose connectivity issues
- Packet Capture: Capture network traffic
- VPN Troubleshoot: Diagnose VPN issues

**Example: IP Flow Verify**

```bash
az network watcher test-ip-flow \
  --resource-group rg-network \
  --vm vm-jumpbox \
  --direction Outbound \
  --protocol TCP \
  --local 10.0.7.10:12345 \
  --remote 10.0.4.10:443

# Result:
# Access: Allowed
# Rule: AllowToPrivateEndpoints
```

### Connection Monitor

```hcl
resource "azurerm_network_connection_monitor" "aks_to_keyvault" {
  name                = "connmon-aks-to-kv"
  network_watcher_id  = azurerm_network_watcher.main.id
  location            = azurerm_resource_group.network.location
  
  endpoint {
    name               = "aks-node"
    target_resource_id = azurerm_kubernetes_cluster_node_pool.workload.id
    filter {
      type = "Include"
    }
  }
  
  endpoint {
    name    = "keyvault"
    address = "10.0.4.10"
  }
  
  test_configuration {
    name                      = "tcp-443"
    protocol                  = "Tcp"
    test_frequency_in_seconds = 30
    
    tcp_configuration {
      port                      = 443
      disable_trace_route       = false
    }
    
    success_threshold {
      checks_failed_percent = 5
      round_trip_time_ms    = 100
    }
  }
  
  test_group {
    name                     = "aks-to-keyvault-test"
    destination_endpoints    = ["keyvault"]
    source_endpoints         = ["aks-node"]
    test_configuration_names = ["tcp-443"]
  }
}
```

### Common Troubleshooting Scenarios

**Scenario 1: Pod can’t reach internet**

```bash
# 1. Check network policy
kubectl describe networkpolicy -n production

# 2. Check if egress allowed
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- curl -v https://google.com

# 3. Check firewall logs
az monitor activity-log list \
  --resource-id /subscriptions/.../resourceGroups/rg-network/providers/Microsoft.Network/azureFirewalls/fw-idp-prod \
  --start-time 2024-12-21T00:00:00Z

# 4. Check route table
az network route-table route list --resource-group rg-network --route-table-name rt-aks
```

**Scenario 2: Can’t access private endpoint**

```bash
# 1. Verify private endpoint IP
nslookup kv-idp-prod.vault.azure.net

# Expected: 10.0.4.10 (private IP)
# If public IP returned, DNS not configured correctly

# 2. Test connectivity
nc -zv 10.0.4.10 443

# 3. Check NSG rules
az network nsg rule list \
  --resource-group rg-network \
  --nsg-name nsg-private-endpoints \
  --include-default

# 4. Check private DNS zone
az network private-dns link vnet list \
  --resource-group rg-network \
  --zone-name privatelink.vaultcore.azure.net
```

-----

## 🔄 Disaster Recovery

### Multi-Region Architecture (Future)

```
Primary Region (West Europe)        Secondary Region (North Europe)
─────────────────────────────────────────────────────────────────
VNet: 10.0.0.0/16                   VNet: 10.1.0.0/16
AKS Cluster (Active)                AKS Cluster (Standby)
Azure Firewall                      Azure Firewall
Private Endpoints                   Private Endpoints
                                    
         ↓                                   ↑
    Global Azure Front Door (Active-Passive)
         ↓                                   ↑
         
Data Replication:
  - Key Vault: Geo-replication (automatic)
  - ACR: Geo-replication (enabled)
  - Storage: GRS (Geo-Redundant Storage)
  - SQL: Active Geo-Replication
```

### Backup Networking Configuration

**Critical Network Resources to Backup:**

- NSG rules
- Route tables
- Firewall policies
- Network policies (K8s)
- DNS zones

```bash
# Export NSG rules
az network nsg show --resource-group rg-network --name nsg-aks-system > nsg-aks-system-backup.json

# Export route table
az network route-table show --resource-group rg-network --name rt-aks > rt-aks-backup.json

# Export firewall policy
az network firewall policy show --resource-group rg-network --name fwpolicy-idp-prod > firewall-policy-backup.json

# Export Kubernetes network policies
kubectl get networkpolicies --all-namespaces -o yaml > k8s-netpol-backup.yaml
```

-----

## ⚡ Performance Optimization

### Network Performance Best Practices

**1. Proximity Placement Groups**

```hcl
resource "azurerm_proximity_placement_group" "aks" {
  name                = "ppg-aks-prod"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

# Use in AKS node pool
resource "azurerm_kubernetes_cluster_node_pool" "workload" {
  # ... other config ...
  proximity_placement_group_id = azurerm_proximity_placement_group.aks.id
}
```

**2. Accelerated Networking**

- Enabled by default on supported VM sizes
- Reduces latency (up to 60% improvement)
- Increases packets per second (PPS)

**3. Azure CNI for Performance**

- No overlay network (direct routing)
- Lower latency vs. Kubenet
- Better throughput

**4. Load Balancer Optimization**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: high-performance-app
  annotations:
    service.beta.kubernetes.io/azure-load-balancer-tcp-idle-timeout: "30"
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local  # Preserve source IP, reduce hops
  sessionAffinity: ClientIP      # Session stickiness
```

-----

## 📝 Configuration Examples

### Complete VNet Setup

```hcl
# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "vnet-idp-prod"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  
  tags = {
    Environment = "Production"
    CostCenter  = "Platform"
  }
}

# Subnets
resource "azurerm_subnet" "firewall" {
  name                 = "AzureFirewallSubnet"  # Must be this exact name
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.0.0/24"]
}

resource "azurerm_subnet" "aks_system" {
  name                 = "snet-aks-system"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "aks_workload" {
  name                 = "snet-aks-workload"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/23"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.4.0/24"]
  
  private_endpoint_network_policies_enabled = false
}

resource "azurerm_subnet" "appgw" {
  name                 = "snet-appgw"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.5.0/24"]
}

resource "azurerm_subnet" "bastion" {
  name                 = "AzureBastionSubnet"  # Must be this exact name
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.6.0/27"]
}

resource "azurerm_subnet" "management" {
  name                 = "snet-management"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.7.0/24"]
}

# Route Table (Force traffic through Firewall)
resource "azurerm_route_table" "aks" {
  name                          = "rt-aks"
  location                      = azurerm_resource_group.network.location
  resource_group_name           = azurerm_resource_group.network.name
  disable_bgp_route_propagation = false
  
  route {
    name                   = "default-via-firewall"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = "10.0.0.4"  # Azure Firewall IP
  }
}

# Associate route table with AKS subnets
resource "azurerm_subnet_route_table_association" "aks_system" {
  subnet_id      = azurerm_subnet.aks_system.id
  route_table_id = azurerm_route_table.aks.id
}

resource "azurerm_subnet_route_table_association" "aks_workload" {
  subnet_id      = azurerm_subnet.aks_workload.id
  route_table_id = azurerm_route_table.aks.id
}
```

-----

## 📚 Network Policies Reference

### Common Network Policy Patterns

**Pattern 1: Namespace Isolation**

```yaml
# Deny all cross-namespace traffic
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cross-namespace
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector: {}  # Only from same namespace
  egress:
  - to:
    - podSelector: {}  # Only to same namespace
  - to:  # Allow DNS
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
```

**Pattern 2: Database Access**

```yaml
# Only API pods can access database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-access-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: postgres
      tier: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api
          tier: backend
    ports:
    - protocol: TCP
      port: 5432
```

**Pattern 3: External API Access**

```yaml
# Allow specific pods to call external APIs
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      external-api-access: "true"
  policyTypes:
  - Egress
  egress:
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

## 📝 Document Control

**Version History:**

|Version|Date      |Author       |Changes                     |
|-------|----------|-------------|----------------------------|
|1.0    |2024-12-21|Platform Team|Initial network architecture|

**Review Schedule:**

- **Quarterly**: Technical review
- **Annually**: Comprehensive audit
- **Ad-hoc**: After major changes or incidents

**Next Review:** March 21, 2025

**Approvals:**

- [ ] Network Architect
- [ ] Security Team
- [ ] Platform Engineering Lead

-----

**Document Classification:** Internal  
**Distribution:** Engineering, Operations, Security  
**Retention:** 5 years

-----

*Network architecture is the foundation of security. This document will evolve as our platform grows and new Azure networking features become available.*

**For questions or clarifications, contact:** platform-team@crusoe-island.com 🌐
