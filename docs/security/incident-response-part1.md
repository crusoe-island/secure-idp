# Incident Response Plan - Crusoe IDP (Part 1 of 3)

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Owner:** Security Operations Team  
**Status:** Active

-----

## 📋 Table of Contents - Part 1

- [Overview](#overview)
- [Incident Response Team](#incident-response-team)
- [Incident Classification](#incident-classification)
- [Incident Response Lifecycle](#incident-response-lifecycle)
- [Detection and Analysis](#detection-and-analysis)
- [Containment Strategies](#containment-strategies)

-----

## 🎯 Overview

### Purpose

This Incident Response Plan (IRP) provides a structured approach for detecting, analyzing, containing, eradicating, and recovering from security incidents affecting the Crusoe Internal Developer Platform (IDP).

### Objectives

```yaml
Primary Objectives:
  1. Minimize Impact:
     - Reduce business disruption
     - Limit data loss
     - Prevent further damage
     - Protect critical assets

  2. Rapid Response:
     - MTTD (Mean Time To Detect): < 15 minutes
     - MTTR (Mean Time To Respond): < 4 hours
     - MTTC (Mean Time To Contain): < 8 hours
     - MTTRE (Mean Time To Eradicate): < 24 hours

  3. Preserve Evidence:
     - Maintain chain of custody
     - Support forensic analysis
     - Enable legal action if needed
     - Document for lessons learned

  4. Comply with Requirements:
     - GDPR breach notification (72 hours)
     - Contractual obligations
     - Regulatory requirements
     - Industry standards

  5. Continuous Improvement:
     - Learn from incidents
     - Update procedures
     - Enhance detection
     - Improve response times
```

### Scope

```
In Scope:
  ✓ All IDP infrastructure (Azure resources)
  ✓ All environments (production, staging, development)
  ✓ All applications and services
  ✓ User accounts and identities
  ✓ Data stores and backups
  ✓ Third-party integrations
  ✓ Cloud services (Azure)

Out of Scope:
  ✗ Physical security (Azure datacenter responsibility)
  ✗ Personal devices (unless accessing company data)
  ✗ Non-integrated shadow IT
```

### Incident Response Principles

1. **Safety First**: Personnel safety takes priority over systems
1. **Preserve Evidence**: Don’t destroy potential evidence
1. **Document Everything**: Detailed timestamped records
1. **Communicate Clearly**: Transparent, accurate, timely updates
1. **Learn and Adapt**: Every incident improves our response

-----

## 👥 Incident Response Team

### Team Structure

```
┌─────────────────────────────────────────────────────────────┐
│               Incident Response Organization                 │
└─────────────────────────────────────────────────────────────┘

EXECUTIVE LEVEL
  ├─ CEO (Critical incidents only)
  ├─ CISO (All P0/P1 incidents)
  └─ Legal Counsel (Data breaches, legal matters)

INCIDENT COMMANDER (IC)
  ├─ Overall incident coordination
  ├─ Decision authority
  ├─ Stakeholder communication
  └─ Resource allocation

TECHNICAL RESPONSE TEAM
  ├─ Security Lead
  │   ├─ Threat analysis
  │   ├─ Forensics
  │   └─ Security tools
  │
  ├─ Platform Engineering Lead
  │   ├─ Infrastructure response
  │   ├─ System recovery
  │   └─ Technical implementation
  │
  ├─ Application Team Lead
  │   ├─ Application analysis
  │   ├─ Code fixes
  │   └─ Deployment
  │
  └─ Network Engineer
      ├─ Network analysis
      ├─ Traffic monitoring
      └─ Firewall changes

SUPPORT FUNCTIONS
  ├─ Communications Lead
  │   ├─ Internal communications
  │   ├─ Customer notifications
  │   └─ Media relations
  │
  ├─ Legal
  │   ├─ Regulatory compliance
  │   ├─ Breach notifications
  │   └─ Legal implications
  │
  ├─ Privacy Officer (DPO)
  │   ├─ GDPR compliance
  │   ├─ Privacy impact assessment
  │   └─ Data subject notifications
  │
  └─ Scribe
      ├─ Document timeline
      ├─ Record decisions
      └─ Maintain incident log
```

### Roles and Responsibilities

#### Incident Commander (IC)

```yaml
Primary Responsibilities:
  - Overall incident coordination
  - Decision-making authority
  - Resource allocation
  - Stakeholder communication
  - Escalation management

Key Decisions:
  - Incident severity classification
  - Containment strategy approval
  - Communication approval
  - Recovery strategy
  - Incident closure

Qualities:
  - Calm under pressure
  - Strong communication skills
  - Technical understanding
  - Decision-making ability
  - Leadership experience

Designation:
  Primary: Security Operations Manager
  Backup: CISO
  After-hours: On-call rotation
```

#### Security Lead

```yaml
Responsibilities:
  - Threat analysis and assessment
  - Security tool operation
  - Forensic investigation
  - Indicator of Compromise (IoC) identification
  - Attack vector analysis
  - Security containment measures

Tools:
  - Azure Sentinel
  - Microsoft Defender
  - Forensic tools
  - Threat intelligence platforms

Authority:
  - Isolate compromised systems
  - Block malicious traffic
  - Disable accounts
  - Quarantine files
```

#### Platform Engineering Lead

```yaml
Responsibilities:
  - Infrastructure assessment
  - System isolation/recovery
  - Backup restoration
  - Configuration changes
  - Service continuity

Tools:
  - Azure Portal
  - Terraform
  - Kubernetes
  - Monitoring dashboards

Authority:
  - Emergency changes to infrastructure
  - Failover to DR environment
  - Resource scaling
```

#### Communications Lead

```yaml
Responsibilities:
  - Draft communications
  - Manage stakeholder updates
  - Coordinate with PR team
  - Customer notifications
  - Regulatory notifications

Templates:
  - Internal status update
  - Customer notification
  - Regulatory breach notification
  - Media statement

Approval Required:
  - IC approval for all external communications
  - Legal review for breach notifications
  - Executive approval for media statements
```

### Contact Information

```yaml
Emergency Contacts:

24/7 Security Hotline: +XX-XXX-XXX-XXXX
Email: security-incidents@crusoe-island.com
Slack: #security-incidents (monitoring 24/7)

Incident Commander:
  Primary: John Smith
    Phone: +XX-XXX-XXX-XXXX
    Email: john.smith@crusoe-island.com
    Slack: @jsmith
  
  Backup: Jane Doe
    Phone: +XX-XXX-XXX-XXXX
    Email: jane.doe@crusoe-island.com
    Slack: @jdoe

Security Lead:
  Alice Johnson
    Phone: +XX-XXX-XXX-XXXX
    Email: alice.johnson@crusoe-island.com
    Slack: @ajohnson

Platform Engineering:
  Bob Wilson
    Phone: +XX-XXX-XXX-XXXX
    Email: bob.wilson@crusoe-island.com
    Slack: @bwilson

Legal:
  Carol Martinez
    Phone: +XX-XXX-XXX-XXXX
    Email: carol.martinez@crusoe-island.com

External Resources:
  Microsoft Azure Support: [Support Plan]
  Cyber Insurance: [Policy Number]
  External IR Firm: [Contract]
  Law Enforcement: [Local Cybercrime Unit]
```

-----

## 🚨 Incident Classification

### Severity Levels

```yaml
P0 - CRITICAL (Active Attack / Major Breach):
  
  Definition:
    - Active ongoing attack with significant impact
    - Confirmed data breach (PII, payment data)
    - Complete service outage
    - Ransomware deployment
    - Critical infrastructure compromise
  
  Response Time:
    - Initial Response: Immediate (< 15 minutes)
    - Full Team Mobilization: < 30 minutes
    - Executive Notification: Immediate
    - Customer Notification: Per impact (immediate to 24h)
  
  Escalation:
    - Automatic IC notification
    - CISO notification (immediate)
    - CEO notification (within 1 hour)
    - Board notification (within 24 hours if needed)
  
  Examples:
    - Active ransomware spreading
    - Customer database exfiltration
    - Production Kubernetes cluster compromised
    - Multiple systems infected with malware
    - DDoS causing complete outage

P1 - HIGH (Significant Security Event):
  
  Definition:
    - Confirmed security breach (limited scope)
    - Potential data exposure
    - Successful unauthorized access
    - Major service degradation
    - Malware on critical system
  
  Response Time:
    - Initial Response: < 30 minutes
    - Team Mobilization: < 1 hour
    - Executive Notification: < 4 hours
    - Customer Notification: Per impact (24-72h)
  
  Escalation:
    - IC notification
    - CISO notification (within 2 hours)
    - CEO notification (if customer impact)
  
  Examples:
    - Compromised admin account
    - Successful phishing with credential theft
    - Unauthorized access to non-production system
    - Confirmed malware (contained)
    - Sensitive data exposure (limited scope)

P2 - MEDIUM (Security Incident):
  
  Definition:
    - Suspicious activity requiring investigation
    - Policy violation
    - Failed attack attempt (blocked)
    - Minor service impact
    - Potential security issue
  
  Response Time:
    - Initial Response: < 4 hours
    - Investigation: < 8 hours
    - Executive Notification: If escalates
  
  Escalation:
    - Security team notification
    - IC notification if pattern emerges
  
  Examples:
    - Repeated failed login attempts
    - Suspicious network traffic (blocked)
    - Vulnerability exploitation attempt (failed)
    - Policy violation by employee
    - Minor malware detection (quarantined)

P3 - LOW (Security Event):
  
  Definition:
    - Informational security event
    - Automated alerts (false positive likely)
    - Routine security activity
    - No immediate threat
  
  Response Time:
    - Review: Within business hours
    - Investigation: As needed
  
  Escalation:
    - Logged for trending
    - Escalate if pattern detected
  
  Examples:
    - Single failed login
    - Automated security scan alert
    - Minor configuration issue
    - Informational firewall log
```

### Incident Categories

```yaml
Category Classification:

1. Malware Incident:
   Types:
     - Ransomware
     - Trojans
     - Worms
     - Rootkits
     - Cryptominers
   
   Indicators:
     - Antivirus detection
     - Suspicious processes
     - Network beaconing
     - File encryption
     - Performance degradation

2. Unauthorized Access:
   Types:
     - Compromised credentials
     - Privilege escalation
     - Insider threat
     - Account takeover
   
   Indicators:
     - Impossible travel
     - Unusual access patterns
     - Failed MFA challenges
     - Privilege changes
     - Off-hours access

3. Data Breach:
   Types:
     - Exfiltration
     - Unauthorized disclosure
     - Data loss
     - Data corruption
   
   Indicators:
     - Large data transfers
     - Database dumps
     - Unusual queries
     - Access to sensitive data
     - Cloud storage uploads

4. Denial of Service (DoS/DDoS):
   Types:
     - Network flood
     - Application layer attack
     - Resource exhaustion
   
   Indicators:
     - Traffic spikes
     - Service unavailability
     - Resource exhaustion
     - Slow response times

5. Web Application Attack:
   Types:
     - SQL injection
     - XSS (Cross-site scripting)
     - CSRF
     - Authentication bypass
   
   Indicators:
     - WAF alerts
     - Suspicious URLs
     - Unusual parameters
     - Error spikes

6. Supply Chain Attack:
   Types:
     - Compromised dependency
     - Malicious package
     - Vendor breach
   
   Indicators:
     - Dependency alerts
     - Unexpected code changes
     - Vendor notification
     - Hash mismatches

7. Insider Threat:
   Types:
     - Malicious insider
     - Negligent insider
     - Compromised insider
   
   Indicators:
     - Data hoarding
     - Policy violations
     - Unusual hours
     - Disgruntlement
     - Access anomalies

8. Physical Security:
   Types:
     - Unauthorized entry
     - Stolen equipment
     - Lost devices
   
   Indicators:
     - Badge alerts
     - Asset tracking
     - Employee reports
```

-----

## 🔄 Incident Response Lifecycle

### NIST Incident Response Phases

```
┌────────────────────────────────────────────────────────────┐
│                 Incident Response Lifecycle                │
└────────────────────────────────────────────────────────────┘

1. PREPARATION
   │
   ├─→ Develop IR plan
   ├─→ Train IR team
   ├─→ Deploy monitoring
   ├─→ Prepare tools
   └─→ Establish communication channels
   
2. DETECTION & ANALYSIS
   │
   ├─→ Monitor for incidents
   ├─→ Triage alerts
   ├─→ Analyze indicators
   ├─→ Determine scope
   ├─→ Classify severity
   └─→ Notify stakeholders
   
3. CONTAINMENT
   │
   ├─→ Short-term containment
   │    ├─→ Isolate affected systems
   │    ├─→ Block malicious traffic
   │    └─→ Disable accounts
   │
   └─→ Long-term containment
        ├─→ Patch vulnerabilities
        ├─→ Harden systems
        └─→ Implement monitoring
   
4. ERADICATION
   │
   ├─→ Remove malware
   ├─→ Delete backdoors
   ├─→ Fix vulnerabilities
   ├─→ Reset credentials
   └─→ Verify clean state
   
5. RECOVERY
   │
   ├─→ Restore systems
   ├─→ Validate functionality
   ├─→ Monitor closely
   ├─→ Gradual restoration
   └─→ Return to normal ops
   
6. POST-INCIDENT
   │
   ├─→ Document timeline
   ├─→ Lessons learned meeting
   ├─→ Update procedures
   ├─→ Improve controls
   └─→ Close incident

     ↓ Continuous Improvement ↓
     
   (Feed learnings back to PREPARATION)
```

### Phase-by-Phase Activities

```yaml
Phase 1: PREPARATION (Ongoing)

Activities:
  - Maintain incident response plan
  - Train incident response team
  - Conduct tabletop exercises
  - Deploy and configure monitoring
  - Establish communication channels
  - Prepare IR tools and resources
  - Create response playbooks
  - Test backup and recovery
  - Document systems and data flows

Deliverables:
  - Updated IR plan (this document)
  - Trained IR team
  - Operational monitoring (24/7)
  - Communication templates
  - Playbook library
  - Tool inventory
  - Contact lists

Success Criteria:
  - IR plan reviewed quarterly
  - Team trained annually
  - Tabletop exercises quarterly
  - Monitoring coverage > 95%
  - Response time targets met

Phase 2: DETECTION & ANALYSIS (Minutes to Hours)

Activities:
  - Monitor security alerts
  - Receive incident reports
  - Initial triage
  - Gather additional information
  - Determine if security incident
  - Classify severity
  - Assign IC and team
  - Initial notification
  - Begin documentation

Deliverables:
  - Incident ticket created
  - Initial assessment
  - Severity classification
  - Team assignments
  - Stakeholder notification
  - Incident timeline started

Success Criteria:
  - Detection within 15 minutes
  - Initial assessment within 30 minutes
  - Team mobilized per SLA
  - Stakeholders notified per SLA

Phase 3: CONTAINMENT (Hours)

Short-term Containment:
  - Isolate affected systems
  - Block malicious IPs/domains
  - Disable compromised accounts
  - Prevent lateral movement
  - Preserve evidence
  - Implement workarounds

Long-term Containment:
  - Apply patches
  - Reconfigure systems
  - Implement additional monitoring
  - Deploy compensating controls
  - Prepare for eradication

Deliverables:
  - Containment actions log
  - Evidence preserved
  - Systems isolated
  - Patches applied
  - Monitoring enhanced

Success Criteria:
  - Spread stopped within 4 hours
  - No additional systems affected
  - Evidence preserved
  - Service minimally impacted

Phase 4: ERADICATION (Hours to Days)

Activities:
  - Remove malware/backdoors
  - Delete attacker accounts
  - Fix root cause vulnerabilities
  - Reset all credentials
  - Rebuild compromised systems
  - Verify complete removal
  - Scan for persistence mechanisms

Deliverables:
  - Clean systems verified
  - Vulnerabilities patched
  - Credentials rotated
  - Root cause addressed
  - Verification scan results

Success Criteria:
  - No malicious artifacts remain
  - Vulnerabilities remediated
  - Systems hardened
  - Verification scans clean

Phase 5: RECOVERY (Days)

Activities:
  - Restore systems from clean backup
  - Rebuild systems if needed
  - Restore data
  - Validate functionality
  - Monitor for reinfection
  - Gradual service restoration
  - Enhanced monitoring period

Deliverables:
  - Systems operational
  - Data restored
  - Functionality validated
  - Monitoring in place
  - Service restored

Success Criteria:
  - All systems operational
  - No data loss
  - No reinfection
  - Performance normal
  - Users can access services

Phase 6: POST-INCIDENT (Days to Weeks)

Activities:
  - Complete timeline documentation
  - Conduct lessons learned meeting
  - Update IR plan
  - Improve security controls
  - Communicate outcomes
  - Close incident ticket
  - Archive evidence

Deliverables:
  - Incident report
  - Lessons learned document
  - Updated procedures
  - Improvement backlog
  - Final communications
  - Evidence archive

Success Criteria:
  - Report completed within 2 weeks
  - Lessons learned meeting held
  - Improvements identified
  - Plan updated
  - Stakeholders informed
```

-----

## 🔍 Detection and Analysis

### Detection Sources

```yaml
Automated Detection:

Azure Sentinel:
  - Security analytics rules
  - Threat intelligence
  - ML-based anomaly detection
  - Fusion correlation
  
  Alert Priority: High
  Response: Automated ticket creation
  
Microsoft Defender:
  - Endpoint detection (malware, suspicious behavior)
  - Cloud app security
  - Identity protection
  - Vulnerability detection
  
  Alert Priority: Medium to Critical
  Response: Automated response + ticket

Azure Monitor:
  - Infrastructure alerts
  - Performance anomalies
  - Availability issues
  
  Alert Priority: Low to Medium
  Response: Operations ticket

Network Security:
  - Firewall alerts (Azure Firewall)
  - NSG flow logs
  - DDoS protection alerts
  
  Alert Priority: Medium to High
  Response: Network team review

Application Security:
  - WAF alerts (Application Gateway)
  - API security (API Management)
  - Code scanning (GitHub Advanced Security)
  
  Alert Priority: Medium
  Response: Development team review

Manual Detection:

User Reports:
  - Phishing reports
  - Suspicious activity
  - Access issues
  - Performance problems
  
  Channel: security@crusoe-island.com or #security
  Response: Manual triage

Security Team:
  - Threat hunting
  - Log analysis
  - Vulnerability assessments
  - Penetration testing
  
  Response: Immediate investigation

Third-Party:
  - Vendor notifications
  - Threat intelligence feeds
  - Security researchers
  - Law enforcement
  
  Response: Validate and investigate
```

### Initial Triage Process

```yaml
Triage Workflow:

1. Alert Reception (0-5 minutes):
   
   Questions:
     - What triggered the alert?
     - When did it occur?
     - What system/user is affected?
     - Is this a known false positive?
   
   Actions:
     - Create incident ticket
     - Assign to on-call analyst
     - Set initial priority
     - Begin timeline

2. Initial Assessment (5-15 minutes):
   
   Questions:
     - Is this a true positive?
     - What is the potential impact?
     - Is this part of a larger attack?
     - Are there additional indicators?
   
   Actions:
     - Gather context (logs, alerts, SIEM)
     - Check for related events
     - Identify affected assets
     - Determine severity

3. Classification (15-30 minutes):
   
   Determine:
     - Incident type/category
     - Severity level (P0-P3)
     - Scope of impact
     - Affected systems/data
   
   Actions:
     - Classify incident
     - Update ticket
     - Notify IC (if P0/P1)
     - Mobilize response team

4. Escalation (if needed):
   
   P0 (Critical):
     - Immediate IC notification
     - Full team mobilization
     - War room activation
     - Executive notification
   
   P1 (High):
     - IC notification within 30 min
     - Core team mobilization
     - CISO notification
   
   P2 (Medium):
     - Security team handles
     - IC informed
     - Standard investigation
   
   P3 (Low):
     - Logged and tracked
     - Investigate during business hours
```

### Analysis Techniques

```yaml
Log Analysis:

Sources:
  - Azure AD sign-in logs
  - Azure Activity Log
  - AKS audit logs
  - Application logs
  - Firewall logs
  - NSG flow logs

Tools:
  - Azure Sentinel (KQL queries)
  - Log Analytics
  - Azure Monitor
  - Kusto Explorer

Key Indicators:
  - Failed authentication attempts
  - Privilege escalations
  - Unusual access patterns
  - Data exfiltration signs
  - Lateral movement
  - Persistence mechanisms

Network Traffic Analysis:

Sources:
  - NSG flow logs
  - Firewall logs
  - Network Watcher
  - Packet captures (if needed)

Analysis:
  - Unusual destinations
  - Large data transfers
  - Command and control (C2) traffic
  - Port scanning
  - Protocol anomalies

Endpoint Analysis:

Tools:
  - Microsoft Defender for Endpoint
  - Process Explorer
  - Autoruns
  - File analysis

Indicators:
  - Suspicious processes
  - Unauthorized software
  - Registry modifications
  - Scheduled tasks
  - Startup items
  - Network connections

Threat Intelligence:

Sources:
  - Microsoft Threat Intelligence
  - MITRE ATT&CK
  - CISA alerts
  - Vendor advisories
  - VirusTotal
  - AlienVault OTX

Usage:
  - IoC enrichment
  - Attack technique identification
  - Attribution (if possible)
  - Trending threats
```

### Common Indicators of Compromise (IoCs)

```yaml
Account Compromise:

Indicators:
  - Impossible travel (login from two distant locations)
  - Login from unusual location
  - Login at unusual time
  - Multiple failed login attempts followed by success
  - Unusual user agent
  - Password reset without user request
  - MFA fatigue (repeated prompts)
  - Access to unusual resources

Example KQL Query:
```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"  // Successful
| where Location !in ("Authorized Countries")
| or UserAgent !contains "Expected Agent"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, UserAgent
```

Malware Infection:

Indicators:

- Antivirus detection
- Suspicious processes
- Unexpected network connections
- File modifications
- Registry changes
- Performance degradation
- Encrypted files (ransomware)

Example Detection:

```kusto
DeviceProcessEvents
| where ProcessCommandLine contains "powershell"
| where ProcessCommandLine contains "invoke"
| or ProcessCommandLine contains "downloadstring"
| or ProcessCommandLine contains "-enc"
```

Data Exfiltration:

Indicators:

- Large outbound data transfers
- Access to multiple sensitive files
- Database dumps
- Unusual cloud storage uploads
- Off-hours data access
- Access to sensitive data by non-authorized user

Example Detection:

```kusto
StorageBlobLogs
| where TimeGenerated > ago(1h)
| where OperationName == "PutBlob"
| summarize TotalSize=sum(ResponseBodySize), Count=count() by CallerIpAddress, UserAgentHeader
| where TotalSize > 1000000000  // > 1GB
```

Lateral Movement:

Indicators:

- RDP/SSH to multiple systems
- Pass-the-hash attempts
- Mimikatz usage
- Kerberoasting
- SMB enumeration
- Unusual service execution

Example Detection:

```kusto
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType == 3   // Network logon
| summarize Systems=dcount(Computer) by Account
| where Systems > 5
```

```
---

## 🛡️ Containment Strategies

### Short-Term Containment

```yaml
Immediate Actions (0-4 hours):

Network Isolation:
  
  Compromised System:
    Method: Network Security Group (NSG) modification
    ```bash
    # Block all traffic to/from compromised VM
    az network nsg rule create \
      --resource-group rg-idp-prod \
      --nsg-name nsg-compromised-system \
      --name block-all-traffic \
      --priority 100 \
      --access Deny \
      --protocol '*' \
      --source-address-prefixes '*' \
      --destination-address-prefixes '*'
    ```
    
    Impact: System isolated, no network access
    Recovery: Remove rule when clean
  
  Compromised Kubernetes Pod:
    Method: Network Policy
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: isolate-compromised-pod
      namespace: production
    spec:
      podSelector:
        matchLabels:
          app: compromised-app
      policyTypes:
      - Ingress
      - Egress
      # No ingress or egress rules = deny all
    ```
    
    Impact: Pod isolated within cluster
    Recovery: Delete policy when clean
  
  Subnet Isolation:
    Method: NSG + Route Table
    ```bash
    # Deny all traffic from subnet
    az network nsg rule create \
      --resource-group rg-network \
      --nsg-name nsg-compromised-subnet \
      --name deny-all-from-subnet \
      --priority 100 \
      --access Deny \
      --protocol '*' \
      --source-address-prefixes '10.0.2.0/24' \
      --destination-address-prefixes '*'
    ```

Account Lockout:
  
  Compromised User Account:
    Method: Azure AD account disable
    ```bash
    # Disable user account
    az ad user update \
      --id compromised.user@crusoe-island.com \
      --account-enabled false
    
    # Revoke all sessions
    az ad user revoke-sign-in-sessions \
      --id compromised.user@crusoe-island.com
    ```
    
    Impact: User cannot sign in, all sessions invalidated
    Recovery: Re-enable after password reset + investigation
  
  Compromised Service Principal:
    Method: Disable or delete credentials
    ```bash
    # Remove service principal credentials
    az ad sp credential delete \
      --id <service-principal-id> \
      --key-id <credential-key-id>
    ```
    
    Impact: Service principal cannot authenticate
    Recovery: Generate new credentials
  
  Compromised Service Account (K8s):
    Method: Delete service account or revoke tokens
    ```bash
    # Delete all tokens for service account
    kubectl delete secret -n production \
      $(kubectl get secret -n production | grep compromised-sa | awk '{print $1}')
    ```

Firewall Rules:
  
  Block Malicious IP/Domain:
    Method: Azure Firewall rule
    ```bash
    # Add deny rule in firewall policy
    az network firewall policy rule-collection-group collection rule add \
      --resource-group rg-network \
      --policy-name fwpolicy-idp-prod \
      --rule-collection-group-name threat-blocking \
      --collection-name block-malicious \
      --name block-c2-server \
      --rule-type NetworkRule \
      --ip-protocols TCP \
      --source-addresses '*' \
      --destination-addresses 192.0.2.100 \
      --destination-ports '*' \
      --action Deny \
      --priority 100
    ```
    
    Impact: All traffic to/from IP blocked
    Duration: Until confirmed benign or IOC expires

Evidence Preservation:
  
  Snapshot Virtual Machine:
    ```bash
    # Create snapshot before any changes
    az snapshot create \
      --resource-group rg-forensics \
      --name snapshot-compromised-vm-$(date +%Y%m%d-%H%M%S) \
      --source /subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/disks/osdisk
    ```
    
    Purpose: Preserve state for forensics
    Retention: 90 days minimum
  
  Export Logs:
    ```bash
    # Export relevant logs to immutable storage
    az monitor log-analytics query \
      --workspace WORKSPACE_ID \
      --analytics-query "SecurityEvent | where TimeGenerated > ago(24h)" \
      --output tsv > evidence-logs-$(date +%Y%m%d).tsv
    ```

Service Degradation:
  
  If Complete Containment Impacts Services:
    - Implement temporary workarounds
    - Route traffic to backup systems
    - Enable maintenance mode
    - Communicate with users
    - Balance security vs availability
    
    Example: Ransomware spreading
      Immediate: Isolate infected systems (may cause outage)
      Workaround: Failover to DR environment
      Communication: Status page update
```

### Long-Term Containment

```yaml
Sustained Protection (4-24 hours):

System Hardening:
  
  Patch Vulnerabilities:
    - Apply emergency patches
    - Deploy compensating controls
    - Update security configurations
    
    Example:
    ```bash
    # Apply patch to all VMs in resource group
    az vm run-command invoke \
      --resource-group rg-idp-prod \
      --name vm-web-* \
      --command-id RunShellScript \
      --scripts "apt-get update && apt-get upgrade -y"
    ```
  
  Harden Configurations:
    - Remove unnecessary services
    - Disable unused accounts
    - Tighten firewall rules
    - Enable additional logging
    
    Example:
    ```yaml
    # Kubernetes Pod Security Policy
    apiVersion: policy/v1beta1
    kind: PodSecurityPolicy
    metadata:
      name: restricted-after-incident
    spec:
      privileged: false
      allowPrivilegeEscalation: false
      requiredDropCapabilities:
        - ALL
      runAsUser:
        rule: MustRunAsNonRoot
      seLinux:
        rule: RunAsAny
      fsGroup:
        rule: RunAsAny
      readOnlyRootFilesystem: true
    ```

Enhanced Monitoring:
  
  Deploy Additional Detections:
    - Create incident-specific analytics rules
    - Enable verbose logging
    - Deploy honeypots/canaries
    - Monitor for reinfection
    
    Example:
    ```kusto
    // Azure Sentinel analytics rule
    // Detect if attacker returns
    SigninLogs
    | where IPAddress in ("known_malicious_ips")
    | or UserAgent contains "known_malicious_ua"
    | project TimeGenerated, UserPrincipalName, IPAddress, Location
    ```

Credential Rotation:
  
  Reset Affected Credentials:
    - User passwords
    - Service principal secrets
    - API keys
    - SSH keys
    - Database passwords
    
    Scope:
      Minimum: All compromised accounts
      Recommended: All accounts with same privilege level
      Maximum: All accounts (if widespread breach)
    
    Process:
    ```bash
    # Reset all service principal secrets
    for sp in $(az ad sp list --query "[].appId" -o tsv); do
      az ad sp credential reset --id $sp
    done
    ```

Compensating Controls:
  
  Temporary Additional Security:
    - Require step-up authentication
    - Restrict access by IP
    - Enable approval workflows
    - Increase monitoring
    
    Example:
    ```bash
    # Temporary conditional access policy
    # Require MFA for all access
    az ad policy conditional-access create \
      --display-name "Incident Response - Require MFA" \
      --conditions users=All apps=All \
      --grant-controls requireMfa=true \
      --state enabled
    ```
```

-----

**End of Part 1**

**Continue to Part 2 for:**

- Eradication Procedures
- Recovery Procedures
- Post-Incident Activities
- Communication Protocols
- Incident Response Playbooks (Ransomware, Compromised Account, Data Breach)

-----

**Document Classification:** Internal - Confidential  
**Emergency Contact:** security-incidents@crusoe-island.com | +XX-XXX-XXX-XXXX 🚨
