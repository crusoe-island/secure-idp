# Incident Response Plan - Crusoe IDP (Part 3 of 3)

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Owner:** Security Operations Team  
**Status:** Active

-----

## 📋 Table of Contents - Part 3

- [Additional Playbooks](#additional-playbooks)
- [Forensics and Evidence Collection](#forensics-and-evidence-collection)
- [Tools and Resources](#tools-and-resources)
- [Training and Exercises](#training-and-exercises)
- [Metrics and KPIs](#metrics-and-kpis)
- [Legal and Regulatory Considerations](#legal-and-regulatory-considerations)
- [Appendices](#appendices)

-----

## 📚 Additional Playbooks

### Playbook: Compromised User Account

```yaml
PLAYBOOK: Compromised User Account
Severity: P1 (High) or P2 (Medium)
Owner: Security Operations

DETECTION INDICATORS:
  - Impossible travel (login from two distant locations)
  - Login from unfamiliar location
  - Unusual access patterns
  - Failed MFA challenges followed by success
  - Data exfiltration indicators
  - User report of suspicious activity

IMMEDIATE ACTIONS (0-15 minutes):

1. DISABLE ACCOUNT:
   ```bash
   # Disable Azure AD account
   az ad user update \
     --id compromised.user@crusoe-island.com \
     --account-enabled false
   
   # Revoke all sessions
   az ad user revoke-sign-in-sessions \
     --id compromised.user@crusoe-island.com
```

1. VERIFY WITH USER:
- Call user directly (not email)
- Confirm legitimate activity or compromise
- If legitimate: re-enable with MFA verification
- If compromised: proceed with full response
1. ASSESS IMPACT:
   
   ```kusto
   // What did the attacker access?
   AuditLogs
   | where TimeGenerated > ago(24h)
   | where InitiatedBy.user.userPrincipalName == "compromised.user@crusoe-island.com"
   | where Result == "success"
   | project TimeGenerated, OperationName, TargetResources
   ```
1. CHECK FOR LATERAL MOVEMENT:
   
   ```kusto
   // Did attacker pivot to other accounts?
   SigninLogs
   | where TimeGenerated > ago(24h)
   | where IPAddress in (<attacker_ips>)
   | where UserPrincipalName != "compromised.user@crusoe-island.com"
   ```

CONTAINMENT (15-60 minutes):

1. RESET CREDENTIALS:
   
   ```bash
   # Generate strong temporary password
   temp_pass=$(openssl rand -base64 16)
   
   # Reset password
   az ad user update \
     --id compromised.user@crusoe-island.com \
     --password $temp_pass \
     --force-change-password-next-sign-in true
   ```
1. CHECK FOR PERSISTENCE:
- Application consents
- OAuth tokens
- Forwarding rules
- Mailbox delegates
   
   ```bash
   # List app consents
   az ad user show \
     --id compromised.user@crusoe-island.com \
     --query "appRoleAssignments"
   
   # Remove suspicious consents
   az ad app permission delete \
     --id <app-id> \
     --api <api-id>
   ```
1. BLOCK ATTACKER IP:
   
   ```bash
   # Add to firewall blocklist
   az network firewall policy rule-collection-group collection rule add \
     --resource-group rg-network \
     --policy-name fwpolicy-idp-prod \
     --rule-collection-group-name threat-blocking \
     --collection-name block-attacker \
     --name block-incident-12345 \
     --rule-type NetworkRule \
     --ip-protocols '*' \
     --source-addresses <attacker-ip> \
     --destination-addresses '*' \
     --destination-ports '*' \
     --action Deny
   ```

ERADICATION (1-4 hours):

1. REVIEW ALL ACCESS:
- What data was accessed?
- What systems were accessed?
- What changes were made?
- Were any backdoors created?
1. REVOKE ALL TOKENS:
   
   ```bash
   # Revoke all refresh tokens
   az ad user revoke-sign-in-sessions \
     --id compromised.user@crusoe-island.com
   ```
1. AUDIT CHANGES:
- Check for permission changes
- Check for new users created
- Check for configuration changes
- Check for data exfiltration
1. REMOVE PERSISTENCE:
- Delete forwarding rules
- Remove delegates
- Revoke application consents
- Delete suspicious OAuth apps

RECOVERY (4-8 hours):

1. RE-ENABLE ACCOUNT:
   
   ```bash
   # Only after confirming clean
   az ad user update \
     --id compromised.user@crusoe-island.com \
     --account-enabled true
   ```
1. USER COMMUNICATION:
- Inform user of compromise
- Provide secure password
- Require MFA re-enrollment
- Security awareness reminder
1. ENHANCED MONITORING:
- Watch user account for 30 days
- Alert on any unusual activity
- Reduced alert thresholds

POST-INCIDENT:

1. ROOT CAUSE:
- How were credentials compromised?
- Phishing? Credential stuffing? Malware?
1. PREVENTION:
- Additional training if phishing
- Conditional access policies
- Passwordless authentication
- Improved detection

ESCALATION:

- Escalate to P1 if:
  - Sensitive data accessed
  - Admin account compromised
  - Multiple accounts affected
  - Evidence of data exfiltration

```
### Playbook: Data Breach

```yaml
PLAYBOOK: Data Breach / Data Exfiltration
Severity: P0 (Critical)
Owner: Security Operations & Legal

DETECTION INDICATORS:
  - Large outbound data transfers
  - Database dumps
  - Access to sensitive files
  - Cloud storage uploads
  - Unusual API calls
  - Data exfiltration tools detected

IMMEDIATE ACTIONS (0-30 minutes):

1. CONFIRM BREACH:
   - Verify data was actually exfiltrated
   - Not just accessed
   - Determine data type and sensitivity
   - Estimate number of records

2. STOP EXFILTRATION:
   ```bash
   # Block outbound connections from source
   az network nsg rule create \
     --resource-group rg-network \
     --nsg-name nsg-source-system \
     --name block-outbound-emergency \
     --priority 100 \
     --access Deny \
     --direction Outbound \
     --protocol '*' \
     --source-address-prefixes '*' \
     --destination-address-prefixes 'Internet'
```

1. PRESERVE EVIDENCE:
   
   ```bash
   # Snapshot everything
   # Export logs
   # Capture network traffic
   
   # Export database query logs
   az sql db audit-policy show \
     --resource-group rg-idp-prod \
     --server sql-idp-prod \
     --name db-customers
   
   # Export to immutable storage
   ```
1. NOTIFY IMMEDIATELY:
- IC
- CISO
- CEO
- Legal Counsel
- DPO (Data Protection Officer)
- Cyber Insurance
- Do NOT notify customers yet (legal review first)

ASSESSMENT (30-120 minutes):

1. DETERMINE SCOPE:
   
   What Data:
- Personal data (PII)?
- Financial data?
- Health data (PHI)?
- Trade secrets?
- Credentials?
   
   How Many Records:
- Exact count or estimate
- Categories of data subjects
   
   Sensitivity Classification:
- Highly Sensitive (passwords, payment cards)
- Confidential (PII, financial)
- Internal (business data)
- Public (already public info)
1. LEGAL ASSESSMENT:
   
   Notification Requirements:
- GDPR: 72 hours to authority, “without undue delay” to subjects
- CCPA: 45 days (if SSN/payment)
- HIPAA: 60 days (if PHI)
- State laws: Varies
- Contractual: Check contracts
   
   Questions for Legal:
- Must we notify?
- Who must we notify?
- What timeline?
- What must notification include?
- Any legal holds?
1. FORENSIC INVESTIGATION:
   
   ```bash
   # Analyze exfiltration
   # What queries were run?
   az monitor activity-log list \
     --resource-group rg-idp-prod \
     --start-time "2024-12-21T00:00:00Z" \
     --query "[?contains(operationName.value, 'Microsoft.Sql')]"
   
   # Where was data sent?
   # Network flow logs
   az network watcher flow-log show \
     --resource-group NetworkWatcherRG \
     --nsg nsg-database-subnet \
     --name flowlog-database
   ```

CONTAINMENT (2-4 hours):

1. CLOSE ATTACK VECTOR:
- Patch vulnerability
- Fix misconfigurations
- Remove attacker access
- Reset credentials
1. PREVENT FURTHER DAMAGE:
- Can we recall/delete exfiltrated data?
- Takedown requests (if applicable)
- Legal injunctions (if applicable)

NOTIFICATION (24-72 hours):

1. REGULATORY NOTIFICATIONS:
   
   GDPR (72 hours):
   
   ```markdown
   To: Data Protection Authority
   Subject: Personal Data Breach Notification
   
   1. Nature of breach: [description]
   2. Categories of data subjects: Customers (~X,XXX)
   3. Categories of data: [list]
   4. Likely consequences: [assessment]
   5. Measures taken: [actions]
   6. DPO Contact: privacy@crusoe-island.com
   ```
   
   State Notifications:
- Attorney General (if required)
- Consumer reporting agencies (if >1,000 affected)
1. CUSTOMER NOTIFICATIONS:
   
   Required Information:
- What happened
- What data was involved
- What we’re doing
- What they should do
- Contact information
   
   Template:
   
   ```markdown
   Subject: Important Security Notice
   
   Dear [Name],
   
   We are writing to inform you of a data security incident that
   may have affected your personal information.
   
   WHAT HAPPENED:
   On [date], we discovered that an unauthorized party accessed our
   database containing customer information.
   
   WHAT INFORMATION WAS INVOLVED:
   The following information may have been accessed:
   - Name
   - Email address
   - [other fields]
   
   WHAT WE ARE DOING:
   - We have secured our systems
   - We are working with law enforcement
   - We have engaged cybersecurity experts
   - We are implementing additional security measures
   
   WHAT YOU SHOULD DO:
   - Monitor your accounts for suspicious activity
   - Consider placing a fraud alert
   - Be cautious of phishing attempts
   - [Credit monitoring if appropriate]
   
   We sincerely apologize for this incident and any concern it may
   cause. The security of your information is extremely important
   to us.
   
   For questions: databreachresponse@crusoe-island.com
   Toll-free: 1-800-XXX-XXXX
   
   Sincerely,
   [Name], [Title]
   ```
1. CREDIT MONITORING (if applicable):
- Offer free credit monitoring (12-24 months)
- Identity theft protection
- Engage vendor (Experian, etc.)

POST-INCIDENT:

1. ROOT CAUSE ANALYSIS:
- How did breach occur?
- Why wasn’t it prevented?
- Why wasn’t it detected sooner?
1. REMEDIATION:
- Fix all vulnerabilities
- Improve access controls
- Enhance monitoring
- Data minimization
1. REGULATORY FOLLOW-UP:
- Respond to authority questions
- Provide updates as requested
- Potential fines/penalties
1. LITIGATION PREPARATION:
- Preserve all evidence
- Class action lawsuits likely
- Work with legal counsel

CRITICAL TIMELINES:

- GDPR Authority: 72 hours from discovery
- GDPR Subjects: Without undue delay (typically <72h)
- CCPA: 45 days (if applicable)
- HIPAA: 60 days (if PHI)

CHECKLIST:
☐ Breach confirmed and scoped
☐ Legal counsel engaged
☐ DPO notified
☐ Regulatory requirements identified
☐ Authority notified (if required)
☐ Customers notified (if required)
☐ Credit monitoring arranged (if applicable)
☐ PR strategy developed
☐ Remediation implemented
☐ Lessons learned documented

```
---

## 🔬 Forensics and Evidence Collection

### Evidence Handling

```yaml
Chain of Custody:

Definition:
  Documented trail showing:
    - Who collected evidence
    - When it was collected
    - How it was collected
    - Who has handled it
    - Where it has been stored

Importance:
  - Legal admissibility
  - Investigation integrity
  - Regulatory compliance

Chain of Custody Form:

```markdown
EVIDENCE COLLECTION FORM

Incident ID: INC-12345
Case Number: CASE-2024-001
Date: 2024-12-21

EVIDENCE INFORMATION:
  Item #: EVD-001
  Description: Azure VM disk snapshot
  Source: VM-WEB-01
  Collection Method: Azure snapshot
  File Hash (SHA-256): a1b2c3d4...
  File Size: 128 GB
  
COLLECTOR INFORMATION:
  Name: Alice Johnson
  Title: Security Analyst
  Department: Security Operations
  Date/Time: 2024-12-21 10:45 UTC
  Signature: _______________

TRANSFER LOG:
  Transferred To: Bob Wilson
  Date/Time: 2024-12-21 14:30 UTC
  Purpose: Forensic analysis
  Signature: _______________
  
  Transferred To: Evidence Storage
  Date/Time: 2024-12-21 18:00 UTC
  Storage Location: AZ-EVIDENCE-001
  Signature: _______________

NOTES:
  [Any relevant observations]
```

Evidence Collection Best Practices:

1. Minimize Changes:
- Do not modify original evidence
- Work on copies when possible
- Document any necessary changes
1. Hash Everything:
   
   ```bash
   # Calculate hash before collection
   ssh user@compromised-system "sha256sum /path/to/evidence" > evidence.hash
   
   # Verify after collection
   sha256sum evidence-file
   # Compare with original hash
   ```
1. Document Thoroughly:
- Timestamps (UTC)
- Who collected
- From where
- How
- Any observations
1. Secure Storage:
   
   ```bash
   # Store in immutable Azure Storage
   az storage account create \
     --name stevidence \
     --resource-group rg-forensics \
     --sku Standard_LRS \
     --enable-hierarchical-namespace false
   
   # Enable immutability
   az storage blob service-properties update \
     --account-name stevidence \
     --enable-container-delete-retention true \
     --container-delete-retention-days 365
   
   # Upload evidence with metadata
   az storage blob upload \
     --account-name stevidence \
     --container-name evidence \
     --name EVD-001-disk-snapshot.vhd \
     --file snapshot.vhd \
     --metadata incident=INC-12345 collector="Alice Johnson" date=2024-12-21
   ```

```
### Data Sources to Collect

```yaml
Azure Virtual Machines:
  
  Disk Snapshots:
    ```bash
    # Create snapshot of OS disk
    az snapshot create \
      --resource-group rg-forensics \
      --name snapshot-vm-web-01-$(date +%Y%m%d-%H%M%S) \
      --source /subscriptions/.../resourceGroups/rg-idp-prod/providers/Microsoft.Compute/disks/vm-web-01-osdisk
    ```

Azure Logs:
  
  Export All Relevant Logs:
    ```bash
    # Azure AD Sign-in Logs
    az monitor activity-log list \
      --resource-group rg-idp-prod \
      --start-time "2024-12-20T00:00:00Z" \
      --end-time "2024-12-22T00:00:00Z" \
      --output json > evidence-activity-log.json
    ```

Kubernetes:
  
  Pod Logs:
    ```bash
    # Export logs from pods
    kubectl logs pod-name -n production --all-containers > pod-logs.txt
    
    # Export previous logs (if restarted)
    kubectl logs pod-name -n production --previous > pod-logs-previous.txt
    ```
```

-----

## 🛠️ Tools and Resources

### Incident Response Tools

```yaml
Detection and Monitoring:

Azure Sentinel:
  Purpose: SIEM, threat detection, investigation
  Access: portal.azure.com → Sentinel
  Key Features:
    - Analytics rules
    - Workbooks
    - Hunting queries
    - Incident management

Microsoft Defender for Cloud:
  Purpose: Cloud security posture management
  Access: portal.azure.com → Defender for Cloud
  
Analysis and Investigation:

KQL (Kusto Query Language):
  Purpose: Log analysis in Azure Sentinel/Log Analytics
  Learning: https://docs.microsoft.com/kusto

Network Watcher:
  Purpose: Network diagnostics and monitoring
  Access: portal.azure.com → Network Watcher

Containment and Response:

Azure CLI:
  Purpose: Scripted Azure operations
  Installation: https://docs.microsoft.com/cli/azure/install-azure-cli

kubectl:
  Purpose: Kubernetes management
  Installation: az aks install-cli
```

-----

## 🎓 Training and Exercises

### Tabletop Exercises

```yaml
Tabletop Exercise Program:

Frequency: Quarterly
Duration: 2-3 hours
Participants: IR team, management, key stakeholders

Exercise Format:

1. Introduction (15 min):
   - Exercise objectives
   - Scenario overview
   - Ground rules
   - Participant roles

2. Scenario Presentation (15 min):
   - Initial inject
   - Background information
   - Systems affected

3. Discussion Rounds (90 min):
   - Detection and Initial Response
   - Containment
   - Eradication and Recovery
   - External Communication

4. Hot Wash / Debrief (30 min):
   - What went well?
   - What was confusing?
   - Gaps identified?
   - Action items

Example Scenarios:

Scenario 1: Ransomware Attack
  - Detection: Sentinel alert on mass file encryption
  - Scope: 50 VMs affected
  - Impact: Production services down

Scenario 2: Data Breach
  - Detection: DLP alert on large data download
  - Scope: Customer database accessed
  - Impact: 10,000 customer records potentially exfiltrated

Scenario 3: Insider Threat
  - Detection: User accessing unusual amount of data
  - Scope: Employee preparing to leave company
  - Impact: Intellectual property at risk
```

-----

## 📈 Metrics and KPIs

### Incident Metrics

```yaml
Response Time Metrics:

MTTD (Mean Time To Detect):
  Definition: Time from incident occurrence to detection
  Target: < 15 minutes

MTTR (Mean Time To Respond):
  Definition: Time from detection to response initiation
  Target: < 30 minutes (P0), < 4 hours (P1)

MTTC (Mean Time To Contain):
  Definition: Time from detection to containment
  Target: < 4 hours (P0), < 8 hours (P1)

MTTRE (Mean Time To Eradicate):
  Definition: Time from detection to complete eradication
  Target: < 24 hours (P0), < 48 hours (P1)

Volume Metrics:

Incidents by Severity:
  Targets:
    - P0: < 1 per quarter (goal: 0)
    - P1: < 5 per quarter
    - P2: < 20 per month

False Positive Rate:
  Target: < 20%

Effectiveness Metrics:

Detection Coverage:
  Target: > 80% of MITRE ATT&CK techniques

Containment Effectiveness:
  Target: > 95% contained before significant damage

Recurring Incidents:
  Target: < 5% same root cause within 90 days
```

-----

## ⚖️ Legal and Regulatory Considerations

### Breach Notification Requirements

```yaml
GDPR (General Data Protection Regulation):
  
  Authority Notification:
    Deadline: 72 hours from becoming aware
    Recipient: Supervisory Authority (DPA)
    Required Information:
      - Nature of breach
      - Categories and number of data subjects
      - Contact point (DPO)
      - Likely consequences
      - Measures taken

  Data Subject Notification:
    Deadline: Without undue delay
    Trigger: If high risk to rights and freedoms

CCPA (California Consumer Privacy Act):
  Notification Requirement:
    Trigger: Unencrypted personal information
    Deadline: No later than 45 days

State Breach Notification Laws:
  US States: All 50 states + DC have laws
  General Requirements:
    - Notify without unreasonable delay
    - Notify Attorney General (many states)
```

### Legal Hold

```yaml
Legal Hold Notice:

```markdown
LEGAL HOLD NOTICE

Date: [Date]
Matter: [Case Name/Number]
Custodians: [List of people]

You are hereby notified that you must preserve all documents and
information relating to [matter description].

DO NOT:
- Delete any potentially relevant information
- Modify any potentially relevant information

DO:
- Preserve all potentially relevant information
- Suspend auto-deletion processes
- Notify IT of this hold

Questions: legal@crusoe-island.com
```

IT Implementation:

```bash
# Suspend deletion policies
az storage management-policy delete \
  --account-name stidpprod \
  --resource-group rg-idp-prod \
  --name data-lifecycle-policy
```

```
---

## 📚 Appendices

### Appendix A: Glossary

```yaml
Common Terms:

APT (Advanced Persistent Threat):
  Sophisticated, sustained cyber attack

C2 (Command and Control):
  Server used by attacker to control compromised systems

IoC (Indicator of Compromise):
  Artifact that indicates a security breach

MTTR (Mean Time To Respond/Recover):
  Average time to respond to or recover from incident

SIEM (Security Information and Event Management):
  System for log aggregation and analysis

SOC (Security Operations Center):
  Team/facility for security monitoring

War Room:
  Dedicated space for incident response coordination
```

### Appendix B: Contact Lists

```yaml
Internal Contacts:

Executive Team:
  CEO: [Name, Phone, Email]
  CISO: [Name, Phone, Email]
  CTO: [Name, Phone, Email]
  General Counsel: [Name, Phone, Email]

Incident Response Team:
  IC (Primary): [Name, Phone, Email]
  IC (Backup): [Name, Phone, Email]
  Security Lead: [Name, Phone, Email]
  Platform Lead: [Name, Phone, Email]

External Contacts:

Microsoft Azure Support:
  Support Portal: https://portal.azure.com
  Phone: [Support Number]

Cyber Insurance:
  Provider: [Insurance Company]
  Policy: [Policy Number]
  24/7 Hotline: [Number]

Law Enforcement:
  FBI Cyber Division: [Local Field Office]
  Secret Service: [Contact]
```

-----

## 📝 Document Control

**Version History:**

|Version|Date      |Author             |Changes                                     |
|-------|----------|-------------------|--------------------------------------------|
|1.0    |2024-12-21|Security Operations|Initial incident response plan (Part 3 of 3)|

**Review Schedule:**

- **Quarterly**: Plan review and updates
- **Post-Incident**: Update after every P0/P1 incident
- **Annually**: Comprehensive review

**Next Review:** March 21, 2025

**Approvals:**

- [☐] CISO
- [☐] Incident Commander
- [☐] Legal Counsel
- [☐] CEO

-----

**Document Classification:** Internal - Confidential  
**Distribution:** IR Team, Security Team, Leadership

-----

## 🎯 Complete Incident Response Plan Summary

**Parts 1-3 Coverage:**

**Part 1: Foundation**

- Overview and objectives
- Incident Response Team structure
- Incident Classification (P0-P3)
- IR Lifecycle (6 phases)
- Detection and Analysis
- Containment Strategies

**Part 2: Operations**

- Eradication Procedures
- Recovery Procedures
- Post-Incident Activities
- Communication Protocols
- Main Playbooks (Ransomware)

**Part 3: Advanced Topics**

- Additional Playbooks (Compromised Account, Data Breach)
- Forensics and Evidence Collection
- Tools and Resources
- Training and Exercises
- Metrics and KPIs
- Legal and Regulatory
- Appendices

**Total Documentation:**

- 17 major sections
- 3 detailed playbooks
- Complete IR lifecycle
- Communication templates
- Forensics procedures
- Training programs
- ~8,000 words of comprehensive guidance

-----

*“The time to prepare for an incident is before it happens. This plan is our blueprint for that preparation.”*

**Emergency Contact:** security-incidents@crusoe-island.com | +XX-XXX-XXX-XXXX 🚨

**Remember: Stay calm, follow the plan, document everything, and communicate clearly.** 📞🔒
