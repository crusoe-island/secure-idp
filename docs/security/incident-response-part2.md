# Incident Response Plan - Crusoe IDP (Part 2 of 3)

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Owner:** Security Operations Team  
**Status:** Active

-----

## 📋 Table of Contents - Part 2

- [Eradication Procedures](#eradication-procedures)
- [Recovery Procedures](#recovery-procedures)
- [Post-Incident Activities](#post-incident-activities)
- [Communication Protocols](#communication-protocols)
- [Incident Response Playbooks](#incident-response-playbooks)

-----

## 🗑️ Eradication Procedures

### Malware Removal

```yaml
Complete Malware Eradication:

1. Identify All Infected Systems:
   
   Methods:
     - Scan all systems with updated AV
     - Check for IoC across environment
     - Review lateral movement indicators
     - Check for persistence mechanisms
   
   Tools:
     - Microsoft Defender for Endpoint
     - Malwarebytes (if needed)
     - YARA rules
     - IoC scanner scripts

2. Remove Malware:
   
   Preferred: Rebuild from clean image
   ```bash
   # Delete compromised VM
   az vm delete --resource-group rg-idp-prod --name vm-compromised --yes
   
   # Deploy new VM from known-good image
   az vm create \
     --resource-group rg-idp-prod \
     --name vm-replacement \
     --image /subscriptions/.../images/golden-image-v1.2.3 \
     --size Standard_D4s_v5
```

Alternative: Clean in place (not recommended)

```bash
# If rebuild not possible, clean thoroughly
# 1. Boot from clean media
# 2. Run offline scan
# 3. Remove all malicious files
# 4. Check startup locations
# 5. Verify clean
```

1. Remove Persistence Mechanisms:
   
   Common Locations:
- Scheduled tasks
- Startup folders
- Registry run keys
- Service installations
- WMI subscriptions
- Kubernetes CronJobs
   
   Kubernetes Example:
   
   ```bash
   # List all CronJobs
   kubectl get cronjobs --all-namespaces
   
   # Delete suspicious CronJob
   kubectl delete cronjob -n production malicious-cron
   ```
1. Verify Clean State:
   
   Scans:
- Full antivirus scan
- Rootkit scan
- IoC scan
- Behavioral monitoring (24h minimum)
   
   Validation:
   
   ```bash
   # Scan with Defender
   Update-MpSignature
   Start-MpScan -ScanType FullScan
   
   # Check for IoCs
   Get-MpThreatDetection
   ```

```
### Vulnerability Remediation

```yaml
Fix Root Cause:

1. Identify Exploited Vulnerability:
   
   Sources:
     - Vulnerability scanners
     - Exploit logs
     - CVE databases
     - Vendor advisories
   
   Documentation:
     - CVE number (if applicable)
     - Affected versions
     - Exploitation method
     - Available patches

2. Apply Patches:
   
   Priority Order:
     1. Critical vulnerabilities (CVSS 9.0-10.0)
     2. High vulnerabilities (CVSS 7.0-8.9)
     3. Medium vulnerabilities (CVSS 4.0-6.9)
   
   Process:
   ```bash
   # For VMs
   az vm run-command invoke \
     --resource-group rg-idp-prod \
     --name vm-web-01 \
     --command-id RunShellScript \
     --scripts "apt-get update && apt-get dist-upgrade -y"
   
   # For containers - update base image
   docker build --no-cache -t myapp:patched .
   docker push acridpprod.azurecr.io/myapp:patched
   
   # Update Kubernetes deployment
   kubectl set image deployment/myapp \
     myapp=acridpprod.azurecr.io/myapp:patched
```

1. Implement Workarounds (if patch unavailable):
   
   Options:
- Disable vulnerable feature
- Deploy WAF rules
- Implement network controls
- Add authentication
- Deploy IDS signatures
   
   Example:
   
   ```yaml
   # WAF rule to block exploitation
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     annotations:
       nginx.ingress.kubernetes.io/server-snippet: |
         # Block malicious patterns
         if ($request_uri ~* "exploit_pattern") {
           return 403;
         }
   ```
1. Verify Remediation:
   
   Testing:
- Rescan with vulnerability scanner
- Attempt exploitation (safe environment)
- Verify patch installation
- Monitor for exploitation attempts
   
   Validation:
   
   ```bash
   # Scan with Trivy
   trivy image acridpprod.azurecr.io/myapp:patched
   
   # Should show vulnerability fixed
   # 0 CRITICAL, 0 HIGH
   ```

```
### Account and Credential Reset

```yaml
Complete Credential Reset:

1. Identify Scope:
   
   Questions:
     - Which accounts were compromised?
     - What access did they have?
     - What secrets did they access?
     - What systems did they touch?
   
   Scope Options:
     - Minimal: Only confirmed compromised accounts
     - Moderate: All accounts with same access level
     - Maximum: All accounts (mass compromise)

2. Reset User Accounts:
   
   ```bash
   # Force password reset for all users
   for user in $(az ad user list --query "[].userPrincipalName" -o tsv); do
     az ad user update --id $user \
       --force-change-password-next-sign-in true
   done
   
   # Revoke all sessions
   for user in $(az ad user list --query "[].userPrincipalName" -o tsv); do
     az ad user revoke-sign-in-sessions --id $user
   done
```

1. Rotate Service Credentials:
   
   Azure Service Principals:
   
   ```bash
   # Reset all service principal secrets
   for sp in $(az ad sp list --query "[].appId" -o tsv); do
     echo "Resetting $sp"
     az ad sp credential reset --id $sp
   done
   ```
   
   Kubernetes Service Accounts:
   
   ```bash
   # Delete and recreate service account tokens
   kubectl delete secret -n production sa-token-xyz
   kubectl create token my-service-account -n production
   ```
   
   Azure Key Vault Secrets:
   
   ```bash
   # Rotate all secrets in Key Vault
   for secret in $(az keyvault secret list \
       --vault-name kv-idp-prod \
       --query "[].name" -o tsv); do
     
     # Generate new secret value
     new_value=$(openssl rand -base64 32)
     
     # Update secret
     az keyvault secret set \
       --vault-name kv-idp-prod \
       --name $secret \
       --value $new_value
   done
   ```
1. Rotate Encryption Keys:
   
   ```bash
   # Rotate Key Vault keys
   az keyvault key rotate \
     --vault-name kv-idp-prod \
     --name encryption-key
   
   # Update applications to use new key version
   ```
1. Reset Database Credentials:
   
   ```sql
   -- PostgreSQL example
   ALTER USER app_user WITH PASSWORD 'new_secure_password';
   
   -- Revoke and recreate if needed
   DROP USER IF EXISTS compromised_user;
   CREATE USER new_app_user WITH PASSWORD 'new_secure_password';
   GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO new_app_user;
   ```
1. API Key Rotation:
   
   ```bash
   # If API keys stored in Key Vault
   az keyvault secret set \
     --vault-name kv-idp-prod \
     --name stripe-api-key \
     --value sk_live_new_key_here
   
   # Update application configuration
   kubectl set env deployment/payment-service \
     STRIPE_API_KEY_VERSION=v2
   ```
1. SSH Key Rotation:
   
   ```bash
   # Generate new SSH key pair
   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new -C "security@crusoe-island.com"
   
   # Deploy new public key to all systems
   for vm in $(az vm list -g rg-idp-prod --query "[].name" -o tsv); do
     az vm user update \
       --resource-group rg-idp-prod \
       --name $vm \
       --username azureuser \
       --ssh-key-value @~/.ssh/id_ed25519_new.pub
   done
   
   # Revoke old key
   # (Remove from authorized_keys on all systems)
   ```
1. Certificate Rotation:
   
   ```bash
   # Revoke compromised certificate
   az keyvault certificate set-attributes \
     --vault-name kv-idp-prod \
     --name app-tls-cert \
     --enabled false
   
   # Issue new certificate
   az keyvault certificate create \
     --vault-name kv-idp-prod \
     --name app-tls-cert-new \
     --policy @cert-policy.json
   
   # Update ingress to use new certificate
   kubectl create secret tls app-tls-new \
     --cert=new-cert.crt \
     --key=new-cert.key
   ```

```
---

## 🔄 Recovery Procedures

### System Restoration

```yaml
Phased Recovery Approach:

Phase 1: Prepare for Recovery (Hour 0-4)
  
  Verification:
    ☐ Eradication confirmed complete
    ☐ No malware detected (multiple scans)
    ☐ Vulnerabilities patched
    ☐ All credentials rotated
    ☐ Monitoring enhanced
    ☐ Recovery plan documented
  
  Pre-Recovery Checks:
    ☐ Backups verified clean
    ☐ Recovery environment prepared
    ☐ Dependencies identified
    ☐ Rollback plan ready
    ☐ Communication plan ready

Phase 2: Restore Non-Critical Systems (Hour 4-12)
  
  Order:
    1. Development environment
    2. Staging environment
    3. Internal tools
    4. Non-customer-facing services
  
  Process:
    ```bash
    # Restore from backup
    az backup restore restore-azurevm \
      --resource-group rg-backup \
      --vault-name rsv-idp-prod \
      --container-name vm-container \
      --item-name vm-dev-01 \
      --restore-mode AlternateLocation \
      --recovery-point-id <recovery-point-id> \
      --target-resource-group rg-recovery
    
    # Or rebuild from Infrastructure as Code
    cd terraform/environments/dev
    terraform apply
    ```
  
  Validation:
    - Functionality testing
    - Security scanning
    - Performance testing
    - 24-hour monitoring period

Phase 3: Restore Critical Systems (Hour 12-24)
  
  Order:
    1. Database restore
    2. Application servers
    3. API gateway
    4. Load balancers
    5. CDN
  
  Database Restore Example:
    ```bash
    # Restore Azure SQL from point-in-time
    az sql db restore \
      --resource-group rg-idp-prod \
      --server sql-idp-prod \
      --name db-app \
      --dest-name db-app-restored \
      --time "2024-12-21T10:30:00Z"
    
    # Verify data integrity
    sqlcmd -S sql-idp-prod.database.windows.net \
      -d db-app-restored \
      -U dbadmin \
      -Q "SELECT COUNT(*) FROM critical_table"
    ```
  
  Gradual Traffic Restoration:
    ```bash
    # Start with 10% traffic
    kubectl patch deployment app \
      -p '{"spec":{"replicas":2}}'  # 10% of normal capacity
    
    # Monitor for 1 hour
    # If stable, increase to 25%
    kubectl scale deployment app --replicas=5
    
    # Continue gradually until 100%
    ```

Phase 4: Full Service Restoration (Hour 24-48)
  
  Final Steps:
    - Remove maintenance mode
    - Enable all features
    - Restore full capacity
    - Return to normal operations
    - Continue enhanced monitoring
  
  Communication:
    ```markdown
    Subject: Service Fully Restored - Security Incident Resolved
    
    We're pleased to announce that all systems have been fully restored
    following the security incident detected on [date]. 
    
    Status: All services operational
    Performance: Normal
    Data: No data loss
    Security: Enhanced monitoring in place
    
    We will continue enhanced monitoring for the next 7 days. Thank you
    for your patience during this incident.
    ```

Phase 5: Post-Recovery Monitoring (Day 2-7)
  
  Enhanced Monitoring:
    - 24/7 SOC watch
    - Reduced alert thresholds
    - Frequent security scans
    - Daily backup verification
    - User behavior analytics
  
  Metrics to Watch:
    - Failed authentication attempts
    - Unusual access patterns
    - Network traffic anomalies
    - System performance
    - Error rates
```

### Backup Restoration

```yaml
Backup Types and Restoration:

Azure VM Backup:
  
  List Available Recovery Points:
    ```bash
    az backup recoverypoint list \
      --resource-group rg-backup \
      --vault-name rsv-idp-prod \
      --container-name IaasVMContainer;iaasvmcontainerv2;rg-idp-prod;vm-web-01 \
      --item-name vm;iaasvmcontainerv2;rg-idp-prod;vm-web-01 \
      --query "[].{Name:name, Time:properties.recoveryPointTime}" \
      --output table
    ```
  
  Restore VM:
    ```bash
    az backup restore restore-azurevm \
      --resource-group rg-backup \
      --vault-name rsv-idp-prod \
      --container-name IaasVMContainer;iaasvmcontainerv2;rg-idp-prod;vm-web-01 \
      --item-name vm;iaasvmcontainerv2;rg-idp-prod;vm-web-01 \
      --restore-mode AlternateLocation \
      --recovery-point-id <recovery-point-id> \
      --target-resource-group rg-recovery \
      --storage-account strecovery
    ```

Azure SQL Database:
  
  Point-in-Time Restore:
    ```bash
    # Restore to specific point in time
    az sql db restore \
      --resource-group rg-idp-prod \
      --server sql-idp-prod \
      --name db-customers \
      --dest-name db-customers-restored \
      --time "2024-12-21T10:00:00Z"
    ```
  
  Geo-Restore (Disaster Recovery):
    ```bash
    az sql db restore \
      --resource-group rg-idp-dr \
      --server sql-idp-dr \
      --name db-customers \
      --dest-name db-customers-restored \
      --geo-backup-id /subscriptions/.../backups/...
    ```

Kubernetes Persistent Volumes:
  
  Using Velero:
    ```bash
    # List available backups
    velero backup get
    
    # Restore specific backup
    velero restore create restore-20241221 \
      --from-backup backup-20241221-daily
    
    # Restore specific namespace
    velero restore create restore-production \
      --from-backup backup-20241221-daily \
      --include-namespaces production
    ```

Azure Storage:
  
  Blob Soft Delete Recovery:
    ```bash
    # List soft-deleted blobs
    az storage blob list \
      --account-name stidpprod \
      --container-name data \
      --include d \
      --query "[?properties.deletedTime].name"
    
    # Restore soft-deleted blob
    az storage blob undelete \
      --account-name stidpprod \
      --container-name data \
      --name important-file.txt
    ```
  
  Point-in-Time Restore (if enabled):
    ```bash
    az storage account blob-service-properties update \
      --account-name stidpprod \
      --enable-restore-policy true \
      --restore-days 7
    
    # Restore to point in time
    az storage blob restore \
      --account-name stidpprod \
      --time-to-restore "2024-12-21T10:00:00Z" \
      --blob-range container/prefix
    ```
```

### Validation and Testing

```yaml
Recovery Validation Checklist:

Functional Testing:
  ☐ All critical services responding
  ☐ Authentication working
  ☐ Database connectivity verified
  ☐ API endpoints responding
  ☐ UI rendering correctly
  ☐ Scheduled jobs running
  ☐ Integrations working
  ☐ Monitoring operational

Security Testing:
  ☐ Vulnerability scan clean
  ☐ Malware scan clean
  ☐ No suspicious processes
  ☐ Firewall rules correct
  ☐ Access controls verified
  ☐ Encryption enabled
  ☐ Logging operational
  ☐ Alerts functional

Performance Testing:
  ☐ Response times normal
  ☐ CPU utilization normal
  ☐ Memory utilization normal
  ☐ Disk I/O normal
  ☐ Network throughput normal
  ☐ Database performance normal

Data Integrity:
  ☐ Record counts match
  ☐ Critical data present
  ☐ No data corruption
  ☐ Referential integrity intact
  ☐ Checksums verified

User Acceptance:
  ☐ Internal team testing
  ☐ Limited user pilot
  ☐ Feedback collected
  ☐ Issues resolved
  ☐ Sign-off obtained
```

-----

## 📊 Post-Incident Activities

### Incident Documentation

```yaml
Incident Report Template:

1. Executive Summary:
   - One-paragraph overview
   - Impact statement
   - Resolution summary
   - Lessons learned (high-level)

2. Incident Timeline:
   
   Format:
   | Time (UTC) | Event | Actor | Notes |
   |------------|-------|-------|-------|
   | 2024-12-21 10:23 | Initial detection | Sentinel | Suspicious login detected |
   | 2024-12-21 10:25 | Incident created | Analyst | Ticket INC-12345 |
   | 2024-12-21 10:30 | IC notified | On-call | P1 escalation |
   | 2024-12-21 10:45 | Containment started | Security | Account disabled |
   | ... | ... | ... | ... |

3. Incident Details:
   - Incident ID: INC-12345
   - Classification: Unauthorized Access
   - Severity: P1 (High)
   - Affected Systems: [list]
   - Data Impacted: [description]
   - Root Cause: Compromised credentials via phishing
   
4. Impact Assessment:
   - Systems Affected: 3 VMs, 1 database
   - Users Affected: 150 users (downtime during containment)
   - Data Affected: 500 customer records accessed (no exfiltration)
   - Business Impact: 4 hours degraded service
   - Financial Impact: $XX,XXX (estimated)

5. Response Actions:
   
   Detection (10:23-10:30):
     - Azure Sentinel detected anomalous login
     - Analyst validated threat
     - Escalated to IC
   
   Containment (10:30-14:00):
     - Disabled compromised account
     - Isolated affected systems
     - Blocked attacker IP
     - Reset credentials
   
   Eradication (14:00-18:00):
     - Removed attacker persistence
     - Patched vulnerabilities
     - Hardened configurations
   
   Recovery (18:00-22:00):
     - Restored systems from backup
     - Validated functionality
     - Gradual service restoration
     - Resumed normal operations

6. Root Cause Analysis:
   
   Attack Chain:
     1. User received spear-phishing email
     2. User clicked link, entered credentials
     3. Attacker obtained valid credentials
     4. Attacker logged in from external IP
     5. Attacker accessed customer database
     6. Detection triggered on impossible travel
   
   Root Cause:
     - Primary: Successful phishing attack
     - Contributing: User did not report phishing
     - Contributing: No conditional access for external IPs
   
   Why-Why Analysis:
     Q: Why did breach occur?
     A: Attacker had valid credentials
     
     Q: Why did attacker have credentials?
     A: User entered credentials on phishing site
     
     Q: Why did user fall for phishing?
     A: Email was convincing, user rushed
     
     Q: Why wasn't phishing blocked?
     A: Email passed spam filters
     
     Q: Why wasn't unauthorized access blocked?
     A: Credentials were valid, no geo-restrictions

7. Lessons Learned:
   
   What Went Well:
     ✓ Detection within 7 minutes (target: 15 minutes)
     ✓ Response team mobilized quickly
     ✓ Containment prevented data exfiltration
     ✓ Communication clear and timely
     ✓ Recovery completed ahead of schedule
   
   What Could Be Improved:
     ⚠ User didn't report phishing email
     ⚠ Conditional access not restrictive enough
     ⚠ Phishing training effectiveness
     ⚠ Customer notification took too long
   
   Action Items:
     1. Implement geo-based conditional access [P1, Security, 1 week]
     2. Deploy additional phishing protection [P1, Security, 2 weeks]
     3. Mandatory phishing training for all users [P2, HR, 1 month]
     4. Review and update incident communication templates [P2, Comms, 2 weeks]
     5. Add detection for database access anomalies [P1, Security, 1 week]

8. Metrics:
   - MTTD (Mean Time To Detect): 7 minutes ✓
   - MTTR (Mean Time To Respond): 7 minutes ✓
   - MTTC (Mean Time To Contain): 3.5 hours ✓
   - MTTRE (Mean Time To Eradicate): 8 hours ✓
   - Total Duration: 11.6 hours
   - Downtime: 4 hours (degraded service)

9. Regulatory Notifications:
   - GDPR: Not required (no data breach, access only)
   - Customers: Notified within 24 hours
   - Board: Briefed in next meeting
   - Cyber Insurance: Notified (precautionary)

10. Appendices:
    - A: Detailed timeline
    - B: Evidence collected
    - C: IoC list
    - D: Communication sent
    - E: Scripts and queries used
```

### Lessons Learned Meeting

```yaml
Lessons Learned Process:

Timing:
  - Schedule within 5 business days of incident closure
  - Duration: 2 hours
  - Location: Conference room or video call

Attendees:
  Required:
    - Incident Commander
    - All IR team members
    - Affected system owners
    - CISO
  
  Optional:
    - Executive sponsor
    - External auditors (if applicable)
    - Legal counsel (if applicable)

Agenda:

1. Incident Overview (15 min):
   - IC presents incident summary
   - Timeline review
   - Impact assessment

2. What Went Well (20 min):
   - Effective detections
   - Good response actions
   - Strong team coordination
   - Successes to replicate

3. What Could Be Improved (30 min):
   - Gaps identified
   - Delayed responses
   - Communication issues
   - Process breakdowns
   - Tool limitations

4. Root Cause Deep Dive (20 min):
   - Technical root cause
   - Process root cause
   - People root cause
   - Avoid blame, focus on systems

5. Action Items (25 min):
   - Specific, measurable improvements
   - Assign owners
   - Set deadlines
   - Prioritize (P0/P1/P2/P3)
   - Resource requirements

6. Wrap-up (10 min):
   - Summarize key takeaways
   - Next steps
   - Thank the team

Ground Rules:
  - Blameless post-mortem
  - Focus on systems, not individuals
  - Assume good intentions
  - Speak freely and honestly
  - What's said here stays here (unless actionable)

Documentation:
  - Meeting notes
  - Action item tracker
  - Update incident report
  - Share with leadership
  - Archive for future reference
```

### Continuous Improvement

```yaml
Improvement Process:

Action Item Tracking:

Format:
| ID | Action | Owner | Priority | Due Date | Status |
|----|--------|-------|----------|----------|--------|
| AI-001 | Implement geo-based conditional access | Security | P1 | 2024-12-28 | In Progress |
| AI-002 | Deploy phishing protection | Security | P1 | 2025-01-04 | Not Started |
| AI-003 | Mandatory phishing training | HR | P2 | 2025-01-21 | Not Started |

Status Updates:
  - Weekly review in security team meeting
  - Monthly report to CISO
  - Quarterly report to board

Metrics to Track:

Effectiveness Metrics:
  - MTTD (Mean Time To Detect)
  - MTTR (Mean Time To Respond)
  - MTTC (Mean Time To Contain)
  - MTTRE (Mean Time To Eradicate)
  - Incident recurrence rate
  - False positive rate

Efficiency Metrics:
  - Number of incidents per month
  - Incidents by severity
  - Incidents by category
  - Response team utilization
  - Tool effectiveness

Trend Analysis:
  - Month-over-month comparison
  - Year-over-year comparison
  - Seasonal patterns
  - Attack vector trends
  - Control effectiveness trends

Plan Updates:

Triggers for Plan Review:
  - After every P0/P1 incident
  - Quarterly scheduled review
  - Major tool/process changes
  - Regulatory changes
  - Organization changes

Review Process:
  1. Identify gaps from recent incidents
  2. Review industry best practices
  3. Assess regulatory requirements
  4. Update procedures
  5. Update playbooks
  6. Update contact lists
  7. Test changes in tabletop
  8. Obtain approvals
  9. Communicate updates
  10. Train team on changes
```

-----

## 📞 Communication Protocols

### Internal Communication

```yaml
Communication Matrix:

Incident Severity → Notification Timeline → Audience

P0 (Critical):
  Immediate (< 15 min):
    - IC
    - Security team
    - Platform engineering
    - CISO
  
  Within 30 min:
    - CEO
    - Affected business unit leaders
    - Communications team
  
  Within 1 hour:
    - All employees (if widespread impact)
    - Board (if significant)

P1 (High):
  Within 30 min:
    - IC
    - Security team
    - CISO
  
  Within 4 hours:
    - CEO (if customer impact)
    - Affected teams
  
  Within 24 hours:
    - Broader notification if needed

P2 (Medium):
  Within 4 hours:
    - Security team
    - IC
  
  Within business day:
    - CISO
    - Affected teams

P3 (Low):
  Within business day:
    - Security team logs
  
  Weekly summary:
    - CISO
    - Security metrics report

Communication Channels:

Emergency (P0):
  - Phone calls (don't rely on email/Slack)
  - Emergency hotline: +XX-XXX-XXX-XXXX
  - Backup: Secondary phone numbers
  - War room: Teams/Zoom bridge

Standard (P1/P2):
  - Slack: #security-incidents
  - Email: security-incidents@crusoe-island.com
  - Incident management system
  - Status page (internal)

Regular Updates:
  - Every 4 hours during active incident (P0/P1)
  - Daily updates during recovery
  - Final notification on closure
```

### External Communication

```yaml
Customer Notification:

Decision Criteria:
  Notify if ANY of these are true:
    - Customer data accessed or exfiltrated
    - Service unavailability > 1 hour
    - Security controls compromised
    - Potential customer impact
    - Regulatory requirement (GDPR 72h)

Approval Required:
  - IC approval
  - Legal review
  - CISO approval
  - CEO approval (if significant)

Notification Timeline:
  Data Breach: Within 72 hours (GDPR requirement)
  Service Impact: As soon as assessed
  Resolution: Within 24 hours of restoration

Template:
```markdown
Subject: Security Notice - [Brief Description]

Dear Valued Customer,

We are writing to inform you of a security incident that may have 
affected your account.

WHAT HAPPENED:
On [date], we detected [brief description]. We immediately initiated
our incident response procedures to contain and resolve the issue.

WHAT INFORMATION WAS INVOLVED:
[Specific data types that were potentially accessed/affected]

WHAT WE ARE DOING:
- [Action 1]
- [Action 2]
- [Action 3]

WHAT YOU SHOULD DO:
- [Recommendation 1]
- [Recommendation 2]

We take the security of your information very seriously and sincerely
apologize for any concern this may cause.

For questions, please contact: security@crusoe-island.com

Sincerely,
[Name], CISO
Crusoe Island
```

Regulatory Notification:

GDPR Data Breach (72 hours):

Report to: Supervisory Authority (DPA)

Required Information:
- Nature of the breach
- Categories and approximate number of data subjects
- Categories and approximate number of records
- Name and contact details of DPO
- Likely consequences
- Measures taken or proposed

Template:

```markdown
GDPR Data Breach Notification

To: [Data Protection Authority]
From: [Company Name], [DPO Contact]
Date: [Notification Date]

1. Nature of Personal Data Breach:
   [Description]

2. Categories of Data Subjects:
   - Customers: ~500
   - Employees: 0
   - Other: 0

3. Approximate Number of Records:
   - Personal records: ~500
   - Sensitive data: 0

4. Contact Point:
   Name: [DPO Name]
   Email: privacy@crusoe-island.com
   Phone: +XX-XXX-XXX-XXXX

5. Likely Consequences:
   [Assessment of potential impact]

6. Measures Taken:
   - [Action 1]
   - [Action 2]
   - [Action 3]
```

Media Relations:

If Media Inquiries:

- All media inquiries to communications team
- No employee comments to media
- Prepared statement only
- CEO or designated spokesperson

Statement Template:

```markdown
[Company Name] Statement on Security Incident

On [date], we detected suspicious activity on our systems. We
immediately initiated our incident response procedures and engaged
external security experts.

Our investigation is ongoing. We have found no evidence of [specific
claims if applicable]. We have implemented additional security
measures and continue to monitor our systems.

The security and privacy of our customers' information is our top
priority. We will provide updates as more information becomes
available.

For more information: [URL]
Contact: press@crusoe-island.com
```

```
### Status Page Updates

```yaml
Status Page Communication:

Platform: status.crusoe-island.com

Status Levels:
  - Operational (Green)
  - Degraded Performance (Yellow)
  - Partial Outage (Orange)
  - Major Outage (Red)
  - Under Maintenance (Blue)

Update Frequency:
  - Initial: As soon as impact confirmed
  - During incident: Every 30-60 minutes
  - Resolution: Immediate
  - Post-incident: Final summary

Example Updates:

Initial Notification:
```markdown
[2024-12-21 10:30 UTC] Investigating - We are investigating reports
of authentication issues. Some users may be unable to log in. We are
actively investigating and will provide updates as soon as we have
more information.

Status: Investigating
Affected: Authentication Service
Impact: Some users may be unable to log in
```

Progress Update:

```markdown
[2024-12-21 11:00 UTC] Identified - We have identified the issue
affecting authentication. Our team is working on a fix. We expect
to have services restored within 2 hours.

Status: Identified
Affected: Authentication Service
Impact: Login functionality degraded
ETA: 13:00 UTC
```

Resolution:

```markdown
[2024-12-21 12:45 UTC] Resolved - The authentication issue has been
resolved. All systems are operational. We will continue to monitor
closely.

Status: Resolved
Affected: Authentication Service
Impact: None - Service restored
Resolution Time: 2 hours 15 minutes
```

Post-Mortem (optional, if appropriate):

```markdown
[2024-12-22 09:00 UTC] Post-Incident Summary

Incident: Authentication Service Disruption
Date: December 21, 2024
Duration: 2 hours 15 minutes
Root Cause: [Brief, non-technical explanation]
Resolution: [What we did]
Prevention: [What we're doing to prevent recurrence]

We apologize for the disruption and appreciate your patience.
```

```
---

## 📚 Incident Response Playbooks

### Playbook: Ransomware Attack

```yaml
PLAYBOOK: Ransomware Attack
Severity: P0 (Critical)
Owner: Security Operations

DETECTION INDICATORS:
  - Files being encrypted (.encrypted, .locked extensions)
  - Ransom note files (README.txt, DECRYPT_INSTRUCTIONS.html)
  - Abnormal CPU usage
  - Mass file modifications
  - Known ransomware signatures
  - Suspicious scheduled tasks
  - Unusual network traffic (C2 communication)

IMMEDIATE ACTIONS (0-30 minutes):

1. ISOLATE AFFECTED SYSTEMS:
   ```bash
   # Immediately disconnect from network
   # Do NOT shut down (may trigger further encryption)
   
   # For Azure VM - change NSG to deny all
   az network nsg rule create \
     --resource-group rg-idp-prod \
     --nsg-name nsg-infected-vm \
     --name deny-all-emergency \
     --priority 100 \
     --access Deny \
     --protocol '*' \
     --source-address-prefixes '*' \
     --destination-address-prefixes '*'
   
   # For Kubernetes pod
   kubectl apply -f - <<EOF
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: isolate-infected-pod
     namespace: production
   spec:
     podSelector:
       matchLabels:
         app: infected-app
     policyTypes:
     - Ingress
     - Egress
   EOF
```

1. PREVENT SPREAD:
   
   ```bash
   # Disable any automation that might propagate
   # Kubernetes: Scale deployment to 0
   kubectl scale deployment infected-app --replicas=0
   
   # Disable any backup jobs (to prevent encrypting backups)
   az backup protection disable \
     --resource-group rg-backup \
     --vault-name rsv-idp-prod \
     --container-name <container> \
     --item-name <item> \
     --delete-backup-data false
   ```
1. SNAPSHOT EVERYTHING:
   
   ```bash
   # Snapshot ALL disks before any changes
   for disk in $(az disk list -g rg-idp-prod --query "[].id" -o tsv); do
     az snapshot create \
       --resource-group rg-forensics \
       --name snapshot-$(basename $disk)-$(date +%Y%m%d-%H%M%S) \
       --source $disk
   done
   ```
1. NOTIFY:
- IC (immediate)
- CISO (immediate)
- CEO (within 15 min)
- Cyber insurance (immediate)
- Law enforcement (if required)

CONTAINMENT (30-240 minutes):

1. IDENTIFY PATIENT ZERO:
- Review security logs
- Check email logs (phishing?)
- Review VPN logs
- Identify initial infection vector
1. HUNT FOR LATERAL MOVEMENT:
   
   ```kusto
   // Azure Sentinel query
   SecurityEvent
   | where TimeGenerated > ago(24h)
   | where EventID == 4624  // Successful logon
   | where Computer in ("known_infected_systems")
   | summarize Systems=dcount(Computer), Accounts=dcount(Account) by Account
   | where Systems > 1  // Account used on multiple systems
   ```
1. ISOLATE ALL INFECTED:
- Same process as step 1
- May require taking systems offline
- Consider shutting down entire network segments
1. COLLECT EVIDENCE:
- Ransom note
- File samples
- Network traffic captures
- Memory dumps
- Disk images

ERADICATION (4-24 hours):

1. DO NOT PAY RANSOM (company policy):
- Paying doesn’t guarantee decryption
- Funds criminal operations
- May make you a target for future attacks
1. IDENTIFY RANSOMWARE VARIANT:
- Upload ransom note to ID Ransomware
- Check security vendor databases
- Determine if decryption available
1. WIPE AND REBUILD:
   
   ```bash
   # Do NOT attempt to clean
   # Rebuild from known-good images
   
   # Delete all infected VMs
   az vm delete --ids $(az vm list -g rg-idp-prod --query "[].id" -o tsv) --yes
   
   # Redeploy from IaC
   cd terraform/environments/prod
   terraform apply
   ```
1. RESTORE FROM BACKUP:
   
   ```bash
   # Restore from backup BEFORE infection
   # Verify backups are clean first
   
   az backup restore restore-azurevm \
     --resource-group rg-backup \
     --vault-name rsv-idp-prod \
     --container-name <container> \
     --item-name <item> \
     --recovery-point-id <clean-recovery-point>
   ```

RECOVERY (24-72 hours):

1. VERIFY CLEAN STATE:
- Full antivirus scan
- Check for persistence mechanisms
- Verify no suspicious scheduled tasks
- Monitor for 48 hours before production
1. RESTORE DATA:
- Restore from last clean backup
- Verify data integrity
- Test critical functions
1. GRADUAL SERVICE RESTORATION:
- Start with non-production
- Limited production rollout
- Monitor closely
- Full restoration

POST-INCIDENT:

1. ROOT CAUSE ANALYSIS:
- How did they get in?
- How did they spread?
- Why weren’t we protected?
- What controls failed?
1. IMPROVEMENTS:
- Patch vulnerabilities
- Improve email filtering
- Enhance EDR
- Network segmentation
- Backup improvements
1. TRAINING:
- Phishing awareness
- Suspicious activity reporting
- Incident response practice

PREVENTION:

1. Email Security:
- Anti-phishing
- Link protection
- Attachment sandboxing
1. Endpoint Protection:
- Next-gen antivirus
- EDR (Microsoft Defender)
- Application whitelisting
1. Network Segmentation:
- Limit lateral movement
- Microsegmentation
1. Backups:
- Offline backups
- Immutable backups
- Test restoration regularly
1. Access Control:
- Least privilege
- MFA everywhere
- PAM for admin access

DECISION TREE:

```
Ransomware Detected
│
├─ Is it spreading?
│  ├─ YES → Isolate entire segment
│  └─ NO → Isolate affected system
│
├─ Are backups affected?
│  ├─ YES → Critical situation, engage external help
│  └─ NO → Proceed with isolation and recovery
│
├─ Can we restore from backup?
│  ├─ YES → Wipe and restore (preferred)
│  └─ NO → Engage decryption experts, consider options
│
└─ Is this a variant with free decryption?
   ├─ YES → Use free decryption tool
   └─ NO → Restore from backup or rebuild
```

CONTACTS:

- IC: [Phone]
- CISO: [Phone]
- Cyber Insurance: [Policy #, Phone]
- External IR Firm: [Contract #, Phone]
- FBI Cyber Division: [Local office]

```
---

**End of Part 2**

**Continue to Part 3 for:**
- Additional Playbooks (Compromised Account, Data Breach)
- Forensics and Evidence Collection
- Tools and Resources
- Training and Exercises
- Metrics and KPIs
- Legal and Regulatory Considerations

---

**Document Classification:** Internal - Confidential  
**Emergency Contact:** security-incidents@crusoe-island.com | +XX-XXX-XXX-XXXX 🚨
```
