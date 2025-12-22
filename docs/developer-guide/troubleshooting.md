# Troubleshooting Guide - Crusoe IDP

**Version:** 1.0  
**Last Updated:** December 21, 2024  
**Audience:** Developers, DevOps Engineers  
**Prerequisites:** Basic familiarity with Kubernetes and Azure

This guide helps you diagnose and resolve common issues on the Crusoe Internal Developer Platform. Use the quick index to jump to your specific problem.

-----

## 📋 Table of Contents

- [Quick Problem Index](#quick-problem-index)
- [General Debugging Approach](#general-debugging-approach)
- [Pod Issues](#pod-issues)
- [Networking Issues](#networking-issues)
- [Storage Issues](#storage-issues)
- [Authentication & Authorization](#authentication--authorization)
- [Performance Issues](#performance-issues)
- [Application Issues](#application-issues)
- [CI/CD Pipeline Issues](#cicd-pipeline-issues)
- [Azure-Specific Issues](#azure-specific-issues)
- [Debugging Tools & Techniques](#debugging-tools--techniques)
- [Emergency Procedures](#emergency-procedures)
- [Getting Help](#getting-help)

-----

## 🔍 Quick Problem Index

**Can’t find what you need? Use this index:**

```yaml
Pod Problems:
  - Pod won't start → See: ImagePullBackOff, CrashLoopBackOff
  - Pod stuck pending → See: Pending Pods
  - Pod restarting → See: Pod Restart Issues
  - Pod evicted → See: Pod Eviction
  - Pod slow to start → See: Slow Startup

Network Problems:
  - Can't access service → See: Service Connectivity
  - DNS not working → See: DNS Resolution
  - Ingress 404/503 → See: Ingress Issues
  - Connection timeout → See: Network Timeouts
  - Can't reach external API → See: Egress Issues

Storage Problems:
  - PVC stuck pending → See: Storage Provisioning
  - Out of disk space → See: Disk Space Issues
  - Can't write files → See: Permission Issues

Auth Problems:
  - Can't login to Azure → See: Azure Authentication
  - kubectl unauthorized → See: RBAC Issues
  - Can't pull images → See: Registry Authentication
  - Secret not found → See: Secret Access

Performance Problems:
  - Application slow → See: Application Performance
  - High CPU usage → See: Resource Limits
  - Out of memory → See: Memory Issues
  - Database slow → See: Database Performance

Pipeline Problems:
  - Build fails → See: Build Failures
  - Tests fail → See: Test Failures
  - Deployment fails → See: Deployment Failures
  - Security scan fails → See: Security Scan Issues
```

-----

## 🎯 General Debugging Approach

### The 5-Step Debugging Process

```yaml
Step 1: Identify the Problem (2-5 min)
  Questions:
    - What is not working?
    - What is the error message?
    - When did it start?
    - What changed recently?
  
  Actions:
    - Check kubectl get pods
    - Check application logs
    - Check recent deployments
    - Check monitoring dashboards

Step 2: Gather Information (5-10 min)
  Actions:
    - kubectl describe <resource>
    - kubectl logs <pod>
    - Check events: kubectl get events
    - Check resource usage: kubectl top
    - Review recent changes in Git
  
  Document:
    - Error messages (exact text)
    - Timestamps
    - Resource names
    - Recent changes

Step 3: Form Hypothesis (2-5 min)
  Consider:
    - Common issues (see index)
    - Recent changes
    - Similar past issues
    - Error message meaning
  
  Prioritize:
    1. Most likely causes first
    2. Quick checks before deep dives
    3. Non-destructive tests

Step 4: Test Hypothesis (5-15 min)
  Actions:
    - Apply fix
    - Verify solution
    - Check for side effects
    - Document what worked
  
  If Fixed:
    - Document root cause
    - Update runbooks
    - Share with team
  
  If Not Fixed:
    - Return to Step 3
    - Try next hypothesis
    - Escalate if stuck

Step 5: Prevent Recurrence (10-30 min)
  Actions:
    - Identify root cause
    - Implement permanent fix
    - Add monitoring/alerting
    - Update documentation
    - Share lessons learned
```

### Information Gathering Commands

```bash
# Quick health check script
cat > ~/health-check.sh << 'EOF'
#!/bin/bash
# Quick cluster health check

NAMESPACE=${1:-default}

echo "=== Cluster Info ==="
kubectl cluster-info

echo -e "\n=== Nodes ==="
kubectl get nodes
kubectl top nodes

echo -e "\n=== Pods in $NAMESPACE ==="
kubectl get pods -n $NAMESPACE
kubectl get pods -n $NAMESPACE --field-selector=status.phase!=Running

echo -e "\n=== Recent Events ==="
kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' | tail -20

echo -e "\n=== Deployments ==="
kubectl get deployments -n $NAMESPACE

echo -e "\n=== Services ==="
kubectl get svc -n $NAMESPACE

echo -e "\n=== Ingresses ==="
kubectl get ingress -n $NAMESPACE
EOF

chmod +x ~/health-check.sh
~/health-check.sh production
```

-----

## 🐛 Pod Issues

### Issue: ImagePullBackOff

**Symptom:** Pod stuck with `ImagePullBackOff` or `ErrImagePull` status.

**What it means:** Kubernetes cannot pull the container image from the registry.

**Diagnosis:**

```bash
# Check pod status
kubectl get pods

# Get detailed error
kubectl describe pod <pod-name>

# Look for lines like:
# Failed to pull image "acridpdev.azurecr.io/my-app:v1.0.0": 
# rpc error: code = Unknown desc = Error response from daemon: 
# Get https://acridpdev.azurecr.io/v2/: unauthorized: authentication required
```

**Common Causes & Solutions:**

```yaml
Cause 1: Image doesn't exist
  
  Check:
    az acr repository show-tags \
      --name acridpdev \
      --repository my-app \
      --output table
  
  Solutions:
    - Verify image name and tag
    - Check if image was pushed successfully
    - Build and push image if missing
    - Fix image name in deployment YAML

Cause 2: Authentication failure
  
  Check:
    # Test ACR access
    az acr login --name acridpdev
    docker pull acridpdev.azurecr.io/my-app:v1.0.0
  
  Solutions:
    # Verify service account has imagePullSecrets
    kubectl get sa <service-account> -o yaml
    
    # If missing, add:
    kubectl patch serviceaccount <service-account> \
      -p '{"imagePullSecrets": [{"name": "acr-secret"}]}'
    
    # Or recreate ACR secret
    kubectl create secret docker-registry acr-secret \
      --docker-server=acridpdev.azurecr.io \
      --docker-username=$ACR_USERNAME \
      --docker-password=$ACR_PASSWORD \
      --docker-email=$USER_EMAIL

Cause 3: Wrong registry URL
  
  Check:
    kubectl get deployment <name> -o yaml | grep image:
  
  Solutions:
    - Fix registry URL (should be: acridpdev.azurecr.io)
    - Update deployment with correct image

Cause 4: Network issues
  
  Check:
    # From a debug pod
    kubectl run -it --rm debug --image=busybox --restart=Never -- sh
    nslookup acridpdev.azurecr.io
    wget https://acridpdev.azurecr.io
  
  Solutions:
    - Check firewall rules
    - Verify DNS resolution
    - Check network policies

Cause 5: Rate limiting
  
  Check:
    # Look for "Too Many Requests" in events
    kubectl describe pod <pod-name>
  
  Solutions:
    - Wait a few minutes
    - Use image pull secrets to authenticate
    - Contact platform team if persistent
```

**Quick Fix:**

```bash
# 1. Verify image exists
az acr repository show-tags --name acridpdev --repository my-app

# 2. Test image pull locally
docker pull acridpdev.azurecr.io/my-app:v1.0.0

# 3. If works locally but not in cluster, check service account
kubectl get sa default -o yaml | grep imagePullSecrets

# 4. Delete pod to retry with fixed configuration
kubectl delete pod <pod-name>
```

-----

### Issue: CrashLoopBackOff

**Symptom:** Pod repeatedly crashes and restarts.

**What it means:** Container starts but then exits with an error, Kubernetes keeps restarting it.

**Diagnosis:**

```bash
# Check pod status and restart count
kubectl get pods

# View current logs
kubectl logs <pod-name>

# View previous crash logs (most important!)
kubectl logs <pod-name> --previous

# Check if multiple containers in pod
kubectl get pod <pod-name> -o jsonpath='{.spec.containers[*].name}'

# View logs from specific container
kubectl logs <pod-name> -c <container-name> --previous

# Describe pod for events
kubectl describe pod <pod-name>
```

**Common Causes & Solutions:**

```yaml
Cause 1: Application error on startup

  Symptoms:
    - Error in logs: "Cannot connect to database"
    - Error in logs: "Missing required environment variable"
    - Error in logs: "Port 8080 already in use"
  
  Check logs:
    kubectl logs <pod-name> --previous | tail -50
  
  Solutions:
    # Missing environment variable
    kubectl set env deployment/<name> DATABASE_URL=<value>
    
    # Wrong configuration
    kubectl edit configmap <config-name>
    kubectl rollout restart deployment/<name>
    
    # Dependencies not ready
    # Add initContainer to wait:
    spec:
      initContainers:
      - name: wait-for-db
        image: busybox
        command: ['sh', '-c']
        args:
        - until nc -z postgres-service 5432; do
            echo "Waiting for DB...";
            sleep 2;
          done

Cause 2: Health check failing

  Check:
    kubectl describe pod <pod-name> | grep -A 5 "Liveness\|Readiness"
  
  Symptoms:
    - Pod starts, then killed by liveness probe
    - Events: "Liveness probe failed"
  
  Solutions:
    # Increase initialDelaySeconds
    kubectl patch deployment <name> -p '
      {"spec":{"template":{"spec":{"containers":[{
        "name":"app",
        "livenessProbe":{"initialDelaySeconds":60}
      }]}}}}'
    
    # Or fix health check endpoint
    # Make sure /health endpoint returns 200 OK

Cause 3: Insufficient resources

  Check:
    kubectl describe pod <pod-name> | grep -A 5 "Limits\|Requests"
    kubectl top pod <pod-name>
  
  Symptoms:
    - OOMKilled in pod status
    - Last State: Terminated (Reason: OOMKilled)
  
  Solutions:
    # Increase memory limit
    kubectl set resources deployment <name> \
      --limits=memory=512Mi \
      --requests=memory=256Mi

Cause 4: File permissions

  Check logs:
    kubectl logs <pod-name> --previous
    # Look for: "Permission denied", "EACCES"
  
  Solutions:
    # Add initContainer to fix permissions:
    spec:
      initContainers:
      - name: fix-permissions
        image: busybox
        command: ['sh', '-c']
        args: ['chown -R 1000:1000 /data']
        volumeMounts:
        - name: data
          mountPath: /data
    
    # Or set fsGroup in securityContext:
    spec:
      securityContext:
        fsGroup: 1000
        runAsUser: 1000

Cause 5: Command or arguments incorrect

  Check:
    kubectl get pod <pod-name> -o yaml | grep -A 10 "command:\|args:"
  
  Solutions:
    # Fix command in deployment
    kubectl edit deployment <name>
    # Update command and args
    
    # Or test command manually:
    kubectl run -it --rm debug \
      --image=acridpdev.azurecr.io/my-app:v1.0.0 \
      --restart=Never \
      -- /bin/sh
    # Then run your command manually

Cause 6: Port conflict

  Check logs:
    # Look for: "EADDRINUSE", "Address already in use"
  
  Solutions:
    # Check if multiple containers using same port
    kubectl get pod <pod-name> -o yaml | grep containerPort
    
    # Change port in application or container spec
    # Make sure containerPort matches application port
```

**Interactive Debugging:**

```bash
# If pod stays up long enough, exec into it
kubectl exec -it <pod-name> -- /bin/sh

# Check environment
env

# Check file system
ls -la /
df -h

# Check processes
ps aux

# Check network
netstat -tuln

# Test application manually
curl localhost:8080/health
```

**Testing Locally:**

```bash
# Pull the same image
docker pull acridpdev.azurecr.io/my-app:v1.0.0

# Run with same environment
kubectl get deployment <name> -o yaml > /tmp/deploy.yaml
# Extract env vars from /tmp/deploy.yaml

# Run locally
docker run -it --rm \
  -e DATABASE_URL="..." \
  -e API_KEY="..." \
  -p 8080:8080 \
  acridpdev.azurecr.io/my-app:v1.0.0

# Check logs
docker logs <container-id>
```

-----

### Issue: Pending Pods

**Symptom:** Pod stuck in `Pending` state, not starting.

**What it means:** Kubernetes cannot schedule the pod onto a node.

**Diagnosis:**

```bash
# Check pod status
kubectl get pods

# Get detailed scheduling information
kubectl describe pod <pod-name>

# Look for events at bottom:
# "FailedScheduling: 0/3 nodes are available: 
#  3 Insufficient memory."

# Check node resources
kubectl describe nodes
kubectl top nodes
```

**Common Causes & Solutions:**

```yaml
Cause 1: Insufficient resources on nodes

  Events show:
    "Insufficient cpu" or "Insufficient memory"
  
  Check:
    kubectl describe nodes | grep -A 5 "Allocated resources"
    kubectl top nodes
  
  Solutions:
    # Option 1: Reduce resource requests
    kubectl set resources deployment <name> \
      --requests=cpu=100m,memory=128Mi
    
    # Option 2: Add more nodes (contact platform team)
    
    # Option 3: Delete unused pods
    kubectl delete pod <unused-pod>

Cause 2: Node selector doesn't match any nodes

  Check:
    kubectl get pod <pod-name> -o yaml | grep -A 5 nodeSelector
    kubectl get nodes --show-labels
  
  Events show:
    "0/3 nodes are available: 3 node(s) didn't match node selector"
  
  Solutions:
    # Remove or fix node selector
    kubectl patch deployment <name> -p '{"spec":{"template":{"spec":{"nodeSelector":null}}}}'

Cause 3: Taints and tolerations

  Check:
    kubectl describe nodes | grep Taints
  
  Events show:
    "0/3 nodes are available: 3 node(s) had taints that the pod didn't tolerate"
  
  Solutions:
    # Add toleration to pod
    spec:
      tolerations:
      - key: "dedicated"
        operator: "Equal"
        value: "gpu"
        effect: "NoSchedule"

Cause 4: Persistent volume not available

  Check:
    kubectl get pvc
    kubectl describe pvc <pvc-name>
  
  Events show:
    "persistentvolumeclaim not found" or "waiting for a volume to be created"
  
  Solutions:
    # See Storage Issues section

Cause 5: Pod anti-affinity rules

  Check:
    kubectl get pod <pod-name> -o yaml | grep -A 10 affinity
  
  Solutions:
    # Relax anti-affinity rules or add more nodes

Cause 6: Resource quota exceeded

  Check:
    kubectl describe resourcequota -n <namespace>
  
  Events show:
    "exceeded quota"
  
  Solutions:
    # Request quota increase
    # Or delete unused resources
    # Contact platform team
```

**Quick Fix:**

```bash
# Check why pod is pending
kubectl describe pod <pod-name> | grep -A 10 Events

# Check node capacity
kubectl describe nodes | grep -A 10 "Allocated resources"

# If insufficient resources, reduce requests
kubectl patch deployment <name> --type='json' \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/resources/requests/memory","value":"128Mi"}]'
```

-----

### Issue: Pod Restart Issues

**Symptom:** Pod shows increasing restart count.

**Diagnosis:**

```bash
# Check restart count
kubectl get pods

# NAME                     READY   STATUS    RESTARTS   AGE
# my-app-7d4b8f6c9d-abcde  1/1     Running   15         30m

# Check why it's restarting
kubectl describe pod <pod-name>

# Check logs from previous crashes
kubectl logs <pod-name> --previous
```

**Common Causes:**

```yaml
Cause 1: Liveness probe failing
  
  Check:
    kubectl describe pod <pod-name> | grep "Liveness probe failed"
  
  Solutions:
    # Increase timeout or initialDelay
    # Fix health check endpoint
    # See health check section

Cause 2: OOMKilled (out of memory)
  
  Check:
    kubectl describe pod <pod-name> | grep "OOMKilled"
  
  Solutions:
    # Increase memory limit
    kubectl set resources deployment <name> --limits=memory=512Mi

Cause 3: Application crash
  
  Check logs:
    kubectl logs <pod-name> --previous
  
  Solutions:
    # Fix application bug
    # Add error handling
    # Improve logging

Cause 4: SIGTERM not handled gracefully
  
  Symptoms:
    - Pod terminated during updates
    - Connections dropped
  
  Solutions:
    # Increase terminationGracePeriodSeconds
    spec:
      terminationGracePeriodSeconds: 60
    
    # Implement graceful shutdown in app
```

-----

### Issue: Pod Eviction

**Symptom:** Pod shows `Evicted` status.

**Diagnosis:**

```bash
# Find evicted pods
kubectl get pods | grep Evicted

# Check why
kubectl describe pod <pod-name>

# Common reasons in status.reason:
# - "Evicted" with message "The node was low on resource: memory"
# - "Evicted" with message "The node had condition: DiskPressure"
```

**Common Causes & Solutions:**

```yaml
Cause 1: Node out of memory

  Check:
    kubectl describe nodes | grep "MemoryPressure"
  
  Solutions:
    # Increase node size (contact platform team)
    # Reduce memory requests
    # Set appropriate limits
    # Fix memory leaks in application

Cause 2: Node out of disk space

  Check:
    kubectl describe nodes | grep "DiskPressure"
  
  Solutions:
    # Clean up old images
    # Increase disk size
    # Fix excessive logging
    # Implement log rotation

Cause 3: Ephemeral storage exceeded

  Check:
    kubectl describe pod <pod-name> | grep ephemeral-storage
  
  Solutions:
    # Increase ephemeral storage limit
    spec:
      containers:
      - resources:
          limits:
            ephemeral-storage: "2Gi"
    
    # Or use persistent volume
```

**Cleanup Evicted Pods:**

```bash
# Delete all evicted pods in namespace
kubectl get pods -n <namespace> | \
  grep Evicted | \
  awk '{print $1}' | \
  xargs kubectl delete pod -n <namespace>
```

-----

## 🌐 Networking Issues

### Issue: Service Connectivity

**Symptom:** Cannot connect to a service from within the cluster.

**Diagnosis:**

```bash
# Check if service exists
kubectl get svc <service-name>

# Check service endpoints
kubectl get endpoints <service-name>

# No endpoints = no pods matching selector

# Check service details
kubectl describe svc <service-name>

# Test from debug pod
kubectl run -it --rm debug --image=busybox --restart=Never -- sh
wget -O- http://<service-name>.<namespace>.svc.cluster.local
```

**Common Causes & Solutions:**

```yaml
Cause 1: No endpoints (selector mismatch)

  Check:
    kubectl get endpoints <service-name>
    # If ENDPOINTS column is empty
  
  Compare:
    # Service selector
    kubectl get svc <service-name> -o yaml | grep selector: -A 3
    
    # Pod labels
    kubectl get pods --show-labels
  
  Solutions:
    # Fix service selector
    kubectl edit svc <service-name>
    
    # Or fix pod labels
    kubectl label pod <pod-name> app=my-app

Cause 2: Pods not ready

  Check:
    kubectl get pods -l app=<app-name>
    # Look at READY column
  
  Solutions:
    # Fix readiness probe
    # Ensure app starts correctly
    # Check logs: kubectl logs <pod-name>

Cause 3: Wrong port

  Check:
    # Service targetPort
    kubectl get svc <service-name> -o yaml | grep targetPort
    
    # Container port
    kubectl get pod <pod-name> -o yaml | grep containerPort
  
  Solutions:
    # Fix service targetPort to match container port
    kubectl edit svc <service-name>

Cause 4: Network policies blocking traffic

  Check:
    kubectl get networkpolicies -n <namespace>
    kubectl describe networkpolicy <policy-name>
  
  Solutions:
    # Add policy to allow traffic
    # Or temporarily delete policy to test:
    kubectl delete networkpolicy <policy-name>
    # (Recreate after testing)

Cause 5: Service type issues

  Check:
    kubectl get svc <service-name> -o yaml | grep "type:"
  
  Solutions:
    # ClusterIP: Only accessible within cluster
    # NodePort: Accessible on node IP:NodePort
    # LoadBalancer: External load balancer
    
    # Change service type if needed
    kubectl patch svc <service-name> -p '{"spec":{"type":"LoadBalancer"}}'
```

**Debugging Steps:**

```bash
# Step 1: Verify service exists
kubectl get svc <service-name>

# Step 2: Check endpoints
kubectl get endpoints <service-name>

# Step 3: Test DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- sh
nslookup <service-name>
nslookup <service-name>.<namespace>.svc.cluster.local

# Step 4: Test connectivity
wget -O- http://<service-name>:80
# Or telnet <service-name> 80

# Step 5: Test pod directly (bypass service)
POD_IP=$(kubectl get pod <pod-name> -o jsonpath='{.status.podIP}')
wget -O- http://$POD_IP:8080

# Step 6: Check from another pod in same namespace
kubectl exec -it <another-pod> -- curl http://<service-name>
```

-----

### Issue: DNS Resolution

**Symptom:** Cannot resolve service names.

**Diagnosis:**

```bash
# Test DNS from a pod
kubectl run -it --rm debug --image=busybox --restart=Never -- sh
nslookup kubernetes.default
nslookup my-service.production.svc.cluster.local

# Check CoreDNS pods
kubectl get pods -n kube-system -l k8s-app=kube-dns

# Check CoreDNS logs
kubectl logs -n kube-system -l k8s-app=kube-dns
```

**Common Causes & Solutions:**

```yaml
Cause 1: CoreDNS pods not running

  Check:
    kubectl get pods -n kube-system -l k8s-app=kube-dns
  
  Solutions:
    # Restart CoreDNS
    kubectl rollout restart deployment/coredns -n kube-system

Cause 2: Wrong DNS configuration in pod

  Check:
    kubectl exec <pod-name> -- cat /etc/resolv.conf
    # Should show:
    # nameserver 10.0.0.10
    # search <namespace>.svc.cluster.local svc.cluster.local cluster.local
  
  Solutions:
    # Usually managed by Kubernetes
    # If wrong, recreate pod

Cause 3: Network policies blocking DNS

  Check:
    kubectl get networkpolicies
  
  Solutions:
    # Ensure DNS (port 53) is allowed
    # Add policy:
    spec:
      egress:
      - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
        ports:
        - protocol: UDP
          port: 53

Cause 4: Service name incorrect

  Solutions:
    # Full FQDN format:
    # <service>.<namespace>.svc.cluster.local
    
    # Within same namespace:
    # <service>
    
    # Different namespace:
    # <service>.<namespace>
```

-----

### Issue: Ingress Issues

**Symptom:** External URL returns 404, 503, or connection refused.

**Diagnosis:**

```bash
# Check ingress exists
kubectl get ingress

# Check ingress details
kubectl describe ingress <ingress-name>

# Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx

# Check backend service
kubectl get svc <backend-service>

# Test service directly (bypass ingress)
kubectl port-forward svc/<service-name> 8080:80
curl http://localhost:8080
```

**Common Causes & Solutions:**

```yaml
Cause 1: Backend service doesn't exist or wrong name

  Check:
    kubectl describe ingress <ingress-name>
    # Look at Backend field
    
    kubectl get svc <backend-service>
  
  Solutions:
    # Fix ingress backend service name
    kubectl edit ingress <ingress-name>

Cause 2: Service has no endpoints

  Check:
    kubectl get endpoints <service-name>
  
  Solutions:
    # Fix pod selector in service
    # Ensure pods are running and ready

Cause 3: Path not matching

  Check:
    kubectl get ingress <ingress-name> -o yaml | grep path:
  
  Common mistakes:
    # path: /api → Only matches /api exactly
    # Should be: /api/ or use pathType: Prefix
  
  Solutions:
    # Use pathType: Prefix for prefix matching
    # Use pathType: Exact for exact matching
    spec:
      rules:
      - http:
          paths:
          - path: /api
            pathType: Prefix  # Matches /api, /api/, /api/users, etc.

Cause 4: Ingress class not set

  Check:
    kubectl get ingress <ingress-name> -o yaml | grep ingressClassName
  
  Solutions:
    # Set ingress class
    kubectl patch ingress <ingress-name> -p \
      '{"spec":{"ingressClassName":"nginx"}}'

Cause 5: TLS/SSL certificate issues

  Check:
    kubectl describe ingress <ingress-name> | grep -A 5 TLS
    kubectl get secret <tls-secret-name>
  
  Solutions:
    # Verify certificate exists
    # Check certificate is valid
    # Ensure secret in same namespace as ingress

Cause 6: DNS not pointing to ingress

  Check:
    nslookup my-app.crusoe-island.com
    # Should point to ingress IP
  
  Solutions:
    # Update DNS records
    # Wait for DNS propagation (up to 48h)

Cause 7: Ingress controller not running

  Check:
    kubectl get pods -n ingress-nginx
  
  Solutions:
    # Contact platform team
```

**Testing Ingress:**

```bash
# Get ingress address
INGRESS_IP=$(kubectl get ingress <ingress-name> \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# Test with curl (bypass DNS)
curl -H "Host: my-app.crusoe-island.com" http://$INGRESS_IP

# Test HTTPS
curl -k -H "Host: my-app.crusoe-island.com" https://$INGRESS_IP

# Check TLS certificate
openssl s_client -connect $INGRESS_IP:443 \
  -servername my-app.crusoe-island.com
```

-----

### Issue: Network Timeouts

**Symptom:** Connections to services time out.

**Diagnosis:**

```bash
# Test connectivity with timeout
kubectl run -it --rm debug --image=busybox --restart=Never -- sh
wget --timeout=5 -O- http://<service-name>

# Check if port is open
telnet <service-name> 80

# Check network policies
kubectl get networkpolicies -n <namespace>

# Check firewall rules (Azure NSG)
az network nsg rule list \
  --resource-group rg-idp-prod \
  --nsg-name nsg-aks-subnet \
  --output table
```

**Common Causes & Solutions:**

```yaml
Cause 1: Service not listening

  Check:
    kubectl exec <pod-name> -- netstat -tuln
  
  Solutions:
    # Verify application is listening on correct port
    # Check application configuration

Cause 2: Network policy blocking

  Check:
    kubectl describe networkpolicy <policy-name>
  
  Solutions:
    # Add allow rule for source
    # Or temporarily delete policy to test

Cause 3: Firewall/NSG blocking

  Check:
    az network nsg rule list --nsg-name <nsg-name>
  
  Solutions:
    # Contact platform team to update NSG rules

Cause 4: Health checks taking too long

  Check:
    kubectl describe pod <pod-name> | grep -A 10 "Liveness\|Readiness"
  
  Solutions:
    # Increase timeout
    livenessProbe:
      timeoutSeconds: 10  # Increase from 1
      periodSeconds: 30   # Increase check interval

Cause 5: External service unreachable

  Check:
    kubectl exec <pod-name> -- curl -v https://api.external.com
  
  Solutions:
    # Check egress rules
    # Verify external service is up
    # Check Azure Firewall rules
```

-----

### Issue: Egress Issues (Can’t Reach External Services)

**Symptom:** Pod cannot connect to external services/APIs.

**Diagnosis:**

```bash
# Test from pod
kubectl exec <pod-name> -- curl -v https://api.external.com

# Check Azure Firewall rules
az network firewall network-rule list \
  --resource-group rg-network \
  --firewall-name fw-idp-prod \
  --collection-name egress-rules

# Check if DNS resolution works
kubectl exec <pod-name> -- nslookup api.external.com

# Check network policies
kubectl get networkpolicies
```

**Common Causes & Solutions:**

```yaml
Cause 1: Azure Firewall blocking

  Check:
    # Firewall logs in Azure Portal
    # Or contact platform team
  
  Solutions:
    # Request firewall rule:
    # Slack: #platform-support
    # Provide: destination URL, port, justification

Cause 2: DNS resolution failing

  Check:
    kubectl exec <pod-name> -- nslookup api.external.com
  
  Solutions:
    # Check if DNS server is reachable
    # May need to configure external DNS

Cause 3: Network policy blocking egress

  Check:
    kubectl describe networkpolicy <policy-name>
  
  Solutions:
    # Add egress rule:
    spec:
      egress:
      - to:
        - ipBlock:
            cidr: 0.0.0.0/0  # Allow all egress (not recommended for prod)

Cause 4: Proxy configuration needed

  Solutions:
    # Set HTTP_PROXY environment variables
    env:
    - name: HTTP_PROXY
      value: "http://proxy.example.com:8080"
    - name: HTTPS_PROXY
      value: "http://proxy.example.com:8080"
    - name: NO_PROXY
      value: ".svc.cluster.local,.cluster.local"
```

-----

## 💾 Storage Issues

### Issue: PVC Stuck Pending

**Symptom:** PersistentVolumeClaim stuck in `Pending` state.

**Diagnosis:**

```bash
# Check PVC status
kubectl get pvc

# Get details
kubectl describe pvc <pvc-name>

# Check events
kubectl get events --sort-by='.lastTimestamp' | grep <pvc-name>

# Check storage class
kubectl get storageclass
kubectl describe storageclass <storage-class-name>
```

**Common Causes & Solutions:**

```yaml
Cause 1: Storage class doesn't exist

  Check:
    kubectl get pvc <pvc-name> -o yaml | grep storageClassName
    kubectl get storageclass <storage-class-name>
  
  Solutions:
    # Use existing storage class
    kubectl patch pvc <pvc-name> -p \
      '{"spec":{"storageClassName":"managed-premium"}}'
    
    # Available storage classes:
    # - managed-premium: Premium SSD
    # - managed: Standard HDD
    # - azurefile: Azure Files

Cause 2: No available persistent volumes

  Check:
    kubectl get pv
  
  Solutions:
    # Dynamic provisioning should create PV automatically
    # If not, check storage class provisioner
    # Contact platform team

Cause 3: Volume provisioning failed

  Check events:
    kubectl describe pvc <pvc-name>
  
  Error examples:
    # "InvalidParameter: The value for parameter zones is invalid"
    # "QuotaExceeded: Disk quota exceeded"
  
  Solutions:
    # Check Azure quota
    az vm list-usage --location westeurope -o table
    
    # Request quota increase if needed

Cause 4: Access mode incompatible

  Check:
    kubectl get pvc <pvc-name> -o yaml | grep accessModes
  
  Solutions:
    # Azure Disk only supports ReadWriteOnce
    # For ReadWriteMany, use Azure Files
    
    # Change to Azure Files:
    spec:
      storageClassName: azurefile
      accessModes:
      - ReadWriteMany

Cause 5: Size too small

  Check:
    kubectl get pvc <pvc-name> -o yaml | grep "storage:"
  
  Solutions:
    # Azure managed disks minimum: 1Gi
    # Increase size if needed
```

-----

### Issue: Disk Space Issues

**Symptom:** Pod logs show “No space left on device”.

**Diagnosis:**

```bash
# Check disk usage in pod
kubectl exec <pod-name> -- df -h

# Check pod's ephemeral storage usage
kubectl describe pod <pod-name> | grep ephemeral-storage

# Check node disk usage
kubectl describe node <node-name> | grep -A 5 "Allocated resources"
```

**Solutions:**

```yaml
Solution 1: Increase ephemeral storage limit

  spec:
    containers:
    - name: app
      resources:
        limits:
          ephemeral-storage: "2Gi"
        requests:
          ephemeral-storage: "1Gi"

Solution 2: Use persistent volume

  # Instead of writing to container filesystem
  # Use PVC for persistent data
  spec:
    volumes:
    - name: data
      persistentVolumeClaim:
        claimName: my-app-data
    containers:
    - name: app
      volumeMounts:
      - name: data
        mountPath: /data

Solution 3: Implement log rotation

  # Configure application log rotation
  # Or use sidecar for log shipping

Solution 4: Clean up old files

  # Add cleanup job
  spec:
    containers:
    - name: cleanup
      image: busybox
      command: ["/bin/sh", "-c"]
      args:
      - |
        while true; do
          find /tmp -type f -mtime +7 -delete
          sleep 3600
        done
```

-----

### Issue: Permission Issues with Volumes

**Symptom:** Cannot write to mounted volume, permission denied errors.

**Diagnosis:**

```bash
# Check volume mount permissions
kubectl exec <pod-name> -- ls -la /mounted/path

# Check pod security context
kubectl get pod <pod-name> -o yaml | grep -A 10 securityContext

# Check volume details
kubectl describe pvc <pvc-name>
```

**Solutions:**

```yaml
Solution 1: Set fsGroup

  spec:
    securityContext:
      fsGroup: 1000  # Group ID that owns volume
      runAsUser: 1000
      runAsGroup: 1000

Solution 2: Use initContainer to fix permissions

  spec:
    initContainers:
    - name: fix-permissions
      image: busybox
      command: ["sh", "-c"]
      args:
      - |
        chown -R 1000:1000 /data
        chmod -R 755 /data
      volumeMounts:
      - name: data
        mountPath: /data
      securityContext:
        runAsUser: 0  # Run as root to change ownership

Solution 3: Use subPath

  volumeMounts:
  - name: data
    mountPath: /app/logs
    subPath: logs  # Use subdirectory

Solution 4: Check Azure File mount options

  # For Azure Files, set mount options:
  spec:
    volumes:
    - name: data
      persistentVolumeClaim:
        claimName: my-app-data
      # Mount options set in StorageClass
```

-----

## 🔐 Authentication & Authorization

### Issue: Azure Authentication

**Symptom:** Cannot login to Azure CLI or authentication fails.

**Diagnosis:**

```bash
# Check current authentication
az account show

# Try to login
az login

# Check available subscriptions
az account list --output table
```

**Common Issues & Solutions:**

```yaml
Issue 1: Browser doesn't open

  Error:
    "Unable to open browser"
  
  Solutions:
    # Use device code flow
    az login --use-device-code
    
    # Or use service principal
    az login --service-principal \
      --username $CLIENT_ID \
      --password $CLIENT_SECRET \
      --tenant $TENANT_ID

Issue 2: MFA required

  Solutions:
    # Complete MFA in browser
    # Use authenticator app
    # Contact IT if MFA not set up

Issue 3: Wrong subscription

  Check:
    az account list --output table
  
  Solutions:
    # Set correct subscription
    az account set --subscription "IDP-Production"

Issue 4: Token expired

  Error:
    "The access token has expired"
  
  Solutions:
    # Re-login
    az login
    
    # Get new AKS credentials
    az aks get-credentials \
      --resource-group rg-idp-prod \
      --name aks-idp-prod \
      --overwrite-existing

Issue 5: Wrong tenant

  Solutions:
    # Specify tenant
    az login --tenant <tenant-id>
    
    # List available tenants
    az account tenant list
```

-----

### Issue: Kubernetes RBAC Issues

**Symptom:** `kubectl` commands return “Forbidden” or “Unauthorized”.

**Diagnosis:**

```bash
# Check current user
kubectl auth whoami

# Check if you can perform action
kubectl auth can-i create deployments
kubectl auth can-i create deployments --namespace=production

# List permissions
kubectl auth can-i --list

# Check role bindings
kubectl get rolebindings -n <namespace>
kubectl get clusterrolebindings
```

**Common Issues & Solutions:**

```yaml
Issue 1: No access to namespace

  Error:
    "Error from server (Forbidden): pods is forbidden: 
     User cannot list resource"
  
  Check:
    kubectl auth can-i list pods -n <namespace>
  
  Solutions:
    # Request access via Slack: #platform-support
    # Provide: namespace, required permissions, justification

Issue 2: Service account lacks permissions

  Check:
    kubectl get sa <service-account> -n <namespace>
    kubectl get rolebinding -n <namespace>
  
  Solutions:
    # Create role binding
    kubectl create rolebinding <name> \
      --clusterrole=edit \
      --serviceaccount=<namespace>:<service-account> \
      -n <namespace>

Issue 3: Wrong context/cluster

  Check:
    kubectl config current-context
    kubectl config get-contexts
  
  Solutions:
    # Switch context
    kubectl config use-context aks-idp-prod
    
    # Or get fresh credentials
    az aks get-credentials \
      --resource-group rg-idp-prod \
      --name aks-idp-prod \
      --overwrite-existing

Issue 4: Token expired

  Solutions:
    # Refresh Azure login
    az login
    
    # Get new credentials
    az aks get-credentials --resource-group <rg> --name <cluster>

Issue 5: Wrong kubeconfig

  Check:
    echo $KUBECONFIG
    ls -la ~/.kube/config
  
  Solutions:
    # Use default kubeconfig
    unset KUBECONFIG
    
    # Or set to correct file
    export KUBECONFIG=~/.kube/config
```

**Testing Permissions:**

```bash
# Check specific permissions
kubectl auth can-i create pods
kubectl auth can-i delete deployments --namespace=production
kubectl auth can-i get secrets --namespace=production

# List all permissions
kubectl auth can-i --list --namespace=production

# Check permissions for service account
kubectl auth can-i list pods \
  --as=system:serviceaccount:production:my-app
```

-----

### Issue: Container Registry Authentication

**Symptom:** Cannot pull images from ACR.

**Diagnosis:**

```bash
# Test ACR access
az acr login --name acridpdev

# Try to pull image manually
docker pull acridpdev.azurecr.io/my-app:v1.0.0

# Check service account has imagePullSecrets
kubectl get sa <service-account> -o yaml

# Check if secret exists
kubectl get secret acr-secret -o yaml
```

**Solutions:**

```yaml
Solution 1: Login to ACR

  # For local development
  az acr login --name acridpdev
  
  # Test
  docker pull acridpdev.azurecr.io/my-app:v1.0.0

Solution 2: Create image pull secret

  # Get ACR credentials
  ACR_USERNAME=$(az acr credential show --name acridpdev --query username -o tsv)
  ACR_PASSWORD=$(az acr credential show --name acridpdev --query "passwords[0].value" -o tsv)
  
  # Create secret
  kubectl create secret docker-registry acr-secret \
    --docker-server=acridpdev.azurecr.io \
    --docker-username=$ACR_USERNAME \
    --docker-password=$ACR_PASSWORD \
    --namespace=<namespace>

Solution 3: Attach secret to service account

  # Patch service account
  kubectl patch serviceaccount <service-account> \
    -p '{"imagePullSecrets": [{"name": "acr-secret"}]}' \
    -n <namespace>

Solution 4: Use managed identity (production)

  # Service principal with ACR pull role
  # Configured by platform team
  # Contact #platform-support if issues
```

-----

## ⚡ Performance Issues

### Issue: High CPU Usage

**Symptom:** Pod using more CPU than expected.

**Diagnosis:**

```bash
# Check current CPU usage
kubectl top pod <pod-name>

# Check CPU limits
kubectl describe pod <pod-name> | grep -A 5 "Limits\|Requests"

# Get detailed metrics
kubectl top pod <pod-name> --containers

# Check application logs for errors
kubectl logs <pod-name> | grep -i error

# Check for CPU throttling
kubectl describe pod <pod-name> | grep -i throttl
```

**Common Causes & Solutions:**

```yaml
Cause 1: Insufficient CPU requests

  Symptoms:
    - Pod slow to respond
    - CPU throttling
  
  Check:
    kubectl top pod <pod-name>
    # Usage near or exceeding limit
  
  Solutions:
    # Increase CPU limit
    kubectl set resources deployment <name> \
      --limits=cpu=1000m \
      --requests=cpu=500m

Cause 2: Inefficient code

  Solutions:
    # Profile application
    # Optimize hot code paths
    # Add caching
    # Use connection pooling

Cause 3: Too many requests

  Check:
    # Application metrics/logs
  
  Solutions:
    # Scale horizontally
    kubectl scale deployment <name> --replicas=5
    
    # Add HPA (Horizontal Pod Autoscaler)
    kubectl autoscale deployment <name> \
      --cpu-percent=70 \
      --min=3 \
      --max=10

Cause 4: Background tasks

  Check logs:
    kubectl logs <pod-name>
  
  Solutions:
    # Move to separate job/cronjob
    # Optimize scheduled tasks
    # Add rate limiting

Cause 5: Resource limits too low

  Solutions:
    # Profile actual usage over time
    # Set limits 20-30% above average
    # Use HPA for variable load
```

**Profiling CPU Usage:**

```bash
# For Node.js apps
kubectl exec <pod-name> -- node --prof index.js

# For Python apps (py-spy)
kubectl exec <pod-name> -- pip install py-spy
kubectl exec <pod-name> -- py-spy record -o profile.svg -- python app.py

# Check what processes are using CPU
kubectl exec <pod-name> -- top -b -n 1
```

-----

### Issue: Memory Issues (OOMKilled)

**Symptom:** Pod shows `OOMKilled` status or high memory usage.

**Diagnosis:**

```bash
# Check memory usage
kubectl top pod <pod-name>

# Check memory limits
kubectl describe pod <pod-name> | grep -A 5 "Limits\|Requests"

# Check if pod was OOMKilled
kubectl describe pod <pod-name> | grep -i oom

# Check events
kubectl get events --field-selector involvedObject.name=<pod-name>
```

**Common Causes & Solutions:**

```yaml
Cause 1: Memory leak

  Symptoms:
    - Memory usage steadily increases
    - Eventually OOMKilled
  
  Diagnosis:
    # Monitor over time
    kubectl top pod <pod-name> --watch
    
    # Check application metrics
  
  Solutions:
    # Fix memory leak in code
    # Implement proper cleanup
    # Add memory profiling

Cause 2: Memory limit too low

  Check:
    # Actual memory usage
    kubectl top pod <pod-name>
  
  Solutions:
    # Increase memory limit
    kubectl set resources deployment <name> \
      --limits=memory=1Gi \
      --requests=memory=512Mi

Cause 3: Large dataset in memory

  Solutions:
    # Paginate database queries
    # Stream large files
    # Use caching layer (Redis)
    # Process in batches

Cause 4: Too many connections

  Check logs:
    kubectl logs <pod-name>
  
  Solutions:
    # Implement connection pooling
    # Set max connection limits
    # Use connection timeout

Cause 5: No limits set

  Check:
    kubectl describe pod <pod-name> | grep Limits
  
  Solutions:
    # Always set limits!
    spec:
      containers:
      - resources:
          limits:
            memory: "512Mi"
          requests:
            memory: "256Mi"
```

**Memory Profiling:**

```bash
# For Node.js
kubectl exec <pod-name> -- node --inspect app.js
# Connect with Chrome DevTools

# For Python
kubectl exec <pod-name> -- pip install memory_profiler
kubectl exec <pod-name> -- python -m memory_profiler app.py

# Check memory breakdown
kubectl exec <pod-name> -- cat /proc/meminfo
kubectl exec <pod-name> -- free -h
```

-----

### Issue: Application Performance

**Symptom:** Application slow to respond, high latency.

**Diagnosis:**

```bash
# Check pod resource usage
kubectl top pod <pod-name>

# Check application logs
kubectl logs <pod-name> --tail=100

# Test response time
time kubectl exec <pod-name> -- curl http://localhost:8080/api/health

# Check for throttling
kubectl describe pod <pod-name> | grep -i throttl

# Check HPA status
kubectl get hpa
```

**Common Causes & Solutions:**

```yaml
Cause 1: Database slow queries

  Check logs:
    kubectl logs <pod-name> | grep -i "slow\|timeout\|query"
  
  Solutions:
    # Add database indexes
    # Optimize queries
    # Use query caching
    # Add connection pooling
    # Scale database (contact platform team)

Cause 2: External API slow

  Check:
    kubectl exec <pod-name> -- curl -w "@curl-format.txt" https://api.external.com
    
    # curl-format.txt:
    #   time_total: %{time_total}s
    #   time_connect: %{time_connect}s
    #   time_starttransfer: %{time_starttransfer}s
  
  Solutions:
    # Add timeout and retry logic
    # Implement circuit breaker
    # Add caching layer
    # Use async/background processing

Cause 3: Insufficient replicas

  Check:
    kubectl get deployment <name>
    kubectl top pods -l app=<name>
  
  Solutions:
    # Scale horizontally
    kubectl scale deployment <name> --replicas=5
    
    # Add HPA
    kubectl autoscale deployment <name> \
      --cpu-percent=70 \
      --min=3 \
      --max=10

Cause 4: Cold start issues

  Symptoms:
    - First request slow
    - Subsequent requests fast
  
  Solutions:
    # Keep minimum replicas warm
    # Implement readiness probe properly
    # Pre-load data/connections on startup
    # Increase minReadySeconds

Cause 5: Inefficient code

  Solutions:
    # Profile application
    # Add APM (Application Performance Monitoring)
    # Optimize hot paths
    # Add caching (Redis)
    # Use CDN for static assets
```

-----

### Issue: Database Performance

**Symptom:** Database queries slow, connections timing out.

**Diagnosis:**

```bash
# Check database pod resources
kubectl top pod -l app=postgres

# Check database logs
kubectl logs -l app=postgres --tail=100

# Test database connection from app pod
kubectl exec <app-pod> -- psql -h postgres-service -U app -c "SELECT 1"

# Check active connections
kubectl exec <db-pod> -- psql -U postgres -c \
  "SELECT count(*) FROM pg_stat_activity WHERE state = 'active'"
```

**Common Causes & Solutions:**

```yaml
Cause 1: Too many connections

  Check:
    # PostgreSQL
    kubectl exec <db-pod> -- psql -U postgres -c \
      "SELECT count(*) FROM pg_stat_activity"
    
    # Check max_connections
    kubectl exec <db-pod> -- psql -U postgres -c \
      "SHOW max_connections"
  
  Solutions:
    # Implement connection pooling in app
    # Increase max_connections (if resources allow)
    # Close idle connections
    # Use PgBouncer

Cause 2: Missing indexes

  Check slow queries:
    kubectl exec <db-pod> -- psql -U postgres -d app -c \
      "SELECT query, mean_time, calls 
       FROM pg_stat_statements 
       ORDER BY mean_time DESC 
       LIMIT 10"
  
  Solutions:
    # Add indexes on frequently queried columns
    # Analyze query execution plans
    # Use database migration to add indexes

Cause 3: Insufficient resources

  Check:
    kubectl top pod -l app=postgres
    kubectl describe pod <db-pod> | grep -A 5 Limits
  
  Solutions:
    # Increase CPU/memory limits
    # Use premium storage for better IOPS
    # Scale vertically (larger node)

Cause 4: Long-running transactions

  Check:
    kubectl exec <db-pod> -- psql -U postgres -c \
      "SELECT pid, now() - pg_stat_activity.query_start AS duration, query 
       FROM pg_stat_activity 
       WHERE state = 'active' 
       AND now() - pg_stat_activity.query_start > interval '5 minutes'"
  
  Solutions:
    # Add query timeouts
    # Optimize long queries
    # Kill long-running queries
    # Investigate and fix application logic

Cause 5: Lock contention

  Check:
    kubectl exec <db-pod> -- psql -U postgres -c \
      "SELECT * FROM pg_locks WHERE NOT granted"
  
  Solutions:
    # Optimize transaction isolation levels
    # Reduce transaction scope
    # Use row-level locking
    # Batch updates
```

-----

## 🐞 Application Issues

### Issue: Application Crashes

**Symptom:** Application exits unexpectedly.

**Diagnosis:**

```bash
# Check logs from crashed container
kubectl logs <pod-name> --previous

# Check exit code
kubectl describe pod <pod-name> | grep "Exit Code"

# Common exit codes:
# 0: Success (shouldn't restart)
# 1: Generic error
# 137: SIGKILL (OOMKilled)
# 143: SIGTERM (graceful shutdown)
# 255: Exit code out of range

# Check events
kubectl get events --field-selector involvedObject.name=<pod-name>
```

**Common Exit Codes:**

```yaml
Exit Code 0:
  Meaning: Successful exit
  Solutions:
    # Application shouldn't exit
    # Check if command is wrong
    # Should run continuously

Exit Code 1:
  Meaning: Application error
  Solutions:
    # Check logs: kubectl logs <pod> --previous
    # Fix application bug
    # Check configuration

Exit Code 137 (SIGKILL):
  Meaning: Killed by system (usually OOM)
  Solutions:
    # Increase memory limit
    # Fix memory leak
    # See Memory Issues section

Exit Code 143 (SIGTERM):
  Meaning: Terminated by system
  Solutions:
    # Implement graceful shutdown
    # Handle SIGTERM signal
    # Complete requests before exiting
    # Increase terminationGracePeriodSeconds

Exit Code 255:
  Meaning: Exit code out of range
  Solutions:
    # Usually indicates missing executable
    # Check command in deployment
    # Verify path in container
```

-----

### Issue: Application Not Starting

**Symptom:** Pod starts but application doesn’t respond.

**Diagnosis:**

```bash
# Check if process is running
kubectl exec <pod-name> -- ps aux

# Check logs
kubectl logs <pod-name>

# Check if listening on port
kubectl exec <pod-name> -- netstat -tuln

# Check health endpoint
kubectl exec <pod-name> -- curl http://localhost:8080/health
```

**Common Causes:**

```yaml
Cause 1: Wrong startup command

  Check:
    kubectl get pod <pod-name> -o yaml | grep -A 5 "command:\|args:"
  
  Solutions:
    # Fix command in deployment
    # Test command in container:
    kubectl run -it --rm debug \
      --image=<image> \
      --restart=Never \
      -- /bin/sh

Cause 2: Missing dependencies

  Check logs:
    kubectl logs <pod-name>
    # Look for: "ModuleNotFoundError", "Cannot find module"
  
  Solutions:
    # Install dependencies in Dockerfile
    # Check package.json/requirements.txt
    # Rebuild image

Cause 3: Environment variables missing

  Check:
    kubectl exec <pod-name> -- env
  
  Solutions:
    # Add required env vars to deployment
    # Check ConfigMap/Secret references

Cause 4: Port mismatch

  Check:
    # What port app listens on
    kubectl logs <pod-name> | grep -i listen
    
    # What port is exposed
    kubectl get pod <pod-name> -o yaml | grep containerPort
  
  Solutions:
    # Make sure they match
    # Update deployment or app config

Cause 5: Waiting for dependencies

  Solutions:
    # Add initContainer to wait for dependencies
    # See CrashLoopBackOff section
```

-----

## 🔧 CI/CD Pipeline Issues

### Issue: Build Failures

**Symptom:** Docker build fails in CI/CD pipeline.

**Common Causes:**

```yaml
Cause 1: Dockerfile syntax error

  Error:
    "Dockerfile parse error"
  
  Solutions:
    # Validate Dockerfile locally
    docker build -t test .
    
    # Check syntax
    # Common issues:
    # - Missing quotes
    # - Wrong instruction order
    # - Invalid escape characters

Cause 2: Build context too large

  Error:
    "failed to solve with frontend dockerfile.v0: failed to read dockerfile"
  
  Solutions:
    # Add .dockerignore
    cat > .dockerignore << EOF
    .git
    node_modules
    .env
    *.log
    .vscode
    .idea
    EOF
    
    # Check build context size
    du -sh .

Cause 3: Base image not found

  Error:
    "failed to solve with frontend dockerfile.v0: 
     failed to pull base image"
  
  Solutions:
    # Check base image name
    # Use specific version tag
    # Example: node:20-alpine not node:latest

Cause 4: COPY source doesn't exist

  Error:
    "COPY failed: file not found in build context"
  
  Solutions:
    # Check file exists in repository
    # Check COPY path is correct
    # Case sensitive!

Cause 5: Build out of memory

  Error:
    "build failed: signal: killed"
  
  Solutions:
    # Simplify build process
    # Use multi-stage builds
    # Increase CI/CD runner memory
```

-----

### Issue: Test Failures

**Symptom:** Tests fail in CI/CD but pass locally.

**Common Causes:**

```yaml
Cause 1: Environment differences

  Solutions:
    # Use same test environment
    # Pin all dependency versions
    # Use Docker for consistent environment
    
    # Run tests in container locally:
    docker build -t test-image .
    docker run --rm test-image npm test

Cause 2: Tests depend on external services

  Solutions:
    # Mock external services
    # Use test doubles/stubs
    # Set up service containers in CI
    
    # Example GitHub Actions:
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s

Cause 3: Race conditions

  Symptoms:
    - Tests pass sometimes, fail sometimes
    - "Connection refused", "Timeout"
  
  Solutions:
    # Add proper waits
    # Use test frameworks' retry logic
    # Ensure services ready before tests

Cause 4: Test data conflicts

  Solutions:
    # Clean up after tests
    # Use unique test data
    # Isolate test databases

Cause 5: Insufficient resources

  Solutions:
    # Increase timeout
    # Run fewer tests in parallel
    # Request more CI resources
```

-----

### Issue: Deployment Failures

**Symptom:** CI/CD pipeline fails during deployment step.

**Common Causes:**

```yaml
Cause 1: kubectl unauthorized

  Error:
    "Error from server (Forbidden)"
  
  Solutions:
    # Check service principal permissions
    # Verify AZURE_CREDENTIALS secret
    # Re-generate credentials if expired

Cause 2: Invalid Kubernetes YAML

  Error:
    "error validating data"
  
  Solutions:
    # Validate YAML locally
    kubectl apply --dry-run=client -f deployment.yaml
    
    # Use kubeval or kube-score
    kubeval deployment.yaml

Cause 3: Image not found

  Error:
    "Failed to pull image: not found"
  
  Solutions:
    # Verify image was pushed
    # Check image name/tag
    # Verify ACR access

Cause 4: Resource quota exceeded

  Error:
    "exceeded quota"
  
  Solutions:
    # Check quota usage
    kubectl describe resourcequota
    
    # Delete old resources
    # Request quota increase

Cause 5: Deployment timeout

  Error:
    "timed out waiting for condition"
  
  Solutions:
    # Increase timeout
    # Check why pods not starting
    # Check pod logs
```

-----

### Issue: Security Scan Failures

**Symptom:** Pipeline fails on security scans.

**Common Causes:**

```yaml
Cause 1: Secrets detected in code

  Error:
    "Potential secret detected: AWS_ACCESS_KEY"
  
  Solutions:
    # Remove secret from code
    # Use environment variables
    # Use Azure Key Vault
    # Update .secrets.baseline if false positive

Cause 2: Vulnerable dependencies

  Error:
    "Critical vulnerability found in package X"
  
  Solutions:
    # Update vulnerable package
    npm update <package>
    npm audit fix
    
    # If no fix available:
    # - Find alternative package
    # - Assess risk
    # - Document exception

Cause 3: Container vulnerabilities

  Error:
    "Critical vulnerability in base image"
  
  Solutions:
    # Update base image
    FROM node:20-alpine  # Use newer version
    
    # Use minimal images
    FROM gcr.io/distroless/nodejs20-debian11

Cause 4: SAST findings

  Error:
    "Potential SQL injection"
  
  Solutions:
    # Fix security issue
    # Use parameterized queries
    # Input validation
    # Output encoding
```

-----

## ☁️ Azure-Specific Issues

### Issue: Azure Resource Limits

**Symptom:** Cannot create resources, quota exceeded errors.

**Check Quotas:**

```bash
# VM quota
az vm list-usage --location westeurope -o table

# Network quota
az network list-usages --location westeurope -o table

# Storage quota
az storage account list -o table

# AKS quota
az aks list -o table
```

**Solutions:**

```yaml
Option 1: Request quota increase
  
  Steps:
    1. Azure Portal → Support
    2. Create support request
    3. Issue type: "Service and subscription limits (quotas)"
    4. Quota type: Select resource type
    5. Provide justification
    
    # Or via Azure CLI
    # (Requires support ticket)

Option 2: Clean up unused resources
  
  Check:
    # Find unused VMs
    az vm list --query "[?powerState!='VM running']" -o table
    
    # Find unused disks
    az disk list --query "[?managedBy==null]" -o table
    
    # Find unused IPs
    az network public-ip list \
      --query "[?ipConfiguration==null]" -o table

Option 3: Use different region
  
  # Check quota in other regions
  az vm list-usage --location northeurope -o table
```

-----

### Issue: Azure Networking

**Symptom:** Cannot reach Azure services, connection errors.

**Common Issues:**

```yaml
Issue 1: NSG blocking traffic

  Check:
    az network nsg rule list \
      --resource-group rg-network \
      --nsg-name nsg-aks-subnet \
      --output table
  
  Solutions:
    # Request NSG rule update
    # Slack: #platform-support

Issue 2: Service endpoints not configured

  Check:
    az network vnet subnet show \
      --resource-group rg-network \
      --vnet-name vnet-idp \
      --name aks-subnet \
      --query "serviceEndpoints"
  
  Solutions:
    # Enable service endpoint
    az network vnet subnet update \
      --resource-group rg-network \
      --vnet-name vnet-idp \
      --name aks-subnet \
      --service-endpoints Microsoft.Storage Microsoft.Sql

Issue 3: Private endpoint issues

  Check:
    az network private-endpoint list \
      --resource-group rg-network \
      --output table
  
  Solutions:
    # Verify private DNS zone
    # Check private endpoint connection
    # Contact platform team

Issue 4: Azure Firewall blocking

  Solutions:
    # Request firewall rule
    # Provide: destination, port, justification
    # Slack: #platform-support
```

-----

## 🛠️ Debugging Tools & Techniques

### Essential Debugging Tools

```bash
# 1. kubectl debug (Kubernetes 1.23+)
# Creates ephemeral container in running pod
kubectl debug <pod-name> -it --image=busybox

# 2. Debug pod with network tools
kubectl run -it --rm debug \
  --image=nicolaka/netshoot \
  --restart=Never \
  -- /bin/bash

# Inside debug pod:
nslookup my-service
curl http://my-service
traceroute my-service
tcpdump -i eth0

# 3. Port forwarding for local testing
kubectl port-forward pod/<pod-name> 8080:80
kubectl port-forward svc/<service-name> 8080:80

# 4. Execute commands in pod
kubectl exec <pod-name> -- ps aux
kubectl exec <pod-name> -- env
kubectl exec <pod-name> -- ls -la /app

# 5. Copy files from pod
kubectl cp <pod-name>:/path/to/file ./local-file

# 6. Interactive shell
kubectl exec -it <pod-name> -- /bin/sh

# 7. Stern for multi-pod logs
stern <app-name> --namespace=production

# 8. K9s for interactive cluster management
k9s

# 9. Telepresence for local development
telepresence connect
telepresence intercept <service-name> --port 8080

# 10. kubectx/kubens for context switching
kubectx aks-idp-prod
kubens production
```

### Logging Best Practices

```yaml
Application Logging:
  
  What to log:
    ✓ Request start/end
    ✓ Errors and exceptions
    ✓ Important state changes
    ✓ Performance metrics
    ✓ Security events
  
  What NOT to log:
    ✗ Passwords or secrets
    ✗ Personal data (GDPR)
    ✗ Full credit card numbers
    ✗ Excessive debug info in production
  
  Log format:
    # Use structured logging (JSON)
    {
      "timestamp": "2024-12-21T10:30:00Z",
      "level": "ERROR",
      "message": "Failed to connect to database",
      "error": "Connection refused",
      "host": "postgres-service",
      "port": 5432,
      "traceId": "abc-123-def"
    }

  Log levels:
    - DEBUG: Detailed info for debugging
    - INFO: General informational messages
    - WARN: Warning messages
    - ERROR: Error messages
    - FATAL: Critical errors

Kubernetes Logging:
  
  # View logs
  kubectl logs <pod-name>
  
  # Follow logs
  kubectl logs -f <pod-name>
  
  # Previous container logs
  kubectl logs <pod-name> --previous
  
  # Multiple containers
  kubectl logs <pod-name> -c <container-name>
  
  # All pods with label
  kubectl logs -l app=my-app --all-containers
  
  # With timestamps
  kubectl logs <pod-name> --timestamps
  
  # Tail last N lines
  kubectl logs <pod-name> --tail=100
  
  # Since time
  kubectl logs <pod-name> --since=1h
```

### Network Debugging

```bash
# DNS debugging
kubectl run -it --rm debug --image=busybox --restart=Never -- sh
nslookup kubernetes.default
nslookup my-service.production.svc.cluster.local

# Connectivity testing
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- bash
ping my-service
curl http://my-service
telnet my-service 80
nc -zv my-service 80

# Trace route
traceroute my-service

# Check DNS from node
kubectl run -it --rm debug --image=busybox --restart=Never -- sh
cat /etc/resolv.conf

# Network policy testing
kubectl run -it --rm test-source \
  --image=busybox \
  --labels="app=test-source" \
  --restart=Never \
  -- wget -O- http://my-service

# Packet capture
kubectl sniff <pod-name>  # Using ksniff plugin
```

### Performance Debugging

```bash
# Resource usage
kubectl top nodes
kubectl top pods
kubectl top pod <pod-name> --containers

# Detailed metrics
kubectl describe node <node-name>
kubectl describe pod <pod-name>

# Events
kubectl get events --sort-by='.lastTimestamp'
kubectl get events --field-selector type=Warning

# HPA status
kubectl get hpa
kubectl describe hpa <hpa-name>

# PDB (Pod Disruption Budget)
kubectl get pdb
kubectl describe pdb <pdb-name>
```

-----

## 🚨 Emergency Procedures

### Production Outage Response

```yaml
IMMEDIATE ACTIONS (0-5 minutes):

1. Acknowledge Alert:
   ☐ Respond in #incidents channel
   ☐ Update status page
   ☐ Start incident timeline

2. Assess Impact:
   ☐ What's affected?
   ☐ How many users?
   ☐ Data integrity OK?
   ☐ Security incident?

3. Quick Health Check:
   ```bash
   # Check pods
   kubectl get pods -n production
   
   # Check services
   kubectl get svc -n production
   
   # Check recent events
   kubectl get events --sort-by='.lastTimestamp' | tail -20
   
   # Check deployments
   kubectl get deployments -n production
```

1. Notify Stakeholders:
   ☐ #incidents channel
   ☐ On-call engineer
   ☐ Platform lead
   ☐ Customer support (if needed)

INVESTIGATION (5-15 minutes):

1. Gather Information:
   ☐ Check monitoring dashboards
   ☐ Review error logs
   ☐ Check recent deployments
   ☐ Check external dependencies
1. Identify Root Cause:
   ☐ Recent change?
   ☐ Resource exhaustion?
   ☐ External dependency?
   ☐ Configuration issue?

MITIGATION (15-30 minutes):

1. Apply Fix:
   
   Option A: Rollback deployment
   
   ```bash
   kubectl rollout undo deployment/<name> -n production
   kubectl rollout status deployment/<name> -n production
   ```
   
   Option B: Scale up
   
   ```bash
   kubectl scale deployment/<name> --replicas=10 -n production
   ```
   
   Option C: Restart pods
   
   ```bash
   kubectl rollout restart deployment/<name> -n production
   ```
   
   Option D: Apply hotfix
   
   ```bash
   # Emergency fix via kubectl
   kubectl set image deployment/<name> <container>=<image>:<fixed-tag>
   ```
1. Verify Fix:
   ☐ Check pods running
   ☐ Check error rates
   ☐ Run smoke tests
   ☐ Verify user reports
1. Communication:
   ☐ Update #incidents
   ☐ Update status page
   ☐ Notify customers if needed

POST-INCIDENT (30min - 24h):

1. Document:
   ☐ Complete incident timeline
   ☐ Document root cause
   ☐ List action items
   ☐ Update runbooks
1. Follow-up:
   ☐ Schedule post-mortem
   ☐ Implement permanent fix
   ☐ Add monitoring
   ☐ Update documentation

```
### Emergency Contacts

```yaml
Critical Issues (Production Down):
  Slack: #incidents
  On-call: +XX-XXX-XXX-XXXX
  Platform Lead: +XX-XXX-XXX-XXXX

Non-Critical Issues:
  Slack: #platform-support
  Email: platform-team@crusoe-island.com

Security Issues:
  Slack: #security-incidents
  CISO: +XX-XXX-XXX-XXXX
  Email: security@crusoe-island.com

After Hours:
  On-call rotation: Check PagerDuty
  Emergency escalation: CEO +XX-XXX-XXX-XXXX
```

-----

## 🆘 Getting Help

### Self-Service Resources

```yaml
1. Search This Guide:
   - Use browser search (Ctrl+F / Cmd+F)
   - Check Quick Problem Index
   - Follow debugging approach

2. Platform Documentation:
   - Getting Started: docs/developer-guide/getting-started.md
   - Deployment Guide: docs/developer-guide/deployment-guide.md
   - Security Guide: docs/security/security-guide.md
   - Runbooks: docs/runbooks/

3. Search Previous Issues:
   - Slack #platform-support history
   - Jira IDP project
   - GitHub Issues in idp-platform repo

4. Check Status Page:
   - https://status.crusoe-island.com
   - Known issues
   - Planned maintenance

5. Kubernetes Documentation:
   - https://kubernetes.io/docs/
   - Troubleshooting section
   - API reference
```

### When to Ask for Help

```yaml
Ask in Slack #platform-support if:
  - Issue not in this guide
  - Tried solutions, didn't work
  - Need permissions/access
  - Need infrastructure changes
  - Questions about platform

Create Jira ticket if:
  - Bug in platform
  - Feature request
  - Complex issue requiring investigation
  - Need to track resolution

Escalate to #incidents if:
  - Production outage
  - Security incident
  - Data loss risk
  - Customer impact

When asking for help, provide:
  ✓ What you're trying to do
  ✓ What's not working (exact error)
  ✓ What you've tried
  ✓ Relevant logs/output
  ✓ kubectl describe output
  ✓ Timeline (when did it start?)
  ✓ Recent changes
```

### Help Request Template

```markdown
## Issue Description
[Clear description of the problem]

## Environment
- Namespace: production
- Application: my-app
- Cluster: aks-idp-prod

## Error Message
```

[Exact error message or kubectl output]

```
## Steps to Reproduce
1. [First step]
2. [Second step]
3. [Error occurs]

## What I've Tried
- [Solution 1 from troubleshooting guide]
- [Solution 2 attempted]
- [Still not working]

## Additional Context
- Started happening: [timestamp]
- Recent changes: [deployment, config change, etc.]
- Urgency: [low/medium/high/critical]

## Relevant Logs
```

[kubectl logs output]

```

```

[kubectl describe output]

```

```

### Office Hours

```yaml
Platform Team Office Hours:
  When: Wednesdays 2-3 PM CET
  Where: Zoom (link in #platform-support topic)
  Format: Drop-in, ask anything
  
Topics:
  - Architecture questions
  - Best practices
  - Platform features
  - Troubleshooting help
  - Pair debugging

No appointment needed!
```

-----

## 📚 Additional Resources

### Internal Resources

- **Platform Wiki:** https://wiki.crusoe-island.com/idp
- **Runbooks:** docs/runbooks/
- **Architecture:** docs/architecture/
- **Security:** docs/security/

### External Resources

- **Kubernetes Troubleshooting:** https://kubernetes.io/docs/tasks/debug/
- **kubectl Cheat Sheet:** https://kubernetes.io/docs/reference/kubectl/cheatsheet/
- **Azure AKS Troubleshooting:** https://docs.microsoft.com/azure/aks/troubleshooting
- **Docker Debugging:** https://docs.docker.com/config/containers/

### Recommended Tools

- **k9s:** Terminal UI for Kubernetes
- **stern:** Multi-pod log tailing
- **kubectx/kubens:** Context and namespace switching
- **krew:** kubectl plugin manager
- **lens:** Kubernetes IDE

-----

## 📝 Feedback

**Found an issue not covered here?**

- Create an issue: https://github.com/crusoe-island/idp-platform/issues
- Slack: #platform-support
- Email: platform-team@crusoe-island.com

**Have a solution to add?**

- Submit a pull request!
- Share in #platform-support

-----

**Document Version:** 1.0  
**Last Updated:** December 21, 2024  
**Maintained by:** Platform Engineering Team

-----

*Remember: When in doubt, ask for help! The platform team is here to support you.* 🤝
