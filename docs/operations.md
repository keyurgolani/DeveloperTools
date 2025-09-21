# Operations Runbook

This runbook provides operational procedures for the Developer Utilities MCP Server.

## Table of Contents

- [Service Overview](#service-overview)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Common Operations](#common-operations)
- [Troubleshooting](#troubleshooting)
- [Incident Response](#incident-response)
- [Maintenance Procedures](#maintenance-procedures)
- [Security Operations](#security-operations)
- [Disaster Recovery](#disaster-recovery)

## Service Overview

### Service Architecture
- **Service Name**: Developer Utilities MCP Server
- **Language**: Go 1.22+
- **Framework**: Gin HTTP framework
- **Database**: Redis (optional, for rate limiting)
- **Deployment**: Docker containers on Kubernetes

### Key Components
- HTTP API server (port 8080)
- Cryptography module
- Text processing module
- Data transformation module
- Network utilities module
- Rate limiting system
- Metrics collection (Prometheus)
- Structured logging
- Distributed tracing (OpenTelemetry)

### Dependencies
- **External**: DNS servers, NTP servers
- **Internal**: Redis (optional)
- **Infrastructure**: Kubernetes, Load Balancer

## Monitoring and Alerting

### Key Metrics to Monitor

#### Application Metrics
- **HTTP Request Rate**: `http_requests_total`
- **HTTP Request Duration**: `http_request_duration_seconds`
- **HTTP Error Rate**: `http_requests_total{status_code=~"5.."}` 
- **Rate Limit Hits**: `rate_limit_hits_total`
- **Crypto Operations**: `crypto_operations_total`

#### System Metrics
- **CPU Usage**: Target < 70%
- **Memory Usage**: Target < 80%
- **Disk Usage**: Target < 85%
- **Network I/O**: Monitor for anomalies

#### Business Metrics
- **Active Users**: Unique API key usage
- **Popular Endpoints**: Request distribution
- **Error Patterns**: Common error types

### Alerting Rules

#### Critical Alerts (Page immediately)
```yaml
# High error rate
- alert: HighErrorRate
  expr: rate(http_requests_total{status_code=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
  for: 2m
  
# Service down
- alert: ServiceDown
  expr: up{job="dev-utilities"} == 0
  for: 1m

# High memory usage
- alert: HighMemoryUsage
  expr: container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.9
  for: 5m
```

#### Warning Alerts (Investigate during business hours)
```yaml
# High response time
- alert: HighResponseTime
  expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
  for: 5m

# High CPU usage
- alert: HighCPUUsage
  expr: rate(container_cpu_usage_seconds_total[5m]) > 0.8
  for: 10m
```

### Dashboards

#### Main Dashboard Panels
1. **Request Rate and Latency**
2. **Error Rate by Endpoint**
3. **Resource Usage (CPU, Memory)**
4. **Rate Limiting Statistics**
5. **Top Endpoints by Usage**
6. **Geographic Distribution**

## Common Operations

### Scaling Operations

#### Horizontal Scaling
```bash
# Scale up
kubectl scale deployment dev-utilities --replicas=5

# Scale down
kubectl scale deployment dev-utilities --replicas=2

# Auto-scaling
kubectl autoscale deployment dev-utilities \
  --cpu-percent=70 --min=3 --max=10
```

#### Vertical Scaling
```yaml
# Update resource limits
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### Configuration Updates

#### Environment Variables
```bash
# Update configuration
kubectl patch deployment dev-utilities -p \
  '{"spec":{"template":{"spec":{"containers":[{"name":"dev-utilities","env":[{"name":"LOG_LEVEL","value":"debug"}]}]}}}}'

# Restart pods to pick up changes
kubectl rollout restart deployment dev-utilities
```

#### Secrets Management
```bash
# Update API keys
kubectl create secret generic dev-utilities-secrets \
  --from-literal=api-keys="new-key-1,new-key-2,new-key-3" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart to pick up new secrets
kubectl rollout restart deployment dev-utilities
```

### Deployment Operations

#### Rolling Updates
```bash
# Update image
kubectl set image deployment/dev-utilities \
  dev-utilities=ghcr.io/example/dev-utilities:v1.1.0

# Check rollout status
kubectl rollout status deployment/dev-utilities

# Rollback if needed
kubectl rollout undo deployment/dev-utilities
```

#### Blue-Green Deployment
```bash
# Deploy new version to staging
kubectl apply -f k8s-deployment-staging.yaml

# Test staging environment
curl https://staging-api.example.com/health

# Switch traffic (update ingress/service)
kubectl patch service dev-utilities -p \
  '{"spec":{"selector":{"version":"v1.1.0"}}}'
```

## Troubleshooting

### Common Issues

#### High Memory Usage
**Symptoms**: Memory alerts, OOM kills
**Investigation**:
```bash
# Check memory usage
kubectl top pods -l app=dev-utilities

# Check for memory leaks
kubectl logs -l app=dev-utilities | grep -i "memory\|oom"

# Get detailed metrics
curl http://pod-ip:8080/metrics | grep go_memstats
```

**Resolution**:
1. Check for memory leaks in application logs
2. Adjust Argon2 memory parameters if crypto operations are heavy
3. Scale horizontally if needed
4. Increase memory limits if justified

#### High CPU Usage
**Symptoms**: CPU alerts, slow response times
**Investigation**:
```bash
# Check CPU usage
kubectl top pods -l app=dev-utilities

# Check for CPU-intensive operations
kubectl logs -l app=dev-utilities | grep -i "crypto\|hash\|password"
```

**Resolution**:
1. Check if crypto operations are causing high CPU
2. Implement or adjust rate limiting for crypto endpoints
3. Scale horizontally
4. Optimize Argon2 parameters

#### Rate Limiting Issues
**Symptoms**: 429 errors, user complaints
**Investigation**:
```bash
# Check rate limit metrics
curl http://pod-ip:8080/metrics | grep rate_limit

# Check Redis connectivity (if using Redis)
kubectl exec -it redis-pod -- redis-cli ping
```

**Resolution**:
1. Adjust rate limits if too restrictive
2. Check Redis connectivity and performance
3. Consider switching to memory-based rate limiting for testing

#### SSRF Protection Blocking Valid Requests
**Symptoms**: Network operation failures, blocked requests
**Investigation**:
```bash
# Check logs for SSRF blocks
kubectl logs -l app=dev-utilities | grep -i "ssrf\|blocked\|private"
```

**Resolution**:
1. Review SSRF protection rules
2. Whitelist specific IP ranges if needed
3. Update network policies

### Performance Issues

#### Slow Response Times
**Investigation Steps**:
1. Check application metrics for slow endpoints
2. Review database/Redis performance
3. Check network latency
4. Analyze distributed traces

**Resolution**:
1. Optimize slow endpoints
2. Add caching where appropriate
3. Scale resources
4. Review and optimize database queries

#### High Error Rates
**Investigation Steps**:
1. Check error logs for patterns
2. Review recent deployments
3. Check external dependencies
4. Analyze error distribution by endpoint

**Resolution**:
1. Fix application bugs
2. Rollback problematic deployments
3. Implement circuit breakers for external dependencies
4. Add retry logic where appropriate

## Incident Response

### Severity Levels

#### SEV-1 (Critical)
- Service completely down
- Data loss or corruption
- Security breach
- **Response Time**: Immediate (< 15 minutes)

#### SEV-2 (High)
- Significant performance degradation
- Partial service outage
- **Response Time**: < 1 hour

#### SEV-3 (Medium)
- Minor performance issues
- Non-critical feature failures
- **Response Time**: < 4 hours

#### SEV-4 (Low)
- Cosmetic issues
- Enhancement requests
- **Response Time**: Next business day

### Incident Response Procedures

#### Initial Response (First 15 minutes)
1. **Acknowledge** the incident
2. **Assess** severity and impact
3. **Notify** stakeholders
4. **Start** incident channel/bridge
5. **Begin** investigation

#### Investigation Phase
1. **Gather** logs and metrics
2. **Identify** root cause
3. **Implement** immediate mitigation
4. **Document** findings

#### Resolution Phase
1. **Apply** permanent fix
2. **Verify** resolution
3. **Monitor** for recurrence
4. **Update** stakeholders

#### Post-Incident
1. **Conduct** post-mortem
2. **Document** lessons learned
3. **Implement** preventive measures
4. **Update** runbooks

### Emergency Contacts
- **On-call Engineer**: [Pager/Phone]
- **Engineering Manager**: [Contact]
- **DevOps Team**: [Contact]
- **Security Team**: [Contact]

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily
- [ ] Check service health and metrics
- [ ] Review error logs
- [ ] Monitor resource usage
- [ ] Check security alerts

#### Weekly
- [ ] Review performance trends
- [ ] Update dependencies (security patches)
- [ ] Rotate API keys (if needed)
- [ ] Clean up old logs

#### Monthly
- [ ] Review and update documentation
- [ ] Conduct disaster recovery tests
- [ ] Review and update monitoring
- [ ] Security audit

#### Quarterly
- [ ] Performance optimization review
- [ ] Capacity planning
- [ ] Update operational procedures
- [ ] Team training updates

### Planned Maintenance

#### Pre-Maintenance Checklist
- [ ] Schedule maintenance window
- [ ] Notify stakeholders
- [ ] Prepare rollback plan
- [ ] Test changes in staging
- [ ] Backup critical data

#### During Maintenance
- [ ] Follow change procedures
- [ ] Monitor system health
- [ ] Document any issues
- [ ] Communicate progress

#### Post-Maintenance
- [ ] Verify system functionality
- [ ] Monitor for issues
- [ ] Update documentation
- [ ] Notify completion

## Security Operations

### Security Monitoring

#### Key Security Metrics
- Authentication failures
- Rate limit violations
- SSRF protection triggers
- Unusual traffic patterns
- Failed health checks

#### Security Alerts
```yaml
# Multiple authentication failures
- alert: AuthenticationFailures
  expr: rate(auth_failures_total[5m]) > 10
  
# SSRF protection triggers
- alert: SSRFAttempts
  expr: rate(ssrf_blocks_total[5m]) > 5
  
# Unusual traffic patterns
- alert: UnusualTraffic
  expr: rate(http_requests_total[5m]) > 1000
```

### Security Procedures

#### API Key Rotation
```bash
# Generate new keys
NEW_KEYS="$(openssl rand -hex 32),$(openssl rand -hex 32)"

# Update secret
kubectl create secret generic dev-utilities-secrets \
  --from-literal=api-keys="$NEW_KEYS" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart services
kubectl rollout restart deployment dev-utilities

# Notify users of old key deprecation
```

#### Security Incident Response
1. **Isolate** affected systems
2. **Preserve** evidence
3. **Assess** impact
4. **Contain** breach
5. **Eradicate** threat
6. **Recover** services
7. **Document** incident

## Disaster Recovery

### Backup Procedures

#### Configuration Backup
```bash
# Backup Kubernetes manifests
kubectl get all -o yaml > backup-$(date +%Y%m%d).yaml

# Backup secrets (encrypted)
kubectl get secrets -o yaml > secrets-backup-$(date +%Y%m%d).yaml
```

#### Data Backup
```bash
# Redis backup (if used)
kubectl exec redis-pod -- redis-cli BGSAVE
kubectl cp redis-pod:/data/dump.rdb ./redis-backup-$(date +%Y%m%d).rdb
```

### Recovery Procedures

#### Service Recovery
1. **Assess** damage and requirements
2. **Restore** from backups
3. **Redeploy** services
4. **Verify** functionality
5. **Monitor** for issues

#### Data Recovery
1. **Stop** affected services
2. **Restore** data from backups
3. **Verify** data integrity
4. **Restart** services
5. **Test** functionality

### Business Continuity

#### RTO/RPO Targets
- **Recovery Time Objective (RTO)**: 4 hours
- **Recovery Point Objective (RPO)**: 1 hour

#### Failover Procedures
1. **Activate** secondary region
2. **Update** DNS records
3. **Redirect** traffic
4. **Monitor** performance
5. **Communicate** status

## Contact Information

### Team Contacts
- **DevOps Team**: devops@example.com
- **Security Team**: security@example.com
- **Engineering Team**: engineering@example.com

### Escalation Path
1. On-call Engineer
2. Engineering Manager
3. Director of Engineering
4. CTO

### External Vendors
- **Cloud Provider**: [Support contact]
- **Monitoring Service**: [Support contact]
- **Security Service**: [Support contact]

---

**Document Version**: 1.0  
**Last Updated**: [Current Date]  
**Next Review**: [Date + 3 months]