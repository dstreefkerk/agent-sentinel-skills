# How to Use the KQL Expert Skill

This skill provides expert guidance for writing, optimizing, and validating Kusto Query Language (KQL) queries for Microsoft Sentinel and Azure Monitor. **Version 2.0 adds schema validation against M365 and Sentinel table schemas.**

## Quick Start

Hey Claude - Can you help me optimize this KQL query for better performance?

## Example Invocations

### Schema Validation (NEW in v2.0)

**Example 0: Validate Against Schemas**
```
Hey Claude - Validate this query against Sentinel table schemas:

SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| project TimeGenerated, Account, IpAddres  // typo in column name
```

**Example 0b: Check M365 Defender Tables**
```
Hey Claude - Validate this Advanced Hunting query against M365 schemas:

DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### Query Optimization

**Example 1: Performance Optimization**
```
Hey Claude—I just added the "kql-expert" skill. This query is timing out after 3 minutes. Can you analyze it and suggest optimizations?

[Paste your KQL query]
```

**Example 2: Resource Consumption**
```
Hey Claude—I just added the "kql-expert" skill. My analytics rule was auto-disabled due to excessive resource consumption. Can you identify the issues?

[Paste your query]
```

### Analytics Rule Creation

**Example 3: Create Detection Rule**
```
Hey Claude—I just added the "kql-expert" skill. Create a Sentinel analytics rule to detect:
- Brute force authentication attempts
- 10+ failed logins in 5 minutes
- From the same source IP
- Using ASIM normalization
- With proper entity mapping and MITRE ATT&CK tags
```

**Example 4: Multi-Source Detection**
```
Hey Claude—I just added the "kql-expert" skill. Build an analytics rule that detects impossible travel across Azure AD, AWS, and Okta using ASIM.
```

### SPL to KQL Migration

**Example 5: Splunk Migration**
```
Hey Claude—I just added the "kql-expert" skill. Migrate this Splunk detection rule to KQL:

index=windows EventCode=4625
| stats count by src_ip, user
| where count > 5
```

**Example 6: Complex SPL Conversion**
```
Hey Claude—I just added the "kql-expert" skill. Convert this Splunk correlation search to KQL with ASIM normalization:

[Paste complex SPL query]
```

### ASIM Normalization

**Example 7: Source-Agnostic Query**
```
Hey Claude—I just added the "kql-expert" skill. Rewrite this SecurityEvent query to use ASIM Authentication parser with proper filtering parameters.
```

**Example 8: Multi-Schema Detection**
```
Hey Claude—I just added the "kql-expert" skill. Create a hunting query that correlates ASIM Authentication failures with ASIM Network Session data to detect credential stuffing.
```

### False Positive Tuning

**Example 9: Reduce Alert Noise**
```
Hey Claude—I just added the "kql-expert" skill. This rule generates 200 alerts/day with 80% false positives. Help me tune it using watchlists and conditional logic.
```

**Example 10: Exception Management**
```
Hey Claude—I just added the "kql-expert" skill. How do I exclude service accounts and corporate VPN IPs from this brute force detection rule using watchlists?
```

### Threat Hunting

**Example 11: Lateral Movement Hunt**
```
Hey Claude—I just added the "kql-expert" skill. Create a hunting query to detect lateral movement using RDP, WinRM, and PsExec across my environment.
```

**Example 12: Anomaly Detection**
```
Hey Claude—I just added the "kql-expert" skill. Build a time-series anomaly detection query for unusual PowerShell execution frequency.
```

### Cross-Workspace Queries

**Example 13: MSSP Multi-Tenant**
```
Hey Claude—I just added the "kql-expert" skill. Write a cross-workspace query that searches for IOCs across 5 customer workspaces with proper performance optimization.
```

### Cost Optimization

**Example 14: Reduce Ingestion Costs**
```
Hey Claude—I just added the "kql-expert" skill. Analyze this query and recommend table plan changes (Analytics vs Basic vs Auxiliary) to reduce costs.
```

### Validation

**Example 15: Pre-Deployment Check**
```
Hey Claude—I just added the "kql-expert" skill. Validate this analytics rule before deployment:
- Syntax correctness
- Entity mapping
- MITRE ATT&CK tags
- Best practices compliance
```

## What to Provide

### For Schema Validation
- KQL query text
- Target environment (sentinel, m365, or m365_with_sentinel)
- Custom tables if any

### For Query Optimization
- KQL query text
- Performance issues (timeouts, slow execution, high resource consumption)
- Target tables and data volume
- Query context (analytics rule, hunting, ad-hoc)

### For Analytics Rule Creation
- Detection hypothesis or threat scenario
- Data sources available
- Alert criteria (thresholds, time windows)
- Severity level
- Required entity mappings
- MITRE ATT&CK tactics/techniques

### For SPL Migration
- Splunk SPL query
- Splunk CIM data model references
- Expected behavior/output
- Target ASIM schemas

### For False Positive Tuning
- Current query
- False positive patterns (specific IPs, accounts, processes, etc.)
- Business context for exceptions
- Alert volume statistics

## What You'll Get

### Schema Validation
- Valid/invalid status
- Referenced tables and columns
- Unknown tables with suggestions
- Unknown columns with similar name hints
- Environment-specific warnings

### Optimized Queries
- Rewritten query with performance improvements
- Before/after performance estimates
- Explanation of each optimization
- Resource consumption predictions
- Best practice alignment

### Analytics Rules
- Complete rule configuration
- KQL query with proper structure
- Entity mapping configuration
- MITRE ATT&CK taxonomy
- Scheduling recommendations
- Watchlist integration patterns
- False positive reduction strategies
- Testing and validation guidance

### Migration Output
- Converted KQL query
- SPL-to-KQL command mapping
- Schema mapping (CIM to ASIM)
- Key differences explained
- Manual review checklist
- Optimization opportunities

### Validation Reports
- Syntax validation results
- Best practices compliance
- Entity mapping correctness
- MITRE framework alignment
- Performance bottleneck identification
- Security coverage gaps

### Optimization Analysis
- Performance issues prioritized by impact
- Anti-pattern detection
- Resource consumption estimates
- Cost implications
- Implementation guidance

## Advanced Use Cases

### Pattern Library Access
```
Hey Claude—I just added the "kql-expert" skill. Show me query patterns for:
- Brute force detection
- Lateral movement
- Persistence mechanisms
- IoC threat intelligence matching
- Anomaly detection
```

### Multi-Phase Detection
```
Hey Claude—I just added the "kql-expert" skill. Create a detection chain:
1. Phishing email (EmailEvents)
2. Followed by credential dump (DeviceProcessEvents)
3. Followed by lateral movement (DeviceNetworkEvents)
```

### Cost Analysis
```
Hey Claude—I just added the "kql-expert" skill. Analyze my workspace's top 10 tables and recommend table plan optimizations to reduce costs by 30%.
```

### Compliance Queries
```
Hey Claude—I just added the "kql-expert" skill. Create audit queries for:
- PCI-DSS requirement 10.2.4
- HIPAA 164.312(b)
- SOC2 CC6.1
```

## Tips for Best Results

1. **Provide Context**: Include what you're trying to detect and why
2. **Share Constraints**: Mention data volume, time ranges, performance requirements
3. **Include Errors**: Share timeout messages, resource consumption metrics
4. **Business Context**: Explain false positive patterns and business processes
5. **Data Sources**: Specify which tables/logs are available
6. **Compliance**: Mention any regulatory requirements (HIPAA, GDPR, etc.)

## Common Workflows

### Workflow 1: Create New Detection
1. Describe threat scenario
2. Get ASIM-based query template
3. Review entity mapping
4. Add watchlist exceptions
5. Validate and test
6. Deploy to production

### Workflow 2: Optimize Existing Rule
1. Share current query and issues
2. Get performance analysis
3. Review optimization recommendations
4. Apply changes
5. Validate improvement
6. Monitor for 24-48 hours

### Workflow 3: Migrate from Splunk
1. Provide SPL query
2. Get KQL conversion
3. Review schema mapping
4. Test in parallel
5. Compare alert volumes
6. Fine-tune thresholds

### Workflow 4: Reduce False Positives
1. Share current alert volume and FP rate
2. Identify FP patterns
3. Create watchlists
4. Apply conditional logic
5. Test with historical data
6. Monitor improvement

## Need Help?

The kql-expert skill covers:
- **Schema Validation** against M365 and Sentinel table schemas (NEW in v2.0)
- All 12 major KQL topic areas from research
- 100+ authoritative best practices
- MITRE ATT&CK framework (version 18)
- ASIM normalization (all GA schemas)
- SPL to KQL migration
- Cost optimization strategies
- Cross-workspace patterns
- Threat hunting techniques

### File Structure (v2.0)
```
kql-expert/
├── SKILL.md                    # Main skill definition (<500 lines)
├── README.md                   # Installation and overview
├── HOW_TO_USE.md              # This file
├── scripts/                    # Python modules
│   ├── schema_validator.py    # Table schema validation
│   ├── kql_patterns.py        # Query templates
│   ├── kql_optimizer.py       # Performance analysis
│   └── kql_validator.py       # Best practices validation
├── references/                 # Documentation
│   ├── environments.json      # M365/Sentinel table schemas
│   ├── ENVIRONMENTS.md        # Schema file docs
│   ├── kql_best_practices.md  # Optimization guide
│   ├── spl_to_kql_mapping.md  # Migration reference
│   └── asim_schemas.md        # ASIM parser reference
└── sample_*.json / expected_*.json  # Test data
```

Just ask - the skill will guide you through complex KQL challenges with expert-level recommendations!
