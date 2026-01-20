# KQL Expert - Microsoft Sentinel & Azure Monitor Query Optimization Skill

Expert guidance for writing optimized Kusto Query Language (KQL) queries for Microsoft Sentinel analytics rules, threat hunting, ASIM normalization, and performance optimization. **Now with schema validation against M365 and Sentinel table schemas.**

## Overview

This Claude skill provides comprehensive expertise in KQL for Azure Log Analytics and Microsoft Sentinel, covering all 12 major topic areas:

1. **KQL Fundamentals & Syntax** - Pipe-based data flow, operators, functions
2. **Query Performance Optimization** - Filter early, term indexing, join optimization
3. **Analytics Rule Development** - Scheduled & NRT rules, entity mapping, MITRE ATT&CK
4. **Common Mistakes & Anti-Patterns** - String operators, filter placement, joins
5. **Threat Hunting Patterns** - IoC detection, anomaly detection, lateral movement
6. **Testing & Governance** - CI/CD, validation, rule lifecycle management
7. **Cost Optimization & Billing Impact** - Table plans, DCR transformations, commitment tiers
8. **Migration from SPL to KQL** - Splunk to Sentinel migration with command mapping
9. **False Positive Tuning & Alert Fatigue Management** - Watchlists, automation rules
10. **Multi-Workspace and Cross-Tenant Queries** - MSSP scenarios, Azure Lighthouse
11. **ASIM Normalization** - Source-agnostic detection with filtering parameters
12. **Schema Validation** - Validate queries against M365/Sentinel table schemas

## What's Included

### Core Skill Files
- **SKILL.md** - Complete skill definition (~300 lines, condensed)
- **README.md** - This file with installation and overview
- **HOW_TO_USE.md** - Usage examples and invocation patterns

### Scripts (`scripts/` folder)

| File | Purpose |
|------|---------|
| **schema_validator.py** | Validates queries against environments.json table schemas |
| **kql_patterns.py** | Reusable query templates for analytics rules, hunting, ASIM |
| **kql_optimizer.py** | Query performance analysis and optimization recommendations |
| **kql_validator.py** | Query validation, entity mapping, MITRE ATT&CK alignment |

### References (`references/` folder)

| File | Description |
|------|-------------|
| **environments.json** | M365 Defender and Sentinel table schemas (~773KB) |
| **ENVIRONMENTS.md** | Schema file documentation and generation instructions |
| **kql_best_practices.md** | Detailed optimization guide (filter early, term indexing, joins) |
| **spl_to_kql_mapping.md** | Complete SPL to KQL command mapping reference |
| **asim_schemas.md** | ASIM parser reference with all GA schemas and parameters |

### Sample Files

| File | Purpose |
|------|---------|
| sample_input_*.json | Example input formats for skill invocation |
| expected_output_*.json | Expected output formats for validation |

## Installation

### For Claude Code

**Project-Level (Recommended for team collaboration):**
```bash
# Copy skill folder to your project
cp -r kql-expert /path/to/your/project/.claude/skills/

# Or create symlink
ln -s /path/to/kql-expert /path/to/your/project/.claude/skills/kql-expert
```

**User-Level (Available in all Claude Code sessions):**
```bash
# Windows
xcopy /E /I kql-expert "%USERPROFILE%\.claude\skills\kql-expert"

# macOS/Linux
cp -r kql-expert ~/.claude/skills/
```

### For Claude Desktop/Web Apps

1. **Using ZIP file:**
   - Locate `kql-expert.zip` in the parent directory
   - Drag and drop into Claude Desktop
   - Or use the skill-creator skill to import

2. **Manual installation:**
   - Copy all files from `kql-expert/` folder
   - Import through Claude's skill management interface

### Verification

After installation, test the skill:
```
Hey Claude - Can you show me an optimized query pattern for detecting brute force authentication attempts using ASIM?
```

## Key Capabilities

### Schema Validation (NEW in v2.0)
- Validate queries against M365 Defender and Sentinel table schemas
- Column type checking with similar name suggestions
- Support for magic functions (FileProfile, DeviceFromIP)
- Watchlist validation

```python
from scripts.schema_validator import KQLSchemaValidator

validator = KQLSchemaValidator()
result = validator.validate_query(query, environment='sentinel')
print(f"Valid: {result.is_valid}")
print(f"Unknown tables: {result.unknown_tables}")
```

### Query Optimization
- Identify performance bottlenecks (contains vs has, late filtering, missing time bounds)
- Rewrite queries following filter-early principles
- Optimize joins with proper hints (broadcast, shufflekey)
- Reduce resource consumption by 10-100x

### Analytics Rule Development
- Create Sentinel scheduled and NRT rules
- Implement proper entity mapping (Account, IP, Host, File, URL, etc.)
- Tag with MITRE ATT&CK tactics/techniques (framework v18)
- Integrate watchlists for exception management

### ASIM Normalization
- Write source-agnostic detection rules
- Use unifying parsers with filtering parameters
- Support all GA schemas (Authentication, Network Session, Process, File, DNS, Web, Registry, Audit)
- Push filters down to source tables for performance

### SPL to KQL Migration
- Convert Splunk queries to KQL
- Map CIM data models to ASIM schemas
- Translate commands (stats → summarize, eval → extend, table → project)
- Handle function differences (substr indexing, case expressions)

### False Positive Tuning
- Reduce alert fatigue through watchlists
- Implement automation rules with expiration
- Apply conditional logic for known-good patterns

### Threat Hunting
- IoC threat intelligence matching
- Anomaly detection with time-series analysis
- Lateral movement detection (RDP, WinRM, SMB, PsExec)
- Persistence mechanism detection (registry run keys, scheduled tasks)

### Cost Optimization
- Analyze table plans (Analytics vs Basic vs Auxiliary)
- Implement DCR ingestion-time transformations
- Calculate commitment tier savings

## Usage Examples

### Validate Query Against Schema
```
Hey Claude - Validate this query against Sentinel table schemas:

SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| project TimeGenerated, Account, IpAddress
```

### Optimize Slow Query
```
Hey Claude - This query times out after 3 minutes:

SecurityEvent
| join IdentityInfo on Account
| where TimeGenerated > ago(1h)
| where EventID == 4625

Can you optimize it?
```

### Create Analytics Rule
```
Hey Claude - Create a Sentinel analytics rule to detect:
- Failed RDP logins (EventID 4625, LogonType 10)
- 5+ failures in 5 minutes
- From the same source IP
- With entity mapping and MITRE tags
```

### Migrate Splunk Rule
```
Hey Claude - Convert this Splunk detection to KQL:

index=windows EventCode=4688
| stats count by src_ip, process_name
| where count > 10
```

## Python Module Usage

### Schema Validation
```python
from scripts.schema_validator import KQLSchemaValidator, format_schema_validation_result

validator = KQLSchemaValidator()

# Check available environments
print(validator.get_available_environments())
# ['m365', 'sentinel', 'm365_with_sentinel']

# Get table schema
schema = validator.get_table_schema('sentinel', 'SecurityEvent')
print(schema.columns)

# Validate query
result = validator.validate_query(query, environment='sentinel')
print(format_schema_validation_result(result))
```

### Query Patterns
```python
from scripts.kql_patterns import KQLPatterns

patterns = KQLPatterns()
print(patterns.list_all_patterns())

query = patterns.format_pattern('brute_force_auth', threshold=10, timeframe='1h')
print(query)
```

### Query Optimizer
```python
from scripts.kql_optimizer import KQLOptimizer, format_optimization_report

optimizer = KQLOptimizer()
report = optimizer.analyze_query(query)
print(format_optimization_report(report))
```

### Query Validator
```python
from scripts.kql_validator import KQLValidator, format_validation_result

validator = KQLValidator()
result = validator.validate_query(query, context='analytics_rule')
print(format_validation_result(result))
```

## Supported Environments

The skill validates against three environments from `environments.json`:

| Environment | Tables | Use Case |
|-------------|--------|----------|
| `m365` | Defender XDR tables | Advanced Hunting |
| `sentinel` | Log Analytics tables | Microsoft Sentinel |
| `m365_with_sentinel` | Merged (auto-created) | Cross-platform queries |

## Performance Thresholds

| Metric | Excessive | Throttled |
|--------|-----------|-----------|
| CPU time | >100s | >1,000s |
| Time span | >15 days | >90 days |
| Query timeout | 4 min default | 1 hour max |
| Result limits | 500K records OR 64MB |

## Limitations

- Read-only language (cannot modify data)
- Maximum 10,000 characters for analytics rule queries
- Case-sensitive for all identifiers
- Cross-workspace limits (10 for API, 20 for analytics rules, 100 for general queries)
- Basic/Auxiliary table restrictions (single table, 30-day max, no joins)

## Version

**Version:** 2.0.0
**Last Updated:** January 2026
**Changes in 2.0:**
- Added schema_validator.py with environments.json support
- Reorganized to scripts/ and references/ folders
- Condensed SKILL.md to <500 lines
- Added comprehensive reference documentation

## Documentation

Based on authoritative Microsoft documentation:
- Microsoft Learn - KQL Overview, Query Optimization, Analytics Rules
- Microsoft Sentinel - ASIM Normalization, False Positive Handling
- Azure Monitor Logs - Cost Optimization, Cross-Workspace Queries
- FalconForce KQLAnalyzer - Schema validation patterns

## Support

For issues or questions:
1. Review HOW_TO_USE.md for usage examples
2. Check references/ folder for detailed documentation
3. Consult SKILL.md for comprehensive guidance
4. Review Python module docstrings for API details

## License

This skill is based on publicly available Microsoft documentation and best practices. Use in accordance with your organization's security and compliance requirements.
