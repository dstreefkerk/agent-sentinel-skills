# How to Use: Sentinel Use Case Documentor

Quick start guide for documenting Microsoft Sentinel analytics rules as SOC use cases.

---

## Basic Usage

Provide a Sentinel ARM template export and ask Claude to document it:

```
Document this Sentinel rule: @exported_rule.json
```

```
Create SOC use case documentation for @Azure_Sentinel_analytic_rule.json
```

```
Generate use case docs for this detection: @rule.json
```

---

## Two Documentation Modes

### Quick Mode

Generates documentation immediately with AI-inferred content and `[HUMAN INPUT REQUIRED]` placeholders for gaps.

**Best for:**
- Batch processing multiple rules
- Time-sensitive documentation needs
- Rules with good existing metadata

### Guided Mode

Interactive Q&A that walks through each section, showing inferences and asking for input before generating.

**Best for:**
- Critical detection rules
- Compliance audit documentation
- Thorough, complete documentation

---

## What You Need

### Required

- **ARM Template JSON**: Export from Azure Portal or CLI
  - Portal: Analytics rule > Export
  - CLI: `az sentinel alert-rule show --resource-group RG --workspace-name WS --rule-id ID`

### Helpful Context (Optional)

- Detection owner/team
- Notification preferences (email, Slack, Teams, PagerDuty)
- Investigation playbook references
- Known false positive sources
- Compliance requirements

---

## Example Session

**User:**
```
Document this Sentinel rule: @RareProcessAsService.json

Use guided mode - this is a critical detection.
```

**Claude will:**
1. Parse the ARM template
2. Extract tactics, techniques, severity, query details
3. Analyze KQL for tables, thresholds, timeframes
4. Infer problem statement from tactic (Persistence)
5. Map to kill chain phase (Installation)
6. Ask clarifying questions for gaps
7. Generate complete markdown documentation

---

## Output

Documentation is saved as `{original_filename}_UseCase.md` with sections:

1. **Use Case Metadata** - ID, name, severity, purpose, problem statement
2. **MITRE ATT&CK Mapping** - Tactics, techniques, sub-techniques
3. **Detection Logic** - Query overview, data sources, thresholds
4. **Entity Mappings** - Alert enrichment fields
5. **Cyber Kill Chain** - Phase mapping
6. **SOC Response** - Investigation steps, false positive guidance
7. **Assumptions & Limitations** - Data requirements, coverage gaps
8. **References** - Author, external URLs, MITRE links
9. **Document Control** - Version history

---

## Tips

### Minimize Placeholders

Provide context upfront:
```
Document @rule.json

Additional context:
- Owner: SOC Detection Engineering
- Notify: #soc-alerts Slack channel
- Known FPs: Legitimate admin tools like psexec
```

### Batch Processing

For multiple rules, use Quick Mode:
```
Document these Sentinel rules in Quick Mode:
- @rule1.json
- @rule2.json
- @rule3.json
```

### KQL with Embedded Docs

If your KQL query contains structured comments, they'll be extracted:
```kql
// DESCRIPTION: Detects rare processes running as services
// INVESTIGATION STEPS: 1. Check process hash against VT 2. Review parent process
// FALSE POSITIVE: Admin tools, deployment scripts
```

---

## Troubleshooting

### Too Many Placeholders

Provide more context or use Guided Mode for interactive gap-filling.

### Wrong Data Source Mapping

For custom tables not in the mapping, specify explicitly:
```
Document @rule.json

Note: CustomLogs_CL is from our custom application via HTTP Data Collector API.
```

### Incorrect MITRE Mapping

Override with explicit techniques:
```
Document @rule.json

Correct MITRE mapping: T1078.004 (Cloud Accounts), not T1078.
```

