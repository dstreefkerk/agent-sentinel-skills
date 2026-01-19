# How to Use the Sentinel ARM Generator Skill

Hey Claude—I just added the "sentinel-arm-generator" skill. Can you generate a deployment-ready ARM template from this KQL query?

## Example Invocations

### Example 1: Basic KQL to ARM Template
```
@sentinel-arm-generator

I've been working on this KQL detection query:

SigninLogs
| where ResultType != "0"
| where AppDisplayName != "Microsoft Authentication Broker"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| project TimeGenerated, UserPrincipalName, IPAddress, FailedAttempts

Generate the ARM template for deployment.
```

**What Claude will do**:
- Auto-generate rule name: "Multiple Failed Azure AD Sign-In Attempts"
- Assign severity: High
- Map MITRE tactics: [InitialAccess, CredentialAccess]
- Map techniques: [T1078, T1110]
- Extract entities: Account (UserPrincipalName), IP (IPAddress)
- Set frequency: PT5M / PT5M
- Generate complete ARM template JSON
- Provide deployment instructions

### Example 2: With Custom Parameters
```
@sentinel-arm-generator

Generate ARM template for this endpoint detection query:

DeviceFileEvents
| where FolderPath contains "\\Temp\\"
| where FileOriginUrl !contains "microsoft.com"
| project TimeGenerated, DeviceName, FileName, FolderPath, FileOriginUrl

Use these settings:
- Severity: Medium
- Custom description: Detects potentially suspicious file downloads to temp folders
- Query frequency: PT15M
```

**What Claude will do**:
- Use your custom severity (Medium) instead of auto-detecting
- Use your custom description
- Use your specified query frequency (15 minutes)
- Auto-generate everything else (MITRE mappings, entities, rule name)

### Example 3: Batch Generation
```
@sentinel-arm-generator batch-mode

Generate ARM templates for all three detection queries we just developed:

1. Brute force authentication detection
2. Privilege escalation via service creation
3. Lateral movement via PsExec

Here are the KQL queries:
[Paste your three queries]
```

**What Claude will do**:
- Generate three separate ARM template files
- Each with appropriate metadata, MITRE mappings, and entities
- Provide deployment instructions for all three
- Create a summary of what was generated

### Example 4: Validation Only (No File Generation)
```
@sentinel-arm-generator validate-only

Analyze this KQL and show me what the ARM template would contain (don't generate the file yet):

SecurityEvent
| where EventID == 4720
| where TargetUserName contains "admin"
| project TimeGenerated, Computer, TargetUserName, SubjectUserName
```

**What Claude will do**:
- Show you the rule name, description, severity
- Display MITRE tactics/techniques
- Show entity mappings
- Explain frequency and threshold settings
- Wait for your confirmation before generating files

### Example 5: Review and Adjust MITRE Mappings
```
@sentinel-arm-generator

Generate ARM template for this query, but let me review the MITRE mappings first:

OfficeActivity
| where Operation == "FileDownloaded"
| summarize DownloadCount = count() by UserId, OfficeWorkload, bin(TimeGenerated, 1h)
| where DownloadCount > 100
```

**What Claude will do**:
- Show auto-detected MITRE mappings
- Ask if you want to adjust them
- Generate final template with your confirmed mappings

## What to Provide

### Minimum Required
- **KQL Query**: Your tested detection query (must be valid KQL syntax)

### Optional Overrides
- **display_name**: Custom rule name
- **description**: Custom rule description
- **severity**: High, Medium, Low, or Informational
- **query_frequency**: ISO 8601 duration (PT5M, PT1H, P1D, etc.)
- **query_period**: ISO 8601 duration for lookback window
- **trigger_threshold**: Integer threshold value
- **mitre_tactics**: List of MITRE tactics
- **mitre_techniques**: List of MITRE technique IDs
- **entity_mappings**: Custom entity mapping configuration

### Conversation Context
The skill leverages your conversation context, so if you've been discussing:
- "This detects brute force attacks" → Claude understands the purpose
- Data sources and threat types → Better MITRE mapping
- SOC operational needs → Better frequency recommendations

## What You'll Get

### Generated Files
1. **ARM Template JSON**: `sentinel-rule-{rule-name}.json`
   - Complete ARM deployment template
   - Workspace parameter included
   - Valid Azure schema compliance
   - Ready for deployment

2. **Validation Summary** (displayed in chat):
   - Auto-generated rule name and rationale
   - Severity assignment with explanation
   - MITRE ATT&CK mappings with rationale
   - Entity mappings with detected columns
   - Frequency/period settings with rationale
   - Data sources identified

3. **Deployment Instructions**:
   - Azure CLI command
   - PowerShell command
   - Portal deployment steps
   - Validation checklist

### Example Output Structure
```json
{
  "template": { ... complete ARM template ... },
  "validation_summary": {
    "rule_guid": "a1b2c3d4-...",
    "display_name": "Multiple Failed Azure AD Sign-In Attempts",
    "severity": "High",
    "severity_rationale": "High severity assigned due to indicators of active attack",
    "mitre_tactics": ["InitialAccess", "CredentialAccess"],
    "mitre_techniques": ["T1078", "T1110"],
    "detected_entities": [
      {
        "entity_type": "Account",
        "mapped_columns": ["UserPrincipalName"]
      },
      {
        "entity_type": "IP",
        "mapped_columns": ["IPAddress"]
      }
    ]
  },
  "deployment_instructions": "..."
}
```

## Best Practices

### Before Using the Skill
1. **Test Your KQL**: Run the query in Sentinel to confirm it works
2. **Verify Output Columns**: Ensure your query projects/summarizes the columns you need
3. **Check Data Availability**: Confirm required tables exist in your workspace

### When Using the Skill
1. **Provide Context**: Explain what you're detecting (helps with MITRE mapping)
2. **Review Auto-Mappings**: Validate generated MITRE tactics/techniques
3. **Check Entity Mappings**: Verify extracted entities match your intent
4. **Customize if Needed**: Override any auto-generated values that don't fit

### After Generation
1. **Review ARM Template**: Open the JSON and verify all fields
2. **Test Deployment**: Deploy to test environment first
3. **Validate Rule Execution**: Ensure rule triggers correctly
4. **Tune Threshold**: Adjust based on alert volume
5. **Document Changes**: Track rule versions in git

## Common Use Cases

### Use Case 1: Threat Hunting Research to Production
You've developed detection logic during threat hunting. Use the skill to quickly convert your KQL into a production-ready ARM template for deployment.

### Use Case 2: Bulk Rule Creation
You have 10-20 new detection queries. Use batch mode to generate all ARM templates at once, maintaining consistency.

### Use Case 3: Rule Migration/Updates
You're updating existing Sentinel rules. Export current rules, improve the KQL, regenerate ARM templates, and redeploy.

### Use Case 4: Multi-Environment Deployment
Generate ARM template once, deploy to dev/staging/prod with different workspace parameters.

### Use Case 5: SOC Analyst Enablement
SOC analysts create detection logic, skill generates consistent ARM templates without requiring deep ARM knowledge.

## Tips for Maximum Automation

1. **Rich Context**: Provide detailed conversation context about what you're detecting
2. **Standard Column Names**: Use common Sentinel column names (UserPrincipalName, DeviceName, etc.)
3. **Clear Aggregations**: Use explicit summarize/count operations for better threshold detection
4. **Trust the Intelligence**: The skill has comprehensive MITRE and entity mapping databases
5. **Iterate Quickly**: Generate, review, adjust if needed, regenerate

## Troubleshooting

### Issue: Entity mappings are incorrect
**Solution**: Use custom entity_mappings override or adjust your KQL column names to match standard patterns

### Issue: MITRE tactics don't match my detection
**Solution**: Provide more context about what you're detecting, or use custom mitre_tactics override

### Issue: Severity seems wrong
**Solution**: Override with custom severity parameter

### Issue: Query frequency doesn't fit operational needs
**Solution**: Specify custom query_frequency and query_period

### Issue: Generated rule name is too generic
**Solution**: Provide custom display_name or add more descriptive keywords to your KQL comments
