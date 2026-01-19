# Microsoft Sentinel ARM Template Generator

**Version**: 1.0.0
**Skill Type**: Advanced Automation with Intelligence Systems
**Python Modules**: 4

## Overview

The Sentinel ARM Generator skill automatically transforms tested KQL detection queries into deployment-ready Microsoft Sentinel Analytic Rule ARM templates. It eliminates manual template creation overhead by intelligently generating rule names, MITRE ATT&CK mappings, entity extractions, severity assignments, and all required metadata.

## What This Skill Does

This skill provides **maximum automation** for Sentinel rule deployment:

1. **Takes your KQL query** (the detection logic you've already tested)
2. **Analyzes conversation context** to understand what you're detecting
3. **Auto-generates everything needed** for a complete ARM template:
   - Descriptive rule name
   - Detailed description
   - MITRE ATT&CK tactics, techniques, and sub-techniques
   - Entity mappings (Account, IP, Host, Process, File, etc.)
   - Severity level (High/Medium/Low/Informational)
   - Query frequency and lookback period
   - Trigger operator and threshold
4. **Produces deployment-ready ARM template** compliant with Azure API 2023-12-01-preview
5. **Provides deployment instructions** for Azure CLI, PowerShell, and Portal

## Key Features

### Intelligent MITRE ATT&CK Mapping
- Comprehensive pattern database covering all 14 MITRE tactics
- Auto-detects tactics, techniques, and sub-techniques from KQL content
- 30+ attack pattern definitions (brute force, lateral movement, persistence, etc.)
- Provides mapping rationale for transparency

### Entity Extraction Engine
- Analyzes KQL query structure (project, extend, summarize, by clauses)
- Identifies 12+ Sentinel entity types automatically
- Maps columns to proper entity identifiers (FullName, Address, HostName, etc.)
- Handles complex entities like FileHash with algorithm detection

### KQL Analysis Intelligence
- Auto-generates descriptive rule names based on detection patterns
- Creates detailed descriptions with context
- Assigns severity based on threat classification
- Recommends optimal query frequency (PT5M to P1D)
- Determines appropriate lookback periods
- Identifies data sources from table names

### ARM Template Compliance
- Uses official Azure deployment schema
- Microsoft.SecurityInsights API version 2023-12-01-preview
- Parameterized workspace for flexible deployment
- Valid resource ID and naming patterns
- Complete incident configuration structure
- ISO 8601 duration formats

## Python Modules

### 1. `scripts/generate_arm_template.py`
Main template generation engine. Orchestrates analysis, MITRE mapping, entity extraction, and ARM template assembly.

**Key Classes**:
- `SentinelARMGenerator`: Primary template generator
  - `generate_template()`: Creates complete ARM template
  - `save_template()`: Writes JSON to file
  - `get_deployment_instructions()`: Generates deployment guide
  - `get_validation_summary()`: Provides analysis transparency

### 2. `scripts/mitre_attack_mapper.py`
MITRE ATT&CK framework intelligence system with pattern-based mapping.

**Key Classes**:
- `MitreAttackMapper`: Maps detection patterns to MITRE framework
  - `get_mappings()`: Returns tactics, techniques, sub-techniques
  - `_detect_patterns()`: Pattern matching against KQL query
  - `get_technique_description()`: Human-readable technique names

**Pattern Database**: 30+ attack patterns across all MITRE tactics including:
- Authentication/Credential attacks
- Persistence mechanisms
- Lateral movement techniques
- Execution methods
- Defense evasion
- Exfiltration patterns
- Command & control indicators

### 3. `scripts/entity_extractor.py`
KQL query parser for automatic entity identification and Sentinel mapping.

**Key Classes**:
- `EntityExtractor`: Extracts and maps Sentinel entity types
  - `extract_entities()`: Returns entity mappings list
  - `_extract_column_names()`: Parses KQL for column names
  - `get_entity_summary()`: Summary of detected entities
  - `validate_entity_mappings()`: Validates mapping correctness

**Supported Entities**: Account, IP, Host, Process, File, URL, RegistryKey, RegistryValue, DNS, FileHash, CloudApplication, Mailbox

### 4. `scripts/kql_analyzer.py`
Query analysis for metadata generation (severity, frequency, descriptions).

**Key Classes**:
- `KQLAnalyzer`: Comprehensive KQL analysis
  - `analyze()`: Full analysis with all metadata
  - `_generate_display_name()`: Creates descriptive rule names
  - `_generate_description()`: Auto-generates descriptions
  - `_determine_severity()`: Assigns severity level
  - `_determine_frequency()`: Recommends query frequency
  - `_determine_period()`: Sets lookback window

## Installation

### Claude Code (Project-Level)
```bash
# Copy skill folder to project
cp -r sentinel-arm-generator .claude/skills/

# Or copy to user-level for all projects
cp -r sentinel-arm-generator ~/.claude/skills/
```

### Claude Desktop
1. Drag and drop the `sentinel-arm-generator.zip` file into Claude Desktop
2. Skill will be automatically loaded and available

### Manual Installation
```bash
# Create skills directory if it doesn't exist
mkdir -p ~/.claude/skills/

# Copy skill folder
cp -r sentinel-arm-generator ~/.claude/skills/

# Verify installation
ls ~/.claude/skills/sentinel-arm-generator
```

## Quick Start

### Basic Usage
```
@sentinel-arm-generator

I've developed this KQL query for detecting brute force attacks:

SigninLogs
| where ResultType != "0"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5

Generate the ARM template.
```

**Output**:
- ARM template: `sentinel-rule-multiple-failed-azure-ad-sign-in-attempts.json`
- Validation summary showing all auto-generated fields
- Deployment instructions for Azure CLI, PowerShell, Portal

### With Custom Overrides
```
@sentinel-arm-generator

Generate ARM template for this query:

DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-enc"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

Custom settings:
- Severity: High
- Description: Detects encoded PowerShell execution
- Frequency: PT15M
```

## Use Cases

1. **Threat Hunting to Production**: Convert research queries into production rules
2. **Bulk Rule Creation**: Generate multiple ARM templates consistently
3. **Rule Migration**: Update and regenerate templates for existing rules
4. **Multi-Environment Deployment**: Single template, multiple workspaces
5. **SOC Analyst Enablement**: Analysts create detection logic, skill generates templates

## Configuration

The skill accepts optional context overrides:

```python
context = {
    "display_name": "Custom Rule Name",
    "description": "Custom description",
    "severity": "High",  # High|Medium|Low|Informational
    "query_frequency": "PT5M",  # ISO 8601 duration
    "query_period": "PT5M",
    "trigger_threshold": 0,
    "mitre_tactics": ["InitialAccess", "Persistence"],
    "mitre_techniques": ["T1078", "T1543"],
    "mitre_sub_techniques": ["T1078.004"],
    "entity_mappings": [...]  # Custom entity configuration
}
```

## Project Structure

```
sentinel-arm-generator/
├── SKILL.md                      # Main skill definition (YAML + documentation)
├── README.md                     # This file
├── HOW_TO_USE.md                 # Usage examples and invocation patterns
├── sample_input.json             # Example input
├── expected_output.json          # Example output
├── scripts/
│   ├── __init__.py               # Package initialization
│   ├── generate_arm_template.py  # Main template generator
│   ├── mitre_attack_mapper.py    # MITRE ATT&CK intelligence
│   ├── entity_extractor.py       # Entity identification and mapping
│   └── kql_analyzer.py           # KQL analysis and metadata generation
└── references/
    ├── ARM_TEMPLATE.md           # ARM template structure reference
    ├── ENTITY_MAPPINGS.md        # Entity types and identifiers
    ├── MITRE_MAPPINGS.md         # MITRE tactics/techniques
    └── BEST_PRACTICES.md         # Quality checks and limitations
```

## Example Workflow

1. **Develop Detection Logic**: Create and test KQL query in Sentinel workspace
2. **Generate Template**: Use skill with your KQL query
3. **Review Auto-Mappings**: Validate MITRE tactics/techniques and entity mappings
4. **Customize if Needed**: Override any auto-generated values
5. **Deploy to Test**: Test deployment in non-production workspace
6. **Validate Execution**: Confirm rule triggers correctly
7. **Deploy to Production**: Promote to production workspace

## Intelligence Systems

### MITRE ATT&CK Database
- 30+ attack patterns mapped to MITRE framework
- Coverage across all 14 MITRE tactics
- Technique and sub-technique mapping
- Pattern-based keyword detection

### Entity Recognition
- 12+ Sentinel entity types supported
- 100+ column name patterns
- Intelligent identifier mapping
- Hash algorithm auto-detection

### Severity Classification
- Pattern-based severity assignment
- High: Active attacks, critical threats
- Medium: Suspicious behavior, policy violations
- Low: Compliance monitoring, baseline tracking
- Informational: Audit events, statistics

### Frequency Optimization
- PT5M (5 min): Real-time active threat detection
- PT15M (15 min): Near real-time suspicious activity
- PT1H (1 hour): Behavioral pattern detection
- P1D (daily): Trend analysis, compliance monitoring

## Deployment Methods

### Azure CLI
```bash
az deployment group create \
  --resource-group <resource-group-name> \
  --template-file sentinel-rule-{rule-name}.json \
  --parameters workspace=<sentinel-workspace-name>
```

### Azure PowerShell
```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName <resource-group-name> `
  -TemplateFile sentinel-rule-{rule-name}.json `
  -workspace <sentinel-workspace-name>
```

### Azure Portal
1. Navigate to Azure Portal > Deploy a custom template
2. Upload generated JSON file
3. Provide workspace parameter
4. Review and create deployment

### CI/CD Integration
- **Azure DevOps**: Use ARM template deployment task
- **GitHub Actions**: Use azure/arm-deploy action
- **Terraform**: Import as azurerm_sentinel_alert_rule_scheduled resource

## Validation and Quality

### Automatic Validation
- YAML frontmatter compliance
- ARM schema validation
- Entity mapping verification
- MITRE technique validation
- ISO 8601 duration format checking

### Transparency Features
- Validation summary shows all auto-generated fields
- Rationale provided for severity, frequency, MITRE mappings
- Detected entities and columns listed
- User overrides clearly documented

## Limitations

- **KQL Complexity**: Very complex queries may require manual entity review
- **Custom Tables**: Works best with standard Sentinel tables
- **MITRE Accuracy**: Suggestions based on patterns; unusual logic may need review
- **Scheduled Rules Only**: Does not generate Fusion, NRT, or correlation rules

## Support

- **Skill Version**: 1.0.0
- **ARM API Version**: 2023-12-01-preview
- **Template Format**: 1.0.0

## Future Enhancements

- NRT (Near Real-Time) rule template support
- Advanced alert enrichment configuration
- Automated playbook assignment
- Sentinel Content Hub integration
- Correlation rule support
- Custom alert details auto-generation

## License

This skill is part of the Claude Code Skills Factory and follows the same license terms.

---

**Ready to transform your KQL queries into production-ready Sentinel rules!**
