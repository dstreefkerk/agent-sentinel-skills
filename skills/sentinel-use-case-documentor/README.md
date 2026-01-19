# Sentinel Use Case Documentor

**Version**: 2.0
**Category**: Security Operations / SIEM
**Platform**: Microsoft Sentinel

Transforms Sentinel ARM template exports into comprehensive SOC use case documentation following industry-standard templates.

## Features

- **ARM Template Parsing**: Extracts tactics, techniques, severity, entity mappings, and query details
- **KQL Analysis**: Identifies tables, thresholds, timeframes, and embedded documentation comments
- **Intelligent Inference**: Maps tactics to problem statements, kill chain phases, and compliance frameworks
- **Two Documentation Modes**: Quick (batch-friendly) or Guided (interactive Q&A)
- **MCP Integration**: Optional enhancement via mitreattack, MS-Sentinel-MCP-Server, and detection-nexus servers

## Installation

### User-Level (All Projects)

```bash
cp -r sentinel-use-case-documentor ~/.claude/skills/
```

### Project-Level

```bash
cp -r sentinel-use-case-documentor .claude/skills/
```

## Quick Start

```
Document this Sentinel rule: @exported_rule.json
```

```
Create SOC use case documentation for @Azure_Sentinel_analytic_rule.json
```

## Documentation Modes

| Mode | Best For | Behavior |
|------|----------|----------|
| **Quick** | Batch processing, time-sensitive | Generates with `[HUMAN INPUT REQUIRED]` placeholders |
| **Guided** | Critical rules, compliance audits | Interactive Q&A before generating |

## Output

Generates `{filename}_UseCase.md` with:

- Use Case Metadata (ID, purpose, problem statement)
- SMART Objectives
- SOC Notification procedures
- Data Source descriptions
- Detection Logic (KQL query + parameters)
- MITRE ATT&CK Mapping
- Cyber Kill Chain Analysis
- SOC Response Procedures
- Assumptions & Limitations
- Deliverable Profile & Version History

## Project Structure

```
sentinel-use-case-documentor/
├── SKILL.md                  # Main skill instructions
├── README.md                 # This file
├── HOW_TO_USE.md             # Quick start guide
├── sample_input.json         # Example ARM template
├── expected_output.md        # Example output
└── references/
    ├── TEMPLATE.md           # Copyable use case template
    ├── FORMS.md              # Section-by-section guide
    ├── REFERENCE.md          # Technical reference (ARM, KQL, mappings)
    └── MCP_INTEGRATION.md    # MCP server integration guide
```

## Optional MCP Enhancement

When available, these MCP servers enrich documentation:

- **mitreattack**: Official MITRE ATT&CK technique descriptions
- **MS-Sentinel-MCP-Server**: Validate KQL syntax and table schemas
- **detection-nexus**: Find related detections across platforms

See `references/MCP_INTEGRATION.md` for details.

## License

MIT License - Part of the Claude Code Skills Factory.
