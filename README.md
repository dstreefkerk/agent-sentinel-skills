# Agent Sentinel Skills

Agent skills for Claude Code and other skills-compatible agents.

These skills follow the [Agent Skills specification](https://agentskills.io/specification) for broad compatibility.

## Installation

### Claude Code Marketplace

```bash
/plugin marketplace add dstreefkerk/agent-sentinel-skills
/plugin install microsoft-sentinel@agent-sentinel-skills
```

### Manual Installation (Claude Code)

Copy the `skills/` directory to a `/.claude` folder in your project root.

### Manual Installation (Codex CLI)

Copy the `skills/` directory to `~/.codex/skills`.

## Available Skills

| Skill | Description |
|-------|-------------|
| `kql-expert` | KQL query optimization, schema validation, analytics rule development, ASIM normalization, SPL migration, and best practice compliance for Microsoft Sentinel and M365 Defender |
| `sentinel-arm-generator` | Generates deployment-ready Microsoft Sentinel Analytic Rule ARM templates from KQL queries with intelligent MITRE mappings, entity extraction, and metadata generation |
| `sentinel-use-case-documentor` | Documents Microsoft Sentinel analytics rules as comprehensive SOC use cases from ARM templates or KQL detection queries |

## License

MIT
