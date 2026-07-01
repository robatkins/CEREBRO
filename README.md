# CEREBRO

**Cognitive Engine for Recursive Enhancement, Behavioral Reasoning, and Orchestration**

A local multi-agent AI assistant running on your computer to help with codebase improvement, autonomous loops, and intelligent coordination.

## 🚀 What is CEREBRO?

CEREBRO is a **local multi-agent AI system** designed to work directly within your workspace (`C:\Users\USERNAME\Desktop\CEREBRO`). It combines cognitive intelligence with bounded execution to help you:

- **Improve codebases autonomously** through interruptible improvement loops
- **Coordinate specialist sub-agents** for focused, role-based tasks
- **Manage autonomous workflows** with control states and checkpoints
- **Analyze and refactor** Python projects safely
- **Run validation cycles** before committing changes

## 🧠 Core Capabilities

### Multi-Agent Architecture
CEREBRO operates as a manager agent that orchestrates:

- **Planner**: Decomposes goals into actionable steps
- **Coder**: Implements safe, reversible code changes
- **Reviewer**: Validates and critiques results before finalization
- **Researcher**: Gathers context from documentation and tools
- **Quality Gate**: Ensures acceptance criteria are met

### Autonomous Improvement Loops
Run interruptible self-improvement cycles that:
1. Scan for improvement opportunities (complexity, hotspots, TODOs)
2. Select the highest-ranked opportunity
3. Apply safe, minimal changes with validation gates
4. Record outcomes and update learning statistics
5. Continue or wrap up based on control state

### Tool-Enhanced Intelligence
Access to **100+ tools** including:
- **Code Analysis**: Complexity ranking, import graphs, call graphs, hotspots
- **Network/IDS**: DNS resolution, port scanning, traffic analysis, baseline comparison
- **Threat Intel**: CVE lookups, malware hash checks, signature scans
- **Crypto**: AES-GCM, ChaCha20-Poly1305, Fernet encryption/decryption
- **HTTP/API**: Endpoint inspection, JSON schema inference, HTML metadata extraction
- **File Operations**: Semantic search, unified diff application, manifest generation

## 🛠️ Quick Start

### Installation
```bash
cd C:\Users\USER\Desktop\CEREBRO
pip install -r requirements.txt
```

### First Run
```bash
python agent.py
```

### Running an Improvement Cycle
```bash
# Start a self-improvement loop with 5 cycles and default roles
python agent.py --goal "improve this codebase" --max-cycles 5

# Or run through the manager interface
./agent.sh improve --goal "reduce complexity"
```

### Control States
Manage autonomous loops at any time:
```bash
# Continue current cycle
set_control_mode continue

# Wrap up and summarize
set_control_mode wrap_up

# Stop immediately
set_control_mode stop
```

## 📊 Monitoring & Telemetry

CEREBRO tracks its own health through:
- **Cycle Ledger**: Records each improvement attempt with outcomes
- **Blackboard**: Shared multi-agent memory for facts and observations
- **Run History**: Tool call success/failure metrics
- **Workspace Stats**: File counts, sizes, extension distribution

View current state:
```bash
cat .agent_cycle_ledger.json
cat .agent_blackboard.json
```

## 🔧 Configuration

### Agent Config (`.agent_config.json`)
```json
{
  "name": "CEREBRO",
  "version": "1.0.0",
  "max_cycles": 5,
  "default_roles": ["planner", "coder", "reviewer"],
  "tool_registry_path": ".agent_tool_registry.json"
}
```

### External Tools (`.agent_external_tools.json`)
Declare safe external commands like `bandit_scan`, `ruff_check`, or custom scanners.

## 🧪 Validation & Testing

Before committing changes, CEREBRO runs:
- **Compile checks**: Python syntax validation
- **Smoke tests**: Import and basic functionality verification
- **Optional linters**: Ruff/Flake8 if available
- **Git status**: Ensure clean working directory

## 📁 Workspace Structure

```
CEREBRO/
├── agent.py              # Main entry point
├── requirements.txt      # Python dependencies
├── .agent_config.json    # Agent configuration
├── .agent_external_tools.json  # External tool declarations
├── README.md            # This file
├── .agent_checkpoints/   # Self-improvement checkpoints
├── .agent_cycle_ledger.json  # Improvement history
└── .agent_blackboard.json      # Multi-agent memory
```

## 🎯 Example Workflows

### 1. Autonomous Codebase Improvement
```bash
python agent.py --goal "improve this codebase"
# Scans for complexity hotspots, TODOs, orphaned functions
# Selects highest-ranked opportunity
# Applies minimal, validated changes
```

### 2. Network Intelligence Brief
```bash
python agent.py --goal "build network intel brief for example.com"
# Resolves DNS, scans ports (if authorized), inspects TLS
# Builds security headers report
# Returns concise user-facing summary
```

### 3. Threat Intel Enrichment
```bash
python agent.py --goal "lookup CVE-2024-3094"
# Fetches NVD data, checks CISA KEV status
# Returns severity, affected products, mitigation hints
```

## 🔐 Security & Privacy

- **Local-first**: All processing happens on your machine
- **Bounded execution**: Tools have workspace path guards and timeouts
- **SSRF protection**: HTTP tools deny local/private hosts unless allowed
- **Metadata-only traffic capture**: No payload extraction by default
- **Redacted secrets**: Config scanner identifies exposed credentials

## 📈 Performance Tips

1. **Install `cryptography`** for faster encryption (AES-GCM, ChaCha20)
2. **Use role-based sub-agents** for bounded specialist work
3. **Monitor cycle ledger** to track improvement success rates
4. **Set control mode** before long-running autonomous loops
5. **Checkpoint frequently** during substantial refactoring

## 🤝 Contributing

To extend CEREBRO:
1. Add new tools to the registry
2. Create role templates for common tasks
3. Update prompts in manager/role/self-improvement files
4. Document new capabilities in this README

## 📄 License

MIT License - See LICENSE file for details.

---

*This README was generated by Cerebro's documentation system.*
