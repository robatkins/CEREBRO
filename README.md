# Cerebro

Cerebro is a local, workspace-scoped AI coding agent for inspecting, editing, validating, and autonomously improving a codebase. It combines a manager agent, role-based sub-agents, persistent project memory, code intelligence tools, safety gates, and an interruptible self-improvement loop.

## What Cerebro Does

- Reasons about the current workspace and keeps file access confined to that workspace.
- Coordinates specialist sub-agents such as planner, architect, coder, reviewer, safety, tester, maintainer, writer, and meta.
- Reads, writes, searches, patches, validates, and reviews files through built-in tools.
- Runs autonomous improvement cycles with checkpoints, rollback support, policy checks, and per-cycle change ledgers.
- Tracks tasks, memory, user profile facts, blackboard notes, code indexes, experiments, improvement backlog items, and run history.
- Provides a terminal UI with colored `User:` and `Cerebro:` prompts, centered banner rendering, live-width dividers, bold markdown rendering, and activity/status updates.

## Requirements

- Python 3.10+ recommended.
- `openai` Python package for model calls.
- An OpenAI-compatible local or remote model endpoint. The default configuration targets LM Studio at `http://localhost:1234/v1`.
- Git is optional, but recommended for diff, status, history, and recovery workflows.
- `pytest` and `ruff` are optional, but Cerebro can use them when installed.

Install the model client if needed:

```bash
python -m pip install openai
```

## Quick Start

Run Cerebro from the workspace you want it to manage:

```bash
cd C:\path\to\your\workspace
python agent.py
```

If you are working on Cerebro itself from this repository:

```bash
cd C:\Users\maniv\Desktop\Cerebro
python agent.py
```

On first run, Cerebro creates local state files such as `.agent_config.json`, `.agent_memory.json`, `.agent_control.json`, and `.agent_checkpoints/`.

## Configuration

Cerebro reads `.agent_config.json` from the current workspace. Defaults include:

```json
{
  "provider": "lmstudio",
  "base_url": "http://localhost:1234/v1",
  "api_key": "lm-studio",
  "default_model": "local-model",
  "temperature": 0.25,
  "max_steps": 200,
  "monitor": "summary"
}
```

Each role can also have its own model through the `role_models` section. The `autonomy_policy` section controls self-improvement risk limits, changed-file limits, state-file permissions, and rollback behavior.

## Common Commands

You can talk to Cerebro in natural language. Useful examples:

```text
iteratively improve the codebase with 1 cycle
what changed in the last self-improvement cycle?
show the cycle ledger
run internal self tests
scan improvement opportunities
generate a health report
recommend a team for improving error handling
update my user profile preferred_name to Mani
```

Type `quit` or `exit` to stop the interactive session.

## Autonomous Self-Improvement

Cerebro can improve its own codebase through bounded cycles. A typical cycle:

1. Scans the workspace for improvement opportunities.
2. Selects or evaluates a backlog item.
3. Creates a checkpoint before editing.
4. Uses role-based planning, implementation, review, safety, and maintenance logic.
5. Applies file edits.
6. Runs validation when possible.
7. Records a cycle ledger entry with changed files, lines added, lines removed, net line change, validation results, and outcome notes.

Example:

```text
iteratively improve the codebase with 3 cycles
```

To interrupt a running autonomous loop cleanly, edit `.agent_control.json`:

```json
{
  "mode": "wrap_up",
  "monitor": "summary",
  "note": "Stop after the current safe checkpoint."
}
```

Supported modes:

- `continue`: keep running until the requested cycle limit is reached.
- `wrap_up`: finish the current safe unit of work, summarize, and stop.
- `stop`: stop as soon as the loop reaches a safe interruption point.

Monitor modes:

- `summary`: show live status logs while the loop runs.
- `quiet`: hide most monitor logs.

## Change Tracking

Self-improvement cycles write persistent records to `.agent_cycle_ledger.json`. Cerebro can report:

- Files changed in the latest cycle.
- Lines added, lines removed, and net line change.
- Validation commands and outcomes.
- Checkpoint paths for before/after comparison.
- A summary of what the autonomous loop attempted and completed.

The terminal output color-codes line counts: added lines are green, removed lines are red, and net change changes color based on whether the net result is positive, negative, or neutral.

## Role-Based Sub-Agents

Cerebro uses a role catalog and team templates to structure work.

Built-in roles include:

- `researcher`: gathers evidence and relevant context.
- `planner`: decomposes work into concrete steps.
- `architect`: designs durable abstractions and module boundaries.
- `coder`: implements practical code changes.
- `refactorer`: improves structure while preserving behavior.
- `reviewer`: looks for bugs, regressions, and test gaps.
- `safety`: enforces workspace, autonomy, and rollback policies.
- `critic`: challenges assumptions and weak plans.
- `tester`: designs and runs validation.
- `maintainer`: keeps persistent agent state coherent.
- `writer`: improves documentation and summaries.
- `meta`: synthesizes multiple agent outputs into a final direction.

Built-in team templates include:

- `implementation`
- `analysis`
- `validation`
- `refactoring`
- `autonomy`
- `communication`

## Built-In Tools

Cerebro registers 90+ tools across these categories:

- File tools: list, inspect, read, write, append, replace, patch, search, find TODOs, find large or recent files.
- JSON tools: read, validate, and update structured state.
- Shell and Git tools: run bounded commands, inspect status, diff, log, and branches.
- Python validation tools: compile files, validate workspace Python, run smoke tests, run pytest, run ruff, and run internal self-tests.
- Agent/team tools: list roles, recommend teams, run teams, delegate sub-agents, resolve disagreements, apply manager policy, run quality gates, and perform meta-review.
- Checkpoint/control tools: create checkpoints, summarize changes since checkpoints, restore checkpoints, read or set control state, and evaluate autonomy policy.
- Memory and task tools: remember, recall, search memory, create/update/list/complete tasks, use the blackboard, and inspect run history.
- User profile tools: show profile, update profile fields, add profile notes, and forget profile fields.
- Code intelligence tools: index code, summarize Python files, find symbols, build import/call graphs, find callers, detect orphan symbols, rank hotspots, and suggest refactor targets.
- Improvement tools: scan opportunities, select next improvement, evaluate opportunities, record outcomes, manage experiments, show learning, generate health reports, and generate planning briefs.

## Local State Files

Cerebro stores operational state in the workspace:

```text
.agent_config.json
.agent_memory.json
.agent_user_profile.json
.agent_control.json
.agent_tasks.json
.agent_blackboard.json
.agent_code_index.json
.agent_code_graph.json
.agent_code_hotspots.json
.agent_improvement_backlog.json
.agent_improvement_learning.json
.agent_experiments.json
.agent_cycle_ledger.json
.agent_runs.jsonl
.agent_checkpoints/
```

The user profile file can store identity, contact details, important dates, location, preferences, relationships, project notes, and custom facts. It is plaintext local workspace state, so do not store secrets unless you are comfortable keeping them in the project directory.

## Architecture

```text
Cerebro
|-- Terminal Interface
|   |-- colored prompts
|   |-- centered banner
|   |-- live-width dividers
|   `-- autonomous activity stream
|-- Manager Agent
|   |-- manager policy
|   |-- tool selection
|   |-- quality gates
|   `-- meta-review
|-- Role-Based Sub-Agents
|   |-- researcher / planner / architect
|   |-- coder / refactorer / reviewer
|   |-- tester / safety / critic
|   `-- maintainer / writer / meta
|-- Workspace Tools
|   |-- file operations
|   |-- shell and git integration
|   |-- Python validation
|   `-- code intelligence
|-- Persistent State
|   |-- memory, tasks, blackboard, user profile
|   |-- code index, graph, hotspots
|   |-- experiments and improvement learning
|   `-- run logs and cycle ledgers
`-- Autonomous Improvement Loop
    |-- opportunity scanning
    |-- checkpoints
    |-- implementation
    |-- validation
    |-- rollback policy
    `-- change reporting
```

## Safety and Privacy

- Cerebro resolves paths through the current workspace and blocks file access outside that workspace.
- It blocks common dangerous shell command patterns.
- Autonomous improvement cycles create checkpoints before editing.
- The autonomy policy can limit risk level, changed-file count, rollback behavior, and state-file edits.
- Model calls go to the configured OpenAI-compatible endpoint. With the default LM Studio setup, the model server is local.
- Persistent state is stored as plaintext JSON/JSONL files in the workspace.

## Development and Validation

Useful validation commands:

```bash
python -m py_compile agent.py
python -c "import agent; t=agent.AgentTools(agent.AgentState()); r=t.run_internal_self_tests(); print(r.ok, r.meta.get('checked'), len(r.meta.get('failed', [])))"
python -m pytest
python -m ruff check .
```

`pytest` and `ruff` are optional. If they are not installed, Cerebro can still run its internal checks and Python compilation validation.

## License

Proprietary AI agent software.

---

*This README was generated by Cerebro's documentation system.*
