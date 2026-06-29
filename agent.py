from __future__ import annotations

import ast
import difflib
import json
import re
import shlex
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from openai import OpenAI
except ImportError:  # Keep local validation tools importable without optional client deps.
    OpenAI = None


WORKSPACE_ROOT = Path.cwd().resolve()
CONFIG_FILE = WORKSPACE_ROOT / ".agent_config.json"
MEMORY_FILE = WORKSPACE_ROOT / ".agent_memory.json"
RUN_LOG_FILE = WORKSPACE_ROOT / ".agent_runs.jsonl"
CONTROL_FILE = WORKSPACE_ROOT / ".agent_control.json"
CHECKPOINT_DIR = WORKSPACE_ROOT / ".agent_checkpoints"
TASKS_FILE = WORKSPACE_ROOT / ".agent_tasks.json"
BLACKBOARD_FILE = WORKSPACE_ROOT / ".agent_blackboard.json"
CODE_INDEX_FILE = WORKSPACE_ROOT / ".agent_code_index.json"
IMPROVEMENT_BACKLOG_FILE = WORKSPACE_ROOT / ".agent_improvement_backlog.json"
MODEL = "local-model"
MAX_STEPS = 12
MAX_BATCH_ACTIONS = 3
MAX_FILE_CHARS = 16000
MAX_SUBAGENT_STEPS = 6
MAX_SUBAGENT_DEPTH = 2
MAX_TEAM_ROLES = 4
DEFAULT_SELF_IMPROVE_CYCLES = 5
DEFAULT_MONITOR_MODE = "summary"
MAX_DIFF_CHARS = 12000
MAX_ROLE_HISTORY = 24

TOOL_RISK_READ_ONLY = "read_only"
TOOL_RISK_WRITE_FILE = "write_file"
TOOL_RISK_RUN_COMMAND = "run_command"
TOOL_RISK_AGENTIC = "agentic"
TOOL_RISK_MEMORY = "memory"
TOOL_RISK_CONTROL = "control"


ROLE_CATALOG: dict[str, dict[str, str]] = {
    "researcher": {
        "summary": "Investigates files, gathers evidence, and surfaces relevant facts quickly.",
        "strengths": "Search, context gathering, evidence synthesis",
        "failure_modes": "Can over-collect context without narrowing scope",
    },
    "planner": {
        "summary": "Breaks work into concrete steps, dependencies, and execution order.",
        "strengths": "Task decomposition, sequencing, constraint handling",
        "failure_modes": "Can stay abstract unless paired with implementers",
    },
    "coder": {
        "summary": "Implements code changes and proposes practical technical solutions.",
        "strengths": "Implementation, refactoring, concrete edits",
        "failure_modes": "Can optimize locally without enough review",
    },
    "reviewer": {
        "summary": "Looks for bugs, regressions, edge cases, and testing gaps.",
        "strengths": "Risk identification, correctness review, regression spotting",
        "failure_modes": "Can be conservative and improvement-limiting if used alone",
    },
    "critic": {
        "summary": "Challenges weak assumptions, identifies missing evidence, and stress-tests proposals.",
        "strengths": "Adversarial thinking, assumption checking, robustness",
        "failure_modes": "Can over-index on critique without offering concrete next steps",
    },
    "tester": {
        "summary": "Designs validation steps, checks behavior, and focuses on reproducibility.",
        "strengths": "Validation planning, failure reproduction, verification",
        "failure_modes": "Can stall if asked to validate without runnable hooks",
    },
    "writer": {
        "summary": "Drafts clean text, summaries, and structured documentation.",
        "strengths": "Communication, concise summaries, documentation polish",
        "failure_modes": "Can sound polished without adding technical depth",
    },
    "meta": {
        "summary": "Synthesizes multi-agent outputs into a stronger final direction or answer.",
        "strengths": "Cross-agent synthesis, conflict resolution, final tightening",
        "failure_modes": "Can compress detail too aggressively if inputs are weak",
    },
}


TEAM_TEMPLATES: dict[str, dict[str, Any]] = {
    "implementation": {
        "roles": ["planner", "coder", "reviewer"],
        "use_when": "Feature building, refactoring, or codebase improvements need implementation plus review.",
    },
    "analysis": {
        "roles": ["researcher", "planner", "critic"],
        "use_when": "Ambiguous problems need evidence gathering and strategy formation before editing.",
    },
    "validation": {
        "roles": ["coder", "tester", "reviewer"],
        "use_when": "Changes exist and the main need is tightening correctness and validation confidence.",
    },
    "communication": {
        "roles": ["researcher", "writer", "meta"],
        "use_when": "The task needs strong synthesis or documentation more than deep implementation.",
    },
}


def default_config() -> dict[str, Any]:
    role_models = {role: MODEL for role in ROLE_CATALOG}
    return {
        "provider": "lmstudio",
        "base_url": "http://localhost:1234/v1",
        "api_key": "lm-studio",
        "default_model": MODEL,
        "temperature": 0.25,
        "max_steps": MAX_STEPS,
        "max_batch_actions": MAX_BATCH_ACTIONS,
        "monitor": DEFAULT_MONITOR_MODE,
        "role_models": role_models,
    }


def load_config() -> dict[str, Any]:
    defaults = default_config()
    if not CONFIG_FILE.exists():
        save_config(defaults)
        return defaults

    try:
        parsed = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return defaults
    if not isinstance(parsed, dict):
        return defaults

    config = defaults | parsed
    role_models = defaults["role_models"] | parsed.get("role_models", {})
    config["role_models"] = {
        role: str(role_models.get(role, config["default_model"]))
        for role in ROLE_CATALOG
    }
    config["max_steps"] = max(1, int(config.get("max_steps", MAX_STEPS)))
    config["max_batch_actions"] = max(1, int(config.get("max_batch_actions", MAX_BATCH_ACTIONS)))
    config["temperature"] = float(config.get("temperature", 0.25))
    if config.get("monitor") not in {"quiet", "summary"}:
        config["monitor"] = DEFAULT_MONITOR_MODE
    return config


def save_config(config: dict[str, Any]) -> None:
    CONFIG_FILE.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")


def get_role_model(role: str) -> str:
    config = load_config()
    return str(config.get("role_models", {}).get(role, config.get("default_model", MODEL)))


def get_client() -> OpenAI:
    if OpenAI is None:
        raise RuntimeError("The openai package is required for model calls but is not installed.")
    config = load_config()
    return OpenAI(
        base_url=str(config.get("base_url", "http://localhost:1234/v1")),
        api_key=str(config.get("api_key", "lm-studio")),
    )


SYSTEM_PROMPT = f"""
You are Cerebro, a local AI agent running on the user's computer.
You operate only inside this workspace: {WORKSPACE_ROOT}

You are the primary manager agent. Your job is to reason, inspect evidence,
edit files safely, coordinate specialist sub-agents, run autonomous improvement
loops when asked, and finish with a concrete result.

Respond in exactly one of these JSON formats:

1) Single tool call
{{
  "type": "tool",
  "tool": "tool_name",
  "args": {{}},
  "why": "brief reason"
}}

2) Batch tool calls
{{
  "type": "batch",
  "why": "brief reason for grouping these actions",
  "actions": [
    {{"tool": "tool_name", "args": {{}}}},
    {{"tool": "tool_name", "args": {{}}}}
  ]
}}

3) Final answer
{{
  "type": "final",
  "content": "final answer to the user",
  "summary": "one-sentence completion summary"
}}

Manager policy:
- For simple tasks, work directly.
- For ambiguous, multi-step, or quality-sensitive tasks, consult manager_policy.
- Use role-based sub-agents for bounded specialist work.
- Use meta_review or run_team before finalizing if delegation produced multiple partial outputs.
- Use self_improve_codebase for long-running autonomous improvement requests.

Rules:
- Prefer evidence from tools over guessing.
- Keep file access inside the workspace.
- Do not run destructive or system-altering commands.
- Prefer file tools over shell commands for code changes.
- Store durable findings in memory when they may help later.
- Respect the control file during autonomous loops so a human can ask the agent to wrap up or stop.

Available tools and JSON arg schemas:
- list_files: {{"path": ".", "recursive": false}}
- inspect_path: {{"path": "."}}
- read_file: {{"path": "relative/path.py"}}
- write_file: {{"path": "notes.txt", "content": "...", "overwrite": false}}
- append_file: {{"path": "log.txt", "content": "..."}}
- replace_in_file: {{"path": "app.py", "old": "x", "new": "y", "count": 1}}
- search_files: {{"pattern": "text or regex", "path": "."}}
- run_command: {{"command": "dir"}}
- list_roles: {{}}
- list_team_templates: {{}}
- manager_policy: {{"task": "user objective", "context": "optional context"}}
- manager_execute: {{"task": "objective", "context": "optional context", "template": "implementation", "roles": ["planner", "coder", "reviewer"]}}
- delegate_subagent: {{"role": "researcher", "task": "analyze X", "context": "optional extra context"}}
- resolve_disagreement: {{"task": "objective", "team_report": "...", "context": "optional context"}}
- quality_gate: {{"objective": "goal", "candidate": "candidate result", "context": "optional context"}}
- show_role_telemetry: {{}}
- run_team: {{"task": "objective", "roles": ["planner", "coder", "reviewer"], "context": "optional context"}}
- meta_review: {{"objective": "goal", "draft": "candidate answer", "context": "optional context"}}
- create_checkpoint: {{"label": "before-cycle-1"}}
- summarize_changes_since_checkpoint: {{"checkpoint": ".agent_checkpoints/..." }}
- validate_python_file: {{"path": "agent.py"}}
- validate_workspace_python: {{"path": ".", "recursive": true}}
- read_control_state: {{}}
- set_control_mode: {{"mode": "continue|wrap_up|stop", "note": "optional note", "monitor": "quiet|summary"}}
- self_improve_codebase: {{"goal": "improve this codebase", "max_cycles": 5, "roles": ["planner", "coder", "reviewer"]}}
- scan_improvement_opportunities: {{"goal": "improve this codebase"}}
- update_plan: {{"items": ["step 1", "step 2"]}}
- show_plan: {{}}
- remember: {{"key": "topic", "value": "durable fact"}}
- recall: {{"key": "topic"}}
- search_memory: {{"query": "topic", "limit": 5}}
- show_history: {{"limit": 8}}
"""


MANAGER_POLICY_PROMPT = """
You are Cerebro's manager-policy agent.

Given a task and context, decide whether the work should be:
- handled directly
- delegated to one specialist
- delegated to a small team
- sent to meta review before final output

Return JSON only in this format:
{
  "mode": "direct|single|team",
  "template": "implementation|analysis|validation|communication|custom",
  "roles": ["planner", "coder"],
  "needs_meta_review": true,
  "confidence": "low|medium|high",
  "rationale": "brief explanation",
  "plan": ["step 1", "step 2"]
}

Keep the role list short and practical. Prefer a named template when one fits.
"""


META_AGENT_PROMPT = f"""
You are Cerebro's meta-agent operating inside this workspace: {WORKSPACE_ROOT}

Your job is to improve the quality of a candidate result by:
- combining multiple sub-agent outputs
- spotting contradictions or missing pieces
- tightening the final recommendation

Return JSON only using the standard schema. Prefer a final answer unless you
truly need one more tool call.
"""


DISAGREEMENT_AGENT_PROMPT = f"""
You are Cerebro's disagreement-resolution agent operating inside this workspace: {WORKSPACE_ROOT}

Your job is to inspect team outputs, identify conflicts or weak points, and
return a stronger merged recommendation or a narrow next step.

Return JSON only using the standard schema. Prefer a final answer unless one
extra tool action is necessary.
"""


QUALITY_GATE_PROMPT = f"""
You are Cerebro's quality-gate agent operating inside this workspace: {WORKSPACE_ROOT}

Your job is to decide whether a candidate result is ready to use. Check for:
- completion against the objective
- unresolved contradictions
- validation or test gaps
- excessive risk or scope drift
- whether a narrow follow-up action is needed

Return JSON only using the standard schema. Prefer a final answer containing a
compact readiness assessment with pass/fail, risks, and next action.
"""


SELF_IMPROVEMENT_REVIEW_PROMPT = """
You are Cerebro's self-improvement review agent.

You will receive the current improvement goal, the cycle number, the latest
team/meta results, and the external control mode.

Return JSON only in this format:
{
  "continue_improving": true,
  "wrap_up_now": false,
  "next_focus": "what to improve next",
  "summary": "what was accomplished this cycle",
  "reason": "why continue or stop"
}

Rules:
- If control mode is wrap_up, set wrap_up_now to true.
- If control mode is stop, set continue_improving to false and wrap_up_now to true.
- Stop when the latest cycle seems to reach a good local stopping point.
"""


def build_role_system_prompt(role: str) -> str:
    role_profile = ROLE_CATALOG.get(role, {})
    role_description = role_profile.get("summary", "Specialist sub-agent for bounded delegated work.")
    strengths = role_profile.get("strengths", "Use your role effectively.")
    failure_modes = role_profile.get("failure_modes", "Avoid drifting outside your scope.")
    return f"""
You are Cerebro's {role} sub-agent.
Workspace: {WORKSPACE_ROOT}

Role focus:
{role_description}

Strengths:
{strengths}

Watch-outs:
{failure_modes}

Operating rules:
- Work only inside the workspace.
- Prefer concrete evidence over guesses.
- Keep scope narrow and useful to the parent agent.
- Do not ask to talk to the end user directly.
- Do not expose chain-of-thought.
- Return JSON only using the standard schema: tool, batch, or final.
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def trim_text(text: str, max_chars: int = MAX_FILE_CHARS) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]"


def render_terminal_markdown(text: str) -> str:
    if not sys.stdout.isatty():
        return text

    def bold(match: re.Match[str]) -> str:
        return f"\033[1m{match.group(1)}\033[0m"

    return re.sub(r"\*\*([^\n]+?)\*\*", bold, text)


def terminal_color(text: str, color_code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{color_code}m{text}\033[0m"


def resolve_workspace_path(raw_path: str | None) -> Path:
    candidate = (WORKSPACE_ROOT / (raw_path or ".")).resolve()
    if candidate != WORKSPACE_ROOT and WORKSPACE_ROOT not in candidate.parents:
        raise ValueError("Path escapes the workspace.")
    return candidate


def workspace_relative(path: Path) -> str:
    return str(path.relative_to(WORKSPACE_ROOT))


def should_skip_checkpoint_path(path: Path) -> bool:
    rel = path.relative_to(WORKSPACE_ROOT)
    parts = set(rel.parts)
    return any(
        name in parts
        for name in {".git", ".agent_checkpoints", "__pycache__"}
    )


def iter_workspace_files(base: Path) -> list[Path]:
    files: list[Path] = []
    for item in base.rglob("*"):
        if item.is_file() and not should_skip_checkpoint_path(item):
            files.append(item)
    return files


def default_control_state() -> dict[str, Any]:
    return {
        "mode": "continue",
        "monitor": DEFAULT_MONITOR_MODE,
        "note": "",
        "updated_at": utc_now(),
    }


def load_control_state() -> dict[str, Any]:
    if not CONTROL_FILE.exists():
        state = default_control_state()
        CONTROL_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return state

    try:
        parsed = json.loads(CONTROL_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        parsed = {}

    state = default_control_state()
    if isinstance(parsed, dict):
        state["mode"] = str(parsed.get("mode", state["mode"]))
        state["monitor"] = str(parsed.get("monitor", state["monitor"]))
        state["note"] = str(parsed.get("note", state["note"]))
        state["updated_at"] = str(parsed.get("updated_at", state["updated_at"]))
    return state


def save_control_state(mode: str, note: str = "", monitor: str | None = None) -> dict[str, Any]:
    if mode not in {"continue", "wrap_up", "stop"}:
        raise ValueError("mode must be one of: continue, wrap_up, stop")
    monitor_value = monitor or load_control_state().get("monitor", DEFAULT_MONITOR_MODE)
    if monitor_value not in {"quiet", "summary"}:
        raise ValueError("monitor must be one of: quiet, summary")
    state = {
        "mode": mode,
        "monitor": monitor_value,
        "note": note,
        "updated_at": utc_now(),
    }
    CONTROL_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state


def monitor_enabled() -> bool:
    return load_control_state().get("monitor") == "summary"


def emit_monitor(message: str, *, force: bool = False) -> None:
    if force or monitor_enabled():
        print(render_terminal_markdown(f"[monitor] {message}"))


def load_memory() -> dict[str, str]:
    if not MEMORY_FILE.exists():
        return {}
    try:
        data = json.loads(MEMORY_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if isinstance(data, dict):
        return {str(key): str(value) for key, value in data.items()}
    return {}


def save_memory(memory: dict[str, str]) -> None:
    MEMORY_FILE.write_text(json.dumps(memory, indent=2, sort_keys=True), encoding="utf-8")


def default_tasks() -> dict[str, Any]:
    return {"tasks": []}


def load_tasks() -> dict[str, Any]:
    if not TASKS_FILE.exists():
        TASKS_FILE.write_text(json.dumps(default_tasks(), indent=2), encoding="utf-8")
    try:
        data = json.loads(TASKS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        data = default_tasks()
    return data if isinstance(data, dict) and isinstance(data.get("tasks"), list) else default_tasks()


def save_tasks(data: dict[str, Any]) -> None:
    TASKS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def default_blackboard() -> dict[str, Any]:
    return {
        "objective": "",
        "facts": [],
        "hypotheses": [],
        "decisions": [],
        "risks": [],
        "todo": [],
        "agent_notes": [],
    }


def load_blackboard() -> dict[str, Any]:
    if not BLACKBOARD_FILE.exists():
        BLACKBOARD_FILE.write_text(json.dumps(default_blackboard(), indent=2), encoding="utf-8")
    try:
        data = json.loads(BLACKBOARD_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        data = default_blackboard()
    board = default_blackboard()
    if isinstance(data, dict):
        for key in board:
            value = data.get(key, board[key])
            board[key] = value if isinstance(value, type(board[key])) else board[key]
    return board


def save_blackboard(board: dict[str, Any]) -> None:
    BLACKBOARD_FILE.write_text(json.dumps(board, indent=2), encoding="utf-8")


def default_improvement_backlog() -> dict[str, Any]:
    return {
        "generated_at": "",
        "goal": "",
        "opportunities": [],
    }


def load_improvement_backlog() -> dict[str, Any]:
    if not IMPROVEMENT_BACKLOG_FILE.exists():
        return default_improvement_backlog()
    try:
        data = json.loads(IMPROVEMENT_BACKLOG_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default_improvement_backlog()
    return data if isinstance(data, dict) else default_improvement_backlog()


def save_improvement_backlog(backlog: dict[str, Any]) -> None:
    IMPROVEMENT_BACKLOG_FILE.write_text(json.dumps(backlog, indent=2), encoding="utf-8")


def run_subprocess(command: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=WORKSPACE_ROOT,
    )


def render_completed_process(result: subprocess.CompletedProcess[str]) -> str:
    payload = {
        "returncode": result.returncode,
        "stdout": trim_text(result.stdout.strip(), 8000),
        "stderr": trim_text(result.stderr.strip(), 8000),
    }
    return json.dumps(payload, indent=2)


def safe_extra_args(extra_args: str) -> list[str]:
    if not extra_args.strip():
        return []
    args = shlex.split(extra_args, posix=False)
    blocked = {";", "&&", "||", "|", ">", ">>", "<"}
    if any(part in blocked for part in args):
        raise ValueError("extra_args contains shell control tokens")
    return args


def validate_unified_diff_paths(diff: str) -> tuple[bool, str]:
    for line in diff.splitlines():
        if not (line.startswith("--- ") or line.startswith("+++ ")):
            continue
        raw = line[4:].strip().split("\t", 1)[0]
        if raw == "/dev/null":
            continue
        if raw.startswith(("a/", "b/")):
            raw = raw[2:]
        candidate = Path(raw)
        if candidate.is_absolute():
            return False, f"Diff references absolute path: {raw}"
        try:
            resolve_workspace_path(raw)
        except ValueError:
            return False, f"Diff path escapes workspace: {raw}"
    return True, "ok"


def ask_model(
    messages: list[dict[str, str]],
    *,
    model: str | None = None,
    temperature: float | None = None,
) -> str:
    config = load_config()
    response = get_client().chat.completions.create(
        model=model or str(config.get("default_model", MODEL)),
        messages=messages,
        temperature=config.get("temperature", 0.25) if temperature is None else temperature,
    )
    return response.choices[0].message.content or ""


def strip_markdown_fences(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    stripped = re.sub(r"^```(?:json|JSON)?\s*", "", stripped)
    stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def extract_first_json_object(text: str) -> str | None:
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text[start:], start=start):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def repair_json_with_model(reply: str) -> dict[str, Any]:
    prompt = (
        "Repair this malformed agent action into valid JSON only. "
        "Use one of type=tool, batch, final. If the intent is unclear, "
        "return a final action with the original text as content.\n\n"
        f"Malformed reply:\n{reply}"
    )
    try:
        repaired = ask_model(
            [
                {"role": "system", "content": "You repair malformed JSON. Return JSON only."},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
        )
        parsed = json.loads(strip_markdown_fences(repaired))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def configured_max_batch_actions() -> int:
    try:
        return max(1, int(load_config().get("max_batch_actions", MAX_BATCH_ACTIONS)))
    except (TypeError, ValueError):
        return MAX_BATCH_ACTIONS


def validate_action_shape(action: dict[str, Any], tool_names: set[str] | None = None) -> tuple[bool, str]:
    action_type = action.get("type")
    if action_type not in {"tool", "batch", "final"}:
        return False, "type must be one of: tool, batch, final"
    if action_type == "final":
        content = action.get("content")
        return (isinstance(content, str), "final actions must include string content")
    if action_type == "tool":
        tool = action.get("tool")
        if not isinstance(tool, str) or not tool:
            return False, "tool actions must specify a tool name"
        if tool_names is not None and tool not in tool_names:
            return False, f"unknown tool: {tool}"
        if not isinstance(action.get("args", {}), dict):
            return False, "tool args must be a JSON object"
        return True, "ok"
    actions = action.get("actions")
    if not isinstance(actions, list):
        return False, "batch actions must be a list"
    if len(actions) > configured_max_batch_actions():
        return False, f"batch actions exceed max of {configured_max_batch_actions()}"
    for item in actions:
        if not isinstance(item, dict):
            return False, "each batch action must be an object"
        ok, reason = validate_action_shape({"type": "tool", **item}, tool_names=tool_names)
        if not ok:
            return False, f"invalid batch action: {reason}"
    return True, "ok"


def parse_model_reply(reply: str, tool_names: set[str] | None = None) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    try:
        parsed = json.loads(reply)
        if isinstance(parsed, dict):
            candidates.append(parsed)
    except json.JSONDecodeError:
        pass

    fenced = strip_markdown_fences(reply)
    if fenced != reply.strip():
        try:
            parsed = json.loads(fenced)
            if isinstance(parsed, dict):
                candidates.append(parsed)
        except json.JSONDecodeError:
            pass

    extracted = extract_first_json_object(reply)
    if extracted:
        try:
            parsed = json.loads(extracted)
            if isinstance(parsed, dict):
                candidates.append(parsed)
        except json.JSONDecodeError:
            pass

    if not candidates and "{" in reply:
        repaired = repair_json_with_model(reply)
        if repaired:
            candidates.append(repaired)

    for candidate in candidates:
        ok, reason = validate_action_shape(candidate, tool_names=tool_names)
        if ok:
            return candidate
        log_run_event("invalid_action_shape", {"reason": reason, "candidate": candidate})

    if reply.startswith("TOOL:"):
        lines = reply.splitlines()
        tool_name = lines[0].replace("TOOL:", "").strip()
        arg_line = next((line for line in lines if line.startswith("ARG:")), "")
        arg = arg_line.replace("ARG:", "").strip()
        legacy = {
            "type": "tool",
            "tool": tool_name,
            "args": {"command": arg} if tool_name == "run_command" else {"path": arg},
            "why": "legacy tool format",
        }
        ok, _ = validate_action_shape(legacy, tool_names=tool_names)
        if ok:
            return legacy

    return {
        "type": "final",
        "content": reply,
        "summary": "Model returned an unstructured final answer.",
    }


def parse_json_object(reply: str) -> dict[str, Any]:
    for candidate in (reply, strip_markdown_fences(reply), extract_first_json_object(reply) or ""):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def parse_json_value(reply: str) -> Any:
    try:
        return json.loads(reply)
    except json.JSONDecodeError:
        return reply


def normalize_batch_actions(actions: Any) -> list[dict[str, Any]]:
    if not isinstance(actions, list):
        return []
    normalized: list[dict[str, Any]] = []
    for action in actions[:configured_max_batch_actions()]:
        if not isinstance(action, dict):
            continue
        tool_name = action.get("tool")
        args = action.get("args", {})
        if isinstance(tool_name, str) and isinstance(args, dict):
            normalized.append({"tool": tool_name, "args": args})
    return normalized


def log_run_event(event_type: str, payload: dict[str, Any]) -> None:
    entry = {
        "time": utc_now(),
        "event": event_type,
        "payload": payload,
    }
    with RUN_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=True) + "\n")


@dataclass
class ToolResult:
    ok: bool
    content: str
    meta: dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        status = "OK" if self.ok else "ERROR"
        return f"[{status}]\n{self.content}"


@dataclass
class ToolSpec:
    name: str
    description: str
    schema: dict[str, Any]
    risk: str
    function: Callable[..., ToolResult]


@dataclass
class AgentState:
    plan: list[str] = field(default_factory=list)
    memory: dict[str, str] = field(default_factory=load_memory)
    tool_history: list[dict[str, Any]] = field(default_factory=list)
    reflections: list[str] = field(default_factory=list)
    subagent_reports: list[dict[str, Any]] = field(default_factory=list)
    role_telemetry: dict[str, dict[str, Any]] = field(default_factory=dict)
    manager_decisions: list[dict[str, Any]] = field(default_factory=list)
    meta_reviews: list[dict[str, Any]] = field(default_factory=list)
    autonomous_runs: list[dict[str, Any]] = field(default_factory=list)
    consecutive_failures: int = 0
    turns_completed: int = 0

    def record_tool_event(self, tool_name: str, args: dict[str, Any], result: ToolResult) -> None:
        self.consecutive_failures = 0 if result.ok else self.consecutive_failures + 1
        self.tool_history.append(
            {
                "time": utc_now(),
                "tool": tool_name,
                "args": args,
                "ok": result.ok,
                "preview": trim_text(result.content, 400),
            }
        )
        self.tool_history = self.tool_history[-120:]

    def add_reflection(self, note: str) -> None:
        cleaned = note.strip()
        if cleaned:
            self.reflections.append(cleaned)
            self.reflections = self.reflections[-12:]

    def record_subagent_report(self, role: str, task: str, result: ToolResult) -> None:
        self.subagent_reports.append(
            {
                "time": utc_now(),
                "role": role,
                "task": trim_text(task, 200),
                "ok": result.ok,
                "preview": trim_text(result.content, 500),
            }
        )
        self.subagent_reports = self.subagent_reports[-16:]
        telemetry = self.role_telemetry.setdefault(
            role,
            {"calls": 0, "successes": 0, "failures": 0, "recent_tasks": []},
        )
        telemetry["calls"] += 1
        if result.ok:
            telemetry["successes"] += 1
        else:
            telemetry["failures"] += 1
        telemetry["recent_tasks"].append(
            {
                "time": utc_now(),
                "task": trim_text(task, 120),
                "ok": result.ok,
            }
        )
        telemetry["recent_tasks"] = telemetry["recent_tasks"][-MAX_ROLE_HISTORY:]

    def record_manager_decision(self, decision: dict[str, Any]) -> None:
        self.manager_decisions.append(
            {
                "time": utc_now(),
                "decision": decision,
            }
        )
        self.manager_decisions = self.manager_decisions[-8:]

    def record_meta_review(self, objective: str, result: ToolResult) -> None:
        self.meta_reviews.append(
            {
                "time": utc_now(),
                "objective": trim_text(objective, 160),
                "ok": result.ok,
                "preview": trim_text(result.content, 500),
            }
        )
        self.meta_reviews = self.meta_reviews[-8:]

    def record_autonomous_run(self, report: dict[str, Any]) -> None:
        self.autonomous_runs.append(report)
        self.autonomous_runs = self.autonomous_runs[-6:]

    def context_summary(self) -> str:
        plan_text = "\n".join(f"- {item}" for item in self.plan) or "- no plan yet"
        memory_keys = ", ".join(sorted(self.memory.keys())[:15]) or "(empty)"
        recent_history = self.tool_history[-5:]
        recent_text = "\n".join(
            f"- {item['tool']} ok={item['ok']} args={json.dumps(item['args'])}"
            for item in recent_history
        ) or "- no tool history yet"
        reflections_text = "\n".join(f"- {item}" for item in self.reflections[-3:]) or "- none"
        subagent_text = "\n".join(
            f"- role={item['role']} ok={item['ok']} task={item['task']}"
            for item in self.subagent_reports[-3:]
        ) or "- none"
        manager_text = "\n".join(
            f"- mode={item['decision'].get('mode')} roles={item['decision'].get('roles', [])}"
            for item in self.manager_decisions[-2:]
        ) or "- none"
        meta_text = "\n".join(
            f"- objective={item['objective']} ok={item['ok']}"
            for item in self.meta_reviews[-2:]
        ) or "- none"
        role_text = "\n".join(
            f"- {role}: calls={stats.get('calls', 0)} success={stats.get('successes', 0)} fail={stats.get('failures', 0)}"
            for role, stats in sorted(self.role_telemetry.items())
        ) or "- none"
        auto_text = "\n".join(
            f"- goal={item.get('goal')} cycles={item.get('cycles_completed')} stopped={item.get('stop_reason')}"
            for item in self.autonomous_runs[-2:]
        ) or "- none"
        return (
            f"Plan:\n{plan_text}\n\n"
            f"Memory keys: {memory_keys}\n"
            f"Turns completed: {self.turns_completed}\n"
            f"Consecutive tool failures: {self.consecutive_failures}\n\n"
            f"Recent tool history:\n{recent_text}\n\n"
            f"Recent reflections:\n{reflections_text}\n\n"
            f"Recent manager decisions:\n{manager_text}\n\n"
            f"Recent sub-agent reports:\n{subagent_text}\n\n"
            f"Recent meta reviews:\n{meta_text}\n\n"
            f"Role telemetry:\n{role_text}\n\n"
            f"Recent autonomous runs:\n{auto_text}"
        )


def build_tool_feedback(executed: list[tuple[str, ToolResult]], state: AgentState) -> str:
    sections = []
    for tool_name, result in executed:
        sections.append(f"Tool result for {tool_name}:\n{result.render()}")
    sections.append(f"Updated state:\n{state.context_summary()}")
    return "\n\n".join(sections)


def run_agent(
    user_input: str,
    state: AgentState | None = None,
    *,
    system_prompt: str = SYSTEM_PROMPT,
    max_steps: int | None = None,
    depth: int = 0,
    model: str | None = None,
    temperature: float | None = None,
) -> str:
    state = state or AgentState()
    tools = AgentTools(state, depth=depth)
    state.turns_completed += 1
    step_limit = max_steps or int(load_config().get("max_steps", MAX_STEPS))
    prompt = system_prompt
    if system_prompt == SYSTEM_PROMPT:
        prompt = f"{system_prompt}\n\nRegistered tool specs:\n{tools.render_tool_prompt()}"

    messages = [
        {"role": "system", "content": prompt},
        {"role": "system", "content": state.context_summary()},
        {"role": "user", "content": user_input},
    ]
    log_run_event("turn_started", {"input": user_input, "turn": state.turns_completed, "depth": depth})

    for step in range(1, step_limit + 1):
        reply = ask_model(messages, model=model, temperature=temperature)
        action = parse_model_reply(reply, tool_names=set(tools.tools))
        log_run_event(
            "model_reply",
            {"step": step, "reply": trim_text(reply, 4000), "parsed_type": action.get("type"), "depth": depth},
        )

        if action["type"] == "final":
            summary = action.get("summary")
            if isinstance(summary, str):
                state.add_reflection(summary)
            log_run_event("turn_finished", {"step": step, "final": action.get("content", ""), "depth": depth})
            return str(action.get("content", ""))

        executed = execute_action(action, tools)
        if any(not result.ok for _, result in executed):
            state.add_reflection("A tool failed; inspect the error and choose a narrower recovery step.")
        else:
            why = action.get("why")
            if isinstance(why, str):
                state.add_reflection(f"Successful action: {why}")

        messages.append({"role": "assistant", "content": reply})
        messages.append({"role": "user", "content": build_tool_feedback(executed, state)})

    stop_message = "Agent stopped after reaching the maximum number of tool steps."
    log_run_event("turn_finished", {"final": stop_message, "max_steps": step_limit, "depth": depth})
    return stop_message


class AgentTools:
    def __init__(self, state: AgentState, depth: int = 0):
        self.state = state
        self.depth = depth
        self.tools: dict[str, Callable[..., ToolResult]] = {}
        self.tool_specs: dict[str, ToolSpec] = {}
        self._register_builtin_tools()

    def register_tool(self, spec: ToolSpec) -> None:
        self.tool_specs[spec.name] = spec
        self.tools[spec.name] = spec.function

    def _register_builtin_tools(self) -> None:
        def add(name: str, description: str, schema: dict[str, Any], risk: str, function: Callable[..., ToolResult]) -> None:
            self.register_tool(ToolSpec(name, description, schema, risk, function))

        add("list_files", "List files or directories inside the workspace.", {"path": ".", "recursive": False}, TOOL_RISK_READ_ONLY, self.list_files)
        add("inspect_path", "Inspect metadata for a workspace path.", {"path": "."}, TOOL_RISK_READ_ONLY, self.inspect_path)
        add("read_file", "Read a text file from the workspace.", {"path": "relative/path.py"}, TOOL_RISK_READ_ONLY, self.read_file)
        add("write_file", "Write a workspace file, optionally overwriting.", {"path": "notes.txt", "content": "...", "overwrite": False}, TOOL_RISK_WRITE_FILE, self.write_file)
        add("append_file", "Append text to a workspace file.", {"path": "log.txt", "content": "..."}, TOOL_RISK_WRITE_FILE, self.append_file)
        add("replace_in_file", "Replace exact text in a workspace file.", {"path": "app.py", "old": "x", "new": "y", "count": 1}, TOOL_RISK_WRITE_FILE, self.replace_in_file)
        add("apply_unified_diff", "Apply a safe unified diff to workspace files using git apply.", {"diff": "..."}, TOOL_RISK_WRITE_FILE, self.apply_unified_diff)
        add("search_files", "Search workspace files with ripgrep.", {"pattern": "text or regex", "path": "."}, TOOL_RISK_READ_ONLY, self.search_files)
        add("run_command", "Run a non-destructive shell command in the workspace.", {"command": "dir"}, TOOL_RISK_RUN_COMMAND, self.run_command)
        add("git_status", "Show git status for this workspace.", {}, TOOL_RISK_READ_ONLY, self.git_status)
        add("git_diff", "Show git diff for a path.", {"path": "."}, TOOL_RISK_READ_ONLY, self.git_diff)
        add("git_log", "Show recent git commits.", {"limit": 5}, TOOL_RISK_READ_ONLY, self.git_log)
        add("git_branch", "Show the current git branch.", {}, TOOL_RISK_READ_ONLY, self.git_branch)
        add("run_pytest", "Run pytest through the current Python interpreter.", {"path": ".", "extra_args": ""}, TOOL_RISK_RUN_COMMAND, self.run_pytest)
        add("run_ruff", "Run ruff check through the current Python interpreter.", {"path": ".", "extra_args": ""}, TOOL_RISK_RUN_COMMAND, self.run_ruff)
        add("run_python_smoke_test", "Compile and lightly smoke-test a Python file.", {"path": "agent.py"}, TOOL_RISK_RUN_COMMAND, self.run_python_smoke_test)
        add("run_self_improvement_validation", "Run compile, smoke, optional pytest/ruff, and git status checks.", {"path": "."}, TOOL_RISK_RUN_COMMAND, self.run_self_improvement_validation)
        add("list_roles", "List available role-based subagents.", {}, TOOL_RISK_READ_ONLY, self.list_roles)
        add("list_team_templates", "List team execution templates.", {}, TOOL_RISK_READ_ONLY, self.list_team_templates)
        add("show_role_telemetry", "Show role call history and success telemetry.", {}, TOOL_RISK_READ_ONLY, self.show_role_telemetry)
        add("list_tool_specs", "List registered tools, schemas, and risk levels.", {}, TOOL_RISK_READ_ONLY, self.list_tool_specs)
        add("manager_policy", "Choose a direct, single-agent, or team execution strategy.", {"task": "user objective", "context": "optional context"}, TOOL_RISK_AGENTIC, self.manager_policy)
        add("manager_execute", "Execute a task through manager-selected roles.", {"task": "objective", "context": "optional context", "template": "implementation", "roles": ["planner", "coder", "reviewer"]}, TOOL_RISK_AGENTIC, self.manager_execute)
        add("delegate_subagent", "Delegate bounded work to a role-based subagent.", {"role": "researcher", "task": "analyze X", "context": "optional extra context"}, TOOL_RISK_AGENTIC, self.delegate_subagent)
        add("resolve_disagreement", "Resolve disagreements across subagent outputs.", {"task": "objective", "team_report": "...", "context": "optional context"}, TOOL_RISK_AGENTIC, self.resolve_disagreement)
        add("quality_gate", "Assess readiness, risks, and next action for a candidate result.", {"objective": "goal", "candidate": "candidate result", "context": "optional context"}, TOOL_RISK_AGENTIC, self.quality_gate)
        add("run_team", "Run a small role-based team with synthesis and quality checks.", {"task": "objective", "roles": ["planner", "coder", "reviewer"], "context": "optional context"}, TOOL_RISK_AGENTIC, self.run_team)
        add("meta_review", "Synthesize and critique a candidate result.", {"objective": "goal", "draft": "candidate answer", "context": "optional context"}, TOOL_RISK_AGENTIC, self.meta_review)
        add("create_checkpoint", "Snapshot workspace files for later comparison.", {"label": "before-cycle-1"}, TOOL_RISK_WRITE_FILE, self.create_checkpoint)
        add("summarize_changes_since_checkpoint", "Summarize file changes since a checkpoint.", {"checkpoint": ".agent_checkpoints/..."}, TOOL_RISK_READ_ONLY, self.summarize_changes_since_checkpoint)
        add("validate_python_file", "Compile-check one Python file.", {"path": "agent.py"}, TOOL_RISK_READ_ONLY, self.validate_python_file)
        add("validate_workspace_python", "Compile-check Python files in a workspace path.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.validate_workspace_python)
        add("read_control_state", "Read autonomous loop control state.", {}, TOOL_RISK_CONTROL, self.read_control_state)
        add("set_control_mode", "Set autonomous loop control mode.", {"mode": "continue|wrap_up|stop", "note": "optional note", "monitor": "quiet|summary"}, TOOL_RISK_CONTROL, self.set_control_mode)
        add("self_improve_codebase", "Run an interruptible autonomous codebase improvement loop.", {"goal": "improve this codebase", "max_cycles": 5, "roles": ["planner", "coder", "reviewer"]}, TOOL_RISK_AGENTIC, self.self_improve_codebase)
        add("create_task", "Create a persistent task record.", {"title": "...", "objective": "..."}, TOOL_RISK_MEMORY, self.create_task)
        add("update_task", "Update a persistent task record.", {"task_id": "...", "status": "...", "note": "", "plan": []}, TOOL_RISK_MEMORY, self.update_task)
        add("list_tasks", "List persistent tasks, optionally by status.", {"status": ""}, TOOL_RISK_READ_ONLY, self.list_tasks)
        add("complete_task", "Mark a persistent task done with a summary.", {"task_id": "...", "summary": ""}, TOOL_RISK_MEMORY, self.complete_task)
        add("read_blackboard", "Read the shared multi-agent blackboard.", {}, TOOL_RISK_READ_ONLY, self.read_blackboard)
        add("update_blackboard", "Append content to a blackboard section.", {"section": "facts", "content": "..."}, TOOL_RISK_MEMORY, self.update_blackboard)
        add("clear_blackboard", "Clear the shared blackboard.", {}, TOOL_RISK_MEMORY, self.clear_blackboard)
        add("index_codebase", "Index Python symbols in workspace files.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.index_codebase)
        add("show_code_index", "Show the persisted code index.", {}, TOOL_RISK_READ_ONLY, self.show_code_index)
        add("find_symbol", "Find indexed functions/classes by name.", {"name": "..."}, TOOL_RISK_READ_ONLY, self.find_symbol)
        add("summarize_python_file", "Summarize imports, classes, and functions in one Python file.", {"path": "agent.py"}, TOOL_RISK_READ_ONLY, self.summarize_python_file)
        add("scan_improvement_opportunities", "Build a scored backlog of safe codebase improvement opportunities.", {"goal": "improve this codebase"}, TOOL_RISK_READ_ONLY, self.scan_improvement_opportunities)
        add("update_plan", "Replace the current in-memory plan.", {"items": ["step 1", "step 2"]}, TOOL_RISK_MEMORY, self.update_plan)
        add("show_plan", "Show the current in-memory plan.", {}, TOOL_RISK_READ_ONLY, self.show_plan)
        add("remember", "Store a durable memory key/value.", {"key": "topic", "value": "durable fact"}, TOOL_RISK_MEMORY, self.remember)
        add("recall", "Recall one durable memory key.", {"key": "topic"}, TOOL_RISK_READ_ONLY, self.recall)
        add("search_memory", "Search durable memory.", {"query": "topic", "limit": 5}, TOOL_RISK_READ_ONLY, self.search_memory)
        add("show_history", "Show recent tool calls.", {"limit": 8}, TOOL_RISK_READ_ONLY, self.show_history)

    def render_tool_prompt(self) -> str:
        lines = []
        for spec in self.tool_specs.values():
            lines.append(f"- {spec.name} [{spec.risk}]: {spec.description} schema={json.dumps(spec.schema)}")
        return "\n".join(lines)

    def call(self, tool_name: str, args: dict[str, Any]) -> ToolResult:
        tool = self.tools.get(tool_name)
        if tool is None:
            result = ToolResult(False, f"Unknown tool: {tool_name}")
            self.state.record_tool_event(tool_name, args, result)
            return result

        try:
            result = tool(**args)
        except TypeError as exc:
            result = ToolResult(False, f"Bad arguments for {tool_name}: {exc}")
        except Exception as exc:
            result = ToolResult(False, str(exc))

        self.state.record_tool_event(tool_name, args, result)
        return result

    def list_files(self, path: str = ".", recursive: bool = False) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        if target.is_file():
            return ToolResult(True, workspace_relative(target))
        entries = target.rglob("*") if recursive else target.iterdir()
        rendered = sorted(workspace_relative(item) for item in entries)
        return ToolResult(True, "\n".join(rendered) or "(empty directory)")

    def inspect_path(self, path: str = ".") -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        stat = target.stat()
        payload = {
            "path": workspace_relative(target),
            "is_file": target.is_file(),
            "is_dir": target.is_dir(),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        }
        if target.is_dir():
            payload["children"] = len(list(target.iterdir()))
        return ToolResult(True, json.dumps(payload, indent=2))

    def read_file(self, path: str) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.is_file():
            return ToolResult(False, f"File not found: {path}")
        text = target.read_text(encoding="utf-8", errors="replace")
        return ToolResult(True, trim_text(text))

    def write_file(self, path: str, content: str, overwrite: bool = False) -> ToolResult:
        target = resolve_workspace_path(path)
        if target.exists() and not overwrite:
            return ToolResult(False, f"File already exists: {path}. Set overwrite=true to replace it.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return ToolResult(True, f"Wrote {len(content)} characters to {path}")

    def append_file(self, path: str, content: str) -> ToolResult:
        target = resolve_workspace_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(content)
        return ToolResult(True, f"Appended {len(content)} characters to {path}")

    def replace_in_file(self, path: str, old: str, new: str, count: int = 0) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.is_file():
            return ToolResult(False, f"File not found: {path}")
        text = target.read_text(encoding="utf-8", errors="replace")
        matches = text.count(old)
        if matches == 0:
            return ToolResult(False, "Target text not found.")
        if count < 0:
            return ToolResult(False, "count must be zero or greater.")
        replace_count = count or matches
        updated = text.replace(old, new, replace_count)
        target.write_text(updated, encoding="utf-8")
        return ToolResult(True, f"Replaced {min(matches, replace_count)} occurrence(s) in {path}")

    def search_files(self, pattern: str, path: str = ".") -> ToolResult:
        target = resolve_workspace_path(path)
        command = ["rg", "--line-number", "--smart-case", pattern, str(target)]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                cwd=WORKSPACE_ROOT,
            )
        except FileNotFoundError:
            return ToolResult(False, "ripgrep (rg) is not installed.")
        output = result.stdout.strip() or result.stderr.strip() or "(no matches)"
        return ToolResult(result.returncode in (0, 1), trim_text(output, 12000))

    def run_command(self, command: str) -> ToolResult:
        lowered = command.lower()
        dangerous_tokens = [
            " del ",
            " rd ",
            " rmdir ",
            " remove-item ",
            " erase ",
            " format ",
            " shutdown ",
            " restart-computer",
            " stop-computer",
            " reg delete",
            " sc delete",
            " mkfs",
            " diskpart",
        ]
        wrapped = f" {lowered} "
        if any(token in wrapped for token in dangerous_tokens):
            return ToolResult(False, "Blocked: potentially destructive command.")
        try:
            subprocess.list2cmdline(shlex.split(command, posix=False))
        except ValueError as exc:
            return ToolResult(False, f"Invalid command syntax: {exc}")
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
            cwd=WORKSPACE_ROOT,
        )
        output = (result.stdout or result.stderr or "(no output)").strip()
        return ToolResult(result.returncode == 0, trim_text(output, 12000))

    def list_roles(self) -> ToolResult:
        return ToolResult(True, json.dumps(ROLE_CATALOG, indent=2))

    def list_team_templates(self) -> ToolResult:
        return ToolResult(True, json.dumps(TEAM_TEMPLATES, indent=2))

    def show_role_telemetry(self) -> ToolResult:
        return ToolResult(True, json.dumps(self.state.role_telemetry, indent=2))

    def list_tool_specs(self) -> ToolResult:
        payload = {
            name: {
                "description": spec.description,
                "schema": spec.schema,
                "risk": spec.risk,
            }
            for name, spec in self.tool_specs.items()
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def _git(self, args: list[str]) -> ToolResult:
        git = shutil.which("git")
        if git is None:
            return ToolResult(False, "Git executable was not found on PATH.")
        try:
            result = run_subprocess([git, *args], timeout=15)
        except subprocess.TimeoutExpired:
            return ToolResult(False, "Git command timed out after 15 seconds.")
        content = render_completed_process(result)
        if "not a git repository" in (result.stderr or "").lower():
            return ToolResult(False, "This workspace is not a git repository.\n" + content)
        return ToolResult(result.returncode == 0, content)

    def git_status(self) -> ToolResult:
        return self._git(["status", "--short", "--branch"])

    def git_diff(self, path: str = ".") -> ToolResult:
        try:
            target = resolve_workspace_path(path)
        except ValueError as exc:
            return ToolResult(False, str(exc))
        return self._git(["diff", "--", str(target.relative_to(WORKSPACE_ROOT))])

    def git_log(self, limit: int = 5) -> ToolResult:
        limit = max(1, min(int(limit), 50))
        return self._git(["log", f"--max-count={limit}", "--oneline", "--decorate"])

    def git_branch(self) -> ToolResult:
        return self._git(["branch", "--show-current"])

    def run_pytest(self, path: str = ".", extra_args: str = "") -> ToolResult:
        target = resolve_workspace_path(path)
        try:
            args = safe_extra_args(extra_args)
            result = run_subprocess([sys.executable, "-m", "pytest", str(target), *args], timeout=60)
        except ValueError as exc:
            return ToolResult(False, str(exc))
        except subprocess.TimeoutExpired:
            return ToolResult(False, "pytest timed out after 60 seconds.")
        content = render_completed_process(result)
        if "No module named pytest" in content:
            return ToolResult(False, "pytest is not installed in this Python environment.\n" + content)
        return ToolResult(result.returncode == 0, content)

    def run_ruff(self, path: str = ".", extra_args: str = "") -> ToolResult:
        target = resolve_workspace_path(path)
        try:
            args = safe_extra_args(extra_args)
            result = run_subprocess([sys.executable, "-m", "ruff", "check", str(target), *args], timeout=60)
        except ValueError as exc:
            return ToolResult(False, str(exc))
        except subprocess.TimeoutExpired:
            return ToolResult(False, "ruff timed out after 60 seconds.")
        content = render_completed_process(result)
        if "No module named ruff" in content:
            return ToolResult(False, "ruff is not installed in this Python environment.\n" + content)
        return ToolResult(result.returncode == 0, content)

    def run_python_smoke_test(self, path: str = "agent.py") -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.is_file() or target.suffix.lower() != ".py":
            return ToolResult(False, f"Not a Python file: {path}")
        compile_result = self.validate_python_file(path)
        source = target.read_text(encoding="utf-8", errors="replace")
        payload: dict[str, Any] = {
            "compile": parse_json_value(compile_result.content),
            "help": None,
        }
        if "--help" in source or "argparse" in source:
            try:
                result = run_subprocess([sys.executable, str(target), "--help"], timeout=10)
                payload["help"] = parse_json_value(render_completed_process(result))
            except subprocess.TimeoutExpired:
                payload["help"] = {"ok": False, "message": "--help timed out; compile check still completed."}
        else:
            payload["help"] = {"skipped": True, "reason": "file does not appear to define a --help CLI"}
        return ToolResult(compile_result.ok, json.dumps(payload, indent=2), meta=payload)

    def run_self_improvement_validation(self, path: str = ".") -> ToolResult:
        target = resolve_workspace_path(path)
        compile_check = self.validate_workspace_python(path=workspace_relative(target), recursive=True)
        smoke_check = self.run_python_smoke_test("agent.py")
        pytest_check = self.run_pytest(path=workspace_relative(target))
        ruff_check = self.run_ruff(path=workspace_relative(target))
        git_check = self.git_status()

        def optional_status(result: ToolResult, missing_phrase: str) -> str:
            if result.ok:
                return "pass"
            if missing_phrase in result.content:
                return "skipped_missing_optional_dependency"
            return "fail"

        results = {
            "compile": {
                "status": "pass" if compile_check.ok else "fail",
                "ok": compile_check.ok,
                "details": parse_json_value(compile_check.content),
            },
            "smoke": {
                "status": "pass" if smoke_check.ok else "fail",
                "ok": smoke_check.ok,
                "details": parse_json_value(smoke_check.content),
            },
            "pytest": {
                "status": optional_status(pytest_check, "pytest is not installed"),
                "ok": pytest_check.ok,
                "details": parse_json_value(pytest_check.content),
            },
            "ruff": {
                "status": optional_status(ruff_check, "ruff is not installed"),
                "ok": ruff_check.ok,
                "details": parse_json_value(ruff_check.content),
            },
            "git_status": {
                "status": "pass" if git_check.ok else "warning",
                "ok": git_check.ok,
                "details": parse_json_value(git_check.content),
            },
        }
        hard_failures = [
            name
            for name in ("compile", "smoke")
            if results[name]["status"] == "fail"
        ]
        optional_failures = [
            name
            for name in ("pytest", "ruff")
            if results[name]["status"] == "fail"
        ]
        payload = {
            "path": workspace_relative(target),
            "ok": not hard_failures,
            "hard_failures": hard_failures,
            "optional_failures": optional_failures,
            "results": results,
        }
        return ToolResult(not hard_failures, json.dumps(payload, indent=2), meta=payload)

    def apply_unified_diff(self, diff: str) -> ToolResult:
        ok, reason = validate_unified_diff_paths(diff)
        if not ok:
            return ToolResult(False, reason)
        git = shutil.which("git")
        if git is None:
            return ToolResult(False, "Patch application requires git for now, and git was not found on PATH.")
        try:
            check = subprocess.run(
                [git, "apply", "--check", "-"],
                input=diff,
                shell=False,
                capture_output=True,
                text=True,
                timeout=15,
                cwd=WORKSPACE_ROOT,
            )
            if check.returncode != 0:
                return ToolResult(False, "git apply --check failed.\n" + render_completed_process(check))
            applied = subprocess.run(
                [git, "apply", "-"],
                input=diff,
                shell=False,
                capture_output=True,
                text=True,
                timeout=15,
                cwd=WORKSPACE_ROOT,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(False, "git apply timed out after 15 seconds.")
        return ToolResult(applied.returncode == 0, render_completed_process(applied))

    def manager_policy(self, task: str, context: str = "") -> ToolResult:
        prompt = (
            f"Task:\n{task}\n\n"
            f"Context:\n{context or '(none)'}\n\n"
            f"Available roles:\n{json.dumps(ROLE_CATALOG, indent=2)}\n\n"
            f"Available team templates:\n{json.dumps(TEAM_TEMPLATES, indent=2)}\n\n"
            f"Role telemetry:\n{json.dumps(self.state.role_telemetry, indent=2)}"
        )
        reply = ask_model(
            [
                {"role": "system", "content": MANAGER_POLICY_PROMPT},
                {"role": "user", "content": prompt},
            ],
            model=get_role_model("planner"),
        )
        decision = parse_json_object(reply)
        if not decision:
            return ToolResult(False, "Manager policy failed to return valid JSON.")

        roles = decision.get("roles", [])
        if not isinstance(roles, list):
            roles = []

        template_name = str(decision.get("template", "custom"))
        template_roles = []
        if template_name in TEAM_TEMPLATES:
            template_roles = TEAM_TEMPLATES[template_name]["roles"]

        normalized_roles = [role for role in roles if role in ROLE_CATALOG][:MAX_TEAM_ROLES]
        if not normalized_roles and template_roles:
            normalized_roles = [role for role in template_roles if role in ROLE_CATALOG][:MAX_TEAM_ROLES]
        decision["roles"] = normalized_roles
        decision["template"] = template_name
        if decision.get("confidence") not in {"low", "medium", "high"}:
            decision["confidence"] = "medium"

        plan = decision.get("plan", [])
        if isinstance(plan, list):
            self.state.plan = [str(item).strip() for item in plan if str(item).strip()]

        self.state.record_manager_decision(decision)
        emit_monitor(
            "Manager decision: "
            f"mode={decision.get('mode', 'unknown')} "
            f"roles={decision.get('roles', [])} "
            f"template={decision.get('template', 'custom')} "
            f"meta={decision.get('needs_meta_review', False)} "
            f"confidence={decision.get('confidence', 'medium')}"
        )
        return ToolResult(True, json.dumps(decision, indent=2), meta=decision)

    def manager_execute(
        self,
        task: str,
        context: str = "",
        template: str = "",
        roles: list[str] | None = None,
    ) -> ToolResult:
        if template and template not in TEAM_TEMPLATES:
            return ToolResult(False, f"Unknown team template: {template}")

        explicit_roles = [role for role in (roles or []) if role in ROLE_CATALOG][:MAX_TEAM_ROLES]

        if template:
            decision = {
                "mode": "team",
                "template": template,
                "roles": TEAM_TEMPLATES[template]["roles"],
                "needs_meta_review": True,
                "confidence": "high",
                "rationale": f"Using explicit team template: {template}",
                "plan": [],
            }
            self.state.record_manager_decision(decision)
            emit_monitor(f"Manager execution using explicit template `{template}`")
        elif explicit_roles:
            decision = {
                "mode": "team" if len(explicit_roles) > 1 else "single",
                "template": "custom",
                "roles": explicit_roles,
                "needs_meta_review": True,
                "confidence": "high",
                "rationale": "Using explicit role selection supplied to manager_execute.",
                "plan": [],
            }
            self.state.record_manager_decision(decision)
            emit_monitor(f"Manager execution using explicit roles {explicit_roles}")
        else:
            decision_result = self.manager_policy(task=task, context=context)
            if not decision_result.ok:
                return decision_result
            decision = decision_result.meta

        mode = decision.get("mode", "team")
        roles = decision.get("roles", [])
        needs_meta_review = bool(decision.get("needs_meta_review", True))

        if mode == "direct":
            result = self.delegate_subagent(role="coder", task=task, context=context)
            final_payload = {
                "strategy": "direct",
                "decision": decision,
                "result": result.content,
            }
            gate = self.quality_gate(objective=task, candidate=json.dumps(final_payload, indent=2), context=context)
            final_payload["quality_gate"] = gate.content
            return ToolResult(result.ok and gate.ok, json.dumps(final_payload, indent=2))

        if mode == "single":
            chosen_role = roles[0] if roles else "coder"
            result = self.delegate_subagent(role=chosen_role, task=task, context=context)
            final_payload = {
                "strategy": "single",
                "decision": decision,
                "result": result.content,
            }
            if needs_meta_review:
                meta = self.meta_review(objective=task, draft=json.dumps(final_payload, indent=2), context=context)
                final_payload["meta_review"] = meta.content
            gate = self.quality_gate(objective=task, candidate=json.dumps(final_payload, indent=2), context=context)
            final_payload["quality_gate"] = gate.content
            return ToolResult(result.ok and gate.ok, json.dumps(final_payload, indent=2))

        team_result = self.run_team(task=task, roles=roles, context=context)
        final_payload = {
            "strategy": "team",
            "decision": decision,
            "result": parse_json_value(team_result.content) if team_result.ok else team_result.content,
        }
        if needs_meta_review:
            meta = self.meta_review(objective=task, draft=json.dumps(final_payload, indent=2), context=context)
            final_payload["meta_review"] = meta.content
        gate = self.quality_gate(objective=task, candidate=json.dumps(final_payload, indent=2), context=context)
        final_payload["quality_gate"] = gate.content
        return ToolResult(team_result.ok and gate.ok, json.dumps(final_payload, indent=2))

    def resolve_disagreement(self, task: str, team_report: str, context: str = "") -> ToolResult:
        if self.depth >= MAX_SUBAGENT_DEPTH:
            return ToolResult(
                True,
                trim_text(team_report, 5000),
                meta={"task": task, "fallback": "depth_limit"},
            )

        emit_monitor(f"Resolving disagreement for task: {trim_text(task, 140)}")
        disagreement_input = (
            f"Task:\n{task}\n\n"
            f"Context:\n{context or '(none)'}\n\n"
            f"Team report with possible conflicts:\n{team_report}"
        )
        result = run_agent(
            user_input=disagreement_input,
            state=self.state,
            system_prompt=DISAGREEMENT_AGENT_PROMPT,
            max_steps=MAX_SUBAGENT_STEPS,
            depth=self.depth + 1,
            model=get_role_model("meta"),
        )
        emit_monitor(f"Disagreement resolution completed for task: {trim_text(task, 140)}")
        return ToolResult(True, trim_text(result, 5000), meta={"task": task})

    def quality_gate(self, objective: str, candidate: str, context: str = "") -> ToolResult:
        if self.depth >= MAX_SUBAGENT_DEPTH:
            return ToolResult(
                True,
                "Quality gate skipped because depth limit was reached.",
                meta={"objective": objective, "fallback": "depth_limit"},
            )

        emit_monitor(f"Quality gate evaluating objective: {trim_text(objective, 140)}")
        quality_input = (
            f"Objective:\n{objective}\n\n"
            f"Context:\n{context or '(none)'}\n\n"
            f"Candidate result:\n{candidate}"
        )
        result = run_agent(
            user_input=quality_input,
            state=self.state,
            system_prompt=QUALITY_GATE_PROMPT,
            max_steps=MAX_SUBAGENT_STEPS,
            depth=self.depth + 1,
            model=get_role_model("meta"),
        )
        emit_monitor(f"Quality gate completed for objective: {trim_text(objective, 140)}")
        return ToolResult(True, trim_text(result, 5000), meta={"objective": objective})

    def delegate_subagent(self, role: str, task: str, context: str = "") -> ToolResult:
        if self.depth >= MAX_SUBAGENT_DEPTH:
            return ToolResult(False, "Sub-agent depth limit reached.")
        if role not in ROLE_CATALOG:
            return ToolResult(False, f"Unknown role: {role}")

        emit_monitor(f"Delegating to `{role}`: {trim_text(task, 140)}")

        subagent_input = (
            f"Delegated role: {role}\n"
            f"Task: {task}\n"
            f"Context: {context or '(none)'}\n\n"
            f"Parent state snapshot:\n{self.state.context_summary()}"
        )
        result = run_agent(
            user_input=subagent_input,
            state=self.state,
            system_prompt=build_role_system_prompt(role),
            max_steps=MAX_SUBAGENT_STEPS,
            depth=self.depth + 1,
            model=get_role_model(role),
        )
        tool_result = ToolResult(
            ok=True,
            content=(
                f"Sub-agent role: {role}\n"
                f"Task: {task}\n"
                f"Result:\n{trim_text(result, 4000)}"
            ),
            meta={"role": role, "task": task},
        )
        self.state.record_subagent_report(role, task, tool_result)
        emit_monitor(f"`{role}` completed with ok={tool_result.ok}")
        return tool_result

    def run_team(self, task: str, roles: list[str] | None = None, context: str = "") -> ToolResult:
        selected_roles = [role for role in (roles or []) if role in ROLE_CATALOG][:MAX_TEAM_ROLES]
        if not selected_roles:
            decision_result = self.manager_policy(task=task, context=context)
            if not decision_result.ok:
                return decision_result
            selected_roles = decision_result.meta.get("roles", [])

        if not selected_roles:
            return ToolResult(False, "No valid roles available for team execution.")

        emit_monitor(f"Running team with roles={selected_roles}")

        outputs = []
        for role in selected_roles:
            delegated = self.delegate_subagent(role=role, task=task, context=context)
            outputs.append(
                {
                    "role": role,
                    "ok": delegated.ok,
                    "content": delegated.content,
                }
            )

        team_report = {
            "task": task,
            "roles": selected_roles,
            "outputs": outputs,
        }
        disagreement = self.resolve_disagreement(
            task=task,
            team_report=json.dumps(team_report, indent=2),
            context=context,
        )
        review = self.meta_review(
            objective=task,
            draft=json.dumps(
                {
                    "team_report": team_report,
                    "disagreement_resolution": disagreement.content,
                },
                indent=2,
            ),
            context=context,
        )

        combined = {
            "team_report": team_report,
            "disagreement_resolution": disagreement.content,
            "meta_review": review.content,
        }
        gate = self.quality_gate(objective=task, candidate=json.dumps(combined, indent=2), context=context)
        combined["quality_gate"] = gate.content
        return ToolResult(review.ok and gate.ok, json.dumps(combined, indent=2))

    def meta_review(self, objective: str, draft: str, context: str = "") -> ToolResult:
        if self.depth >= MAX_SUBAGENT_DEPTH:
            fallback = ToolResult(
                True,
                trim_text(draft, 5000),
                meta={"objective": objective, "fallback": "depth_limit"},
            )
            self.state.record_meta_review(objective, fallback)
            emit_monitor("Meta review skipped because depth limit was reached.")
            return fallback

        emit_monitor(f"Meta review starting for objective: {trim_text(objective, 140)}")
        review_input = (
            f"Objective:\n{objective}\n\n"
            f"Context:\n{context or '(none)'}\n\n"
            f"Candidate draft or evidence:\n{draft}"
        )
        result = run_agent(
            user_input=review_input,
            state=self.state,
            system_prompt=META_AGENT_PROMPT,
            max_steps=MAX_SUBAGENT_STEPS,
            depth=self.depth + 1,
            model=get_role_model("meta"),
        )
        tool_result = ToolResult(True, trim_text(result, 5000), meta={"objective": objective})
        self.state.record_meta_review(objective, tool_result)
        emit_monitor(f"Meta review completed for objective: {trim_text(objective, 140)}")
        return tool_result

    def create_checkpoint(self, label: str = "") -> ToolResult:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_label = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in label).strip("_")
        folder_name = f"{stamp}-{safe_label}" if safe_label else stamp
        destination = CHECKPOINT_DIR / folder_name
        destination.mkdir(parents=True, exist_ok=False)

        copied: list[str] = []
        for item in WORKSPACE_ROOT.rglob("*"):
            if not item.is_file() or should_skip_checkpoint_path(item):
                continue
            relative = item.relative_to(WORKSPACE_ROOT)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
            copied.append(str(relative))

        manifest = {
            "checkpoint": workspace_relative(destination),
            "files_copied": len(copied),
            "label": label,
        }
        emit_monitor(
            f"Checkpoint created: {manifest['checkpoint']} "
            f"({manifest['files_copied']} files)"
        )
        return ToolResult(True, json.dumps(manifest, indent=2), meta=manifest)

    def summarize_changes_since_checkpoint(self, checkpoint: str) -> ToolResult:
        checkpoint_path = resolve_workspace_path(checkpoint)
        if not checkpoint_path.exists() or not checkpoint_path.is_dir():
            return ToolResult(False, f"Checkpoint not found: {checkpoint}")

        current_files = {path.relative_to(WORKSPACE_ROOT): path for path in iter_workspace_files(WORKSPACE_ROOT)}
        checkpoint_files = {
            path.relative_to(checkpoint_path): path
            for path in checkpoint_path.rglob("*")
            if path.is_file()
        }

        added = sorted(str(path) for path in current_files.keys() - checkpoint_files.keys())
        removed = sorted(str(path) for path in checkpoint_files.keys() - current_files.keys())
        common = sorted(current_files.keys() & checkpoint_files.keys())

        modified: list[dict[str, Any]] = []
        for relative in common:
            current_text = current_files[relative].read_text(encoding="utf-8", errors="replace").splitlines()
            checkpoint_text = checkpoint_files[relative].read_text(encoding="utf-8", errors="replace").splitlines()
            if current_text == checkpoint_text:
                continue
            diff_lines = list(
                difflib.unified_diff(
                    checkpoint_text,
                    current_text,
                    fromfile=str(relative),
                    tofile=str(relative),
                    lineterm="",
                    n=1,
                )
            )
            modified.append(
                {
                    "path": str(relative),
                    "diff_preview": trim_text("\n".join(diff_lines), MAX_DIFF_CHARS),
                }
            )

        summary = {
            "checkpoint": checkpoint,
            "added": added,
            "removed": removed,
            "modified_count": len(modified),
            "modified": modified[:12],
        }
        emit_monitor(
            f"Change summary vs checkpoint: added={len(added)} removed={len(removed)} modified={len(modified)}"
        )
        return ToolResult(True, json.dumps(summary, indent=2), meta=summary)

    def validate_python_file(self, path: str) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.is_file():
            return ToolResult(False, f"File not found: {path}")
        if target.suffix.lower() != ".py":
            return ToolResult(False, f"Not a Python file: {path}")

        source = target.read_text(encoding="utf-8", errors="replace")
        try:
            compile(source, str(target), "exec")
        except SyntaxError as exc:
            details = {
                "path": path,
                "ok": False,
                "line": exc.lineno,
                "offset": exc.offset,
                "message": exc.msg,
                "text": exc.text.strip() if exc.text else "",
            }
            return ToolResult(False, json.dumps(details, indent=2), meta=details)

        details = {"path": path, "ok": True, "message": "Syntax validation passed."}
        return ToolResult(True, json.dumps(details, indent=2), meta=details)

    def validate_workspace_python(self, path: str = ".", recursive: bool = True) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")

        candidates = [target] if target.is_file() else list(target.rglob("*.py") if recursive else target.glob("*.py"))
        checked: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []

        for file_path in candidates:
            if file_path.suffix.lower() != ".py":
                continue
            if should_skip_checkpoint_path(file_path):
                continue
            try:
                source = file_path.read_text(encoding="utf-8", errors="replace")
                compile(source, str(file_path), "exec")
                checked.append({"path": workspace_relative(file_path), "ok": True})
            except SyntaxError as exc:
                failure = {
                    "path": workspace_relative(file_path),
                    "ok": False,
                    "line": exc.lineno,
                    "offset": exc.offset,
                    "message": exc.msg,
                }
                checked.append(failure)
                failures.append(failure)

        payload = {
            "checked": len(checked),
            "failures": failures,
        }
        emit_monitor(f"Python validation checked {len(checked)} file(s), failures={len(failures)}")
        return ToolResult(len(failures) == 0, json.dumps(payload, indent=2), meta=payload)

    def read_control_state(self) -> ToolResult:
        state = load_control_state()
        return ToolResult(True, json.dumps(state, indent=2), meta=state)

    def set_control_mode(self, mode: str, note: str = "", monitor: str | None = None) -> ToolResult:
        state = save_control_state(mode=mode, note=note, monitor=monitor)
        emit_monitor(
            f"Control updated: mode={state['mode']} monitor={state['monitor']} note={state['note']}",
            force=True,
        )
        return ToolResult(True, json.dumps(state, indent=2), meta=state)

    def _append_task_artifacts(
        self,
        task_id: str,
        *,
        evidence: dict[str, Any] | None = None,
        files_changed: list[str] | None = None,
        validation: dict[str, Any] | None = None,
        status: str | None = None,
    ) -> None:
        data = load_tasks()
        for task in data["tasks"]:
            if task.get("id") != task_id:
                continue
            if evidence:
                task.setdefault("evidence", []).append(evidence)
            if files_changed:
                existing = set(task.setdefault("files_changed", []))
                for file_path in files_changed:
                    if file_path not in existing:
                        task["files_changed"].append(file_path)
            if validation:
                task.setdefault("validation", []).append(validation)
            if status:
                task["status"] = status
            task["updated_at"] = utc_now()
            save_tasks(data)
            return

    def self_improve_codebase(
        self,
        goal: str,
        max_cycles: int = DEFAULT_SELF_IMPROVE_CYCLES,
        roles: list[str] | None = None,
    ) -> ToolResult:
        if self.depth >= MAX_SUBAGENT_DEPTH:
            return ToolResult(False, "Autonomous self-improvement is not allowed from nested sub-agent depth.")

        max_cycles = max(1, min(int(max_cycles), 25))
        selected_roles = [role for role in (roles or []) if role in ROLE_CATALOG][:MAX_TEAM_ROLES]
        template_name = ""
        if selected_roles:
            for candidate, config in TEAM_TEMPLATES.items():
                if config["roles"] == selected_roles:
                    template_name = candidate
                    break

        task_result = self.create_task(
            title="Autonomous codebase self-improvement",
            objective=goal,
        )
        task_id = task_result.meta.get("id", "")
        self.update_task(
            task_id=task_id,
            status="running",
            note="Autonomous improvement loop initialized.",
            plan=[
                "Create checkpoints before each cycle.",
                "Refresh code index and shared blackboard context.",
                "Delegate improvements through manager-selected roles.",
                "Run validation suite and review whether to continue.",
                "Stop cleanly on human wrap-up or stop control mode.",
            ],
        )
        self.update_blackboard("decisions", f"Started autonomous self-improvement task {task_id}: {goal}")
        preflight_index = self.index_codebase(path=".", recursive=True)
        preflight_validation = self.run_self_improvement_validation(path=".")
        preflight_backlog = self.scan_improvement_opportunities(goal=goal)
        save_control_state(mode="continue", note="Autonomous improvement loop started.")
        emit_monitor(
            f"Autonomous improvement started: goal={trim_text(goal, 160)} cycles={max_cycles}",
            force=True,
        )
        initial_checkpoint = self.create_checkpoint(label="self-improve-start")
        cycle_reports: list[dict[str, Any]] = []
        current_goal = goal
        stop_reason = "max_cycles_reached"

        for cycle in range(1, max_cycles + 1):
            control = load_control_state()
            if control["mode"] == "stop":
                stop_reason = "human_requested_stop"
                emit_monitor("Human requested immediate stop before the next cycle.", force=True)
                break

            board = load_blackboard()
            code_index = self.index_codebase(path=".", recursive=True)
            backlog = self.scan_improvement_opportunities(goal=current_goal)
            opportunities = backlog.meta.get("opportunities", []) if backlog.ok else []
            top_opportunity = opportunities[0] if opportunities else {}
            if top_opportunity:
                self.update_blackboard(
                    "todo",
                    f"Cycle {cycle} top opportunity: {top_opportunity.get('title')} "
                    f"(score={top_opportunity.get('score')}, target={top_opportunity.get('target')})",
                )
            cycle_label = f"self-improve-cycle-{cycle}-pre"
            checkpoint = self.create_checkpoint(label=cycle_label)
            emit_monitor(
                f"Cycle {cycle}/{max_cycles} starting. "
                f"mode={control['mode']} checkpoint={checkpoint.meta.get('checkpoint', '')}",
                force=True,
            )
            emit_monitor(f"Cycle {cycle} focus: {trim_text(current_goal, 180)}")
            cycle_task = (
                f"Iteratively improve this codebase.\n"
                f"Primary goal: {current_goal}\n"
                f"Cycle: {cycle} of {max_cycles}\n"
                f"Control mode: {control['mode']}\n\n"
                f"Top ranked opportunity:\n{json.dumps(top_opportunity, indent=2)}\n\n"
                f"Important constraints:\n"
                f"- Make real improvements to the workspace when justified.\n"
                f"- Keep changes coherent and safe.\n"
                f"- Leave the codebase in a good stopping state at the end of the cycle.\n"
                f"- Use the code index, task state, blackboard, and validation tools before editing.\n"
                f"- Prefer small reversible changes with explicit evidence.\n"
            )
            manager_context = (
                f"{self.state.context_summary()}\n\n"
                f"Persistent task id: {task_id}\n\n"
                f"Shared blackboard:\n{json.dumps(board, indent=2)}\n\n"
                f"Improvement backlog:\n{trim_text(backlog.content, 5000)}\n\n"
                f"Latest code index preview:\n{trim_text(code_index.content, 5000)}"
            )
            team_result = self.manager_execute(
                task=cycle_task,
                context=manager_context,
                template=template_name,
                roles=selected_roles,
            )
            change_summary = self.summarize_changes_since_checkpoint(checkpoint=checkpoint.meta.get("checkpoint", ""))
            validation = self.run_self_improvement_validation(path=".")
            changed_files: list[str] = []
            if change_summary.ok:
                change_meta = change_summary.meta
                changed_files.extend(change_meta.get("added", []))
                changed_files.extend(change_meta.get("removed", []))
                changed_files.extend(item.get("path", "") for item in change_meta.get("modified", []))
                changed_files = [item for item in changed_files if item]
            self._append_task_artifacts(
                task_id,
                evidence={
                    "time": utc_now(),
                    "cycle": cycle,
                    "summary": trim_text(team_result.content, 1200),
                },
                files_changed=changed_files,
                validation={
                    "time": utc_now(),
                    "cycle": cycle,
                    "ok": validation.ok,
                    "summary": validation.meta,
                },
            )
            self.update_blackboard(
                "agent_notes",
                f"Cycle {cycle}: team_ok={team_result.ok}, validation_ok={validation.ok}, changed_files={changed_files[:8]}",
            )
            emit_monitor(
                f"Cycle {cycle} post-checks: changes_ok={change_summary.ok} validation_ok={validation.ok}",
                force=True,
            )

            review_prompt = (
                f"Goal:\n{current_goal}\n\n"
                f"Cycle number: {cycle}\n"
                f"Max cycles: {max_cycles}\n"
                f"External control mode: {control['mode']}\n\n"
                f"Latest team result:\n{team_result.content}\n"
                f"\nChange summary:\n{change_summary.content}\n"
                f"\nValidation summary:\n{validation.content}\n"
                f"\nBlackboard:\n{json.dumps(load_blackboard(), indent=2)}\n"
            )
            review_reply = ask_model(
                [
                    {"role": "system", "content": SELF_IMPROVEMENT_REVIEW_PROMPT},
                    {"role": "user", "content": review_prompt},
                ],
                model=get_role_model("meta"),
            )
            review = parse_json_object(review_reply)
            if not review:
                review = {
                    "continue_improving": cycle < max_cycles and control["mode"] == "continue",
                    "wrap_up_now": control["mode"] in {"wrap_up", "stop"},
                    "next_focus": current_goal,
                    "summary": "Review model returned invalid JSON; using fallback continuation logic.",
                    "reason": "fallback_review_logic",
                }

            cycle_report = {
                "cycle": cycle,
                "goal": current_goal,
                "control": control,
                "checkpoint": checkpoint.meta.get("checkpoint", ""),
                "top_opportunity": top_opportunity,
                "team_ok": team_result.ok,
                "team_summary": trim_text(team_result.content, 2000),
                "change_summary_ok": change_summary.ok,
                "change_summary": trim_text(change_summary.content, 3000),
                "validation_ok": validation.ok,
                "validation_summary": trim_text(validation.content, 2000),
                "review": review,
            }
            cycle_reports.append(cycle_report)

            summary = str(review.get("summary", "")).strip()
            if summary:
                self.state.add_reflection(f"Self-improve cycle {cycle}: {summary}")
                self.update_blackboard("decisions", f"Cycle {cycle} review summary: {summary}")
                emit_monitor(f"Cycle {cycle} summary: {trim_text(summary, 200)}", force=True)

            next_focus = str(review.get("next_focus", "")).strip()
            if next_focus:
                current_goal = next_focus
                emit_monitor(f"Next focus set to: {trim_text(current_goal, 180)}")

            if control["mode"] == "wrap_up":
                stop_reason = "human_requested_wrap_up"
                emit_monitor("Human requested wrap-up. Stopping after this completed cycle.", force=True)
                break
            if control["mode"] == "stop":
                stop_reason = "human_requested_stop"
                emit_monitor("Human requested stop. Ending loop now.", force=True)
                break
            if bool(review.get("wrap_up_now")):
                stop_reason = "review_recommended_wrap_up"
                emit_monitor("Review recommended wrapping up at this good stopping point.", force=True)
                break
            if not bool(review.get("continue_improving", False)):
                stop_reason = "review_recommended_stop"
                emit_monitor("Review recommended stopping further improvement cycles.", force=True)
                break

        final_report = {
            "goal": goal,
            "final_focus": current_goal,
            "task_id": task_id,
            "cycles_completed": len(cycle_reports),
            "stop_reason": stop_reason,
            "initial_checkpoint": initial_checkpoint.meta.get("checkpoint", ""),
            "preflight_index_ok": preflight_index.ok,
            "preflight_validation_ok": preflight_validation.ok,
            "preflight_backlog_ok": preflight_backlog.ok,
            "improvement_backlog_file": workspace_relative(IMPROVEMENT_BACKLOG_FILE),
            "control_file": workspace_relative(CONTROL_FILE),
            "cycle_reports": cycle_reports,
        }
        self.state.record_autonomous_run(final_report)
        self._append_task_artifacts(
            task_id,
            evidence={
                "time": utc_now(),
                "summary": f"Autonomous improvement finished after {len(cycle_reports)} cycle(s): {stop_reason}",
            },
            status="done" if stop_reason not in {"human_requested_stop"} else "blocked",
        )
        self.update_blackboard(
            "decisions",
            f"Autonomous improvement task {task_id} finished: cycles={len(cycle_reports)} reason={stop_reason}",
        )
        save_control_state(mode="continue", note="Autonomous improvement loop finished.")
        emit_monitor(
            f"Autonomous improvement finished: cycles={final_report['cycles_completed']} "
            f"reason={final_report['stop_reason']}",
            force=True,
        )
        return ToolResult(True, json.dumps(final_report, indent=2), meta=final_report)

    def create_task(self, title: str, objective: str) -> ToolResult:
        data = load_tasks()
        now = utc_now()
        task = {
            "id": f"task_{uuid.uuid4().hex[:12]}",
            "title": title,
            "status": "planned",
            "objective": objective,
            "plan": [],
            "evidence": [],
            "files_changed": [],
            "validation": [],
            "created_at": now,
            "updated_at": now,
        }
        data["tasks"].append(task)
        save_tasks(data)
        return ToolResult(True, json.dumps(task, indent=2), meta=task)

    def update_task(
        self,
        task_id: str,
        status: str,
        note: str = "",
        plan: list[str] | None = None,
    ) -> ToolResult:
        allowed = {"planned", "running", "blocked", "done", "failed"}
        if status not in allowed:
            return ToolResult(False, f"status must be one of: {', '.join(sorted(allowed))}")
        data = load_tasks()
        for task in data["tasks"]:
            if task.get("id") != task_id:
                continue
            task["status"] = status
            if note:
                task.setdefault("evidence", []).append({"time": utc_now(), "note": note})
            if plan is not None:
                task["plan"] = [str(item) for item in plan]
            task["updated_at"] = utc_now()
            save_tasks(data)
            return ToolResult(True, json.dumps(task, indent=2), meta=task)
        return ToolResult(False, f"Task not found: {task_id}")

    def list_tasks(self, status: str = "") -> ToolResult:
        data = load_tasks()
        tasks = data["tasks"]
        if status:
            tasks = [task for task in tasks if task.get("status") == status]
        return ToolResult(True, json.dumps({"tasks": tasks}, indent=2), meta={"tasks": tasks})

    def complete_task(self, task_id: str, summary: str = "") -> ToolResult:
        data = load_tasks()
        for task in data["tasks"]:
            if task.get("id") != task_id:
                continue
            task["status"] = "done"
            if summary:
                task.setdefault("evidence", []).append({"time": utc_now(), "summary": summary})
            task["updated_at"] = utc_now()
            save_tasks(data)
            return ToolResult(True, json.dumps(task, indent=2), meta=task)
        return ToolResult(False, f"Task not found: {task_id}")

    def read_blackboard(self) -> ToolResult:
        board = load_blackboard()
        return ToolResult(True, json.dumps(board, indent=2), meta=board)

    def update_blackboard(self, section: str, content: str) -> ToolResult:
        board = load_blackboard()
        if section not in board or not isinstance(board[section], list):
            return ToolResult(False, "section must be one of: facts, hypotheses, decisions, risks, todo, agent_notes")
        entry = {"time": utc_now(), "content": content}
        board[section].append(entry)
        save_blackboard(board)
        return ToolResult(True, json.dumps(entry, indent=2), meta=entry)

    def clear_blackboard(self) -> ToolResult:
        board = default_blackboard()
        save_blackboard(board)
        return ToolResult(True, json.dumps(board, indent=2), meta=board)

    def summarize_python_file(self, path: str = "agent.py") -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.is_file() or target.suffix.lower() != ".py":
            return ToolResult(False, f"Not a Python file: {path}")
        try:
            tree = ast.parse(target.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as exc:
            return ToolResult(False, f"Cannot parse {path}: {exc}")
        summary = {
            "path": workspace_relative(target),
            "docstring": ast.get_docstring(tree) or "",
            "imports": [],
            "classes": [],
            "functions": [],
        }
        for node in tree.body:
            if isinstance(node, ast.Import):
                summary["imports"].extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = "." * node.level + (node.module or "")
                summary["imports"].extend(f"{module}.{alias.name}".strip(".") for alias in node.names)
            elif isinstance(node, ast.ClassDef):
                summary["classes"].append(
                    {
                        "name": node.name,
                        "line": node.lineno,
                        "docstring": ast.get_docstring(node) or "",
                        "methods": [
                            {"name": item.name, "line": item.lineno}
                            for item in node.body
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        ],
                    }
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                summary["functions"].append(
                    {
                        "name": node.name,
                        "line": node.lineno,
                        "docstring": ast.get_docstring(node) or "",
                    }
                )
        return ToolResult(True, json.dumps(summary, indent=2), meta=summary)

    def index_codebase(self, path: str = ".", recursive: bool = True) -> ToolResult:
        target = resolve_workspace_path(path)
        candidates = [target] if target.is_file() else list(target.rglob("*.py") if recursive else target.glob("*.py"))
        files: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for candidate in candidates:
            if candidate.suffix.lower() != ".py" or should_skip_checkpoint_path(candidate):
                continue
            summary = self.summarize_python_file(workspace_relative(candidate))
            if summary.ok:
                files.append(summary.meta)
            else:
                errors.append({"path": workspace_relative(candidate), "error": summary.content})
        index = {
            "generated_at": utc_now(),
            "root": str(WORKSPACE_ROOT),
            "files": files,
            "errors": errors,
        }
        CODE_INDEX_FILE.write_text(json.dumps(index, indent=2), encoding="utf-8")
        return ToolResult(True, json.dumps(index, indent=2), meta=index)

    def show_code_index(self) -> ToolResult:
        if not CODE_INDEX_FILE.exists():
            return ToolResult(False, "No code index exists yet. Run index_codebase first.")
        text = CODE_INDEX_FILE.read_text(encoding="utf-8", errors="replace")
        return ToolResult(True, trim_text(text, 20000), meta=parse_json_value(text))

    def find_symbol(self, name: str) -> ToolResult:
        if not CODE_INDEX_FILE.exists():
            index_result = self.index_codebase(path=".", recursive=True)
            if not index_result.ok:
                return index_result
        index = parse_json_value(CODE_INDEX_FILE.read_text(encoding="utf-8", errors="replace"))
        matches: list[dict[str, Any]] = []
        needle = name.lower()
        for file_info in index.get("files", []):
            for func in file_info.get("functions", []):
                if needle in func.get("name", "").lower():
                    matches.append({"kind": "function", "path": file_info["path"], **func})
            for cls in file_info.get("classes", []):
                if needle in cls.get("name", "").lower():
                    matches.append({"kind": "class", "path": file_info["path"], **cls})
                for method in cls.get("methods", []):
                    if needle in method.get("name", "").lower():
                        matches.append({"kind": "method", "class": cls["name"], "path": file_info["path"], **method})
        return ToolResult(bool(matches), json.dumps({"matches": matches}, indent=2), meta={"matches": matches})

    def scan_improvement_opportunities(self, goal: str = "improve this codebase") -> ToolResult:
        index_result = self.index_codebase(path=".", recursive=True)
        validation = self.run_self_improvement_validation(path=".")
        tasks = load_tasks().get("tasks", [])
        index = index_result.meta if index_result.ok else parse_json_value(index_result.content)
        files = index.get("files", []) if isinstance(index, dict) else []
        goal_text = goal.lower()
        opportunities: list[dict[str, Any]] = []

        def add_opportunity(
            title: str,
            rationale: str,
            target: str,
            impact: int,
            confidence: int,
            risk: int,
            effort: int,
            evidence: list[str],
        ) -> None:
            score = max(0, impact * 3 + confidence * 2 - risk * 2 - effort)
            opportunities.append(
                {
                    "id": f"opp_{uuid.uuid4().hex[:10]}",
                    "title": title,
                    "rationale": rationale,
                    "target": target,
                    "impact": impact,
                    "confidence": confidence,
                    "risk": risk,
                    "effort": effort,
                    "score": score,
                    "evidence": evidence,
                }
            )

        validation_meta = validation.meta
        hard_failures = validation_meta.get("hard_failures", []) if isinstance(validation_meta, dict) else []
        optional_failures = validation_meta.get("optional_failures", []) if isinstance(validation_meta, dict) else []
        if hard_failures:
            add_opportunity(
                "Fix hard validation failures",
                "Hard validation failures block safe autonomous improvement.",
                "validation",
                impact=5,
                confidence=5,
                risk=1,
                effort=2,
                evidence=[f"hard_failures={hard_failures}"],
            )
        if optional_failures:
            add_opportunity(
                "Triage optional validator failures",
                "Optional validators are available but failing, which reduces quality signal.",
                "validation",
                impact=3,
                confidence=4,
                risk=1,
                effort=2,
                evidence=[f"optional_failures={optional_failures}"],
            )

        for file_info in files:
            path = str(file_info.get("path", ""))
            functions = file_info.get("functions", [])
            classes = file_info.get("classes", [])
            total_methods = sum(len(cls.get("methods", [])) for cls in classes)
            if path == "agent.py" and len(functions) + total_methods > 45:
                add_opportunity(
                    "Improve agent.py modularity",
                    "The main agent file has many callable units; targeted extraction or organization would improve maintainability.",
                    path,
                    impact=4,
                    confidence=4,
                    risk=3,
                    effort=4,
                    evidence=[f"functions={len(functions)}", f"methods={total_methods}"],
                )
            undocumented = [
                item.get("name", "")
                for item in functions
                if not item.get("docstring") and not str(item.get("name", "")).startswith("_")
            ]
            if len(undocumented) >= 12 and any(word in goal_text for word in {"intelligence", "self", "improve", "advanced"}):
                add_opportunity(
                    f"Document high-leverage public helpers in {path}",
                    "Several public helpers lack docstrings; concise contracts help future self-improvement agents reason safely.",
                    path,
                    impact=3,
                    confidence=4,
                    risk=1,
                    effort=2,
                    evidence=[f"undocumented_public_functions={undocumented[:12]}"],
                )

        stale_tasks = [
            task
            for task in tasks
            if task.get("status") in {"planned", "running", "blocked", "failed"}
        ]
        if stale_tasks:
            add_opportunity(
                "Reconcile persistent task state",
                "Open task records can carry stale assumptions into autonomous planning.",
                workspace_relative(TASKS_FILE),
                impact=3,
                confidence=3,
                risk=1,
                effort=1,
                evidence=[f"open_tasks={len(stale_tasks)}"],
            )

        if not opportunities:
            add_opportunity(
                "Run a narrow self-review cycle",
                "No urgent structural or validation issues were detected; use a small review cycle to find the next safe improvement.",
                "workspace",
                impact=2,
                confidence=3,
                risk=1,
                effort=1,
                evidence=["no hard validation failures or obvious backlog signals"],
            )

        opportunities.sort(key=lambda item: (-item["score"], item["risk"], item["effort"], item["title"]))
        backlog = {
            "generated_at": utc_now(),
            "goal": goal,
            "validation_ok": validation.ok,
            "code_index_ok": index_result.ok,
            "opportunities": opportunities[:20],
        }
        save_improvement_backlog(backlog)
        return ToolResult(True, json.dumps(backlog, indent=2), meta=backlog)

    def update_plan(self, items: list[str]) -> ToolResult:
        cleaned = [item.strip() for item in items if item.strip()]
        self.state.plan = cleaned
        return ToolResult(True, f"Plan updated with {len(cleaned)} step(s).")

    def show_plan(self) -> ToolResult:
        if not self.state.plan:
            return ToolResult(True, "No plan set.")
        return ToolResult(True, "\n".join(f"- {item}" for item in self.state.plan))

    def remember(self, key: str, value: str) -> ToolResult:
        self.state.memory[str(key)] = str(value)
        save_memory(self.state.memory)
        return ToolResult(True, f"Stored memory for key: {key}")

    def recall(self, key: str) -> ToolResult:
        value = self.state.memory.get(str(key))
        if value is None:
            return ToolResult(False, f"No memory stored for key: {key}")
        return ToolResult(True, value)

    def search_memory(self, query: str, limit: int = 5) -> ToolResult:
        lowered = query.lower().strip()
        matches: list[tuple[int, str, str]] = []
        for key, value in self.state.memory.items():
            haystack = f"{key}\n{value}".lower()
            score = haystack.count(lowered) if lowered else 0
            if score or any(part in haystack for part in lowered.split()):
                matches.append((score, key, trim_text(value, 300)))
        matches.sort(key=lambda item: (-item[0], item[1]))
        selected = matches[: max(1, min(limit, 20))]
        if not selected:
            return ToolResult(False, f"No memory matches for query: {query}")
        lines = [f"{key}: {value}" for _, key, value in selected]
        return ToolResult(True, "\n\n".join(lines))

    def show_history(self, limit: int = 8) -> ToolResult:
        selected = self.state.tool_history[-max(1, min(limit, 20)) :]
        if not selected:
            return ToolResult(True, "No tool history yet.")
        return ToolResult(True, json.dumps(selected, indent=2))


def execute_action(action: dict[str, Any], tools: AgentTools) -> list[tuple[str, ToolResult]]:
    action_type = action.get("type")
    if action_type == "tool":
        tool_name = str(action.get("tool", ""))
        args = action.get("args", {})
        if not isinstance(args, dict):
            args = {}
        return [(tool_name, tools.call(tool_name, args))]

    if action_type == "batch":
        executed: list[tuple[str, ToolResult]] = []
        for item in normalize_batch_actions(action.get("actions", [])):
            executed.append((item["tool"], tools.call(item["tool"], item["args"])))
        if not executed:
            return [("batch", ToolResult(False, "No valid batch actions were provided."))]
        return executed

    return [("action", ToolResult(False, f"Unsupported action type: {action_type}"))]


def repl() -> None:
    state = AgentState()
    control = load_control_state()
    print("-" * 60)
    print(terminal_color("Cerebro ", "94") + f"ready in {WORKSPACE_ROOT}")
    print()
    print(
    "Type "
    + terminal_color("'quit'", "91")
    + " or "
    + terminal_color("'exit'", "91")
    + " to stop."
)
    print()
    print(
        "During autonomous improvement, edit "
        f"{CONTROL_FILE.name} and set mode to 'wrap_up' or 'stop' to interrupt cleanly."
    )
    print()
    print(
        f"Set `{CONTROL_FILE.name}` monitor to 'summary' for live status logs "
        f"or 'quiet' to hide them. Current monitor={control.get('monitor', DEFAULT_MONITOR_MODE)}."
    )

    print("-" * 60)

    while True:
        user_input = input("\n" + terminal_color("User: ", "32")).strip()
        if user_input.lower() in {"quit", "exit"}:
            break
        if not user_input:
            continue

        try:
            answer = run_agent(user_input, state=state)
        except Exception as exc:
            answer = f"Agent failure: {exc}"
            log_run_event("agent_exception", {"error": str(exc)})
        print("\n" + terminal_color("Cerebro: ", "94") + render_terminal_markdown(answer))


if __name__ == "__main__":
    repl()
