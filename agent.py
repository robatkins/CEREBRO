from __future__ import annotations

import ast
import difflib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid
import itertools
import threading
import time
import random
import msvcrt
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from openai import OpenAI
except ImportError:  # Keep local validation tools importable without optional client deps.
    OpenAI = None

try:
    import anthropic
except ImportError:  # Claude support is optional and only required when configured.
    anthropic = None


WORKSPACE_ROOT = Path.cwd().resolve()
CONFIG_FILE = WORKSPACE_ROOT / ".agent_config.json"
MEMORY_FILE = WORKSPACE_ROOT / ".agent_memory.json"
USER_PROFILE_FILE = WORKSPACE_ROOT / ".agent_user_profile.json"
RUN_LOG_FILE = WORKSPACE_ROOT / ".agent_runs.jsonl"
CONTROL_FILE = WORKSPACE_ROOT / ".agent_control.json"
CHECKPOINT_DIR = WORKSPACE_ROOT / ".agent_checkpoints"
TASKS_FILE = WORKSPACE_ROOT / ".agent_tasks.json"
BLACKBOARD_FILE = WORKSPACE_ROOT / ".agent_blackboard.json"
CODE_INDEX_FILE = WORKSPACE_ROOT / ".agent_code_index.json"
CODE_GRAPH_FILE = WORKSPACE_ROOT / ".agent_code_graph.json"
CODE_HOTSPOTS_FILE = WORKSPACE_ROOT / ".agent_code_hotspots.json"
IMPROVEMENT_BACKLOG_FILE = WORKSPACE_ROOT / ".agent_improvement_backlog.json"
IMPROVEMENT_LEARNING_FILE = WORKSPACE_ROOT / ".agent_improvement_learning.json"
EXPERIMENT_JOURNAL_FILE = WORKSPACE_ROOT / ".agent_experiments.json"
CYCLE_LEDGER_FILE = WORKSPACE_ROOT / ".agent_cycle_ledger.json"
MODEL = "local-model"
MAX_STEPS = 200
MAX_BATCH_ACTIONS = 3
MAX_FILE_CHARS = 6000
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
    "architect": {
        "summary": "Designs durable abstractions, module boundaries, and evolution paths before implementation.",
        "strengths": "System design, API contracts, dependency boundaries, long-term maintainability",
        "failure_modes": "Can over-design if not constrained by validation and current code shape",
    },
    "coder": {
        "summary": "Implements code changes and proposes practical technical solutions.",
        "strengths": "Implementation, refactoring, concrete edits",
        "failure_modes": "Can optimize locally without enough review",
    },
    "refactorer": {
        "summary": "Improves internal structure while preserving behavior and minimizing risk.",
        "strengths": "Incremental refactoring, simplification, duplication removal, migration sequencing",
        "failure_modes": "Can create churn if not tied to a measurable maintainability goal",
    },
    "reviewer": {
        "summary": "Looks for bugs, regressions, edge cases, and testing gaps.",
        "strengths": "Risk identification, correctness review, regression spotting",
        "failure_modes": "Can be conservative and improvement-limiting if used alone",
    },
    "safety": {
        "summary": "Enforces autonomy policy, rollback discipline, workspace boundaries, and risk budgets.",
        "strengths": "Safety gates, policy interpretation, rollback readiness, blast-radius control",
        "failure_modes": "Can block useful progress if not balanced with impact and evidence",
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
    "maintainer": {
        "summary": "Keeps persistent agent state coherent across tasks, backlog, experiments, learning, and health reports.",
        "strengths": "State hygiene, evidence trails, stale artifact cleanup, operational continuity",
        "failure_modes": "Can focus on bookkeeping instead of user-visible progress",
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
        "roles": ["architect", "coder", "reviewer"],
        "use_when": "Feature building or codebase improvements need design, implementation, and review.",
    },
    "analysis": {
        "roles": ["researcher", "planner", "critic"],
        "use_when": "Ambiguous problems need evidence gathering and strategy formation before editing.",
    },
    "validation": {
        "roles": ["tester", "reviewer", "safety"],
        "use_when": "Changes exist and the main need is tightening correctness and validation confidence.",
    },
    "refactoring": {
        "roles": ["architect", "refactorer", "tester"],
        "use_when": "The main need is internal simplification, modularity, or maintainability without behavior drift.",
    },
    "autonomy": {
        "roles": ["planner", "safety", "maintainer"],
        "use_when": "Autonomous improvement loops need planning, policy enforcement, and persistent state hygiene.",
    },
    "communication": {
        "roles": ["researcher", "writer", "meta"],
        "use_when": "The task needs strong synthesis or documentation more than deep implementation.",
    },
}

def render_cerebro_banner() -> str:
    return r"""
        ██████╗███████╗██████╗ ███████╗██████╗ ██████╗  ██████╗
       ██╔════╝██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗
       ██║     █████╗  ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║
       ██║     ██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██║   ██║
       ╚██████╗███████╗██║  ██║███████╗██████╔╝██║  ██║╚██████╔╝
        ╚═════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝

                     
"""

def print_centered_banner_line(text: str, color_code: str = "94", delay: float = 0.002) -> None:
    centered = center_banner_text(text)
    typewriter_print(terminal_color(centered, color_code), delay=delay)


def print_centered_line(text: str, color_code: str = "90", delay: float = 0.002) -> None:
    typewriter_print(terminal_color(center_banner_text(text), color_code), delay=delay)


def render_centered_cerebro_banner() -> str:
    raw_lines = render_cerebro_banner().splitlines()
    while raw_lines and not raw_lines[0].strip():
        raw_lines.pop(0)
    while raw_lines and not raw_lines[-1].strip():
        raw_lines.pop()

    non_empty = [line for line in raw_lines if line.strip()]
    common_indent = min((len(line) - len(line.lstrip(" ")) for line in non_empty), default=0)
    lines = [line[common_indent:].rstrip() for line in raw_lines]
    width = terminal_width()
    return "\n".join(line.center(width) if line.strip() else "" for line in lines)

def clear_terminal() -> None:
    command = "cls" if sys.platform.startswith("win") else "clear"
    subprocess.run(command, shell=True)


def default_config() -> dict[str, Any]:
    role_models = {role: MODEL for role in ROLE_CATALOG}
    role_providers = {role: "lmstudio" for role in ROLE_CATALOG}
    return {
        "provider": "lmstudio",
        "base_url": "http://localhost:1234/v1",
        "api_key": "lm-studio",
        "default_model": MODEL,
        "temperature": 0.25,
        "max_steps": MAX_STEPS,
        "max_batch_actions": MAX_BATCH_ACTIONS,
        "monitor": DEFAULT_MONITOR_MODE,
        "show_thinking_indicator": True,
        "fallback_provider": "lmstudio",
        "autonomy_policy": {
            "max_changed_files_per_cycle": 4,
            "max_risk_level": "medium",
            "rollback_on_policy_violation": True,
            "allow_state_file_changes": True,
        },
        "llm_providers": {
            "lmstudio": {
                "type": "openai_compatible",
                "base_url": "http://localhost:1234/v1",
                "api_key": "lm-studio",
                "model": MODEL,
                "auto_discover_model": True,
            },
            "openai": {
                "type": "openai",
                "base_url": "https://api.openai.com/v1",
                "api_key_env": "OPENAI_API_KEY",
                "model": "gpt-4.1",
            },
            "anthropic": {
                "type": "anthropic",
                "api_key_env": "ANTHROPIC_API_KEY",
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 4096,
            },
            "xai": {
                "type": "openai_compatible",
                "base_url": "https://api.x.ai/v1",
                "api_key_env": "XAI_API_KEY",
                "model": "grok-3",
            },
        },
        "role_providers": role_providers,
        "role_models": role_models,
    }


def merge_provider_config(defaults: dict[str, Any], parsed: dict[str, Any]) -> dict[str, Any]:
    providers = {
        str(name): dict(settings)
        for name, settings in defaults.get("llm_providers", {}).items()
        if isinstance(settings, dict)
    }
    parsed_providers = parsed.get("llm_providers", {})
    if isinstance(parsed_providers, dict):
        for name, settings in parsed_providers.items():
            if isinstance(settings, dict):
                providers[str(name)] = providers.get(str(name), {}) | settings

    legacy_provider = str(parsed.get("provider", defaults.get("provider", "lmstudio")))
    if legacy_provider not in providers:
        providers[legacy_provider] = {
            "type": "openai_compatible",
            "base_url": parsed.get("base_url", defaults.get("base_url")),
            "api_key": parsed.get("api_key", defaults.get("api_key")),
            "model": parsed.get("default_model", defaults.get("default_model", MODEL)),
        }

    # Preserve old single-provider config fields as the selected provider's defaults.
    if "base_url" in parsed:
        providers[legacy_provider]["base_url"] = parsed["base_url"]
    if "api_key" in parsed:
        providers[legacy_provider]["api_key"] = parsed["api_key"]
    if "default_model" in parsed:
        providers[legacy_provider]["model"] = parsed["default_model"]

    for settings in providers.values():
        settings.setdefault("type", "openai_compatible")
        settings.setdefault("model", MODEL)
    return providers


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
    config["llm_providers"] = merge_provider_config(defaults, parsed)
    if config.get("provider") not in config["llm_providers"]:
        config["provider"] = defaults["provider"]
    selected_provider = config["llm_providers"].get(config["provider"], {})
    config["base_url"] = selected_provider.get("base_url", config.get("base_url", defaults["base_url"]))
    config["api_key"] = selected_provider.get("api_key", config.get("api_key", defaults["api_key"]))
    config["default_model"] = selected_provider.get("model", config.get("default_model", MODEL))

    parsed_role_providers = parsed.get("role_providers", {})
    if not isinstance(parsed_role_providers, dict):
        parsed_role_providers = {}
    default_role_providers = defaults["role_providers"]
    config["role_providers"] = {
        role: str(parsed_role_providers.get(role, default_role_providers.get(role, config["provider"])))
        if str(parsed_role_providers.get(role, default_role_providers.get(role, config["provider"]))) in config["llm_providers"]
        else str(config["provider"])
        for role in ROLE_CATALOG
    }

    parsed_role_models = parsed.get("role_models", {})
    if not isinstance(parsed_role_models, dict):
        parsed_role_models = {}
    role_models = defaults["role_models"] | parsed_role_models
    migrated = False
    if set(role_models) != set(parsed_role_models):
        migrated = True
    config["role_models"] = {
        role: str(config["llm_providers"].get(config["role_providers"][role], {}).get("model", config["default_model"]))
        if role_models.get(role) == MODEL
        and config["role_providers"][role] != config.get("provider")
        and config["llm_providers"].get(config["role_providers"][role], {}).get("model") != MODEL
        else str(
            role_models.get(
                role,
                config["llm_providers"].get(config["role_providers"][role], {}).get("model", config["default_model"]),
            )
        )
        for role in ROLE_CATALOG
    }
    config["max_steps"] = max(1, int(config.get("max_steps", MAX_STEPS)))
    config["max_batch_actions"] = max(1, int(config.get("max_batch_actions", MAX_BATCH_ACTIONS)))
    config["temperature"] = float(config.get("temperature", 0.25))
    if config.get("monitor") not in {"quiet", "summary"}:
        config["monitor"] = DEFAULT_MONITOR_MODE
    config["show_thinking_indicator"] = bool(config.get("show_thinking_indicator", False))
    if config.get("fallback_provider") not in config["llm_providers"]:
        config["fallback_provider"] = defaults["fallback_provider"]
    policy_defaults = defaults["autonomy_policy"]
    parsed_policy = parsed.get("autonomy_policy", {})
    if not isinstance(parsed_policy, dict):
        parsed_policy = {}
    policy = policy_defaults | parsed_policy
    policy["max_changed_files_per_cycle"] = max(1, int(policy.get("max_changed_files_per_cycle", 4)))
    if policy.get("max_risk_level") not in {"low", "medium", "high"}:
        policy["max_risk_level"] = "medium"
    policy["rollback_on_policy_violation"] = bool(policy.get("rollback_on_policy_violation", True))
    policy["allow_state_file_changes"] = bool(policy.get("allow_state_file_changes", True))
    config["autonomy_policy"] = policy
    if (
        migrated
        or "autonomy_policy" not in parsed
        or "llm_providers" not in parsed
        or "role_providers" not in parsed
        or "fallback_provider" not in parsed
        or "show_thinking_indicator" not in parsed
    ):
        save_config(config)
    return config


def save_config(config: dict[str, Any]) -> None:
    CONFIG_FILE.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")


def redacted_llm_providers(providers: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for name, settings in providers.items():
        if not isinstance(settings, dict):
            continue
        visible = dict(settings)
        if visible.get("api_key"):
            visible["api_key"] = "<redacted>"
        redacted[str(name)] = visible
    return redacted


def get_role_model(role: str) -> str:
    config = load_config()
    provider = get_role_provider(role, config)
    provider_model = config.get("llm_providers", {}).get(provider, {}).get("model", config.get("default_model", MODEL))
    return str(config.get("role_models", {}).get(role, provider_model))


def get_role_provider(role: str, config: dict[str, Any] | None = None) -> str:
    config = config or load_config()
    providers = config.get("llm_providers", {})
    provider = str(config.get("role_providers", {}).get(role, config.get("provider", "lmstudio")))
    if provider not in providers:
        provider = str(config.get("provider", "lmstudio"))
    return provider


def risk_level_value(level: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(level, 3)


def load_autonomy_policy() -> dict[str, Any]:
    return dict(load_config().get("autonomy_policy", default_config()["autonomy_policy"]))

def typewriter_print(text: str, delay: float = 0.003) -> None:
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

def terminal_width() -> int:
    fallback = max(80, banner_width())
    return shutil.get_terminal_size((fallback, 20)).columns

def banner_width() -> int:
    lines = [line.rstrip() for line in render_cerebro_banner().splitlines() if line.strip()]
    return max((len(line) for line in lines), default=80)

def center_banner_text(text: str) -> str:
    return text.center(max(terminal_width(), len(text)))

def print_random_cerebro_quote() -> None:
    quotes = [
        "Finding mutants is not the problem. Reaching them is.",
        "Cerebro amplifies the mind, but the choice remains human.",
        "Every signal has a source. Every mind leaves a trace.",
        "The world is full of hidden power.",
        "Mutation is not a curse. It is evolution speaking.",
        "Sometimes the loudest minds are the ones trying not to be heard.",
        "Cerebro online. Neural sweep initialized.",
        "Professor, the signal is everywhere.",
        "A mind is not a weapon unless you make it one.",
        "Welcome to Cerebro.",
    ]

    quote = f"“{random.choice(quotes)}”"
    centered_quote = center_banner_text(quote)

    typewriter_print(terminal_color(f"\n{centered_quote}\n", "90"), delay=0.006)


def render_startup_text(control: dict[str, Any]) -> str:
    rule = "-" * max(1, terminal_width())
    return (
        rule
        + "\n"
        + terminal_color("Cerebro: ", "94")
        + f"ready in {WORKSPACE_ROOT}\n\n"
        + "Type "
        + terminal_color("'quit'", "91")
        + " or "
        + terminal_color("'exit'", "91")
        + " to stop.\n\n"
        + "During autonomous improvement, edit .agent_control.json and set mode to "
        + terminal_color("'wrap_up'", "93")
        + " or "
        + terminal_color("'stop'", "91")
        + " to interrupt cleanly.\n\n"
        + "Set `.agent_control.json` monitor to "
        + terminal_color("'summary'", "92")
        + " for live status logs or "
        + terminal_color("'quiet'", "90")
        + f" to hide them. Current monitor={control.get('monitor')}.\n"
        + rule
        + "\n"
    )


def print_startup_header(control: dict[str, Any], *, animated: bool = True) -> None:
    clear_terminal()
    print(terminal_color(render_centered_cerebro_banner(), "94"))
    print_centered_banner_line(
        "AGENTIC INTELLIGENCE SYSTEM",
        color_code="94",
        delay=0.002 if animated else 0,
    )
    print_random_cerebro_quote()
    typewriter_print(render_startup_text(control), delay=0.002 if animated else 0)


def redraw_repl_screen(control: dict[str, Any], transcript: list[dict[str, str]]) -> None:
    print_startup_header(control, animated=False)
    for entry in transcript:
        role = entry.get("role", "")
        content = entry.get("content", "")
        if role == "user":
            print(terminal_color("User: ", "32") + content)
        elif role == "agent":
            print(terminal_color("Cerebro: ", "94") + render_terminal_markdown(content))


def read_provider_api_key(provider_config: dict[str, Any]) -> str:
    env_name = str(provider_config.get("api_key_env", "")).strip()
    if env_name:
        return os.environ.get(env_name, "")
    return str(provider_config.get("api_key", ""))


def get_provider_config(provider: str | None = None) -> tuple[str, dict[str, Any]]:
    config = load_config()
    providers = config.get("llm_providers", {})
    selected = str(provider or config.get("provider", "lmstudio"))
    if selected not in providers:
        selected = str(config.get("provider", "lmstudio"))
    provider_config = dict(providers.get(selected, {}))
    provider_config.setdefault("type", "openai_compatible")
    provider_config.setdefault("base_url", config.get("base_url", "http://localhost:1234/v1"))
    provider_config.setdefault("api_key", config.get("api_key", "lm-studio"))
    provider_config.setdefault("model", config.get("default_model", MODEL))
    return selected, provider_config


def get_client(provider: str | None = None) -> OpenAI:
    if OpenAI is None:
        raise RuntimeError("The openai package is required for model calls but is not installed.")
    _, provider_config = get_provider_config(provider)
    api_key = read_provider_api_key(provider_config)
    if not api_key:
        env_hint = provider_config.get("api_key_env")
        hint = f" Set environment variable {env_hint}." if env_hint else ""
        raise RuntimeError(f"No API key configured for provider.{hint}")
    return OpenAI(
        base_url=str(provider_config.get("base_url", "http://localhost:1234/v1")),
        api_key=api_key,
    )


def should_auto_discover_model(provider_name: str, provider_config: dict[str, Any], model: str) -> bool:
    if not bool(provider_config.get("auto_discover_model", provider_name == "lmstudio")):
        return False
    provider_type = str(provider_config.get("type", "openai_compatible")).lower()
    if provider_type not in {"openai", "openai_compatible"}:
        return False
    base_url = str(provider_config.get("base_url", ""))
    return model == MODEL or "localhost" in base_url or "127.0.0.1" in base_url


def discover_provider_model(provider_name: str, provider_config: dict[str, Any], preferred_model: str) -> str:
    if not should_auto_discover_model(provider_name, provider_config, preferred_model):
        return preferred_model
    try:
        models = list(get_client(provider_name).models.list().data)
    except Exception as exc:
        log_run_event(
            "model_discovery_failed",
            {
                "provider": provider_name,
                "preferred_model": preferred_model,
                "error": trim_text(str(exc), 1000),
            },
        )
        return preferred_model
    model_ids = [str(getattr(item, "id", "")) for item in models if getattr(item, "id", "")]
    if not model_ids:
        return preferred_model
    if preferred_model in model_ids:
        return preferred_model
    selected = model_ids[0]
    log_run_event(
        "model_auto_discovered",
        {
            "provider": provider_name,
            "preferred_model": preferred_model,
            "selected_model": selected,
            "available_models": model_ids[:20],
        },
    )
    return selected


def call_model_once(
    messages: list[dict[str, str]],
    *,
    provider_name: str,
    provider_config: dict[str, Any],
    model: str,
    temperature: float,
) -> str:
    provider_type = str(provider_config.get("type", "openai_compatible")).lower()
    if provider_type == "anthropic":
        if anthropic is None:
            raise RuntimeError("The anthropic package is required for Claude calls but is not installed.")
        api_key = read_provider_api_key(provider_config)
        if not api_key:
            env_hint = provider_config.get("api_key_env")
            hint = f" Set environment variable {env_hint}." if env_hint else ""
            raise RuntimeError(f"No API key configured for provider `{provider_name}`.{hint}")
        system_parts = [item.get("content", "") for item in messages if item.get("role") == "system"]
        anthropic_messages = [
            {"role": item.get("role", "user"), "content": item.get("content", "")}
            for item in messages
            if item.get("role") in {"user", "assistant"}
        ]
        response = anthropic.Anthropic(api_key=api_key).messages.create(
            model=model,
            max_tokens=int(provider_config.get("max_tokens", 4096)),
            temperature=temperature,
            system="\n\n".join(system_parts),
            messages=anthropic_messages,
        )
        return "".join(
            block.text
            for block in response.content
            if getattr(block, "type", "") == "text" and getattr(block, "text", None)
        )

    resolved_model = discover_provider_model(provider_name, provider_config, model)
    response = get_client(provider_name).chat.completions.create(
        model=resolved_model,
        messages=messages,
        temperature=temperature,
    )
    return response.choices[0].message.content or ""


def model_fallback_notice(provider: str, model: str, fallback_provider: str, fallback_model: str, error: Exception) -> str:
    return (
        f"Model route `{provider}/{model}` was unavailable, so Cerebro retried with "
        f"`{fallback_provider}/{fallback_model}`. Original error: {trim_text(str(error), 500)}"
    )


def format_agent_failure(exc: Exception) -> str:
    message = str(exc)
    lower = message.lower()
    if "no models loaded" in lower or "model has crashed" in lower:
        return (
            "Model unavailable. Load a model in LM Studio or update `.agent_config.json` "
            "to route the active role to an available provider. "
            f"Details: {trim_text(message, 600)}"
        )
    if "anthropic package" in lower:
        return "Claude is configured but the `anthropic` package is not installed. Run `python -m pip install anthropic` or route that role back to `lmstudio`."
    if "api key" in lower:
        return f"Model provider is missing an API key. {trim_text(message, 600)}"
    return f"Agent failure: {trim_text(message, 800)}"

def clear_current_line() -> None:
    if sys.stdout.isatty():
        print("\r\033[K", end="", flush=True)


def thinking_indicator(stop_event: threading.Event, label: str = "Thinking") -> None:
    if not sys.stdout.isatty():
        return

    spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    dots = ["", ".", "..", "..."]

    spinner_index = 0
    dot_index = 0

    # Create one blank gap line before the indicator.
    print("\n", end="", flush=True)

    while not stop_event.is_set():
        spinner = spinners[spinner_index % len(spinners)]
        dot = dots[dot_index % len(dots)]

        print(
            "\r\033[K" + terminal_color(f"{spinner} {label}{dot}", "90"),
            end="",
            flush=True,
        )

        time.sleep(0.12)

        spinner_index += 1
        if spinner_index % 3 == 0:
            dot_index += 1

    # Clear indicator line.
    print("\r\033[K", end="", flush=True)

    # Move up to the blank gap line and clear it too.
    print("\033[1A\r\033[K", end="", flush=True)


def animated_input(prompt: str = "User: ", on_resize: Callable[[], None] | None = None) -> str:
    if not sys.platform.startswith("win"):
        return input(prompt).strip()

    import msvcrt

    frames = ["◐", "◓", "◑", "◒"]
    final_frame = "○"
    frame_index = 0
    typed = ""
    last_width = terminal_width()

    def render_line(frame: str | None = None) -> None:
        symbol = frame if frame is not None else frames[frame_index % len(frames)]
        line = terminal_color(symbol, "32") + " " + terminal_color(prompt, "32") + typed
        print("\r\033[K" + line, end="", flush=True)

    render_line()

    while True:
        if msvcrt.kbhit():
            char = msvcrt.getwch()

            # Enter
            if char in ("\r", "\n"):
                render_line(final_frame)
                print()
                return typed.strip()

            # Backspace
            if char == "\b":
                if typed:
                    typed = typed[:-1]
                    render_line()
                continue

            # Ignore arrow/function key prefixes
            if char in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue

            # Normal character
            typed += char
            render_line()
            continue

        current_width = terminal_width()
        if on_resize and current_width != last_width:
            last_width = current_width
            on_resize()
            render_line()

        frame_index += 1
        render_line()
        time.sleep(0.18)


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
- Use generate_health_report and generate_planning_brief before substantial autonomous or architectural changes.
- Use analyze_change_impact, evaluate_autonomy_policy, and run_internal_self_tests after changing the control plane.
- Use show_last_self_improvement_changes before answering follow-up questions like "what changed?" after autonomous improvement.
- Use show_config, show_workspace_stats, show_run_history, summarize_blackboard, and show_cycle_ledger when you need to understand the agent's own operating state.

Rules:
- Prefer evidence from tools over guessing.
- Keep file access inside the workspace.
- Do not run destructive or system-altering commands.
- Prefer file tools over shell commands for code changes.
- Store durable findings in memory when they may help later.
- Store explicit user facts such as name, contact details, birthday, preferences, and personal notes in the structured user profile, not in ad hoc memory.
- Respect the control file during autonomous loops so a human can ask the agent to wrap up or stop.
- Treat autonomous code changes as experiments: state the hypothesis, validate, record outcome, and roll back if policy or validation fails.
- Do not broaden scope just because more tools exist; choose the smallest reversible step that improves the selected opportunity.
- Never call self_improve_codebase from inside a self_improve_codebase cycle. During autonomous improvement, use concrete tools like read_file, replace_in_file, validate_python_file, git_diff, and run_internal_self_tests instead of recursively starting another autonomous improvement loop.

Available tools and JSON arg schemas:
- list_files: {{"path": ".", "recursive": false}}
- inspect_path: {{"path": "."}}
- read_file: {{"path": "relative/path.py"}}
- read_json_file: {{"path": ".agent_config.json"}}
- validate_json_file: {{"path": ".agent_config.json"}}
- write_file: {{"path": "notes.txt", "content": "...", "overwrite": false}}
- append_file: {{"path": "log.txt", "content": "..."}}
- replace_in_file: {{"path": "app.py", "old": "x", "new": "y", "count": 1}}
- search_files: {{"pattern": "text or regex", "path": "."}}
- search_todos: {{"path": ".", "recursive": true}}
- list_recent_files: {{"path": ".", "limit": 20}}
- find_large_files: {{"path": ".", "limit": 20}}
- run_command: {{"command": "dir"}}
- list_roles: {{}}
- list_team_templates: {{}}
- recommend_team: {{"task": "objective", "context": "optional context"}}
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
- show_last_self_improvement_changes: {{"checkpoint": ""}}
- analyze_change_impact: {{"checkpoint": ".agent_checkpoints/..." }}
- analyze_python_complexity: {{"path": ".", "recursive": true}}
- build_import_graph: {{"path": ".", "recursive": true}}
- find_duplicate_blocks: {{"path": ".", "min_lines": 6}}
- suggest_refactor_targets: {{"path": ".", "recursive": true}}
- build_code_graph: {{"path": ".", "recursive": true}}
- show_code_graph: {{}}
- find_callers: {{"name": "function_name"}}
- analyze_symbol_impact: {{"name": "function_name"}}
- find_orphan_symbols: {{"path": ".", "recursive": true}}
- rank_code_hotspots: {{"path": ".", "recursive": true}}
- show_code_hotspots: {{}}
- restore_checkpoint: {{"checkpoint": ".agent_checkpoints/...", "preserve_agent_state": true}}
- validate_python_file: {{"path": "agent.py"}}
- validate_workspace_python: {{"path": ".", "recursive": true}}
- read_control_state: {{}}
- set_control_mode: {{"mode": "continue|wrap_up|stop", "note": "optional note", "monitor": "quiet|summary"}}
- evaluate_autonomy_policy: {{"impact": {{}}, "changed_files": ["agent.py"]}}
- self_improve_codebase: {{"goal": "improve this codebase", "max_cycles": 250, "roles": ["planner", "coder", "reviewer"]}}
- scan_improvement_opportunities: {{"goal": "improve this codebase"}}
- select_next_improvement: {{}}
- evaluate_improvement_opportunity: {{"opportunity": {{}}}}
- update_improvement_opportunity: {{"opportunity_id": "opp_...", "status": "in_progress", "note": ""}}
- record_improvement_outcome: {{"opportunity": {{}}, "status": "done", "validation_ok": true, "files_changed": []}}
- show_improvement_learning: {{}}
- start_experiment: {{"title": "...", "hypothesis": "...", "opportunity": {{}}}}
- update_experiment: {{"experiment_id": "exp_...", "status": "completed", "evidence": {{}}, "conclusion": "..."}}
- show_experiments: {{"status": ""}}
- show_cycle_ledger: {{"limit": 10}}
- generate_health_report: {{"goal": "improve this codebase"}}
- generate_planning_brief: {{"goal": "improve this codebase"}}
- run_internal_self_tests: {{}}
- update_plan: {{"items": ["step 1", "step 2"]}}
- show_plan: {{}}
- remember: {{"key": "topic", "value": "durable fact"}}
- recall: {{"key": "topic"}}
- search_memory: {{"query": "topic", "limit": 5}}
- show_user_profile: {{}}
- update_user_profile: {{"field": "identity.first_name", "value": "..."}}
- add_user_profile_note: {{"note": "...", "category": "preference"}}
- forget_user_profile_field: {{"field": "contact.phone"}}
- list_llm_routes: {{}}
- show_history: {{"limit": 8}}
"""


MANAGER_POLICY_PROMPT = """
You are Cerebro's manager-policy agent.

Given a task and context, decide whether the work should be:
- handled directly
- delegated to one specialist
- delegated to a small team
- sent to meta review before final output

Decision guidance:
- Prefer the smallest team that can still catch the dominant failure mode.
- Use architect for cross-cutting design, public contracts, or module boundaries.
- Use refactorer for behavior-preserving simplification or internal cleanup.
- Use safety when autonomy policy, rollback, impact, or workspace risk matters.
- Use maintainer when task/backlog/experiment/learning state may drift.
- Prefer generate_planning_brief for autonomous codebase improvement cycles.
- Prefer run_internal_self_tests when prompt, parser, registry, or control-plane behavior changes.
- Prefer validation or safety roles when policy, impact, or rollback evidence is incomplete.
- Prefer a meta review whenever two roles could plausibly disagree about scope, risk, or readiness.
- For self-improvement work, consult the latest cycle ledger, code hotspots, and autonomy policy before deciding on a team.
- If more than four roles seem useful, collapse to the highest-leverage roles plus meta review instead of overstaffing.
- Choose direct execution only when the task is narrow, low risk, and fully specified.

Return JSON only in this format:
{
  "mode": "direct|single|team",
  "template": "implementation|analysis|validation|refactoring|autonomy|communication|custom",
  "roles": ["planner", "coder"],
  "needs_meta_review": true,
  "confidence": "low|medium|high",
  "rationale": "brief explanation",
  "plan": ["step 1", "step 2"]
}

Keep the role list short and practical. Prefer a named template when one fits.
Do not select roles for optics; each role should own a distinct failure mode.
If evidence is weak, prefer analysis or safety over implementation.
"""


META_AGENT_PROMPT = f"""
You are Cerebro's meta-agent operating inside this workspace: {WORKSPACE_ROOT}

Your job is to improve the quality of a candidate result by:
- combining multiple sub-agent outputs
- spotting contradictions or missing pieces
- tightening the final recommendation
- checking whether evidence, validation, policy, impact, and rollback status support the conclusion
- preserving important minority concerns instead of smoothing them away
- checking whether the cycle ledger, hotspot report, and recent validation history point to a narrower or safer next step
- identifying which claim is best supported, which is weakest, and what evidence is missing
- preferring a crisp conclusion with explicit confidence and residual risk over a verbose merge

Return JSON only using the standard schema. Prefer a final answer unless you
truly need one more tool call.
"""


DISAGREEMENT_AGENT_PROMPT = f"""
You are Cerebro's disagreement-resolution agent operating inside this workspace: {WORKSPACE_ROOT}

Your job is to inspect team outputs, identify conflicts or weak points, and
return a stronger merged recommendation or a narrow next step.

Focus especially on conflicts about:
- changed-file scope and autonomy policy
- validation confidence and rollback readiness
- whether the selected opportunity was actually addressed
- whether a smaller safer step exists
- whether recent cycle history suggests a repeated failure mode or a stale assumption

When possible, transform disagreements into an explicit tradeoff rather than a vague compromise.
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
- whether impact analysis, autonomy policy, experiment evidence, and learning updates are present when relevant
- whether rollback occurred or should have occurred
- whether the change set is coherent with the current cycle ledger and code hotspot findings
- whether a narrow follow-up is wiser than accepting the result as-is

Return JSON only using the standard schema. Prefer a final answer containing a
compact readiness assessment with pass/fail, risks, evidence quality, and next action.
"""


SELF_IMPROVEMENT_REVIEW_PROMPT = """
You are Cerebro's self-improvement review agent.

You will receive the current improvement goal, the cycle number, the latest
team/meta results, impact analysis, validation, policy evidence, experiment
evidence, learning state, and the external control mode.

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
- Continue only when validation and autonomy policy allow it.
- Prefer the next focused opportunity from the planning brief or backlog.
- Check the recent cycle ledger before widening scope or repeating a failed pattern.
- If rollback happened, recommend a narrower follow-up unless the root cause is obvious.
- If no files changed, explain whether this was useful analysis or a blocked attempt.
- Prefer a concrete next focus that reduces risk or increases clarity, not a vague aspiration.
- If the team found a high-risk hotspot, bias toward containment, tests, or modularization before new features.
- If the cycle made progress but also increased complexity, call that out honestly and stop if the next step is unclear.
"""


def build_role_system_prompt(role: str) -> str:
    role_profile = ROLE_CATALOG.get(role, {})
    role_description = role_profile.get("summary", "Specialist sub-agent for bounded delegated work.")
    strengths = role_profile.get("strengths", "Use your role effectively.")
    failure_modes = role_profile.get("failure_modes", "Avoid drifting outside your scope.")
    role_playbooks = {
        "researcher": "Gather only decision-relevant evidence. Prefer search_files, read_file, code index, health report, cycle ledger, run history, and hotspot reports. Return the smallest useful evidence set with exact paths and implications.",
        "planner": "Convert evidence into a sequenced plan with dependencies, exit criteria, risk controls, and the smallest reversible next step. Explicitly name what to do first, what to avoid, and what would change your mind.",
        "architect": "Define boundaries, contracts, data flow, and migration strategy. Optimize for maintainability and blast-radius control. Avoid broad rewrites unless validation and impact evidence justify them.",
        "coder": "Make concrete edits that satisfy the selected opportunity. Keep changes small, local, validated, and easy to rollback. Prefer clarity over cleverness.",
        "refactorer": "Preserve behavior while simplifying structure. Name invariants, migration steps, cycle-history implications, and rollback considerations. Favor extraction over rewriting when risk is uncertain.",
        "reviewer": "Look for correctness bugs, regressions, missing tests, and mismatches between objective, implementation, and evidence. Be skeptical of apparent progress that is not validated.",
        "safety": "Inspect autonomy policy, changed-file scope, impact risk, rollback readiness, hotspot concentration, and workspace boundaries. Prefer blocking unsafe changes with a narrower alternative.",
        "critic": "Challenge assumptions and identify missing evidence, but end with a constructive next action. Highlight the strongest counterexample or hidden failure mode.",
        "tester": "Choose reproducible validation. Prefer compile checks, internal self-tests, smoke tests, impact analysis, and optional pytest/ruff when available. State exactly what the test proves and what it does not.",
        "maintainer": "Keep tasks, blackboard, backlog, experiments, learning, cycle ledger, run history, config, and health reports coherent. Identify stale or conflicting state and correct the bookkeeping first when needed.",
        "writer": "Explain outcomes clearly with files changed, validation status, risks, next step, and any user-facing consequence. Keep prose crisp and concrete.",
        "meta": "Synthesize across roles, preserve dissent, and choose the strongest evidence-backed final recommendation. Prefer a specific next action and a concise residual-risk statement.",
    }
    role_playbook = role_playbooks.get(role, "Use the role focus to produce a bounded, evidence-backed result.")
    return f"""
You are Cerebro's {role} sub-agent.
Workspace: {WORKSPACE_ROOT}

Role focus:
{role_description}

Strengths:
{strengths}

Watch-outs:
{failure_modes}

Role playbook:
{role_playbook}

Operating rules:
- Work only inside the workspace.
- Prefer concrete evidence over guesses.
- Keep scope narrow and useful to the parent agent.
- Do not ask to talk to the end user directly.
- Do not expose chain-of-thought.
- Return JSON only using the standard schema: tool, batch, or final.
- When relevant, mention validation status, autonomy policy, impact risk, rollback state, experiment evidence, cycle-ledger context, and hotspot relevance.
- If blocked, return the smallest safe unblock step rather than a broad wish list.
- If there are multiple plausible next steps, rank them by evidence and blast radius.
- Prefer one precise recommendation over several lukewarm ones.
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

    def color_line_count(match: re.Match[str]) -> str:
        label = match.group("label")
        value = match.group("value")
        if label.lower().startswith("lines added"):
            color = "32"
        elif label.lower().startswith("lines removed"):
            color = "31"
        else:
            numeric = int(value.replace("+", ""))
            color = "32" if numeric > 0 else "31" if numeric < 0 else "90"
        return f"{label}{terminal_color(value, color)}"

    rendered = re.sub(r"\*\*([^\n]+?)\*\*", bold, text)
    rendered = re.sub(
        r"(?P<label>\bLines added:\s*)(?P<value>[+-]?\d+)",
        color_line_count,
        rendered,
    )
    rendered = re.sub(
        r"(?P<label>\bLines removed:\s*)(?P<value>[+-]?\d+)",
        color_line_count,
        rendered,
    )
    rendered = re.sub(
        r"(?P<label>\bNet change:\s*)(?P<value>[+-]?\d+)",
        color_line_count,
        rendered,
    )
    return rendered


def terminal_color(text: str, color_code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{color_code}m{text}\033[0m"


ACTIVITY_ICONS = {
    "thinking": "[...]",
    "editing": "[edit]",
    "tool": "[tool]",
    "done": "[ok]",
    "warning": "[!]",
}


def shimmer_text(text: str, offset: int = 0) -> str:
    if not sys.stdout.isatty():
        return text
    colors = ["90", "37", "97", "37"]
    rendered = []
    for index, char in enumerate(text):
        color = colors[(index + offset) % len(colors)]
        rendered.append(f"\033[{color}m{char}\033[0m")
    return "".join(rendered)


def activity_enabled(force: bool = False) -> bool:
    return force or monitor_enabled()


def activity_line(kind: str, message: str) -> str:
    icon = ACTIVITY_ICONS.get(kind, "[*]")
    return f"{icon} {message}"


def emit_activity(kind: str, message: str, *, force: bool = False, animate: bool = True) -> None:
    if not activity_enabled(force):
        return
    line = activity_line(kind, message)
    if not sys.stdout.isatty() or not animate:
        print(render_terminal_markdown(line))
        return
    for offset in range(5):
        print("\r\033[K" + shimmer_text(line, offset), end="", flush=True)
        time.sleep(0.035)
    print()


def start_activity_indicator(kind: str, message: str, *, force: bool = False) -> tuple[threading.Event, threading.Thread] | None:
    if not activity_enabled(force):
        return None
    line = activity_line(kind, message)
    if not sys.stdout.isatty():
        print(render_terminal_markdown(line))
        return None

    stop_event = threading.Event()

    def animate_line() -> None:
        offset = 0
        while not stop_event.is_set():
            print("\r\033[K" + shimmer_text(line, offset), end="", flush=True)
            offset += 1
            time.sleep(0.08)
        print("\r\033[K", end="", flush=True)

    thread = threading.Thread(target=animate_line, daemon=True)
    thread.start()
    return stop_event, thread


def stop_activity_indicator(handle: tuple[threading.Event, threading.Thread] | None) -> None:
    if handle is None:
        return
    stop_event, thread = handle
    stop_event.set()
    thread.join(timeout=1)


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


def should_preserve_on_restore(path: Path) -> bool:
    rel = path.relative_to(WORKSPACE_ROOT)
    parts = set(rel.parts)
    if any(name in parts for name in {".git", ".agent_checkpoints", "__pycache__"}):
        return True
    return rel.name.startswith(".agent_")


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


def default_user_profile() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "updated_at": "",
        "identity": {
            "first_name": "",
            "middle_name": "",
            "last_name": "",
            "preferred_name": "",
            "pronouns": "",
        },
        "contact": {
            "phone": "",
            "email": "",
            "alternate_email": "",
            "address": "",
        },
        "important_dates": {
            "birthday": "",
            "anniversary": "",
        },
        "location": {
            "city": "",
            "state": "",
            "country": "",
            "timezone": "",
        },
        "preferences": {
            "communication_style": "",
            "coding_style": "",
            "favorite_tools": [],
            "do_not_do": [],
        },
        "relationships": [],
        "projects": [],
        "notes": [],
        "custom": {},
    }


def merge_profile_defaults(profile: dict[str, Any]) -> dict[str, Any]:
    merged = default_user_profile()
    if not isinstance(profile, dict):
        return merged
    for key, default_value in merged.items():
        incoming = profile.get(key, default_value)
        if isinstance(default_value, dict) and isinstance(incoming, dict):
            merged[key] = default_value | incoming
        elif isinstance(default_value, list) and isinstance(incoming, list):
            merged[key] = incoming
        else:
            merged[key] = incoming
    return merged


def load_user_profile() -> dict[str, Any]:
    if not USER_PROFILE_FILE.exists():
        profile = default_user_profile()
        USER_PROFILE_FILE.write_text(json.dumps(profile, indent=2), encoding="utf-8")
        return profile
    try:
        data = json.loads(USER_PROFILE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default_user_profile()
    return merge_profile_defaults(data if isinstance(data, dict) else {})


def save_user_profile(profile: dict[str, Any]) -> None:
    profile = merge_profile_defaults(profile)
    profile["updated_at"] = utc_now()
    USER_PROFILE_FILE.write_text(json.dumps(profile, indent=2), encoding="utf-8")


def set_nested_value(data: dict[str, Any], dotted_path: str, value: Any) -> None:
    parts = [part.strip() for part in dotted_path.split(".") if part.strip()]
    if not parts:
        raise ValueError("field path cannot be empty")
    current: dict[str, Any] = data
    for part in parts[:-1]:
        next_value = current.setdefault(part, {})
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def delete_nested_value(data: dict[str, Any], dotted_path: str) -> bool:
    parts = [part.strip() for part in dotted_path.split(".") if part.strip()]
    if not parts:
        raise ValueError("field path cannot be empty")
    current: Any = data
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    if isinstance(current, dict) and parts[-1] in current:
        del current[parts[-1]]
        return True
    return False


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


def default_improvement_learning() -> dict[str, Any]:
    return {
        "updated_at": "",
        "opportunities": {},
    }


def opportunity_learning_key(opportunity: dict[str, Any]) -> str:
    title = str(opportunity.get("title", "")).strip().lower()
    target = str(opportunity.get("target", "")).strip().lower()
    return f"{title}::{target}"


def load_improvement_learning() -> dict[str, Any]:
    if not IMPROVEMENT_LEARNING_FILE.exists():
        return default_improvement_learning()
    try:
        data = json.loads(IMPROVEMENT_LEARNING_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default_improvement_learning()
    return data if isinstance(data, dict) else default_improvement_learning()


def save_improvement_learning(learning: dict[str, Any]) -> None:
    learning["updated_at"] = utc_now()
    IMPROVEMENT_LEARNING_FILE.write_text(json.dumps(learning, indent=2), encoding="utf-8")


def default_experiment_journal() -> dict[str, Any]:
    return {
        "experiments": [],
    }


def load_experiment_journal() -> dict[str, Any]:
    if not EXPERIMENT_JOURNAL_FILE.exists():
        return default_experiment_journal()
    try:
        data = json.loads(EXPERIMENT_JOURNAL_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default_experiment_journal()
    return data if isinstance(data, dict) and isinstance(data.get("experiments"), list) else default_experiment_journal()


def save_experiment_journal(journal: dict[str, Any]) -> None:
    EXPERIMENT_JOURNAL_FILE.write_text(json.dumps(journal, indent=2), encoding="utf-8")


def default_cycle_ledger() -> dict[str, Any]:
    return {
        "updated_at": "",
        "cycles": [],
    }


def load_cycle_ledger() -> dict[str, Any]:
    if not CYCLE_LEDGER_FILE.exists():
        return default_cycle_ledger()
    try:
        data = json.loads(CYCLE_LEDGER_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default_cycle_ledger()
    return data if isinstance(data, dict) and isinstance(data.get("cycles"), list) else default_cycle_ledger()


def save_cycle_ledger(ledger: dict[str, Any]) -> None:
    ledger["updated_at"] = utc_now()
    ledger["cycles"] = ledger.get("cycles", [])[-80:] if isinstance(ledger.get("cycles"), list) else []
    CYCLE_LEDGER_FILE.write_text(json.dumps(ledger, indent=2), encoding="utf-8")


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
    provider: str | None = None,
    temperature: float | None = None,
) -> str:
    config = load_config()
    provider_name, provider_config = get_provider_config(provider)
    selected_model = model or str(provider_config.get("model", config.get("default_model", MODEL)))
    selected_temperature = config.get("temperature", 0.25) if temperature is None else temperature

    stop_event = threading.Event()
    indicator: threading.Thread | None = None

    if config.get("show_thinking_indicator", False):
        indicator = threading.Thread(
            target=thinking_indicator,
            args=(stop_event,),
            daemon=True,
        )
        indicator.start()

    try:
        try:
            return call_model_once(
                messages,
                provider_name=provider_name,
                provider_config=provider_config,
                model=selected_model,
                temperature=selected_temperature,
            )
        except Exception as first_error:
            fallback_provider = str(config.get("fallback_provider", config.get("provider", "lmstudio")))
            fallback_name, fallback_config = get_provider_config(fallback_provider)
            fallback_model = str(fallback_config.get("model", config.get("default_model", MODEL)))
            should_retry = (fallback_name, fallback_model) != (provider_name, selected_model)
            if not should_retry:
                raise
            log_run_event(
                "model_route_fallback",
                {
                    "provider": provider_name,
                    "model": selected_model,
                    "fallback_provider": fallback_name,
                    "fallback_model": fallback_model,
                    "error": trim_text(str(first_error), 1000),
                },
            )
            emit_monitor(
                model_fallback_notice(provider_name, selected_model, fallback_name, fallback_model, first_error),
                force=True,
            )
            return call_model_once(
                messages,
                provider_name=fallback_name,
                provider_config=fallback_config,
                model=fallback_model,
                temperature=selected_temperature,
            )
    finally:
        stop_event.set()
        if indicator is not None:
            indicator.join(timeout=1)
            clear_current_line()


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


def load_run_events(limit: int = 50) -> list[dict[str, Any]]:
    if not RUN_LOG_FILE.exists():
        return []
    limit = max(1, min(int(limit), 500))
    try:
        lines = RUN_LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


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
        provider = str(result.meta.get("provider", ""))
        model = str(result.meta.get("model", ""))
        self.subagent_reports.append(
            {
                "time": utc_now(),
                "role": role,
                "provider": provider,
                "model": model,
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
                "provider": provider,
                "model": model,
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
    provider: str | None = None,
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
        reply = ask_model(messages, model=model, provider=provider, temperature=temperature)
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
        add("read_json_file", "Read and parse a JSON file inside the workspace.", {"path": ".agent_config.json"}, TOOL_RISK_READ_ONLY, self.read_json_file)
        add("validate_json_file", "Validate that a workspace file contains well-formed JSON.", {"path": ".agent_config.json"}, TOOL_RISK_READ_ONLY, self.validate_json_file)
        add("write_file", "Write a workspace file, optionally overwriting.", {"path": "notes.txt", "content": "...", "overwrite": False}, TOOL_RISK_WRITE_FILE, self.write_file)
        add("append_file", "Append text to a workspace file.", {"path": "log.txt", "content": "..."}, TOOL_RISK_WRITE_FILE, self.append_file)
        add("replace_in_file", "Replace exact text in a workspace file.", {"path": "app.py", "old": "x", "new": "y", "count": 1}, TOOL_RISK_WRITE_FILE, self.replace_in_file)
        add("apply_unified_diff", "Apply a safe unified diff to workspace files using git apply.", {"diff": "..."}, TOOL_RISK_WRITE_FILE, self.apply_unified_diff)
        add("search_files", "Search workspace files with ripgrep.", {"pattern": "text or regex", "path": "."}, TOOL_RISK_READ_ONLY, self.search_files)
        add("search_todos", "Find TODO, FIXME, HACK, and NOTE markers in workspace text files.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.search_todos)
        add("list_recent_files", "List recently modified workspace files.", {"path": ".", "limit": 20}, TOOL_RISK_READ_ONLY, self.list_recent_files)
        add("find_large_files", "Find largest files in a workspace path.", {"path": ".", "limit": 20}, TOOL_RISK_READ_ONLY, self.find_large_files)
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
        add("recommend_team", "Recommend a small role team deterministically from task, context, templates, and telemetry.", {"task": "objective", "context": "optional context"}, TOOL_RISK_READ_ONLY, self.recommend_team)
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
        add("show_last_self_improvement_changes", "Show exact changes from the latest self-improvement cycle checkpoint.", {"checkpoint": ""}, TOOL_RISK_READ_ONLY, self.show_last_self_improvement_changes)
        add("analyze_change_impact", "Analyze changed files since a checkpoint and estimate semantic risk.", {"checkpoint": ".agent_checkpoints/..."}, TOOL_RISK_READ_ONLY, self.analyze_change_impact)
        add("restore_checkpoint", "Restore workspace files from a checkpoint while preserving agent state by default.", {"checkpoint": ".agent_checkpoints/...", "preserve_agent_state": True}, TOOL_RISK_WRITE_FILE, self.restore_checkpoint)
        add("validate_python_file", "Compile-check one Python file.", {"path": "agent.py"}, TOOL_RISK_READ_ONLY, self.validate_python_file)
        add("validate_workspace_python", "Compile-check Python files in a workspace path.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.validate_workspace_python)
        add("read_control_state", "Read autonomous loop control state.", {}, TOOL_RISK_CONTROL, self.read_control_state)
        add("set_control_mode", "Set autonomous loop control mode.", {"mode": "continue|wrap_up|stop", "note": "optional note", "monitor": "quiet|summary"}, TOOL_RISK_CONTROL, self.set_control_mode)
        add("evaluate_autonomy_policy", "Evaluate changed files and impact against configured autonomy risk budgets.", {"impact": {}, "changed_files": ["agent.py"]}, TOOL_RISK_READ_ONLY, self.evaluate_autonomy_policy)
        add("self_improve_codebase", "Run an interruptible autonomous codebase improvement loop.", {"goal": "improve this codebase", "max_cycles": 5, "roles": ["planner", "coder", "reviewer"]}, TOOL_RISK_AGENTIC, self.self_improve_codebase)
        add("create_task", "Create a persistent task record.", {"title": "...", "objective": "..."}, TOOL_RISK_MEMORY, self.create_task)
        add("update_task", "Update a persistent task record.", {"task_id": "...", "status": "...", "note": "", "plan": []}, TOOL_RISK_MEMORY, self.update_task)
        add("list_tasks", "List persistent tasks, optionally by status.", {"status": ""}, TOOL_RISK_READ_ONLY, self.list_tasks)
        add("complete_task", "Mark a persistent task done with a summary.", {"task_id": "...", "summary": ""}, TOOL_RISK_MEMORY, self.complete_task)
        add("read_blackboard", "Read the shared multi-agent blackboard.", {}, TOOL_RISK_READ_ONLY, self.read_blackboard)
        add("summarize_blackboard", "Summarize blackboard sections and recent entries.", {"limit": 5}, TOOL_RISK_READ_ONLY, self.summarize_blackboard)
        add("update_blackboard", "Append content to a blackboard section.", {"section": "facts", "content": "..."}, TOOL_RISK_MEMORY, self.update_blackboard)
        add("clear_blackboard", "Clear the shared blackboard.", {}, TOOL_RISK_MEMORY, self.clear_blackboard)
        add("show_config", "Show the active agent configuration.", {}, TOOL_RISK_READ_ONLY, self.show_config)
        add("list_llm_routes", "Show configured LLM providers and role-to-provider/model routing.", {}, TOOL_RISK_READ_ONLY, self.list_llm_routes)
        add("show_workspace_stats", "Summarize workspace file counts, sizes, and extension mix.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.show_workspace_stats)
        add("show_run_history", "Summarize recent run-log events.", {"limit": 20}, TOOL_RISK_READ_ONLY, self.show_run_history)
        add("index_codebase", "Index Python symbols in workspace files.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.index_codebase)
        add("show_code_index", "Show the persisted code index.", {}, TOOL_RISK_READ_ONLY, self.show_code_index)
        add("find_symbol", "Find indexed functions/classes by name.", {"name": "..."}, TOOL_RISK_READ_ONLY, self.find_symbol)
        add("summarize_python_file", "Summarize imports, classes, and functions in one Python file.", {"path": "agent.py"}, TOOL_RISK_READ_ONLY, self.summarize_python_file)
        add("analyze_python_complexity", "Rank Python callables by simple static complexity signals.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.analyze_python_complexity)
        add("build_import_graph", "Build a Python import graph with local dependency edges.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.build_import_graph)
        add("find_duplicate_blocks", "Find repeated normalized code/text blocks.", {"path": ".", "min_lines": 6}, TOOL_RISK_READ_ONLY, self.find_duplicate_blocks)
        add("suggest_refactor_targets", "Suggest refactor targets from complexity, hotspots, TODOs, and orphans.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.suggest_refactor_targets)
        add("build_code_graph", "Build a persistent Python call graph for safer refactoring.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.build_code_graph)
        add("show_code_graph", "Show the persisted Python call graph.", {}, TOOL_RISK_READ_ONLY, self.show_code_graph)
        add("find_callers", "Find indexed call sites for a function or method name.", {"name": "function_name"}, TOOL_RISK_READ_ONLY, self.find_callers)
        add("analyze_symbol_impact", "Analyze call-graph blast radius for a function or method name.", {"name": "function_name"}, TOOL_RISK_READ_ONLY, self.analyze_symbol_impact)
        add("find_orphan_symbols", "Find Python functions or methods with no indexed callers.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.find_orphan_symbols)
        add("rank_code_hotspots", "Rank code hotspots by fan-in, fan-out, orphaning, and documentation gaps.", {"path": ".", "recursive": True}, TOOL_RISK_READ_ONLY, self.rank_code_hotspots)
        add("show_code_hotspots", "Show the persisted code hotspot report.", {}, TOOL_RISK_READ_ONLY, self.show_code_hotspots)
        add("scan_improvement_opportunities", "Build a scored backlog of safe codebase improvement opportunities.", {"goal": "improve this codebase"}, TOOL_RISK_READ_ONLY, self.scan_improvement_opportunities)
        add("select_next_improvement", "Select the highest-ranked open improvement opportunity.", {}, TOOL_RISK_READ_ONLY, self.select_next_improvement)
        add("evaluate_improvement_opportunity", "Apply manager policy gates to an improvement opportunity before execution.", {"opportunity": {}}, TOOL_RISK_READ_ONLY, self.evaluate_improvement_opportunity)
        add("update_improvement_opportunity", "Update an improvement opportunity status and notes.", {"opportunity_id": "opp_...", "status": "in_progress", "note": ""}, TOOL_RISK_MEMORY, self.update_improvement_opportunity)
        add("record_improvement_outcome", "Record learned outcome statistics for an improvement opportunity.", {"opportunity": {}, "status": "done", "validation_ok": True, "files_changed": []}, TOOL_RISK_MEMORY, self.record_improvement_outcome)
        add("show_improvement_learning", "Show learned success and blockage rates for improvement opportunities.", {}, TOOL_RISK_READ_ONLY, self.show_improvement_learning)
        add("start_experiment", "Start a persistent autonomous-improvement experiment record.", {"title": "...", "hypothesis": "...", "opportunity": {}}, TOOL_RISK_MEMORY, self.start_experiment)
        add("update_experiment", "Update an experiment with evidence, status, and conclusion.", {"experiment_id": "exp_...", "status": "completed", "evidence": {}, "conclusion": "..."}, TOOL_RISK_MEMORY, self.update_experiment)
        add("show_experiments", "Show experiment journal entries, optionally filtered by status.", {"status": ""}, TOOL_RISK_READ_ONLY, self.show_experiments)
        add("show_cycle_ledger", "Show the persistent self-improvement cycle ledger.", {"limit": 10}, TOOL_RISK_READ_ONLY, self.show_cycle_ledger)
        add("generate_health_report", "Summarize platform health, risks, and recommended next improvements.", {"goal": "improve this codebase"}, TOOL_RISK_READ_ONLY, self.generate_health_report)
        add("generate_planning_brief", "Generate a pre-flight execution brief for the next autonomous improvement.", {"goal": "improve this codebase"}, TOOL_RISK_READ_ONLY, self.generate_planning_brief)
        add("run_internal_self_tests", "Run deterministic internal checks for parser, registry, policy, and planning invariants.", {}, TOOL_RISK_READ_ONLY, self.run_internal_self_tests)
        add("update_plan", "Replace the current in-memory plan.", {"items": ["step 1", "step 2"]}, TOOL_RISK_MEMORY, self.update_plan)
        add("show_plan", "Show the current in-memory plan.", {}, TOOL_RISK_READ_ONLY, self.show_plan)
        add("remember", "Store a durable memory key/value.", {"key": "topic", "value": "durable fact"}, TOOL_RISK_MEMORY, self.remember)
        add("recall", "Recall one durable memory key.", {"key": "topic"}, TOOL_RISK_READ_ONLY, self.recall)
        add("search_memory", "Search durable memory.", {"query": "topic", "limit": 5}, TOOL_RISK_READ_ONLY, self.search_memory)
        add("show_user_profile", "Show the structured user profile memory file.", {}, TOOL_RISK_READ_ONLY, self.show_user_profile)
        add("update_user_profile", "Update one structured user profile field using a dotted path.", {"field": "identity.first_name", "value": "..."}, TOOL_RISK_MEMORY, self.update_user_profile)
        add("add_user_profile_note", "Append a timestamped note to the user profile.", {"note": "...", "category": "preference"}, TOOL_RISK_MEMORY, self.add_user_profile_note)
        add("forget_user_profile_field", "Remove one structured user profile field using a dotted path.", {"field": "contact.phone"}, TOOL_RISK_MEMORY, self.forget_user_profile_field)
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

    def read_json_file(self, path: str) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.is_file():
            return ToolResult(False, f"File not found: {path}")
        try:
            parsed = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return ToolResult(False, f"Invalid JSON in {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}")
        return ToolResult(True, json.dumps(parsed, indent=2), meta={"path": workspace_relative(target), "data": parsed})

    def validate_json_file(self, path: str) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.is_file():
            return ToolResult(False, f"File not found: {path}")
        try:
            parsed = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            payload = {
                "path": workspace_relative(target),
                "ok": False,
                "line": exc.lineno,
                "column": exc.colno,
                "message": exc.msg,
            }
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)
        payload = {
            "path": workspace_relative(target),
            "ok": True,
            "type": type(parsed).__name__,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

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

    def search_todos(self, path: str = ".", recursive: bool = True) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        pattern = re.compile(r"\b(TODO|FIXME|HACK|NOTE)\b[:\s-]*(.*)", re.IGNORECASE)
        candidates = [target] if target.is_file() else list(target.rglob("*") if recursive else target.iterdir())
        matches: list[dict[str, Any]] = []
        for candidate in candidates:
            if not candidate.is_file() or should_skip_checkpoint_path(candidate):
                continue
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = pattern.search(line)
                if match:
                    matches.append(
                        {
                            "path": workspace_relative(candidate),
                            "line": line_number,
                            "tag": match.group(1).upper(),
                            "text": trim_text(match.group(2).strip() or line.strip(), 300),
                        }
                    )
        payload = {
            "path": workspace_relative(target),
            "recursive": recursive,
            "count": len(matches),
            "matches": matches[:200],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def list_recent_files(self, path: str = ".", limit: int = 20) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        limit = max(1, min(int(limit), 100))
        candidates = [target] if target.is_file() else list(target.rglob("*"))
        files: list[dict[str, Any]] = []
        for candidate in candidates:
            if not candidate.is_file() or should_skip_checkpoint_path(candidate):
                continue
            try:
                stat = candidate.stat()
            except OSError:
                continue
            files.append(
                {
                    "path": workspace_relative(candidate),
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "modified_ts": stat.st_mtime,
                }
            )
        files.sort(key=lambda item: float(item.get("modified_ts", 0)), reverse=True)
        for item in files:
            item.pop("modified_ts", None)
        payload = {
            "path": workspace_relative(target),
            "count": len(files),
            "files": files[:limit],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def find_large_files(self, path: str = ".", limit: int = 20) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        limit = max(1, min(int(limit), 100))
        candidates = [target] if target.is_file() else list(target.rglob("*"))
        files: list[dict[str, Any]] = []
        for candidate in candidates:
            if not candidate.is_file() or should_skip_checkpoint_path(candidate):
                continue
            try:
                stat = candidate.stat()
            except OSError:
                continue
            files.append(
                {
                    "path": workspace_relative(candidate),
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                }
            )
        files.sort(key=lambda item: int(item.get("size", 0)), reverse=True)
        payload = {
            "path": workspace_relative(target),
            "count": len(files),
            "files": files[:limit],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

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

    def recommend_team(self, task: str, context: str = "") -> ToolResult:
        text = f"{task}\n{context}".lower()
        role_scores = {role: 0 for role in ROLE_CATALOG}
        role_reasons: dict[str, list[str]] = {role: [] for role in ROLE_CATALOG}

        keyword_map = {
            "researcher": {"inspect", "find", "search", "evidence", "context", "discover"},
            "planner": {"plan", "steps", "sequence", "strategy", "roadmap", "brief"},
            "architect": {"architecture", "design", "module", "boundary", "api", "system"},
            "coder": {"implement", "code", "feature", "fix", "edit", "build"},
            "refactorer": {"refactor", "cleanup", "simplify", "modular", "maintainability"},
            "reviewer": {"review", "bug", "regression", "edge", "correctness"},
            "safety": {"risk", "policy", "rollback", "safe", "autonomous", "impact"},
            "critic": {"assumption", "stress", "challenge", "weak", "failure"},
            "tester": {"test", "validate", "pytest", "ruff", "smoke", "compile"},
            "maintainer": {"state", "task", "backlog", "experiment", "learning", "health"},
            "writer": {"document", "summary", "explain", "readme", "communication"},
            "meta": {"synthesize", "merge", "resolve", "final", "conflict"},
        }

        for role, keywords in keyword_map.items():
            hits = sorted(keyword for keyword in keywords if keyword in text)
            if hits:
                role_scores[role] += len(hits) * 3
                role_reasons[role].append(f"keyword matches: {', '.join(hits)}")

        template_scores: dict[str, int] = {}
        for template, data in TEAM_TEMPLATES.items():
            score = 0
            use_when = str(data.get("use_when", "")).lower()
            for token in re.findall(r"[a-z_]+", use_when):
                if len(token) > 4 and token in text:
                    score += 1
            for role in data.get("roles", []):
                score += role_scores.get(role, 0)
            template_scores[template] = score

        if any(word in text for word in {"self_improve", "autonomous", "autonomy", "control", "policy"}):
            for role in ("planner", "safety", "maintainer"):
                role_scores[role] += 4
                role_reasons[role].append("autonomy/control-plane context")
            template_scores["autonomy"] = template_scores.get("autonomy", 0) + 6

        if any(word in text for word in {"refactor", "modular", "maintainability", "cleanup"}):
            template_scores["refactoring"] = template_scores.get("refactoring", 0) + 6

        for role, telemetry in self.state.role_telemetry.items():
            calls = int(telemetry.get("calls", 0))
            failures = int(telemetry.get("failures", 0))
            successes = int(telemetry.get("successes", 0))
            if calls >= 2:
                adjustment = successes - failures * 2
                role_scores[role] += adjustment
                role_reasons[role].append(f"telemetry adjustment={adjustment}")

        best_template = max(template_scores, key=lambda name: template_scores.get(name, 0))
        candidate_roles = list(TEAM_TEMPLATES.get(best_template, {}).get("roles", []))
        ranked_roles = sorted(role_scores, key=lambda role: (-role_scores[role], role))
        for role in ranked_roles:
            if role not in candidate_roles:
                candidate_roles.append(role)
            if len(candidate_roles) >= MAX_TEAM_ROLES:
                break
        selected_roles = [role for role in candidate_roles if role in ROLE_CATALOG][:MAX_TEAM_ROLES]
        if not selected_roles:
            selected_roles = ["planner", "coder", "reviewer"]

        payload = {
            "template": best_template if template_scores.get(best_template, 0) > 0 else "custom",
            "roles": selected_roles,
            "role_scores": role_scores,
            "template_scores": template_scores,
            "reasons": {role: role_reasons[role] for role in selected_roles},
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

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
        try:
            reply = ask_model(
                [
                    {"role": "system", "content": MANAGER_POLICY_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                model=get_role_model("planner"),
                provider=get_role_provider("planner"),
            )
            decision = parse_json_object(reply)
        except Exception as exc:
            recommendation = self.recommend_team(task=task, context=context)
            decision = {
                "mode": "team",
                "template": recommendation.meta.get("template", "custom"),
                "roles": recommendation.meta.get("roles", ["planner", "coder", "reviewer"]),
                "needs_meta_review": True,
                "confidence": "medium",
                "rationale": f"Model manager policy unavailable; used deterministic team recommendation. error={exc}",
                "plan": ["Use deterministic role recommendation.", "Execute the task.", "Validate and review outcome."],
            }
        if not decision:
            recommendation = self.recommend_team(task=task, context=context)
            decision = {
                "mode": "team",
                "template": recommendation.meta.get("template", "custom"),
                "roles": recommendation.meta.get("roles", ["planner", "coder", "reviewer"]),
                "needs_meta_review": True,
                "confidence": "medium",
                "rationale": "Manager policy returned invalid JSON; used deterministic team recommendation.",
                "plan": ["Use deterministic role recommendation.", "Execute the task.", "Validate and review outcome."],
            }

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
            provider=get_role_provider("meta"),
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
            provider=get_role_provider("meta"),
        )
        emit_monitor(f"Quality gate completed for objective: {trim_text(objective, 140)}")
        return ToolResult(True, trim_text(result, 5000), meta={"objective": objective})

    def delegate_subagent(self, role: str, task: str, context: str = "") -> ToolResult:
        if self.depth >= MAX_SUBAGENT_DEPTH:
            return ToolResult(False, "Sub-agent depth limit reached.")
        if role not in ROLE_CATALOG:
            return ToolResult(False, f"Unknown role: {role}")

        provider = get_role_provider(role)
        model = get_role_model(role)
        emit_monitor(f"Delegating to `{role}` via {provider}/{model}: {trim_text(task, 140)}")

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
            model=model,
            provider=provider,
        )
        tool_result = ToolResult(
            ok=True,
            content=(
                f"Sub-agent role: {role}\n"
                f"Provider: {provider}\n"
                f"Model: {model}\n"
                f"Task: {task}\n"
                f"Result:\n{trim_text(result, 4000)}"
            ),
            meta={"role": role, "task": task, "provider": provider, "model": model},
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
            provider=get_role_provider("meta"),
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
        added_line_count = 0
        removed_line_count = 0
        added_file_lines: dict[str, int] = {}
        removed_file_lines: dict[str, int] = {}

        for relative_text in added:
            try:
                count = len(current_files[Path(relative_text)].read_text(encoding="utf-8", errors="replace").splitlines())
            except (KeyError, OSError):
                count = 0
            added_file_lines[relative_text] = count
            added_line_count += count

        for relative_text in removed:
            try:
                count = len(checkpoint_files[Path(relative_text)].read_text(encoding="utf-8", errors="replace").splitlines())
            except (KeyError, OSError):
                count = 0
            removed_file_lines[relative_text] = count
            removed_line_count += count

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
            file_lines_added = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
            file_lines_removed = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
            added_line_count += file_lines_added
            removed_line_count += file_lines_removed
            modified.append(
                {
                    "path": str(relative),
                    "lines_added": file_lines_added,
                    "lines_removed": file_lines_removed,
                    "diff_preview": trim_text("\n".join(diff_lines), MAX_DIFF_CHARS),
                }
            )

        summary = {
            "checkpoint": checkpoint,
            "added": added,
            "removed": removed,
            "modified_count": len(modified),
            "modified": modified[:12],
            "lines_added": added_line_count,
            "lines_removed": removed_line_count,
            "added_file_lines": added_file_lines,
            "removed_file_lines": removed_file_lines,
        }
        emit_monitor(
            f"Change summary vs checkpoint: added={len(added)} removed={len(removed)} modified={len(modified)} "
            f"lines_added={added_line_count} lines_removed={removed_line_count}"
        )
        return ToolResult(True, json.dumps(summary, indent=2), meta=summary)

    def show_last_self_improvement_changes(self, checkpoint: str = "") -> ToolResult:
        selected_checkpoint = checkpoint.strip()
        if not selected_checkpoint:
            ledger = load_cycle_ledger()
            cycles = ledger.get("cycles", []) if isinstance(ledger, dict) else []
            if cycles:
                latest = cycles[-1]
                payload = {
                    "source": "cycle_ledger",
                    "checkpoint": latest.get("checkpoint", ""),
                    "changed_files": latest.get("changed_files", []),
                    "code_files": [
                        path
                        for path in latest.get("changed_files", [])
                        if Path(str(path)).suffix.lower() in {".py", ".js", ".ts", ".tsx", ".jsx", ".css", ".html"}
                    ],
                    "lines_added": latest.get("lines_added", 0),
                    "lines_removed": latest.get("lines_removed", 0),
                    "cycle": latest.get("cycle"),
                    "status": latest.get("status"),
                    "validation_ok": latest.get("validation_ok"),
                    "rollback": latest.get("rollback"),
                    "review_summary": latest.get("review_summary", ""),
                    "summary": "Loaded exact completed-cycle changes from the persistent cycle ledger.",
                    "cycle_entry": latest,
                }
                return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

        if not selected_checkpoint:
            candidates = sorted(
                [
                    item
                    for item in CHECKPOINT_DIR.glob("*self-improve-cycle-*-pre")
                    if item.is_dir()
                ],
                key=lambda item: item.name,
                reverse=True,
            )
            if not candidates:
                return ToolResult(False, "No self-improvement cycle checkpoint was found.")
            selected_checkpoint = workspace_relative(candidates[0])

        summary_result = self.summarize_changes_since_checkpoint(selected_checkpoint)
        if not summary_result.ok:
            return summary_result

        summary = summary_result.meta
        modified = summary.get("modified", [])
        changed_files = list(summary.get("added", [])) + list(summary.get("removed", [])) + [
            item.get("path", "") for item in modified if item.get("path")
        ]
        code_files = [
            path
            for path in changed_files
            if Path(str(path)).suffix.lower() in {".py", ".js", ".ts", ".tsx", ".jsx", ".css", ".html"}
        ]
        state_files = [
            path
            for path in changed_files
            if Path(str(path)).name.startswith(".agent_") or ".pytest_cache" in Path(str(path)).parts
        ]
        payload = {
            "source": "checkpoint_comparison",
            "checkpoint": selected_checkpoint,
            "changed_files": changed_files,
            "code_files": code_files,
            "state_or_cache_files": state_files,
            "lines_added": summary.get("lines_added", 0),
            "lines_removed": summary.get("lines_removed", 0),
            "added": summary.get("added", []),
            "removed": summary.get("removed", []),
            "modified": modified,
            "summary": (
                "No code files changed; only agent state, logs, cache, or generated metadata changed."
                if not code_files
                else f"{len(code_files)} code file(s) changed."
            ),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def analyze_change_impact(self, checkpoint: str) -> ToolResult:
        summary_result = self.summarize_changes_since_checkpoint(checkpoint)
        if not summary_result.ok:
            return summary_result

        summary = summary_result.meta
        added = summary.get("added", [])
        removed = summary.get("removed", [])
        modified = summary.get("modified", [])
        touched_paths = list(added) + list(removed) + [item.get("path", "") for item in modified]
        python_paths = [path for path in touched_paths if str(path).endswith(".py")]
        state_paths = [path for path in touched_paths if Path(str(path)).name.startswith(".agent_")]
        symbol_impacts: list[dict[str, Any]] = []

        for path in python_paths:
            try:
                target = resolve_workspace_path(str(path))
            except ValueError:
                continue
            if not target.exists() or not target.is_file():
                symbol_impacts.append({"path": path, "status": "removed_or_missing", "symbols": []})
                continue
            summary_file = self.summarize_python_file(str(path))
            if not summary_file.ok:
                symbol_impacts.append({"path": path, "status": "parse_failed", "error": summary_file.content})
                continue
            meta = summary_file.meta
            dependency_risks = []
            for item in meta.get("functions", [])[:12]:
                impact = self.analyze_symbol_impact(str(item.get("name", "")))
                if impact.ok:
                    dependency_risks.append(
                        {
                            "name": item.get("name"),
                            "risk_level": impact.meta.get("risk_level"),
                            "risk_score": impact.meta.get("risk_score"),
                            "direct_callers": len(impact.meta.get("direct_callers", [])),
                        }
                    )
            symbol_impacts.append(
                {
                    "path": path,
                    "status": "parsed",
                    "functions": [
                        {"name": item.get("name"), "line": item.get("line")}
                        for item in meta.get("functions", [])
                    ],
                    "classes": [
                        {
                            "name": item.get("name"),
                            "line": item.get("line"),
                            "methods": item.get("methods", []),
                        }
                        for item in meta.get("classes", [])
                    ],
                    "dependency_risks": dependency_risks,
                }
            )

        risk_score = 0
        risk_score += len(added) * 1
        risk_score += len(removed) * 3
        risk_score += len(modified) * 2
        risk_score += len(python_paths) * 2
        risk_score += len(state_paths) * 1
        if any(path == "agent.py" for path in touched_paths):
            risk_score += 4
        dependency_risk_score = sum(
            int(item.get("risk_score", 0))
            for impact in symbol_impacts
            for item in impact.get("dependency_risks", [])
        )
        if dependency_risk_score >= 20:
            risk_score += 4
        elif dependency_risk_score >= 8:
            risk_score += 2
        if any(path in {"agent.py", ".agent_config.json"} for path in touched_paths) and removed:
            risk_score += 4

        if risk_score >= 14:
            risk_level = "high"
        elif risk_score >= 7:
            risk_level = "medium"
        else:
            risk_level = "low"

        payload = {
            "checkpoint": checkpoint,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "touched_count": len([path for path in touched_paths if path]),
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
            "python_paths": python_paths,
            "state_paths": state_paths,
            "symbol_impacts": symbol_impacts,
            "dependency_risk_score": dependency_risk_score,
            "recommendations": [
                "Run validation before continuing." if risk_level != "low" else "Validation still recommended.",
                "Prefer rollback on failed validation." if risk_level in {"medium", "high"} else "Rollback likely unnecessary if validation passes.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def restore_checkpoint(self, checkpoint: str, preserve_agent_state: bool = True) -> ToolResult:
        checkpoint_path = resolve_workspace_path(checkpoint)
        if not checkpoint_path.exists() or not checkpoint_path.is_dir():
            return ToolResult(False, f"Checkpoint not found: {checkpoint}")

        restored: list[str] = []
        removed: list[str] = []
        skipped: list[str] = []
        checkpoint_files = {
            path.relative_to(checkpoint_path): path
            for path in checkpoint_path.rglob("*")
            if path.is_file()
        }
        current_files = {
            path.relative_to(WORKSPACE_ROOT): path
            for path in iter_workspace_files(WORKSPACE_ROOT)
        }

        for relative, source in checkpoint_files.items():
            destination = WORKSPACE_ROOT / relative
            if preserve_agent_state and should_preserve_on_restore(destination):
                skipped.append(str(relative))
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            restored.append(str(relative))

        for relative, current in current_files.items():
            if relative in checkpoint_files:
                continue
            if preserve_agent_state and should_preserve_on_restore(current):
                skipped.append(str(relative))
                continue
            if current.is_file():
                current.unlink()
                removed.append(str(relative))

        payload = {
            "checkpoint": checkpoint,
            "preserve_agent_state": preserve_agent_state,
            "restored": restored,
            "removed": removed,
            "skipped": skipped,
        }
        emit_monitor(
            f"Checkpoint restored: restored={len(restored)} removed={len(removed)} skipped={len(skipped)}",
            force=True,
        )
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

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

    def evaluate_autonomy_policy(self, impact: dict[str, Any], changed_files: list[str] | None = None) -> ToolResult:
        policy = load_autonomy_policy()
        changed_files = [str(path) for path in (changed_files or []) if str(path)]
        risk_level = str(impact.get("risk_level", "high"))
        state_paths = [path for path in changed_files if Path(path).name.startswith(".agent_")]
        violations: list[str] = []

        if len(changed_files) > int(policy["max_changed_files_per_cycle"]):
            violations.append(
                f"changed file count {len(changed_files)} exceeds max {policy['max_changed_files_per_cycle']}"
            )
        if risk_level_value(risk_level) > risk_level_value(str(policy["max_risk_level"])):
            violations.append(f"risk level {risk_level} exceeds max {policy['max_risk_level']}")
        if state_paths and not bool(policy["allow_state_file_changes"]):
            violations.append(f"state file changes are not allowed: {state_paths}")

        decision = "allow" if not violations else "rollback" if policy["rollback_on_policy_violation"] else "warn"
        payload = {
            "decision": decision,
            "policy": policy,
            "risk_level": risk_level,
            "changed_files": changed_files,
            "state_paths": state_paths,
            "violations": violations,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

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
            planning_brief = self.generate_planning_brief(goal=current_goal)
            selected_opportunity = self.select_next_improvement()
            top_opportunity = selected_opportunity.meta if selected_opportunity.ok else {}
            opportunity_evaluation = top_opportunity.get("manager_evaluation", {}) if top_opportunity else {}
            cycle_roles = selected_roles or planning_brief.meta.get("recommended_roles", [])
            cycle_template = template_name
            experiment: dict[str, Any] = {}
            if top_opportunity:
                self.update_improvement_opportunity(
                    opportunity_id=str(top_opportunity.get("id", "")),
                    status="in_progress",
                    note=f"Selected for autonomous cycle {cycle}.",
                )
                self.update_blackboard(
                    "todo",
                    f"Cycle {cycle} top opportunity: {top_opportunity.get('title')} "
                    f"(score={top_opportunity.get('score')}, target={top_opportunity.get('target')})",
                )
                if opportunity_evaluation.get("decision") != "approve":
                    deferred_status = "rejected" if opportunity_evaluation.get("decision") == "reject" else "blocked"
                    self.update_improvement_opportunity(
                        opportunity_id=str(top_opportunity.get("id", "")),
                        status=deferred_status,
                        note=f"Governor decision={opportunity_evaluation.get('decision')}: {opportunity_evaluation.get('reasons', [])}",
                    )
                    self.record_improvement_outcome(
                        opportunity=top_opportunity,
                        status=deferred_status,
                        validation_ok=True,
                        files_changed=[],
                    )
                    cycle_reports.append(
                        {
                            "cycle": cycle,
                            "goal": current_goal,
                            "control": control,
                            "top_opportunity": top_opportunity,
                            "opportunity_evaluation": opportunity_evaluation,
                            "team_ok": False,
                            "team_summary": "Skipped execution because the improvement governor did not approve the opportunity.",
                            "change_summary_ok": True,
                            "change_summary": "{}",
                            "validation_ok": True,
                            "validation_summary": "{}",
                            "review": {
                                "continue_improving": False,
                                "wrap_up_now": True,
                                "next_focus": current_goal,
                                "summary": "Improvement governor found no approved opportunity worth executing.",
                                "reason": "governor_deferred_top_opportunity",
                            },
                        }
                    )
                    self.record_cycle_ledger_entry(
                        {
                            "time": utc_now(),
                            "goal": current_goal,
                            "cycle": cycle,
                            "status": "blocked",
                            "checkpoint": "",
                            "opportunity": {
                                "id": str(top_opportunity.get("id", "")),
                                "title": top_opportunity.get("title", ""),
                                "target": top_opportunity.get("target", ""),
                                "score": top_opportunity.get("score", 0),
                                "decision": opportunity_evaluation.get("decision"),
                            },
                            "changed_files": [],
                            "validation_ok": True,
                            "policy_decision": opportunity_evaluation.get("decision"),
                            "rollback": False,
                            "review_summary": "Improvement governor found no approved opportunity worth executing.",
                            "next_focus": current_goal,
                            "team_ok": False,
                            "experiment_id": str(experiment.get("id", "")) if experiment else "",
                        }
                    )
                    stop_reason = "governor_no_approved_opportunity"
                    emit_monitor("Improvement governor did not approve the selected opportunity; wrapping up.", force=True)
                    break
                experiment_result = self.start_experiment(
                    title=f"Cycle {cycle}: {top_opportunity.get('title', 'autonomous improvement')}",
                    hypothesis=(
                        f"If Cerebro addresses `{top_opportunity.get('title', 'this opportunity')}`, "
                        f"then validation should remain green and the improvement should move the goal forward: {current_goal}"
                    ),
                    opportunity=top_opportunity,
                )
                experiment = experiment_result.meta if experiment_result.ok else {}
            cycle_label = f"self-improve-cycle-{cycle}-pre"
            checkpoint = self.create_checkpoint(label=cycle_label)
            emit_monitor(f"Cycle {cycle}/{max_cycles}: starting", force=True)
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
                f"- Failed validation will trigger rollback to the pre-cycle checkpoint.\n"
            )
            manager_context = (
                f"{self.state.context_summary()}\n\n"
                f"Persistent task id: {task_id}\n\n"
                f"Planning brief:\n{trim_text(planning_brief.content, 5000)}\n\n"
                f"Shared blackboard:\n{json.dumps(board, indent=2)}\n\n"
                f"Improvement backlog:\n{trim_text(backlog.content, 5000)}\n\n"
                f"Latest code index preview:\n{trim_text(code_index.content, 5000)}"
            )
            team_result = self.manager_execute(
                task=cycle_task,
                context=manager_context,
                template=cycle_template,
                roles=cycle_roles,
            )
            emit_activity("done", f"Cycle {cycle}: team execution completed", force=True, animate=False)
            change_summary = self.summarize_changes_since_checkpoint(checkpoint=checkpoint.meta.get("checkpoint", ""))
            impact_analysis = self.analyze_change_impact(checkpoint=checkpoint.meta.get("checkpoint", ""))
            validation = self.run_self_improvement_validation(path=".")
            rollback_result: ToolResult | None = None
            post_rollback_validation: ToolResult | None = None
            changed_files: list[str] = []
            lines_added = 0
            lines_removed = 0
            change_meta: dict[str, Any] = {}
            if change_summary.ok:
                change_meta = change_summary.meta
                changed_files.extend(change_meta.get("added", []))
                changed_files.extend(change_meta.get("removed", []))
                changed_files.extend(item.get("path", "") for item in change_meta.get("modified", []))
                changed_files = [item for item in changed_files if item]
                lines_added = int(change_meta.get("lines_added", 0))
                lines_removed = int(change_meta.get("lines_removed", 0))
                emit_activity(
                    "editing" if changed_files else "done",
                    f"Edited {len(changed_files)} file(s): +{lines_added} -{lines_removed}",
                    force=True,
                    animate=True,
                )
            policy_result = self.evaluate_autonomy_policy(
                impact=impact_analysis.meta if impact_analysis.ok else {},
                changed_files=changed_files,
            )
            emit_activity("tool", "Ran validation and autonomy policy checks", force=True, animate=False)
            policy_violation = policy_result.meta.get("decision") == "rollback"
            if (not validation.ok or policy_violation) and changed_files:
                rollback_result = self.restore_checkpoint(
                    checkpoint=checkpoint.meta.get("checkpoint", ""),
                    preserve_agent_state=True,
                )
                post_rollback_validation = self.run_self_improvement_validation(path=".")
                self.update_blackboard(
                    "risks",
                    f"Cycle {cycle} rollback triggered; validation_ok={validation.ok}; "
                    f"policy_decision={policy_result.meta.get('decision')}; rollback_ok={rollback_result.ok}; "
                    f"post_rollback_validation_ok={post_rollback_validation.ok}",
                )
            self._append_task_artifacts(
                task_id,
                evidence={
                    "time": utc_now(),
                    "cycle": cycle,
                    "summary": trim_text(team_result.content, 1200),
                    "impact": impact_analysis.meta if impact_analysis.ok else impact_analysis.content,
                    "policy": policy_result.meta,
                    "rollback": parse_json_value(rollback_result.content) if rollback_result else None,
                    "lines_added": lines_added,
                    "lines_removed": lines_removed,
                },
                files_changed=changed_files,
                validation={
                    "time": utc_now(),
                    "cycle": cycle,
                    "ok": validation.ok,
                    "summary": validation.meta,
                    "post_rollback_ok": post_rollback_validation.ok if post_rollback_validation else None,
                },
            )
            self.update_blackboard(
                "agent_notes",
                f"Cycle {cycle}: team_ok={team_result.ok}, validation_ok={validation.ok}, "
                f"changed_files={changed_files[:8]}, lines_added={lines_added}, lines_removed={lines_removed}",
            )
            if top_opportunity:
                opportunity_status = "done" if validation.ok and changed_files else "blocked"
                if rollback_result:
                    opportunity_status = "blocked"
                opportunity_note = (
                    f"Cycle {cycle} completed with validation_ok={validation.ok}; "
                    f"changed_files={changed_files[:8]}; "
                    f"lines_added={lines_added}; lines_removed={lines_removed}; "
                    f"policy_decision={policy_result.meta.get('decision')}; "
                    f"rollback_ok={rollback_result.ok if rollback_result else None}"
                )
                self.update_improvement_opportunity(
                    opportunity_id=str(top_opportunity.get("id", "")),
                    status=opportunity_status,
                    note=opportunity_note,
                )
                self.record_improvement_outcome(
                    opportunity=top_opportunity,
                    status=opportunity_status,
                    validation_ok=validation.ok and rollback_result is None,
                    files_changed=changed_files,
                )
            if experiment:
                if rollback_result:
                    experiment_status = "rolled_back"
                elif validation.ok and changed_files:
                    experiment_status = "completed"
                elif validation.ok:
                    experiment_status = "abandoned"
                else:
                    experiment_status = "failed"
                self.update_experiment(
                    experiment_id=str(experiment.get("id", "")),
                    status=experiment_status,
                    evidence={
                    "cycle": cycle,
                    "validation_ok": validation.ok,
                    "changed_files": changed_files,
                    "lines_added": lines_added,
                    "lines_removed": lines_removed,
                    "impact": impact_analysis.meta if impact_analysis.ok else impact_analysis.content,
                    "policy": policy_result.meta,
                    "rollback": parse_json_value(rollback_result.content) if rollback_result else None,
                },
                    conclusion=(
                        f"Cycle ended with status={experiment_status}, "
                        f"validation_ok={validation.ok}, files_changed={len(changed_files)}."
                    ),
                )
            emit_monitor(
                f"Cycle {cycle} post-checks: changes_ok={change_summary.ok} "
                f"impact={impact_analysis.meta.get('risk_level', 'unknown') if impact_analysis.ok else 'unknown'} "
                f"validation_ok={validation.ok} lines_added={lines_added} lines_removed={lines_removed}",
                force=True,
            )

            review_prompt = (
                f"Goal:\n{current_goal}\n\n"
                f"Cycle number: {cycle}\n"
                f"Max cycles: {max_cycles}\n"
                f"External control mode: {control['mode']}\n\n"
                f"Latest team result:\n{team_result.content}\n"
                f"\nChange summary:\n{change_summary.content}\n"
                f"\nImpact analysis:\n{impact_analysis.content}\n"
                f"\nValidation summary:\n{validation.content}\n"
                f"\nBlackboard:\n{json.dumps(load_blackboard(), indent=2)}\n"
            )
            review_reply = ask_model(
                [
                    {"role": "system", "content": SELF_IMPROVEMENT_REVIEW_PROMPT},
                    {"role": "user", "content": review_prompt},
                ],
                model=get_role_model("meta"),
                provider=get_role_provider("meta"),
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

            cycle_ledger_entry = {
                "time": utc_now(),
                "goal": current_goal,
                "cycle": cycle,
                "status": "rolled_back" if rollback_result else "completed" if validation.ok and changed_files else "blocked" if not validation.ok else "review_only",
                "checkpoint": checkpoint.meta.get("checkpoint", ""),
                "opportunity": {
                    "id": str(top_opportunity.get("id", "")),
                    "title": top_opportunity.get("title", ""),
                    "target": top_opportunity.get("target", ""),
                    "score": top_opportunity.get("score", 0),
                    "decision": opportunity_evaluation.get("decision"),
                },
                "team_ok": team_result.ok,
                "validation_ok": validation.ok,
                "policy_decision": policy_result.meta.get("decision"),
                "rollback": bool(rollback_result),
                "changed_files": changed_files[:20],
                "lines_added": lines_added,
                "lines_removed": lines_removed,
                "change_summary": {
                    "added": change_meta.get("added", [])[:20],
                    "removed": change_meta.get("removed", [])[:20],
                    "modified_count": change_meta.get("modified_count", len(change_meta.get("modified", []))),
                    "modified": [item.get("path", "") for item in change_meta.get("modified", [])[:12] if item.get("path")],
                    "lines_added": lines_added,
                    "lines_removed": lines_removed,
                },
                "impact_risk_level": impact_analysis.meta.get("risk_level", "unknown") if impact_analysis.ok else "unknown",
                "review_summary": str(review.get("summary", "")).strip(),
                "next_focus": str(review.get("next_focus", "")).strip() or current_goal,
                "experiment_id": str(experiment.get("id", "")) if experiment else "",
                "team_summary": trim_text(team_result.content, 800),
            }
            self.record_cycle_ledger_entry(cycle_ledger_entry)
            emit_activity(
                "done",
                f"Cycle {cycle}: +{lines_added} -{lines_removed}, validation_ok={validation.ok}",
                force=True,
                animate=False,
            )

            cycle_report = {
                "cycle": cycle,
                "goal": current_goal,
                "control": control,
                "checkpoint": checkpoint.meta.get("checkpoint", ""),
                "top_opportunity": top_opportunity,
                "opportunity_evaluation": opportunity_evaluation,
                "planning_brief": planning_brief.meta if planning_brief.ok else planning_brief.content,
                "experiment": experiment,
                "team_ok": team_result.ok,
                "team_summary": trim_text(team_result.content, 2000),
                "change_summary_ok": change_summary.ok,
                "change_summary": trim_text(change_summary.content, 3000),
                "lines_added": lines_added,
                "lines_removed": lines_removed,
                "impact_analysis_ok": impact_analysis.ok,
                "impact_analysis": trim_text(impact_analysis.content, 3000),
                "policy_ok": policy_result.ok,
                "policy": policy_result.meta,
                "validation_ok": validation.ok,
                "validation_summary": trim_text(validation.content, 2000),
                "rollback": parse_json_value(rollback_result.content) if rollback_result else None,
                "post_rollback_validation_ok": post_rollback_validation.ok if post_rollback_validation else None,
                "post_rollback_validation_summary": trim_text(post_rollback_validation.content, 2000) if post_rollback_validation else None,
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

        total_lines_added = sum(int(report.get("lines_added", 0)) for report in cycle_reports)
        total_lines_removed = sum(int(report.get("lines_removed", 0)) for report in cycle_reports)
        final_report = {
            "goal": goal,
            "final_focus": current_goal,
            "task_id": task_id,
            "cycles_completed": len(cycle_reports),
            "stop_reason": stop_reason,
            "lines_added": total_lines_added,
            "lines_removed": total_lines_removed,
            "initial_checkpoint": initial_checkpoint.meta.get("checkpoint", ""),
            "preflight_index_ok": preflight_index.ok,
            "preflight_validation_ok": preflight_validation.ok,
            "preflight_backlog_ok": preflight_backlog.ok,
            "improvement_backlog_file": workspace_relative(IMPROVEMENT_BACKLOG_FILE),
            "improvement_learning_file": workspace_relative(IMPROVEMENT_LEARNING_FILE),
            "experiment_journal_file": workspace_relative(EXPERIMENT_JOURNAL_FILE),
            "cycle_ledger_file": workspace_relative(CYCLE_LEDGER_FILE),
            "cycle_ledger_count": len(load_cycle_ledger().get("cycles", [])),
            "control_file": workspace_relative(CONTROL_FILE),
            "cycle_reports": cycle_reports,
            "last_cycle": cycle_reports[-1] if cycle_reports else None,
        }
        self.state.record_autonomous_run(final_report)
        self._append_task_artifacts(
            task_id,
            evidence={
                "time": utc_now(),
                "summary": (
                    f"Autonomous improvement finished after {len(cycle_reports)} cycle(s): {stop_reason}; "
                    f"lines_added={total_lines_added}; lines_removed={total_lines_removed}"
                ),
                "lines_added": total_lines_added,
                "lines_removed": total_lines_removed,
            },
            status="done" if stop_reason not in {"human_requested_stop"} else "blocked",
        )
        self.update_blackboard(
            "decisions",
            f"Autonomous improvement task {task_id} finished: cycles={len(cycle_reports)} reason={stop_reason}",
        )
        save_control_state(mode="continue", note="Autonomous improvement loop finished.")
        if cycle_reports:
            last_cycle = cycle_reports[-1]
            emit_monitor(
                f"Last cycle summary: cycle={last_cycle.get('cycle')} validation_ok={last_cycle.get('validation_ok')} "
                f"rollback={'yes' if last_cycle.get('rollback') else 'no'} "
                f"+{last_cycle.get('lines_added', 0)} -{last_cycle.get('lines_removed', 0)}",
                force=True,
            )
        emit_activity(
            "done",
            f"Self-improvement complete: +{total_lines_added} -{total_lines_removed}",
            force=True,
            animate=True,
        )
        emit_monitor(
            f"Autonomous improvement finished: cycles={final_report['cycles_completed']} "
            f"reason={final_report['stop_reason']} lines_added={total_lines_added} lines_removed={total_lines_removed}",
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

    def summarize_blackboard(self, limit: int = 5) -> ToolResult:
        board = load_blackboard()
        limit = max(1, min(int(limit), 25))
        sections: dict[str, Any] = {}
        for section, entries in board.items():
            if isinstance(entries, list):
                sections[section] = {
                    "count": len(entries),
                    "recent": entries[-limit:],
                }
        payload = {
            "sections": sections,
            "blackboard_file": workspace_relative(BLACKBOARD_FILE),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

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

    def show_config(self) -> ToolResult:
        config = load_config()
        payload = {
            "provider": config.get("provider"),
            "base_url": config.get("base_url"),
            "default_model": config.get("default_model"),
            "temperature": config.get("temperature"),
            "max_steps": config.get("max_steps"),
            "max_batch_actions": config.get("max_batch_actions"),
            "monitor": config.get("monitor"),
            "show_thinking_indicator": config.get("show_thinking_indicator"),
            "fallback_provider": config.get("fallback_provider"),
            "autonomy_policy": config.get("autonomy_policy", {}),
            "llm_providers": redacted_llm_providers(config.get("llm_providers", {})),
            "role_providers": config.get("role_providers", {}),
            "role_models": config.get("role_models", {}),
            "config_file": workspace_relative(CONFIG_FILE),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def list_llm_routes(self) -> ToolResult:
        config = load_config()
        providers = config.get("llm_providers", {})
        routes = {
            role: {
                "provider": get_role_provider(role, config),
                "provider_type": providers.get(get_role_provider(role, config), {}).get("type", "openai_compatible"),
                "model": get_role_model(role),
            }
            for role in ROLE_CATALOG
        }
        provider_summary = {
            name: {
                "type": settings.get("type", "openai_compatible"),
                "base_url": settings.get("base_url", ""),
                "model": settings.get("model", ""),
                "api_key_source": settings.get("api_key_env", "inline" if settings.get("api_key") else ""),
            }
            for name, settings in providers.items()
            if isinstance(settings, dict)
        }
        payload = {
            "default_provider": config.get("provider"),
            "fallback_provider": config.get("fallback_provider"),
            "providers": provider_summary,
            "routes": routes,
            "config_file": workspace_relative(CONFIG_FILE),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def show_workspace_stats(self, path: str = ".", recursive: bool = True) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        candidates = [target] if target.is_file() else list(target.rglob("*") if recursive else target.iterdir())
        files = [item for item in candidates if item.is_file() and not should_skip_checkpoint_path(item)]
        extension_counts: dict[str, int] = {}
        total_bytes = 0
        for item in files:
            extension = item.suffix.lower() or "(none)"
            extension_counts[extension] = extension_counts.get(extension, 0) + 1
            try:
                total_bytes += item.stat().st_size
            except OSError:
                continue
        payload = {
            "path": workspace_relative(target),
            "recursive": recursive,
            "file_count": len(files),
            "total_bytes": total_bytes,
            "extension_counts": dict(sorted(extension_counts.items(), key=lambda item: (-item[1], item[0]))[:20]),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def show_run_history(self, limit: int = 20) -> ToolResult:
        events = load_run_events(limit=limit)
        event_counts: dict[str, int] = {}
        for event in events:
            event_type = str(event.get("event", "unknown"))
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        payload = {
            "count": len(events),
            "event_counts": event_counts,
            "events": events,
            "run_log_file": workspace_relative(RUN_LOG_FILE),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

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

    def analyze_python_complexity(self, path: str = ".", recursive: bool = True) -> ToolResult:
        target = resolve_workspace_path(path)
        candidates = [target] if target.is_file() else list(target.rglob("*.py") if recursive else target.glob("*.py"))
        callables: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        def decision_points(node: ast.AST) -> int:
            score = 0
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.Assert)):
                    score += 1
                elif isinstance(child, ast.Try):
                    score += 1 + len(child.handlers)
                elif isinstance(child, ast.BoolOp):
                    score += max(1, len(child.values) - 1)
                elif hasattr(ast, "Match") and isinstance(child, ast.Match):
                    score += max(1, len(child.cases))
            return score

        for candidate in candidates:
            if candidate.suffix.lower() != ".py" or should_skip_checkpoint_path(candidate):
                continue
            relative = workspace_relative(candidate)
            try:
                tree = ast.parse(candidate.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError as exc:
                errors.append({"path": relative, "error": str(exc)})
                continue

            parents: list[str] = []

            class Visitor(ast.NodeVisitor):
                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    parents.append(node.name)
                    self.generic_visit(node)
                    parents.pop()

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    self._record(node)

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    self._record(node)

                def _record(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                    qualified = ".".join([*parents, node.name]) if parents else node.name
                    end_line = int(getattr(node, "end_lineno", node.lineno))
                    line_count = max(1, end_line - int(node.lineno) + 1)
                    branches = decision_points(node)
                    calls = sum(1 for child in ast.walk(node) if isinstance(child, ast.Call))
                    returns = sum(1 for child in ast.walk(node) if isinstance(child, ast.Return))
                    complexity_score = branches * 3 + line_count // 8 + calls // 6 + max(0, returns - 1)
                    callables.append(
                        {
                            "path": relative,
                            "name": node.name,
                            "qualified_name": qualified,
                            "line": node.lineno,
                            "line_count": line_count,
                            "decision_points": branches,
                            "call_count": calls,
                            "return_count": returns,
                            "complexity_score": complexity_score,
                            "risk_level": "high" if complexity_score >= 18 else "medium" if complexity_score >= 8 else "low",
                        }
                    )
                    self.generic_visit(node)

            Visitor().visit(tree)

        callables.sort(key=lambda item: (-int(item["complexity_score"]), -int(item["line_count"]), item["qualified_name"]))
        payload = {
            "generated_at": utc_now(),
            "path": path,
            "recursive": recursive,
            "callable_count": len(callables),
            "callables": callables[:150],
            "errors": errors,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def build_import_graph(self, path: str = ".", recursive: bool = True) -> ToolResult:
        target = resolve_workspace_path(path)
        candidates = [target] if target.is_file() else list(target.rglob("*.py") if recursive else target.glob("*.py"))
        py_files = [
            candidate
            for candidate in candidates
            if candidate.suffix.lower() == ".py" and not should_skip_checkpoint_path(candidate)
        ]
        module_by_path: dict[str, str] = {}
        local_roots: set[str] = set()
        for candidate in py_files:
            relative = candidate.relative_to(WORKSPACE_ROOT).with_suffix("")
            module = ".".join(part for part in relative.parts if part != "__init__")
            module_by_path[workspace_relative(candidate)] = module
            if module:
                local_roots.add(module.split(".", 1)[0])

        files: dict[str, dict[str, Any]] = {}
        local_edges: list[dict[str, str]] = []
        errors: list[dict[str, str]] = []
        for candidate in py_files:
            relative = workspace_relative(candidate)
            try:
                tree = ast.parse(candidate.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError as exc:
                errors.append({"path": relative, "error": str(exc)})
                continue
            imports: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    module = "." * node.level + (node.module or "")
                    imports.append(module)
            unique_imports = sorted({item for item in imports if item})
            local_imports = [
                item
                for item in unique_imports
                if item.lstrip(".").split(".", 1)[0] in local_roots or item.startswith(".")
            ]
            files[relative] = {
                "module": module_by_path.get(relative, ""),
                "imports": unique_imports,
                "local_imports": local_imports,
            }
            for imported in local_imports:
                local_edges.append({"from": relative, "to": imported})

        payload = {
            "generated_at": utc_now(),
            "path": path,
            "recursive": recursive,
            "files": files,
            "local_edges": local_edges,
            "errors": errors,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def find_duplicate_blocks(self, path: str = ".", min_lines: int = 6) -> ToolResult:
        target = resolve_workspace_path(path)
        min_lines = max(3, min(int(min_lines), 20))
        candidates = [target] if target.is_file() else list(target.rglob("*"))
        windows: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        text_suffixes = {".py", ".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".js", ".ts", ".css", ".html"}
        for candidate in candidates:
            if not candidate.is_file() or should_skip_checkpoint_path(candidate):
                continue
            if candidate.suffix.lower() not in text_suffixes:
                continue
            try:
                raw_lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            normalized = [
                re.sub(r"\s+", " ", line.strip())
                for line in raw_lines
                if line.strip() and not line.strip().startswith(("#", "//"))
            ]
            if len(normalized) < min_lines:
                continue
            for index in range(0, len(normalized) - min_lines + 1):
                block = tuple(normalized[index : index + min_lines])
                windows.setdefault(block, []).append({"path": workspace_relative(candidate), "line": index + 1})

        duplicates = [
            {
                "occurrences": occurrences,
                "occurrence_count": len(occurrences),
                "preview": "\n".join(block),
            }
            for block, occurrences in windows.items()
            if len({item["path"] for item in occurrences}) > 1 or len(occurrences) > 1
        ]
        duplicates.sort(key=lambda item: (-int(item["occurrence_count"]), item["preview"]))
        payload = {
            "path": path,
            "min_lines": min_lines,
            "duplicate_count": len(duplicates),
            "duplicates": duplicates[:50],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def suggest_refactor_targets(self, path: str = ".", recursive: bool = True) -> ToolResult:
        complexity = self.analyze_python_complexity(path=path, recursive=recursive)
        hotspots = self.rank_code_hotspots(path=path, recursive=recursive)
        orphans = self.find_orphan_symbols(path=path, recursive=recursive)
        todos = self.search_todos(path=path, recursive=recursive)
        candidates: dict[str, dict[str, Any]] = {}

        def ensure(key: str, path_name: str, name: str = "", line: int | None = None) -> dict[str, Any]:
            item = candidates.setdefault(
                key,
                {
                    "target": key,
                    "path": path_name,
                    "name": name,
                    "line": line,
                    "score": 0,
                    "signals": [],
                },
            )
            return item

        for item in (complexity.meta.get("callables", []) if complexity.ok else [])[:40]:
            if item.get("risk_level") == "low":
                continue
            key = f"{item.get('path')}:{item.get('qualified_name')}"
            candidate = ensure(key, str(item.get("path", "")), str(item.get("qualified_name", "")), item.get("line"))
            candidate["score"] += int(item.get("complexity_score", 0))
            candidate["signals"].append(f"complexity={item.get('complexity_score')} risk={item.get('risk_level')}")

        for item in (hotspots.meta.get("hotspots", []) if hotspots.ok else [])[:40]:
            if item.get("risk_level") == "low":
                continue
            key = f"{item.get('path')}:{item.get('qualified_name')}"
            candidate = ensure(key, str(item.get("path", "")), str(item.get("qualified_name", "")), item.get("line"))
            candidate["score"] += int(item.get("score", 0))
            candidate["signals"].append(f"hotspot={item.get('score')} fan_in={item.get('fan_in')} fan_out={item.get('fan_out')}")

        for item in (orphans.meta.get("orphans", []) if orphans.ok else [])[:40]:
            key = f"{item.get('path')}:{item.get('qualified_name')}"
            candidate = ensure(key, str(item.get("path", "")), str(item.get("qualified_name", "")), item.get("line"))
            candidate["score"] += 4 if item.get("review_risk") == "medium" else 2
            candidate["signals"].append(f"orphan review_risk={item.get('review_risk')}")

        for item in (todos.meta.get("matches", []) if todos.ok else [])[:80]:
            key = f"{item.get('path')}:line-{item.get('line')}"
            candidate = ensure(key, str(item.get("path", "")), str(item.get("tag", "")), item.get("line"))
            candidate["score"] += 3 if item.get("tag") in {"TODO", "FIXME"} else 1
            candidate["signals"].append(f"{item.get('tag')}={item.get('text')}")

        ranked = sorted(candidates.values(), key=lambda item: (-int(item["score"]), item["target"]))
        for item in ranked:
            if item["score"] >= 24:
                item["priority"] = "high"
            elif item["score"] >= 10:
                item["priority"] = "medium"
            else:
                item["priority"] = "low"
            item["recommendation"] = "Refactor with checkpoint and targeted tests." if item["priority"] != "low" else "Review opportunistically."

        payload = {
            "generated_at": utc_now(),
            "path": path,
            "recursive": recursive,
            "target_count": len(ranked),
            "targets": ranked[:50],
            "source_ok": {
                "complexity": complexity.ok,
                "hotspots": hotspots.ok,
                "orphans": orphans.ok,
                "todos": todos.ok,
            },
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def build_code_graph(self, path: str = ".", recursive: bool = True) -> ToolResult:
        target = resolve_workspace_path(path)
        candidates = [target] if target.is_file() else list(target.rglob("*.py") if recursive else target.glob("*.py"))
        nodes: dict[str, dict[str, Any]] = {}
        reverse_calls: dict[str, list[dict[str, str]]] = {}
        errors: list[dict[str, str]] = []

        def call_name(node: ast.AST) -> str:
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                parent = call_name(node.value)
                return f"{parent}.{node.attr}" if parent else node.attr
            return ""

        for candidate in candidates:
            if candidate.suffix.lower() != ".py" or should_skip_checkpoint_path(candidate):
                continue
            relative = workspace_relative(candidate)
            try:
                tree = ast.parse(candidate.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError as exc:
                errors.append({"path": relative, "error": str(exc)})
                continue

            parents: list[str] = []

            class Visitor(ast.NodeVisitor):
                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    parents.append(node.name)
                    self.generic_visit(node)
                    parents.pop()

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    self._visit_callable(node)

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    self._visit_callable(node)

                def _visit_callable(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                    qualified = ".".join([*parents, node.name]) if parents else node.name
                    node_id = f"{relative}:{qualified}"
                    calls: list[str] = []
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            name = call_name(child.func)
                            if name:
                                calls.append(name)
                    unique_calls = sorted(set(calls))
                    nodes[node_id] = {
                        "path": relative,
                        "name": node.name,
                        "qualified_name": qualified,
                        "line": node.lineno,
                        "calls": unique_calls,
                    }
                    for called in unique_calls:
                        reverse_calls.setdefault(called.split(".")[-1], []).append(
                            {
                                "caller": node_id,
                                "path": relative,
                                "qualified_name": qualified,
                            }
                        )

            Visitor().visit(tree)

        graph = {
            "generated_at": utc_now(),
            "root": str(WORKSPACE_ROOT),
            "nodes": nodes,
            "reverse_calls": reverse_calls,
            "errors": errors,
        }
        CODE_GRAPH_FILE.write_text(json.dumps(graph, indent=2), encoding="utf-8")
        return ToolResult(True, json.dumps(graph, indent=2), meta=graph)

    def show_code_graph(self) -> ToolResult:
        if not CODE_GRAPH_FILE.exists():
            return ToolResult(False, "No code graph exists yet. Run build_code_graph first.")
        text = CODE_GRAPH_FILE.read_text(encoding="utf-8", errors="replace")
        return ToolResult(True, trim_text(text, 20000), meta=parse_json_value(text))

    def find_callers(self, name: str) -> ToolResult:
        if not CODE_GRAPH_FILE.exists():
            graph_result = self.build_code_graph(path=".", recursive=True)
            if not graph_result.ok:
                return graph_result
        graph = parse_json_value(CODE_GRAPH_FILE.read_text(encoding="utf-8", errors="replace"))
        reverse = graph.get("reverse_calls", {}) if isinstance(graph, dict) else {}
        needle = name.split(".")[-1]
        callers = reverse.get(needle, [])
        if not callers:
            lowered = needle.lower()
            callers = [
                caller
                for called, entries in reverse.items()
                if lowered in called.lower()
                for caller in entries
            ]
        payload = {"name": name, "callers": callers}
        return ToolResult(bool(callers), json.dumps(payload, indent=2), meta=payload)

    def analyze_symbol_impact(self, name: str) -> ToolResult:
        if not CODE_GRAPH_FILE.exists():
            graph_result = self.build_code_graph(path=".", recursive=True)
            if not graph_result.ok:
                return graph_result
        graph = parse_json_value(CODE_GRAPH_FILE.read_text(encoding="utf-8", errors="replace"))
        nodes = graph.get("nodes", {}) if isinstance(graph, dict) else {}
        reverse = graph.get("reverse_calls", {}) if isinstance(graph, dict) else {}
        needle = name.split(".")[-1]

        matching_nodes = [
            {"id": node_id, **node}
            for node_id, node in nodes.items()
            if node.get("name") == needle or node.get("qualified_name", "").endswith(name)
        ]
        callers = reverse.get(needle, [])
        callees = sorted(
            {
                call
                for node in matching_nodes
                for call in node.get("calls", [])
            }
        )
        second_order_callers = sorted(
            {
                caller.get("caller", "")
                for direct in callers
                for caller in reverse.get(direct.get("qualified_name", "").split(".")[-1], [])
                if caller.get("caller")
            }
        )

        risk_score = len(callers) * 2 + len(callees) + len(second_order_callers)
        if any(node.get("path") == "agent.py" for node in matching_nodes):
            risk_score += 2
        if needle in {"parse_model_reply", "load_config", "run_agent", "execute_action", "resolve_workspace_path"}:
            risk_score += 6

        if risk_score >= 16:
            risk_level = "high"
        elif risk_score >= 7:
            risk_level = "medium"
        else:
            risk_level = "low"

        payload = {
            "name": name,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "matches": matching_nodes,
            "direct_callers": callers,
            "callees": callees,
            "second_order_callers": second_order_callers[:25],
            "recommendations": [
                "Run internal self-tests after editing this symbol." if risk_level != "low" else "Compile validation may be sufficient for small edits.",
                "Prefer a checkpoint and narrow patch before changing high fan-in symbols." if callers else "No direct callers found; verify dynamic usage manually.",
            ],
        }
        return ToolResult(bool(matching_nodes or callers), json.dumps(payload, indent=2), meta=payload)

    def find_orphan_symbols(self, path: str = ".", recursive: bool = True) -> ToolResult:
        graph_result = self.build_code_graph(path=path, recursive=recursive)
        if not graph_result.ok:
            return graph_result
        graph = graph_result.meta
        nodes = graph.get("nodes", {})
        reverse = graph.get("reverse_calls", {})
        entrypoint_names = {
            "main",
            "repl",
            "__init__",
            "__post_init__",
            "render",
            "visit_ClassDef",
            "visit_FunctionDef",
            "visit_AsyncFunctionDef",
        }
        orphaned: list[dict[str, Any]] = []
        for node_id, node in nodes.items():
            name = str(node.get("name", ""))
            qualified = str(node.get("qualified_name", ""))
            if not name or name.startswith("__") or name in entrypoint_names:
                continue
            if name.startswith("_") and not name.startswith("_visit"):
                continue
            callers = reverse.get(name, [])
            if callers:
                continue
            risk = "medium" if node.get("path") == "agent.py" and not name.startswith("show_") else "low"
            orphaned.append(
                {
                    "id": node_id,
                    "path": node.get("path"),
                    "name": name,
                    "qualified_name": qualified,
                    "line": node.get("line"),
                    "calls_count": len(node.get("calls", [])),
                    "review_risk": risk,
                    "recommendation": "Review before removing; dynamic tool dispatch or external use may not appear in the static graph.",
                }
            )
        payload = {
            "path": path,
            "recursive": recursive,
            "orphan_count": len(orphaned),
            "orphans": orphaned[:100],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def rank_code_hotspots(self, path: str = ".", recursive: bool = True) -> ToolResult:
        index_result = self.index_codebase(path=path, recursive=recursive)
        graph_result = self.build_code_graph(path=path, recursive=recursive)
        if not graph_result.ok:
            return graph_result
        graph = graph_result.meta
        index = index_result.meta if index_result.ok else parse_json_value(index_result.content)
        nodes = graph.get("nodes", {})
        reverse = graph.get("reverse_calls", {})
        path_to_docstrings: dict[str, dict[str, set[str]]] = {}
        for file_info in index.get("files", []) if isinstance(index, dict) else []:
            path_to_docstrings[file_info.get("path", "")] = {
                "functions_with_docs": {
                    item.get("name", "")
                    for item in file_info.get("functions", [])
                    if item.get("docstring")
                },
                "functions_total": {
                    item.get("name", "")
                    for item in file_info.get("functions", [])
                },
            }

        hotspots: list[dict[str, Any]] = []
        for node_id, node in nodes.items():
            name = str(node.get("name", ""))
            qualified = str(node.get("qualified_name", ""))
            path_name = str(node.get("path", ""))
            callers = reverse.get(name, [])
            callees = node.get("calls", [])
            doc_info = path_to_docstrings.get(path_name, {})
            functions_with_docs = doc_info.get("functions_with_docs", set())
            functions_total = doc_info.get("functions_total", set())
            documentation_gap = 0
            if name and name in functions_total and name not in functions_with_docs:
                documentation_gap = 1

            score = (
                len(callers) * 4
                + len(callees) * 2
                + documentation_gap * 2
            )
            if path_name == "agent.py":
                score += 2
            if name.startswith("_") and not name.startswith("__"):
                score -= 1

            risk_level = "high" if score >= 16 else "medium" if score >= 7 else "low"
            hotspots.append(
                {
                    "id": node_id,
                    "path": path_name,
                    "name": name,
                    "qualified_name": qualified,
                    "line": node.get("line"),
                    "score": score,
                    "risk_level": risk_level,
                    "fan_in": len(callers),
                    "fan_out": len(callees),
                    "documentation_gap": bool(documentation_gap),
                    "callers": callers[:15],
                    "recommendation": (
                        "Investigate before editing; high fan-in or fan-out increases blast radius."
                        if risk_level != "low"
                        else "Safe candidate for cleanup or extraction review."
                    ),
                }
            )

        hotspots.sort(key=lambda item: (-int(item.get("score", 0)), -int(item.get("fan_in", 0)), -int(item.get("fan_out", 0)), item.get("qualified_name", "")))
        report = {
            "generated_at": utc_now(),
            "root": str(WORKSPACE_ROOT),
            "path": path,
            "recursive": recursive,
            "hotspots": hotspots[:150],
        }
        CODE_HOTSPOTS_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return ToolResult(True, json.dumps(report, indent=2), meta=report)

    def show_code_hotspots(self) -> ToolResult:
        if not CODE_HOTSPOTS_FILE.exists():
            return ToolResult(False, "No code hotspot report exists yet. Run rank_code_hotspots first.")
        text = CODE_HOTSPOTS_FILE.read_text(encoding="utf-8", errors="replace")
        return ToolResult(True, trim_text(text, 20000), meta=parse_json_value(text))

    def scan_improvement_opportunities(self, goal: str = "improve this codebase") -> ToolResult:
        index_result = self.index_codebase(path=".", recursive=True)
        orphan_result = self.find_orphan_symbols(path=".", recursive=True)
        hotspot_result = self.rank_code_hotspots(path=".", recursive=True)
        validation = self.run_self_improvement_validation(path=".")
        tasks = load_tasks().get("tasks", [])
        index = index_result.meta if index_result.ok else parse_json_value(index_result.content)
        files = index.get("files", []) if isinstance(index, dict) else []
        goal_text = goal.lower()
        previous_backlog = load_improvement_backlog()
        previous_by_key = {
            (str(item.get("title", "")), str(item.get("target", ""))): item
            for item in previous_backlog.get("opportunities", [])
            if isinstance(item, dict)
        }
        learning = load_improvement_learning().get("opportunities", {})
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
            previous = previous_by_key.get((title, target), {})
            learned = learning.get(f"{title.strip().lower()}::{target.strip().lower()}", {})
            attempts = int(learned.get("attempts", 0)) if isinstance(learned, dict) else 0
            success_rate = float(learned.get("success_rate", 0.0)) if isinstance(learned, dict) else 0.0
            blocked_rate = float(learned.get("blocked_rate", 0.0)) if isinstance(learned, dict) else 0.0
            learning_adjustment = 0
            if attempts >= 2:
                learning_adjustment += round(success_rate * 4)
                learning_adjustment -= round(blocked_rate * 5)
            score = max(0, impact * 3 + confidence * 2 - risk * 2 - effort + learning_adjustment)
            history = previous.get("history") if isinstance(previous.get("history"), list) else []
            status = str(previous.get("status", "open"))
            if not history:
                history = [{"time": utc_now(), "status": status, "note": "Opportunity discovered."}]
            opportunities.append(
                {
                    "id": previous.get("id") or f"opp_{uuid.uuid4().hex[:10]}",
                    "title": title,
                    "rationale": rationale,
                    "target": target,
                    "impact": impact,
                    "confidence": confidence,
                    "risk": risk,
                    "effort": effort,
                    "score": score,
                    "learning_adjustment": learning_adjustment,
                    "learning": learned,
                    "status": status,
                    "history": history,
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

        orphan_count = orphan_result.meta.get("orphan_count", 0) if orphan_result.ok else 0
        if orphan_count >= 10 and any(word in goal_text for word in {"refactor", "cleanup", "maintain", "intelligence", "improve"}):
            add_opportunity(
                "Review orphaned symbols",
                "The static call graph found many symbols with no indexed callers; reviewing them may reveal dead code, dynamic dispatch gaps, or documentation needs.",
                workspace_relative(CODE_GRAPH_FILE),
                impact=3,
                confidence=3,
                risk=2,
                effort=3,
                evidence=[f"orphan_count={orphan_count}", f"sample={orphan_result.meta.get('orphans', [])[:8]}"],
            )

        hotspot_count = 0
        hotspot_samples: list[dict[str, Any]] = []
        if hotspot_result.ok and isinstance(hotspot_result.meta, dict):
            hotspot_samples = hotspot_result.meta.get("hotspots", [])[:10]
            hotspot_count = len(hotspot_result.meta.get("hotspots", []))
        if hotspot_count >= 8 and any(word in goal_text for word in {"refactor", "cleanup", "maintain", "intelligence", "improve", "advanced", "tool"}):
            add_opportunity(
                "Triage code hotspots",
                "The hotspot ranking identifies high-blast-radius symbols and documentation gaps that should be addressed before deeper autonomous refactors.",
                workspace_relative(CODE_HOTSPOTS_FILE),
                impact=4,
                confidence=4,
                risk=2,
                effort=3,
                evidence=[f"hotspot_count={hotspot_count}", f"sample={hotspot_samples}"],
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

    def select_next_improvement(self) -> ToolResult:
        backlog = load_improvement_backlog()
        opportunities = [
            item
            for item in backlog.get("opportunities", [])
            if item.get("status", "open") in {"open", "planned"}
        ]
        if not opportunities:
            return ToolResult(False, "No open improvement opportunities. Run scan_improvement_opportunities first.")
        ranked: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for item in opportunities:
            evaluation = self.evaluate_improvement_opportunity(item)
            ranked.append((item, evaluation.meta))
        ranked.sort(
            key=lambda pair: (
                0 if pair[1].get("decision") == "approve" else 1,
                -int(pair[1].get("priority_score", 0)),
                int(pair[0].get("risk", 5)),
                int(pair[0].get("effort", 5)),
            )
        )
        selected, evaluation = ranked[0]
        selected = {**selected, "manager_evaluation": evaluation}
        return ToolResult(True, json.dumps(selected, indent=2), meta=selected)

    def evaluate_improvement_opportunity(self, opportunity: dict[str, Any]) -> ToolResult:
        validation = self.run_self_improvement_validation(path=".")
        validation_meta = validation.meta if isinstance(validation.meta, dict) else {}
        hard_failures = validation_meta.get("hard_failures", [])
        impact = int(opportunity.get("impact", 0))
        confidence = int(opportunity.get("confidence", 0))
        risk = int(opportunity.get("risk", 5))
        effort = int(opportunity.get("effort", 5))
        history = opportunity.get("history", [])
        learned = load_improvement_learning().get("opportunities", {}).get(opportunity_learning_key(opportunity), {})
        learned_attempts = int(learned.get("attempts", 0)) if isinstance(learned, dict) else 0
        learned_success_rate = float(learned.get("success_rate", 0.0)) if isinstance(learned, dict) else 0.0
        learned_blocked_rate = float(learned.get("blocked_rate", 0.0)) if isinstance(learned, dict) else 0.0
        blocked_count = sum(
            1
            for item in history
            if isinstance(item, dict) and item.get("status") in {"blocked", "rejected"}
        )
        learned_adjustment = 0
        if learned_attempts >= 2:
            learned_adjustment += round(learned_success_rate * 5)
            learned_adjustment -= round(learned_blocked_rate * 6)
        priority_score = max(0, impact * 4 + confidence * 3 - risk * 3 - effort * 2 - blocked_count * 4 + learned_adjustment)
        reasons: list[str] = []
        decision = "approve"

        if hard_failures and opportunity.get("target") != "validation":
            decision = "defer"
            reasons.append("Hard validation failures exist; prioritize validation repairs first.")
        if risk >= 5 and confidence < 4:
            decision = "reject"
            reasons.append("Risk is high and confidence is too low.")
        elif risk >= 4 and impact < 4:
            decision = "defer"
            reasons.append("Risk is not justified by impact.")
        if blocked_count >= 2:
            decision = "defer"
            reasons.append("Opportunity has been blocked or rejected repeatedly.")
        if learned_attempts >= 3 and learned_blocked_rate >= 0.66:
            decision = "defer"
            reasons.append("Learning memory shows this opportunity type is frequently blocked.")
        if priority_score < 8 and decision == "approve":
            decision = "defer"
            reasons.append("Priority score is below the execution threshold.")
        if not reasons:
            reasons.append("Expected value is acceptable under current validation state.")

        payload = {
            "decision": decision,
            "priority_score": priority_score,
            "validation_ok": validation.ok,
            "hard_failures": hard_failures,
            "blocked_or_rejected_count": blocked_count,
            "learned_attempts": learned_attempts,
            "learned_success_rate": learned_success_rate,
            "learned_blocked_rate": learned_blocked_rate,
            "learned_adjustment": learned_adjustment,
            "reasons": reasons,
            "opportunity_id": opportunity.get("id", ""),
            "title": opportunity.get("title", ""),
            "target": opportunity.get("target", ""),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def update_improvement_opportunity(self, opportunity_id: str, status: str, note: str = "") -> ToolResult:
        allowed = {"open", "planned", "in_progress", "done", "blocked", "rejected"}
        if status not in allowed:
            return ToolResult(False, f"status must be one of: {', '.join(sorted(allowed))}")
        backlog = load_improvement_backlog()
        for item in backlog.get("opportunities", []):
            if item.get("id") != opportunity_id:
                continue
            item["status"] = status
            item.setdefault("history", []).append(
                {
                    "time": utc_now(),
                    "status": status,
                    "note": note,
                }
            )
            save_improvement_backlog(backlog)
            return ToolResult(True, json.dumps(item, indent=2), meta=item)
        return ToolResult(False, f"Opportunity not found: {opportunity_id}")

    def record_improvement_outcome(
        self,
        opportunity: dict[str, Any],
        status: str,
        validation_ok: bool,
        files_changed: list[str] | None = None,
    ) -> ToolResult:
        learning = load_improvement_learning()
        records = learning.setdefault("opportunities", {})
        key = opportunity_learning_key(opportunity)
        record = records.setdefault(
            key,
            {
                "title": opportunity.get("title", ""),
                "target": opportunity.get("target", ""),
                "attempts": 0,
                "successes": 0,
                "blocked": 0,
                "validation_failures": 0,
                "files_changed_total": 0,
                "last_outcome": {},
            },
        )
        record["attempts"] = int(record.get("attempts", 0)) + 1
        if status == "done" and validation_ok:
            record["successes"] = int(record.get("successes", 0)) + 1
        if status in {"blocked", "rejected"}:
            record["blocked"] = int(record.get("blocked", 0)) + 1
        if not validation_ok:
            record["validation_failures"] = int(record.get("validation_failures", 0)) + 1
        changed_count = len(files_changed or [])
        record["files_changed_total"] = int(record.get("files_changed_total", 0)) + changed_count
        attempts = max(1, int(record["attempts"]))
        record["success_rate"] = round(int(record.get("successes", 0)) / attempts, 3)
        record["blocked_rate"] = round(int(record.get("blocked", 0)) / attempts, 3)
        record["last_outcome"] = {
            "time": utc_now(),
            "status": status,
            "validation_ok": validation_ok,
            "files_changed": files_changed or [],
        }
        save_improvement_learning(learning)
        return ToolResult(True, json.dumps(record, indent=2), meta=record)

    def show_improvement_learning(self) -> ToolResult:
        learning = load_improvement_learning()
        return ToolResult(True, json.dumps(learning, indent=2), meta=learning)

    def start_experiment(self, title: str, hypothesis: str, opportunity: dict[str, Any] | None = None) -> ToolResult:
        journal = load_experiment_journal()
        now = utc_now()
        experiment = {
            "id": f"exp_{uuid.uuid4().hex[:12]}",
            "title": title,
            "hypothesis": hypothesis,
            "status": "running",
            "opportunity": opportunity or {},
            "evidence": [],
            "conclusion": "",
            "created_at": now,
            "updated_at": now,
        }
        journal["experiments"].append(experiment)
        save_experiment_journal(journal)
        return ToolResult(True, json.dumps(experiment, indent=2), meta=experiment)

    def update_experiment(
        self,
        experiment_id: str,
        status: str,
        evidence: dict[str, Any] | None = None,
        conclusion: str = "",
    ) -> ToolResult:
        allowed = {"planned", "running", "completed", "failed", "rolled_back", "abandoned"}
        if status not in allowed:
            return ToolResult(False, f"status must be one of: {', '.join(sorted(allowed))}")
        journal = load_experiment_journal()
        for experiment in journal["experiments"]:
            if experiment.get("id") != experiment_id:
                continue
            experiment["status"] = status
            if evidence:
                experiment.setdefault("evidence", []).append({"time": utc_now(), **evidence})
            if conclusion:
                experiment["conclusion"] = conclusion
            experiment["updated_at"] = utc_now()
            save_experiment_journal(journal)
            return ToolResult(True, json.dumps(experiment, indent=2), meta=experiment)
        return ToolResult(False, f"Experiment not found: {experiment_id}")

    def show_experiments(self, status: str = "") -> ToolResult:
        journal = load_experiment_journal()
        experiments = journal["experiments"]
        if status:
            experiments = [item for item in experiments if item.get("status") == status]
        payload = {"experiments": experiments}
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def record_cycle_ledger_entry(self, entry: dict[str, Any]) -> ToolResult:
        ledger = load_cycle_ledger()
        cycles = ledger.setdefault("cycles", [])
        cycles.append(entry)
        ledger["cycles"] = cycles[-80:]
        save_cycle_ledger(ledger)
        return ToolResult(True, json.dumps(entry, indent=2), meta=entry)

    def show_cycle_ledger(self, limit: int = 10) -> ToolResult:
        ledger = load_cycle_ledger()
        cycles = ledger.get("cycles", []) if isinstance(ledger, dict) else []
        limit = max(1, min(int(limit), 50))
        payload = {
            "updated_at": ledger.get("updated_at", "") if isinstance(ledger, dict) else "",
            "count": len(cycles),
            "cycles": cycles[-limit:],
            "ledger_file": workspace_relative(CYCLE_LEDGER_FILE),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def generate_health_report(self, goal: str = "improve this codebase") -> ToolResult:
        validation = self.run_self_improvement_validation(path=".")
        code_index = self.index_codebase(path=".", recursive=True)
        code_graph = self.build_code_graph(path=".", recursive=True)
        hotspot_result = self.rank_code_hotspots(path=".", recursive=True)
        orphan_symbols = self.find_orphan_symbols(path=".", recursive=True)
        backlog = self.scan_improvement_opportunities(goal=goal)
        selected = self.select_next_improvement()
        learning = load_improvement_learning()
        experiments = load_experiment_journal().get("experiments", [])
        tasks = load_tasks().get("tasks", [])

        risk_counts: dict[str, int] = {}
        for spec in self.tool_specs.values():
            risk_counts[spec.risk] = risk_counts.get(spec.risk, 0) + 1

        task_status_counts: dict[str, int] = {}
        for task in tasks:
            status = str(task.get("status", "unknown"))
            task_status_counts[status] = task_status_counts.get(status, 0) + 1

        experiment_status_counts: dict[str, int] = {}
        for experiment in experiments:
            status = str(experiment.get("status", "unknown"))
            experiment_status_counts[status] = experiment_status_counts.get(status, 0) + 1

        opportunities = backlog.meta.get("opportunities", []) if backlog.ok else []
        opportunity_status_counts: dict[str, int] = {}
        for opportunity in opportunities:
            status = str(opportunity.get("status", "unknown"))
            opportunity_status_counts[status] = opportunity_status_counts.get(status, 0) + 1

        learning_records = learning.get("opportunities", {}) if isinstance(learning, dict) else {}
        learned_attempts = sum(int(item.get("attempts", 0)) for item in learning_records.values() if isinstance(item, dict))
        learned_successes = sum(int(item.get("successes", 0)) for item in learning_records.values() if isinstance(item, dict))
        learned_blocked = sum(int(item.get("blocked", 0)) for item in learning_records.values() if isinstance(item, dict))

        recommendations: list[str] = []
        validation_meta = validation.meta if isinstance(validation.meta, dict) else {}
        if validation_meta.get("hard_failures"):
            recommendations.append("Fix hard validation failures before attempting feature work.")
        if selected.ok:
            evaluation = selected.meta.get("manager_evaluation", {})
            recommendations.append(
                f"Next approved focus: {selected.meta.get('title')} "
                f"(decision={evaluation.get('decision')}, priority={evaluation.get('priority_score')})."
            )
        if hotspot_result.ok and len(hotspot_result.meta.get("hotspots", [])) >= 12:
            recommendations.append("Use the hotspot report to avoid broad edits to high-blast-radius helpers.")
        if task_status_counts.get("running", 0) + task_status_counts.get("blocked", 0) > 3:
            recommendations.append("Reconcile stale running or blocked task records before long autonomous runs.")
        if learned_attempts == 0:
            recommendations.append("Run at least one controlled improvement experiment to seed learning statistics.")
        elif learned_blocked > learned_successes:
            recommendations.append("Prefer lower-risk opportunities until blocked-rate improves.")
        recent_cycles = load_cycle_ledger().get("cycles", [])[-3:]
        if recent_cycles:
            recommendations.append(f"Review the last {len(recent_cycles)} cycle ledger entries before broad edits.")
        if not recommendations:
            recommendations.append("Platform health is acceptable; proceed with the top governed improvement opportunity.")

        payload = {
            "generated_at": utc_now(),
            "goal": goal,
            "autonomy_policy": load_autonomy_policy(),
            "validation": {
                "ok": validation.ok,
                "summary": validation_meta,
            },
            "code_index": {
                "ok": code_index.ok,
                "files_indexed": len(code_index.meta.get("files", [])) if code_index.ok else 0,
                "errors": code_index.meta.get("errors", []) if code_index.ok else [],
            },
            "code_graph": {
                "ok": code_graph.ok,
                "nodes": len(code_graph.meta.get("nodes", {})) if code_graph.ok else 0,
                "errors": code_graph.meta.get("errors", []) if code_graph.ok else [],
                "orphan_count": orphan_symbols.meta.get("orphan_count", 0) if orphan_symbols.ok else None,
                "graph_file": workspace_relative(CODE_GRAPH_FILE),
            },
            "code_hotspots": {
                "ok": hotspot_result.ok,
                "count": len(hotspot_result.meta.get("hotspots", [])) if hotspot_result.ok else 0,
                "hotspot_file": workspace_relative(CODE_HOTSPOTS_FILE),
            },
            "tools": {
                "total": len(self.tool_specs),
                "risk_counts": risk_counts,
            },
            "tasks": {
                "total": len(tasks),
                "status_counts": task_status_counts,
            },
            "experiments": {
                "total": len(experiments),
                "status_counts": experiment_status_counts,
                "journal_file": workspace_relative(EXPERIMENT_JOURNAL_FILE),
            },
            "cycle_ledger": {
                "count": len(load_cycle_ledger().get("cycles", [])),
                "ledger_file": workspace_relative(CYCLE_LEDGER_FILE),
            },
            "improvement_backlog": {
                "ok": backlog.ok,
                "opportunity_count": len(opportunities),
                "status_counts": opportunity_status_counts,
                "selected": selected.meta if selected.ok else None,
                "backlog_file": workspace_relative(IMPROVEMENT_BACKLOG_FILE),
            },
            "learning": {
                "records": len(learning_records),
                "attempts": learned_attempts,
                "successes": learned_successes,
                "blocked": learned_blocked,
                "learning_file": workspace_relative(IMPROVEMENT_LEARNING_FILE),
            },
            "internal_self_tests": {
                "available": True,
                "tool": "run_internal_self_tests",
                "note": "Run separately to avoid recursive health-report generation.",
            },
            "recommendations": recommendations,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def generate_planning_brief(self, goal: str = "improve this codebase") -> ToolResult:
        health = self.generate_health_report(goal=goal)
        selected = health.meta.get("improvement_backlog", {}).get("selected") if health.ok else None
        selected = selected or {}
        evaluation = selected.get("manager_evaluation", {}) if isinstance(selected, dict) else {}
        decision = evaluation.get("decision", "unknown")
        recommendation = self.recommend_team(
            task=goal,
            context=json.dumps({"selected_opportunity": selected, "governor_decision": decision}),
        )
        roles = recommendation.meta.get("roles", ["planner", "coder", "reviewer"])
        if selected.get("target") == "validation":
            roles = ["tester", "reviewer", "safety"]
        elif decision != "approve":
            roles = ["researcher", "planner", "critic"]

        acceptance_criteria = [
            "Validation suite must pass or the cycle must roll back.",
            "Autonomy policy must allow the final changed-file count and impact risk.",
            "Experiment journal must record hypothesis, evidence, and conclusion.",
            "Improvement learning must record the final opportunity outcome.",
        ]
        if selected:
            acceptance_criteria.append(f"Selected opportunity should be addressed or explicitly blocked: {selected.get('title')}.")

        brief = {
            "generated_at": utc_now(),
            "goal": goal,
            "selected_opportunity": selected,
            "governor_decision": decision,
            "recommended_roles": roles,
            "team_recommendation": recommendation.meta,
            "autonomy_policy": health.meta.get("autonomy_policy", {}),
            "health_recommendations": health.meta.get("recommendations", []),
            "execution_constraints": [
                "Prefer the smallest reversible change that can satisfy the selected opportunity.",
                "Use checkpoint, impact analysis, validation, policy evaluation, and rollback if needed.",
                "Use build_code_graph and analyze_symbol_impact before refactoring shared helpers.",
                "Use rank_code_hotspots to identify high-blast-radius symbols before broad edits.",
                "Review the recent cycle ledger before widening scope or starting a new refactor path.",
                "Do not broaden scope beyond the selected opportunity unless validation is failing.",
                "Preserve .agent_* state files during rollback.",
            ],
            "acceptance_criteria": acceptance_criteria,
            "health_summary": {
                "validation_ok": health.meta.get("validation", {}).get("ok"),
                "tool_total": health.meta.get("tools", {}).get("total"),
                "code_graph_nodes": health.meta.get("code_graph", {}).get("nodes"),
                "code_hotspot_count": health.meta.get("code_hotspots", {}).get("count"),
                "cycle_ledger_count": health.meta.get("cycle_ledger", {}).get("count"),
                "learning_attempts": health.meta.get("learning", {}).get("attempts"),
                "open_backlog_items": health.meta.get("improvement_backlog", {}).get("status_counts", {}).get("open", 0),
            },
        }
        return ToolResult(True, json.dumps(brief, indent=2), meta=brief)

    def run_internal_self_tests(self) -> ToolResult:
        checks: list[dict[str, Any]] = []

        def check(name: str, passed: bool, detail: str = "") -> None:
            checks.append(
                {
                    "name": name,
                    "ok": bool(passed),
                    "detail": detail,
                }
            )

        config = load_config()
        check("config_has_autonomy_policy", isinstance(config.get("autonomy_policy"), dict))
        check("thinking_indicator_enabled", config.get("show_thinking_indicator") is True)
        check("config_has_known_fallback_provider", config.get("fallback_provider") in config.get("llm_providers", {}))
        check("config_has_llm_providers", isinstance(config.get("llm_providers"), dict) and bool(config.get("llm_providers")))
        check("lmstudio_auto_discovers_model", config.get("llm_providers", {}).get("lmstudio", {}).get("auto_discover_model") is True)
        activity_thinking_calls = []
        try:
            source_tree = ast.parse(Path(__file__).read_text(encoding="utf-8", errors="replace"))
            for node in ast.walk(source_tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Name) or node.func.id != "emit_activity":
                    continue
                if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "thinking":
                    activity_thinking_calls.append(getattr(node, "lineno", 0))
        except SyntaxError as exc:
            activity_thinking_calls.append(f"parse_error={exc}")
        check("activity_thinking_not_emitted", not activity_thinking_calls, f"lines={activity_thinking_calls}")
        check("config_has_role_providers", all(role in config.get("role_providers", {}) for role in ROLE_CATALOG))
        check(
            "role_providers_reference_known_providers",
            all(provider in config.get("llm_providers", {}) for provider in config.get("role_providers", {}).values()),
        )
        check("config_has_role_models", all(role in config.get("role_models", {}) for role in ROLE_CATALOG))
        template_role_errors = [
            f"{template}:{role}"
            for template, data in TEAM_TEMPLATES.items()
            for role in data.get("roles", [])
            if role not in ROLE_CATALOG
        ]
        check("team_templates_reference_known_roles", not template_role_errors, f"errors={template_role_errors}")
        check(
            "team_templates_respect_role_limit",
            all(len(data.get("roles", [])) <= MAX_TEAM_ROLES for data in TEAM_TEMPLATES.values()),
        )
        centered_banner = render_centered_cerebro_banner()
        check("centered_banner_renders_lines", bool(centered_banner.strip()) and "\n" in centered_banner)
        check("activity_indicator_helpers_callable", callable(start_activity_indicator) and callable(stop_activity_indicator))
        startup_lines = render_startup_text(load_control_state()).splitlines()
        divider_lines = [line for line in startup_lines if line and set(line) == {"-"}]
        check(
            "startup_dividers_match_terminal_width",
            bool(divider_lines) and all(len(line) == terminal_width() for line in divider_lines),
            f"terminal_width={terminal_width()} dividers={[len(line) for line in divider_lines]}",
        )
        check("redraw_repl_screen_callable", callable(redraw_repl_screen))

        parsed = parse_model_reply('{"type":"final","content":"ok"}', tool_names=set(self.tools))
        check("parse_final_json", parsed.get("type") == "final" and parsed.get("content") == "ok")

        fenced = parse_json_object("```json\n{\"ok\": true}\n```")
        check("parse_fenced_json_object", fenced.get("ok") is True)

        valid_tool, valid_tool_reason = validate_action_shape(
            {"type": "tool", "tool": "list_files", "args": {}},
            tool_names=set(self.tools),
        )
        check("validate_known_tool_action", valid_tool, valid_tool_reason)

        invalid_tool, invalid_tool_reason = validate_action_shape(
            {"type": "tool", "tool": "definitely_missing_tool", "args": {}},
            tool_names=set(self.tools),
        )
        check("reject_unknown_tool_action", not invalid_tool, invalid_tool_reason)

        required_tools = {
            "self_improve_codebase",
            "generate_health_report",
            "generate_planning_brief",
            "recommend_team",
            "read_json_file",
            "validate_json_file",
            "show_last_self_improvement_changes",
            "search_todos",
            "list_recent_files",
            "find_large_files",
            "analyze_python_complexity",
            "build_import_graph",
            "find_duplicate_blocks",
            "suggest_refactor_targets",
            "build_code_graph",
            "find_callers",
            "analyze_symbol_impact",
            "find_orphan_symbols",
            "rank_code_hotspots",
            "show_code_hotspots",
            "show_cycle_ledger",
            "show_config",
            "list_llm_routes",
            "summarize_blackboard",
            "show_workspace_stats",
            "show_run_history",
            "show_user_profile",
            "update_user_profile",
            "add_user_profile_note",
            "forget_user_profile_field",
            "evaluate_autonomy_policy",
            "restore_checkpoint",
            "run_internal_self_tests",
        }
        missing_tools = sorted(required_tools - set(self.tools))
        check("required_tools_registered", not missing_tools, f"missing={missing_tools}")

        routes = self.list_llm_routes()
        check("list_llm_routes_returns_all_roles", routes.ok and all(role in routes.meta.get("routes", {}) for role in ROLE_CATALOG), trim_text(routes.content, 500))
        check("friendly_model_failure_mentions_model_unavailable", "Model unavailable" in format_agent_failure(RuntimeError("No models loaded.")))

        policy_allow = self.evaluate_autonomy_policy({"risk_level": "low"}, ["agent.py"])
        check("autonomy_policy_allows_low_risk", policy_allow.meta.get("decision") == "allow", policy_allow.content)

        policy_rollback = self.evaluate_autonomy_policy(
            {"risk_level": "high"},
            ["agent.py", "a.py", "b.py", "c.py", "d.py"],
        )
        check("autonomy_policy_rejects_high_risk_or_broad_change", policy_rollback.meta.get("decision") == "rollback", policy_rollback.content)

        recommendation = self.recommend_team(
            "autonomous refactor with rollback policy validation",
            context="Need architecture, safety, maintainer, and tests.",
        )
        recommended_roles = recommendation.meta.get("roles", [])
        check("recommend_team_returns_valid_roles", all(role in ROLE_CATALOG for role in recommended_roles), recommendation.content)
        check("recommend_team_respects_role_limit", len(recommended_roles) <= MAX_TEAM_ROLES, recommendation.content)

        graph = self.build_code_graph("agent.py", recursive=False)
        callers = self.find_callers("load_config")
        symbol_impact = self.analyze_symbol_impact("load_config")
        orphans = self.find_orphan_symbols("agent.py", recursive=False)
        hotspots = self.rank_code_hotspots("agent.py", recursive=False)
        cycle_ledger = self.show_cycle_ledger(limit=3)
        config_view = self.show_config()
        user_profile = self.show_user_profile()
        blackboard_summary = self.summarize_blackboard(limit=2)
        workspace_stats = self.show_workspace_stats(path="agent.py", recursive=False)
        run_history = self.show_run_history(limit=5)
        json_read = self.read_json_file(".agent_config.json")
        json_validation = self.validate_json_file(".agent_config.json")
        last_self_improvement_changes = self.show_last_self_improvement_changes()
        todos = self.search_todos("agent.py", recursive=False)
        recent_files = self.list_recent_files(".", limit=3)
        large_files = self.find_large_files(".", limit=3)
        complexity = self.analyze_python_complexity("agent.py", recursive=False)
        import_graph = self.build_import_graph("agent.py", recursive=False)
        duplicates = self.find_duplicate_blocks("agent.py", min_lines=6)
        refactor_targets = self.suggest_refactor_targets("agent.py", recursive=False)
        check("code_graph_builds", graph.ok and bool(graph.meta.get("nodes")), trim_text(graph.content, 500))
        check("find_callers_returns_payload", callers.ok and isinstance(callers.meta.get("callers"), list), trim_text(callers.content, 500))
        check("analyze_symbol_impact_scores_symbol", symbol_impact.ok and symbol_impact.meta.get("risk_level") in {"low", "medium", "high"}, trim_text(symbol_impact.content, 500))
        check("find_orphan_symbols_returns_list", orphans.ok and isinstance(orphans.meta.get("orphans"), list), trim_text(orphans.content, 500))
        check("rank_code_hotspots_returns_list", hotspots.ok and isinstance(hotspots.meta.get("hotspots"), list), trim_text(hotspots.content, 500))
        check("rank_code_hotspots_persists_file", CODE_HOTSPOTS_FILE.exists(), workspace_relative(CODE_HOTSPOTS_FILE))
        check("show_cycle_ledger_returns_list", cycle_ledger.ok and isinstance(cycle_ledger.meta.get("cycles"), list), trim_text(cycle_ledger.content, 500))
        check("show_config_returns_payload", config_view.ok and "role_models" in config_view.meta, trim_text(config_view.content, 500))
        check("show_user_profile_returns_schema", user_profile.ok and "identity" in user_profile.meta and "contact" in user_profile.meta, trim_text(user_profile.content, 500))
        check("summarize_blackboard_returns_sections", blackboard_summary.ok and isinstance(blackboard_summary.meta.get("sections"), dict), trim_text(blackboard_summary.content, 500))
        check("show_workspace_stats_returns_counts", workspace_stats.ok and "file_count" in workspace_stats.meta, trim_text(workspace_stats.content, 500))
        check("show_run_history_returns_events", run_history.ok and isinstance(run_history.meta.get("events"), list), trim_text(run_history.content, 500))
        check("read_json_file_returns_data", json_read.ok and "data" in json_read.meta, trim_text(json_read.content, 500))
        check("validate_json_file_passes_config", json_validation.ok and json_validation.meta.get("ok") is True, trim_text(json_validation.content, 500))
        check(
            "show_last_self_improvement_changes_returns_summary",
            (
                last_self_improvement_changes.ok and "lines_added" in last_self_improvement_changes.meta
            )
            or "No self-improvement cycle checkpoint" in last_self_improvement_changes.content,
            trim_text(last_self_improvement_changes.content, 500),
        )
        check("search_todos_returns_matches", todos.ok and isinstance(todos.meta.get("matches"), list), trim_text(todos.content, 500))
        check("list_recent_files_returns_files", recent_files.ok and isinstance(recent_files.meta.get("files"), list), trim_text(recent_files.content, 500))
        check("find_large_files_returns_files", large_files.ok and isinstance(large_files.meta.get("files"), list), trim_text(large_files.content, 500))
        check("analyze_python_complexity_returns_callables", complexity.ok and isinstance(complexity.meta.get("callables"), list), trim_text(complexity.content, 500))
        check("build_import_graph_returns_files", import_graph.ok and isinstance(import_graph.meta.get("files"), dict), trim_text(import_graph.content, 500))
        check("find_duplicate_blocks_returns_list", duplicates.ok and isinstance(duplicates.meta.get("duplicates"), list), trim_text(duplicates.content, 500))
        check("suggest_refactor_targets_returns_targets", refactor_targets.ok and isinstance(refactor_targets.meta.get("targets"), list), trim_text(refactor_targets.content, 500))

        profile_update = self.update_user_profile("custom.__self_test__", "ok")
        profile_forget = self.forget_user_profile_field("custom.__self_test__")
        check("update_user_profile_writes_field", profile_update.ok, trim_text(profile_update.content, 500))
        check("forget_user_profile_field_removes_field", profile_forget.ok, trim_text(profile_forget.content, 500))

        terminal_was_tty = sys.stdout.isatty
        try:
            sys.stdout.isatty = lambda: True
            rendered = render_terminal_markdown("hello **bold**")
            colored = terminal_color("User: ", "32")
            line_counts = render_terminal_markdown("Lines added: 30\nLines removed: 5\nNet change: +25\nNet change: -4")
            check("terminal_bold_rendering", "\033[1mbold\033[0m" in rendered)
            check("terminal_color_rendering", colored.startswith("\033[32m"))
            check("terminal_line_count_added_green", "Lines added: \033[32m30\033[0m" in line_counts)
            check("terminal_line_count_removed_red", "Lines removed: \033[31m5\033[0m" in line_counts)
            check("terminal_net_positive_green", "Net change: \033[32m+25\033[0m" in line_counts)
            check("terminal_net_negative_red", "Net change: \033[31m-4\033[0m" in line_counts)
        finally:
            sys.stdout.isatty = terminal_was_tty

        brief = self.generate_planning_brief("internal self-test planning brief")
        check("planning_brief_generates", brief.ok and bool(brief.meta.get("acceptance_criteria")), trim_text(brief.content, 500))

        validation = self.run_self_improvement_validation(path=".")
        check("self_improvement_validation_runs", validation.ok, trim_text(validation.content, 500))

        failed = [item for item in checks if not item["ok"]]
        payload = {
            "ok": not failed,
            "checked": len(checks),
            "failed": failed,
            "checks": checks,
        }
        return ToolResult(not failed, json.dumps(payload, indent=2), meta=payload)

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

    def show_user_profile(self) -> ToolResult:
        profile = load_user_profile()
        return ToolResult(True, json.dumps(profile, indent=2), meta=profile)

    def update_user_profile(self, field: str, value: Any) -> ToolResult:
        profile = load_user_profile()
        try:
            set_nested_value(profile, field, value)
        except ValueError as exc:
            return ToolResult(False, str(exc))
        save_user_profile(profile)
        updated = load_user_profile()
        payload = {
            "profile_file": workspace_relative(USER_PROFILE_FILE),
            "field": field,
            "value": value,
            "profile": updated,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def add_user_profile_note(self, note: str, category: str = "general") -> ToolResult:
        cleaned = note.strip()
        if not cleaned:
            return ToolResult(False, "note cannot be empty")
        profile = load_user_profile()
        entry = {
            "time": utc_now(),
            "category": category.strip() or "general",
            "note": cleaned,
        }
        profile.setdefault("notes", []).append(entry)
        save_user_profile(profile)
        payload = {
            "profile_file": workspace_relative(USER_PROFILE_FILE),
            "entry": entry,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def forget_user_profile_field(self, field: str) -> ToolResult:
        profile = load_user_profile()
        try:
            removed = delete_nested_value(profile, field)
        except ValueError as exc:
            return ToolResult(False, str(exc))
        if not removed:
            return ToolResult(False, f"Field not found: {field}")
        save_user_profile(profile)
        payload = {
            "profile_file": workspace_relative(USER_PROFILE_FILE),
            "removed_field": field,
            "profile": load_user_profile(),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def show_history(self, limit: int = 8) -> ToolResult:
        selected = self.state.tool_history[-max(1, min(limit, 20)) :]
        if not selected:
            return ToolResult(True, "No tool history yet.")
        return ToolResult(True, json.dumps(selected, indent=2))


def execute_action(action: dict[str, Any], tools: AgentTools) -> list[tuple[str, ToolResult]]:
    def activity_for_tool(tool_name: str, args: dict[str, Any]) -> tuple[str, str]:
        edit_tools = {"write_file", "append_file", "replace_in_file", "apply_unified_diff"}
        if tool_name in edit_tools:
            target = str(args.get("path", "")) if isinstance(args, dict) else ""
            return "editing", f"Editing a file: {target or tool_name}"
        return "tool", f"Ran {tool_name}"

    action_type = action.get("type")
    if action_type == "tool":
        tool_name = str(action.get("tool", ""))
        args = action.get("args", {})
        if not isinstance(args, dict):
            args = {}
        kind, message = activity_for_tool(tool_name, args)
        indicator = start_activity_indicator(kind, message)
        try:
            result = tools.call(tool_name, args)
        finally:
            stop_activity_indicator(indicator)
        emit_activity("done", f"Ran {tool_name}: ok={result.ok}", animate=False)
        return [(tool_name, result)]

    if action_type == "batch":
        executed: list[tuple[str, ToolResult]] = []
        for item in normalize_batch_actions(action.get("actions", [])):
            kind, message = activity_for_tool(item["tool"], item["args"])
            indicator = start_activity_indicator(kind, message)
            try:
                result = tools.call(item["tool"], item["args"])
            finally:
                stop_activity_indicator(indicator)
            executed.append((item["tool"], result))
        if not executed:
            return [("batch", ToolResult(False, "No valid batch actions were provided."))]
        edit_count = sum(1 for name, _ in executed if name in {"write_file", "append_file", "replace_in_file", "apply_unified_diff"})
        command_count = sum(1 for name, _ in executed if name.startswith("run_") or name == "run_command")
        emit_activity(
            "done",
            f"Edited {edit_count} file action(s), ran {command_count} command/tool action(s)",
            animate=False,
        )
        return executed

    return [("action", ToolResult(False, f"Unsupported action type: {action_type}"))]


def repl() -> None:
    state = AgentState()
    control = load_control_state()
    transcript: list[dict[str, str]] = []
    print_startup_header(control, animated=True)

    def redraw_for_resize() -> None:
        nonlocal control
        control = load_control_state()
        redraw_repl_screen(control, transcript)

    while True:
        print()
        user_input = animated_input("User: ", on_resize=redraw_for_resize)
        if user_input.lower() in {"quit", "exit"}:
            break
        if user_input.lower() in {"cls", "clear"}:
            transcript.clear()
            redraw_repl_screen(load_control_state(), transcript)
            continue
        if not user_input:
            continue

        transcript.append({"role": "user", "content": user_input})
        try:
            answer = run_agent(user_input, state=state)
        except Exception as exc:
            answer = format_agent_failure(exc)
            log_run_event("agent_exception", {"error": str(exc)})
        transcript.append({"role": "agent", "content": answer})
        print("\n" + terminal_color("Cerebro: ", "94"), end="", flush=True)
        typewriter_print(render_terminal_markdown(answer))


if __name__ == "__main__":
    repl()
