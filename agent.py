from __future__ import annotations

import ast
import inspect
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
import collections
import math
import csv
import base64
import hashlib
import hmac
import secrets
import html.parser
import mimetypes
import sqlite3
import tarfile
import zipfile
import struct
import ssl
import urllib.error
import urllib.parse
import urllib.request
import ipaddress
import socket
import threading
import time
import random
try:
    import msvcrt  # Windows-only; used by animated_input.
except ImportError:
    msvcrt = None
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
MODEL_CATALOG_FILE = WORKSPACE_ROOT / ".agent_model_catalog.json"
EXTERNAL_TOOLS_FILE = WORKSPACE_ROOT / ".agent_external_tools.json"
IDS_ALERTS_FILE = WORKSPACE_ROOT / ".agent_ids_alerts.jsonl"
IDS_BASELINE_FILE = WORKSPACE_ROOT / ".agent_ids_baseline.json"
IDS_CAPTURE_DIR = WORKSPACE_ROOT / ".agent_ids_captures"
CONTROL_SERVER_TOKEN_FILE = WORKSPACE_ROOT / ".agent_control_server_token"
CONTROL_SERVER_LOG_FILE = WORKSPACE_ROOT / ".agent_control_server.jsonl"
THREAT_INTEL_CACHE_FILE = WORKSPACE_ROOT / ".agent_threat_intel_cache.json"
MALWARE_SIGNATURES_FILE = WORKSPACE_ROOT / ".agent_malware_signatures.json"
YARA_RULES_DIR = WORKSPACE_ROOT / ".agent_yara_rules"
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
APPROX_CHARS_PER_TOKEN = 4.0
DEFAULT_CONTEXT_ROUTE_LIMITS = (2048, 8192, None)
CONTROL_SERVER_DEFAULT_HOST = "127.0.0.1"
CONTROL_SERVER_DEFAULT_PORT = 8765
CONTROL_SERVER_MAX_PAYLOAD_BYTES = 65536
CONTROL_SERVER_ALLOWED_COMMAND_TYPES = {
    "ping",
    "status",
    "message",
    "sync_context",
    "refresh_config",
}
CONTROL_SERVER_DENIED_COMMAND_TYPES = {
    "cmd",
    "exec",
    "execute",
    "shell",
    "powershell",
    "python",
    "download",
    "download_execute",
    "upload",
    "exfiltrate",
    "persist",
    "persistence",
    "keylog",
    "screenshot",
    "reverse_shell",
    "meterpreter",
    "payload",
}

TOOL_RISK_READ_ONLY = "read_only"
TOOL_RISK_WRITE_FILE = "write_file"
TOOL_RISK_RUN_COMMAND = "run_command"
TOOL_RISK_AGENTIC = "agentic"
TOOL_RISK_MEMORY = "memory"
TOOL_RISK_CONTROL = "control"

WRITE_TOOL_NAMES = {"write_file", "append_file", "replace_in_file", "apply_unified_diff"}
RUNTIME_OUTPUT_SUPPRESSED = False
CONVERSATION_HISTORY_LIMIT = 8

WRITE_INTENT_KEYWORDS = {
    "save",
    "export",
    "write",
    "create file",
    "make file",
    "edit",
    "modify",
    "change",
    "update",
    "replace",
    "append",
    "delete",
    "remove",
    "implement",
    "patch",
    "fix",
    "refactor",
    "improve",
    "self-improve",
    "self improve",
    "rename",
    "copy",
    "move",
    "commit",
}

TOOL_INTENT_KEYWORDS = {
    "analyze",
    "audit",
    "build",
    "check",
    "code",
    "command",
    "debug",
    "edit",
    "file",
    "find",
    "fix",
    "generate",
    "health",
    "implement",
    "inspect",
    "list",
    "modify",
    "open",
    "patch",
    "project",
    "read",
    "refactor",
    "run",
    "save",
    "scan",
    "network",
    "netstat",
    "dns",
    "domain",
    "hostname",
    "ip",
    "ip address",
    "asn",
    "isp",
    "geolocation",
    "geoip",
    "ports",
    "port",
    "tls",
    "ssl",
    "traffic",
    "packet",
    "packets",
    "pcap",
    "pcapng",
    "ids",
    "intrusion",
    "suricata",
    "zeek",
    "flows",
    "flow",
    "anomaly",
    "beacon",
    "cve",
    "cves",
    "critical vulnerability",
    "critical vulnerabilities",
    "vulnerability",
    "vulnerabilities",
    "cvss",
    "kev",
    "known exploited",
    "cisa kev",
    "malware",
    "malware signature",
    "malware signatures",
    "yara",
    "ioc",
    "indicator",
    "hash",
    "encrypt",
    "encryption",
    "decrypt",
    "decryption",
    "crypto",
    "cryptography",
    "cipher",
    "aes",
    "aes-gcm",
    "chacha20",
    "fernet",
    "pbkdf2",
    "hmac",
    "hash lookup",
    "threat intel",
    "threat intelligence",
    "malwarebazaar",
    "csv",
    "jsonl",
    "sqlite",
    "database",
    "archive",
    "zip",
    "tar",
    "pdf",
    "image metadata",
    "json api",
    "html",
    "link extraction",
    "crawl",
    "crawler",
    "security headers",
    "headers",
    "json schema",
    "schema inference",
    "entities",
    "entity extraction",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "diagnostic",
    "diagnostics",
    "snapshot",
    "diff impact",
    "impact report",
    "patch impact",
    "manifest",
    "file manifest",
    "compare files",
    "file diff",
    "python environment",
    "environment",
    "packages",
    "processes",
    "process table",
    "external tool",
    "plugin",
    "server",
    "client",
    "clients",
    "connection",
    "connections",
    "listen",
    "control server",
    "route command",
    "rdap",
    "whois",
    "search",
    "self-improve",
    "self improve",
    "show",
    "summarize",
    "test",
    "tool",
    "update",
    "workspace",
    "write",
}

CONVERSATIONAL_FOLLOWUP_PATTERNS = {
    "and",
    "and?",
    "anything else",
    "anything else?",
    "anything more",
    "anything more?",
    "continue",
    "continue please",
    "elaborate",
    "go on",
    "more",
    "tell me more",
    "what else",
    "what else?",
    "anything to add",
    "anything to add?",
}


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

def default_model_router_config() -> dict[str, Any]:
    """Default token-aware model router settings.

    Empty provider/model values mean "keep the route the caller already selected".
    Users can edit .agent_config.json to map thresholds to specific LM Studio
    models or external providers without changing code.
    """
    return {
        "enabled": True,
        "estimate_chars_per_token": APPROX_CHARS_PER_TOKEN,
        "respect_explicit_model": False,
        "log_decisions": True,
        "enable_prompt_compaction": True,
        "reserve_output_tokens": 1024,
        "min_compaction_tokens": 256,
        "compaction_margin_tokens": 128,
        "routes": [
            {
                "name": "short_context",
                "max_input_tokens": 2048,
                "input_token_budget": 1800,
                "provider": "",
                "model": "",
                "temperature": None,
                "reason": "Fast route for small prompts.",
            },
            {
                "name": "medium_context",
                "max_input_tokens": 8192,
                "input_token_budget": 7600,
                "provider": "",
                "model": "",
                "temperature": None,
                "reason": "Balanced route for normal code and analysis tasks.",
            },
            {
                "name": "long_context",
                "max_input_tokens": None,
                "input_token_budget": 30000,
                "provider": "",
                "model": "",
                "temperature": None,
                "reason": "Long-context fallback route for large files, transcripts, or codebase packs.",
            },
        ],
    }


def default_llm_provider_configs() -> dict[str, dict[str, Any]]:
    """Return provider presets for hosted, local, and OpenAI-compatible model backends.

    The presets intentionally prefer provider-level model discovery over hard-coded
    model names. `known_models` are only seed hints so Cerebro can reason before
    credentials are configured or a live model-list call has succeeded.
    """
    return {
        "lmstudio": {
            "type": "openai_compatible",
            "base_url": "http://localhost:1234/v1",
            "api_key": "lm-studio",
            "model": MODEL,
            "auto_discover_model": True,
            "family": "local",
            "notes": "Local LM Studio OpenAI-compatible server. Load any model in LM Studio and Cerebro can discover it.",
            "known_models": [
                {"id": MODEL, "capabilities": ["local", "configurable"], "status": "placeholder"},
            ],
        },
        "ollama": {
            "type": "openai_compatible",
            "base_url": "http://localhost:11434/v1",
            "api_key": "ollama",
            "model": "llama3.1",
            "auto_discover_model": True,
            "family": "local",
            "notes": "Local Ollama OpenAI-compatible server; model ids depend on installed pulls.",
            "known_models": [
                {"id": "llama3.1", "capabilities": ["local", "open_weights", "general"]},
                {"id": "qwen2.5-coder", "capabilities": ["local", "coding", "open_weights"]},
            ],
        },
        "openai": {
            "type": "openai",
            "base_url": "https://api.openai.com/v1",
            "api_key_env": "OPENAI_API_KEY",
            "model": "gpt-4.1",
            "auto_discover_model": True,
            "family": "openai",
            "notes": "Uses OpenAI's /v1/models endpoint when OPENAI_API_KEY is present.",
            "known_models": [
                {"id": "gpt-4.1", "capabilities": ["general", "coding", "long_context"]},
                {"id": "gpt-4.1-mini", "capabilities": ["fast", "cheap", "general", "coding"]},
                {"id": "gpt-4.1-nano", "capabilities": ["very_fast", "cheap"]},
                {"id": "o3", "capabilities": ["reasoning", "hard_problems"]},
                {"id": "o4-mini", "capabilities": ["reasoning", "fast"]},
                {"id": "gpt-4o", "capabilities": ["general", "vision", "multimodal"]},
                {"id": "gpt-4o-mini", "capabilities": ["fast", "cheap", "vision"]},
            ],
        },
        "anthropic": {
            "type": "anthropic",
            "base_url": "https://api.anthropic.com",
            "api_key_env": "ANTHROPIC_API_KEY",
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4096,
            "auto_discover_model": True,
            "model_list_endpoint": "https://api.anthropic.com/v1/models",
            "family": "anthropic",
            "notes": "Uses Anthropic's Models API when ANTHROPIC_API_KEY is present.",
            "known_models": [
                {"id": "claude-opus-4-20250514", "capabilities": ["reasoning", "writing", "hard_problems"]},
                {"id": "claude-sonnet-4-20250514", "capabilities": ["coding", "reasoning", "general"]},
                {"id": "claude-3-7-sonnet-latest", "capabilities": ["coding", "reasoning"]},
                {"id": "claude-3-5-haiku-latest", "capabilities": ["fast", "cheap"]},
            ],
        },
        "xai": {
            "type": "openai_compatible",
            "base_url": "https://api.x.ai/v1",
            "api_key_env": "XAI_API_KEY",
            "model": "grok-4.3",
            "auto_discover_model": True,
            "model_list_endpoint": "https://api.x.ai/v1/language-models",
            "family": "xai",
            "notes": "Discovers xAI language models using the xAI model-list endpoint when XAI_API_KEY is present.",
            "known_models": [
                {"id": "grok-4.3", "capabilities": ["reasoning", "general", "tools"]},
                {"id": "grok-4", "capabilities": ["reasoning", "general"]},
                {"id": "grok-3-mini", "capabilities": ["fast", "cheap"]},
            ],
        },
        "meta": {
            "type": "openai_compatible",
            "base_url": "https://llama-api.meta.com/compat/v1",
            "api_key_env": "LLAMA_API_KEY",
            "model": "Llama-4-Maverick-17B-128E-Instruct-FP8",
            "auto_discover_model": True,
            "family": "meta",
            "notes": "Meta Llama API OpenAI-compatible endpoint. Model ids may vary by account/preview access.",
            "known_models": [
                {"id": "Llama-4-Maverick-17B-128E-Instruct-FP8", "capabilities": ["open_weights", "vision", "general"]},
                {"id": "Llama-4-Scout-17B-16E-Instruct-FP8", "capabilities": ["open_weights", "fast", "vision"]},
                {"id": "Llama-3.3-70B-Instruct", "capabilities": ["open_weights", "general", "writing"]},
                {"id": "Llama-3.3-8B-Instruct", "capabilities": ["open_weights", "fast", "cheap"]},
            ],
        },
        "openrouter": {
            "type": "openai_compatible",
            "base_url": "https://openrouter.ai/api/v1",
            "api_key_env": "OPENROUTER_API_KEY",
            "model": "openrouter/auto",
            "auto_discover_model": True,
            "family": "router",
            "notes": "Unified OpenAI-compatible router for OpenAI, Anthropic, Meta, Google, Mistral, xAI, and many more.",
            "known_models": [
                {"id": "openrouter/auto", "capabilities": ["router", "auto_select"]},
                {"id": "meta-llama/llama-4-maverick", "capabilities": ["open_weights", "vision", "general"]},
                {"id": "anthropic/claude-sonnet-4", "capabilities": ["coding", "reasoning"]},
                {"id": "openai/gpt-4.1", "capabilities": ["coding", "general"]},
            ],
        },
        "groq": {
            "type": "openai_compatible",
            "base_url": "https://api.groq.com/openai/v1",
            "api_key_env": "GROQ_API_KEY",
            "model": "llama-3.3-70b-versatile",
            "auto_discover_model": True,
            "family": "groq",
            "notes": "Very fast OpenAI-compatible inference, including Llama-family models when available.",
            "known_models": [
                {"id": "llama-3.3-70b-versatile", "capabilities": ["fast", "open_weights", "general"]},
                {"id": "llama-3.1-8b-instant", "capabilities": ["very_fast", "cheap", "open_weights"]},
            ],
        },
        "mistral": {
            "type": "openai_compatible",
            "base_url": "https://api.mistral.ai/v1",
            "api_key_env": "MISTRAL_API_KEY",
            "model": "mistral-large-latest",
            "auto_discover_model": True,
            "family": "mistral",
            "notes": "Mistral's OpenAI-compatible API surface.",
            "known_models": [
                {"id": "mistral-large-latest", "capabilities": ["general", "coding"]},
                {"id": "codestral-latest", "capabilities": ["coding"]},
                {"id": "mistral-small-latest", "capabilities": ["fast", "cheap"]},
            ],
        },
        "google": {
            "type": "openai_compatible",
            "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
            "api_key_env": "GEMINI_API_KEY",
            "model": "gemini-3.5-flash",
            "auto_discover_model": True,
            "family": "google",
            "notes": "Gemini OpenAI-compatible endpoint. Model ids depend on active Google AI Studio access.",
            "known_models": [
                {"id": "gemini-3.5-flash", "capabilities": ["fast", "vision", "reasoning"]},
                {"id": "gemini-2.5-pro", "capabilities": ["reasoning", "long_context", "vision"]},
                {"id": "gemini-2.5-flash", "capabilities": ["fast", "cheap", "vision"]},
            ],
        },
        "together": {
            "type": "openai_compatible",
            "base_url": "https://api.together.ai/v1",
            "api_key_env": "TOGETHER_API_KEY",
            "model": "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
            "auto_discover_model": True,
            "family": "together",
            "notes": "OpenAI-compatible hosted open-weight model provider.",
            "known_models": [
                {"id": "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8", "capabilities": ["open_weights", "vision", "general"]},
                {"id": "meta-llama/Llama-3.3-70B-Instruct-Turbo", "capabilities": ["open_weights", "general"]},
            ],
        },
    }


def default_model_catalog_cache() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "updated_at": "",
        "providers": {},
        "models": [],
        "notes": "Cached live model discovery. Static provider hints live in .agent_config.json.",
    }


def load_model_catalog_cache() -> dict[str, Any]:
    if not MODEL_CATALOG_FILE.exists():
        return default_model_catalog_cache()
    try:
        parsed = json.loads(MODEL_CATALOG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default_model_catalog_cache()
    if not isinstance(parsed, dict):
        return default_model_catalog_cache()
    merged = default_model_catalog_cache() | parsed
    if not isinstance(merged.get("providers"), dict):
        merged["providers"] = {}
    if not isinstance(merged.get("models"), list):
        merged["models"] = []
    return merged


def save_model_catalog_cache(catalog: dict[str, Any]) -> None:
    catalog = default_model_catalog_cache() | dict(catalog)
    catalog["updated_at"] = utc_now()
    MODEL_CATALOG_FILE.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")


def normalize_model_capabilities(provider_name: str, model_id: str, record: dict[str, Any] | None = None) -> list[str]:
    record = record or {}
    capabilities = [str(item) for item in record.get("capabilities", []) if str(item).strip()]
    lowered = model_id.lower()
    provider_lowered = provider_name.lower()

    def add(name: str) -> None:
        if name not in capabilities:
            capabilities.append(name)

    if provider_lowered in {"lmstudio", "ollama"} or "local" in lowered:
        add("local")
    if provider_lowered in {"meta", "ollama", "groq", "together"} or "llama" in lowered or "qwen" in lowered or "mistral" in lowered:
        add("open_weights")
    if any(token in lowered for token in ["code", "coder", "codestral", "gpt-4.1", "sonnet"]):
        add("coding")
    if any(token in lowered for token in ["o3", "o4", "reason", "thinking", "opus", "sonnet", "grok", "gemini"]):
        add("reasoning")
    if any(token in lowered for token in ["mini", "nano", "haiku", "flash", "small", "instant", "8b", "scout"]):
        add("fast")
        add("cheap")
    if any(token in lowered for token in ["vision", "image", "multimodal", "4o", "maverick", "scout", "gemini"]):
        add("vision")
    if any(token in lowered for token in ["1m", "long", "128k", "200k", "1m", "million"]):
        add("long_context")
    if provider_lowered == "openrouter":
        add("router")
    if not capabilities:
        add("general")
    return capabilities


def normalize_model_record(
    provider_name: str,
    raw: Any,
    *,
    source: str,
    provider_config: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    provider_config = provider_config or {}
    if isinstance(raw, str):
        raw_data: dict[str, Any] = {"id": raw}
    elif isinstance(raw, dict):
        raw_data = dict(raw)
    else:
        model_id = str(getattr(raw, "id", "") or "").strip()
        raw_data = {"id": model_id}
        for attr in ("created", "owned_by", "display_name", "type"):
            value = getattr(raw, attr, None)
            if value is not None:
                raw_data[attr] = value

    model_id = str(
        raw_data.get("id")
        or raw_data.get("name")
        or raw_data.get("model")
        or raw_data.get("slug")
        or ""
    ).strip()
    if not model_id:
        return None

    aliases = raw_data.get("aliases", [])
    if isinstance(aliases, str):
        aliases = [aliases]
    elif not isinstance(aliases, list):
        aliases = []

    context_window = (
        raw_data.get("context_window")
        or raw_data.get("context_length")
        or raw_data.get("max_context_tokens")
        or raw_data.get("input_token_limit")
        or raw_data.get("max_input_tokens")
    )
    context_window_int = safe_int(context_window, 0) if context_window is not None else 0

    record = {
        "provider": provider_name,
        "id": model_id,
        "display_name": str(raw_data.get("display_name") or raw_data.get("name") or model_id),
        "source": source,
        "family": provider_config.get("family", provider_name),
        "provider_type": provider_config.get("type", "openai_compatible"),
        "aliases": [str(alias) for alias in aliases if str(alias).strip()],
        "context_window": context_window_int or None,
        "capabilities": normalize_model_capabilities(provider_name, model_id, raw_data),
        "status": str(raw_data.get("status") or raw_data.get("lifecycle") or "available"),
        "raw": {k: v for k, v in raw_data.items() if k not in {"capabilities"}},
    }
    return record


def parse_model_list_payload(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("data", "models", "language_models", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    # Some endpoints return a provider-keyed object. Preserve shallow dicts.
    if payload and all(isinstance(value, dict) for value in payload.values()):
        return [dict(value) | {"id": key} for key, value in payload.items()]
    return []


def model_catalog_static_records(config: dict[str, Any], provider_filter: str = "") -> list[dict[str, Any]]:
    providers = config.get("llm_providers", {})
    records: list[dict[str, Any]] = []
    for provider_name, settings in providers.items():
        if provider_filter and provider_name != provider_filter:
            continue
        if not isinstance(settings, dict):
            continue
        for raw in settings.get("known_models", []) if isinstance(settings.get("known_models"), list) else []:
            record = normalize_model_record(str(provider_name), raw, source="static_hint", provider_config=settings)
            if record:
                records.append(record)
        configured_model = str(settings.get("model", "")).strip()
        if configured_model and configured_model != MODEL:
            record = normalize_model_record(str(provider_name), {"id": configured_model, "capabilities": ["configured"]}, source="configured_default", provider_config=settings)
            if record:
                records.append(record)
    return records


def model_catalog_cached_records(config: dict[str, Any], provider_filter: str = "") -> list[dict[str, Any]]:
    providers = config.get("llm_providers", {})
    cache = load_model_catalog_cache()
    records: list[dict[str, Any]] = []
    for raw in cache.get("models", []):
        if not isinstance(raw, dict):
            continue
        provider_name = str(raw.get("provider", "")).strip()
        if not provider_name:
            continue
        if provider_filter and provider_name != provider_filter:
            continue
        settings = providers.get(provider_name, {}) if isinstance(providers, dict) else {}
        record = normalize_model_record(provider_name, raw, source=str(raw.get("source") or "cache"), provider_config=settings if isinstance(settings, dict) else {})
        if record:
            record["discovered_at"] = raw.get("discovered_at", cache.get("updated_at", ""))
            records.append(record)
    return records


def dedupe_model_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    source_rank = {"live": 4, "cache": 3, "configured_default": 2, "static_hint": 1}
    for record in records:
        key = (str(record.get("provider", "")), str(record.get("id", "")))
        if not key[0] or not key[1]:
            continue
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = dict(record)
            continue
        current_rank = source_rank.get(str(record.get("source", "")), 0)
        existing_rank = source_rank.get(str(existing.get("source", "")), 0)
        if current_rank >= existing_rank:
            merged = dict(existing) | dict(record)
            merged["capabilities"] = sorted(set(existing.get("capabilities", [])) | set(record.get("capabilities", [])))
            by_key[key] = merged
    return sorted(by_key.values(), key=lambda item: (str(item.get("provider", "")), str(item.get("id", "")).lower()))


def combined_model_catalog(
    config: dict[str, Any],
    *,
    provider_filter: str = "",
    include_cache: bool = True,
    include_static: bool = True,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if include_static:
        records.extend(model_catalog_static_records(config, provider_filter=provider_filter))
    if include_cache:
        records.extend(model_catalog_cached_records(config, provider_filter=provider_filter))
    return dedupe_model_records(records)


def http_get_json(url: str, headers: dict[str, str], *, timeout: int = 12) -> Any:
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=max(1, int(timeout))) as response:
        data = response.read()
    return json.loads(data.decode("utf-8", errors="replace"))


def http_post_form_json(url: str, data: dict[str, Any], headers: dict[str, str] | None = None, *, timeout: int = 15) -> Any:
    encoded = urllib.parse.urlencode({str(k): str(v) for k, v in data.items() if v is not None}).encode("utf-8")
    request_headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Cerebro-Agent/1.0"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, data=encoded, headers=request_headers, method="POST")
    with urllib.request.urlopen(request, timeout=max(1, int(timeout))) as response:
        payload = response.read()
    return json.loads(payload.decode("utf-8", errors="replace"))


def discover_provider_models_live(provider_name: str, provider_config: dict[str, Any], *, timeout: int = 12) -> tuple[list[dict[str, Any]], list[str]]:
    """Discover live models for one provider without failing the caller on network/auth errors."""
    warnings: list[str] = []
    provider_type = str(provider_config.get("type", "openai_compatible")).lower()
    api_key = read_provider_api_key(provider_config)
    base_url = str(provider_config.get("base_url", "")).rstrip("/")
    model_list_endpoint = str(provider_config.get("model_list_endpoint", "")).strip()

    local_provider = "localhost" in base_url or "127.0.0.1" in base_url
    if not api_key and not local_provider:
        return [], [f"{provider_name}: missing API key; set {provider_config.get('api_key_env') or 'api_key'} to enable live discovery."]

    raw_items: list[Any] = []
    try:
        if provider_type == "anthropic":
            endpoint = model_list_endpoint or f"{base_url}/v1/models"
            payload = http_get_json(
                endpoint,
                {
                    "x-api-key": api_key,
                    "anthropic-version": str(provider_config.get("anthropic_version", "2023-06-01")),
                    "accept": "application/json",
                },
                timeout=timeout,
            )
            raw_items = parse_model_list_payload(payload)
        elif model_list_endpoint:
            payload = http_get_json(
                model_list_endpoint,
                {
                    "Authorization": f"Bearer {api_key}",
                    "accept": "application/json",
                },
                timeout=timeout,
            )
            raw_items = parse_model_list_payload(payload)
            if not raw_items and provider_type in {"openai", "openai_compatible"} and OpenAI is not None:
                raw_items = list(get_client(provider_name).models.list().data)
        elif provider_type in {"openai", "openai_compatible"}:
            if OpenAI is None:
                return [], [f"{provider_name}: openai package is not installed; cannot call model-list endpoint."]
            raw_items = list(get_client(provider_name).models.list().data)
        else:
            return [], [f"{provider_name}: provider type {provider_type!r} does not have a model discovery adapter."]
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
        return [], [f"{provider_name}: HTTP {exc.code} while listing models: {trim_text(detail, 600)}"]
    except Exception as exc:
        return [], [f"{provider_name}: model discovery failed: {trim_text(str(exc), 600)}"]

    records: list[dict[str, Any]] = []
    for raw in raw_items:
        record = normalize_model_record(provider_name, raw, source="live", provider_config=provider_config)
        if record:
            record["discovered_at"] = utc_now()
            records.append(record)
    return dedupe_model_records(records), warnings


def score_model_record(
    record: dict[str, Any],
    *,
    objective: str = "",
    role: str = "",
    required_context_tokens: int = 0,
    prefer: str = "",
) -> tuple[float, list[str]]:
    text = f"{objective} {role} {prefer}".lower()
    model_id = str(record.get("id", "")).lower()
    provider = str(record.get("provider", "")).lower()
    capabilities = {str(item).lower() for item in record.get("capabilities", [])}
    score = 10.0
    reasons: list[str] = []

    def reward(points: float, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(reason)

    context_window = safe_int(record.get("context_window"), 0)
    if required_context_tokens > 0:
        if context_window and context_window >= required_context_tokens:
            reward(18, f"context_window {context_window} covers required {required_context_tokens}")
        elif not context_window:
            reward(2, "context window unknown; not penalized")
        else:
            score -= 25
            reasons.append(f"context_window {context_window} below required {required_context_tokens}")

    if role in {"coder", "architect", "refactorer", "reviewer", "tester"} or any(term in text for term in ["code", "coding", "debug", "refactor", "python", "software"]):
        if "coding" in capabilities:
            reward(18, "coding capability match")
        if any(token in model_id for token in ["sonnet", "gpt-4.1", "codestral", "code", "qwen"]):
            reward(8, "model id suggests strong coding fit")

    if role in {"planner", "critic", "meta", "safety"} or any(term in text for term in ["reason", "hard", "plan", "architecture", "strategy", "math"]):
        if "reasoning" in capabilities:
            reward(16, "reasoning capability match")
        if any(token in model_id for token in ["o3", "o4", "opus", "sonnet", "grok", "gemini"]):
            reward(7, "model id suggests reasoning fit")

    if any(term in text for term in ["fast", "cheap", "quick", "low cost", "small"]) or role in {"researcher", "writer"}:
        if "fast" in capabilities:
            reward(12, "fast model match")
        if "cheap" in capabilities:
            reward(8, "cost-sensitive match")

    if any(term in text for term in ["vision", "image", "screenshot", "multimodal"]):
        if "vision" in capabilities:
            reward(15, "vision capability match")

    if any(term in text for term in ["local", "private", "offline", "lm studio", "ollama"]):
        if "local" in capabilities or provider in {"lmstudio", "ollama"}:
            reward(20, "local/private preference match")

    if any(term in text for term in ["open", "open source", "open-weight", "open weights", "meta", "llama"]):
        if "open_weights" in capabilities:
            reward(14, "open-weight preference match")

    if provider == "openrouter" and any(term in text for term in ["any provider", "all models", "router", "auto"]):
        reward(10, "router can access many providers")

    if str(record.get("source")) == "live":
        reward(6, "live-discovered model")
    elif str(record.get("source")) == "configured_default":
        reward(3, "configured default model")

    if not reasons:
        reasons.append("general fallback candidate")
    return round(score, 2), reasons[:8]


def default_control_server_config() -> dict[str, Any]:
    """Default safe control-server settings.

    The control server is a local, authenticated coordination channel for
    trusted agent peers/workers. It intentionally does not expose shell
    execution, payload deployment, persistence, exfiltration, or arbitrary
    command execution primitives.
    """
    return {
        "enabled": False,
        "bind_host": CONTROL_SERVER_DEFAULT_HOST,
        "port": CONTROL_SERVER_DEFAULT_PORT,
        "require_token": True,
        "token_env": "CEREBRO_CONTROL_TOKEN",
        "token_file": ".agent_control_server_token",
        "max_clients": 16,
        "max_message_bytes": CONTROL_SERVER_MAX_PAYLOAD_BYTES,
        "allowed_command_types": sorted(CONTROL_SERVER_ALLOWED_COMMAND_TYPES),
        "denied_command_types": sorted(CONTROL_SERVER_DENIED_COMMAND_TYPES),
        "notes": "Local authenticated coordination channel only; intentionally not a payload/C2 executor.",
    }


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
        "control_server": default_control_server_config(),
        "fallback_provider": "lmstudio",
        "model_router": default_model_router_config(),
        "autonomy_policy": {
            "max_changed_files_per_cycle": 4,
            "max_risk_level": "medium",
            "rollback_on_policy_violation": True,
            "allow_state_file_changes": True,
        },
        "llm_providers": default_llm_provider_configs(),
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

    server_defaults = default_control_server_config()
    parsed_server = parsed.get("control_server", {})
    if not isinstance(parsed_server, dict):
        parsed_server = {}
    server_config = server_defaults | parsed_server
    server_config["enabled"] = bool(server_config.get("enabled", False))
    server_config["bind_host"] = str(server_config.get("bind_host") or CONTROL_SERVER_DEFAULT_HOST)
    try:
        server_config["port"] = max(1, min(int(server_config.get("port", CONTROL_SERVER_DEFAULT_PORT)), 65535))
    except (TypeError, ValueError):
        server_config["port"] = CONTROL_SERVER_DEFAULT_PORT
    server_config["require_token"] = bool(server_config.get("require_token", True))
    try:
        server_config["max_clients"] = max(1, min(int(server_config.get("max_clients", 16)), 128))
    except (TypeError, ValueError):
        server_config["max_clients"] = 16
    try:
        server_config["max_message_bytes"] = max(1024, min(int(server_config.get("max_message_bytes", CONTROL_SERVER_MAX_PAYLOAD_BYTES)), 1048576))
    except (TypeError, ValueError):
        server_config["max_message_bytes"] = CONTROL_SERVER_MAX_PAYLOAD_BYTES
    allowed = server_config.get("allowed_command_types", sorted(CONTROL_SERVER_ALLOWED_COMMAND_TYPES))
    if not isinstance(allowed, list):
        allowed = sorted(CONTROL_SERVER_ALLOWED_COMMAND_TYPES)
    server_config["allowed_command_types"] = sorted(
        {
            str(item).strip()
            for item in allowed
            if str(item).strip() and str(item).strip() not in CONTROL_SERVER_DENIED_COMMAND_TYPES
        }
        or CONTROL_SERVER_ALLOWED_COMMAND_TYPES
    )
    denied = server_config.get("denied_command_types", sorted(CONTROL_SERVER_DENIED_COMMAND_TYPES))
    if not isinstance(denied, list):
        denied = sorted(CONTROL_SERVER_DENIED_COMMAND_TYPES)
    server_config["denied_command_types"] = sorted(set(CONTROL_SERVER_DENIED_COMMAND_TYPES) | {str(item).strip() for item in denied if str(item).strip()})
    config["control_server"] = server_config

    if config.get("fallback_provider") not in config["llm_providers"]:
        config["fallback_provider"] = defaults["fallback_provider"]

    router_defaults = default_model_router_config()
    parsed_router = parsed.get("model_router", {})
    if not isinstance(parsed_router, dict):
        parsed_router = {}
    router = router_defaults | parsed_router
    router["enabled"] = bool(router.get("enabled", True))
    router["respect_explicit_model"] = bool(router.get("respect_explicit_model", False))
    router["log_decisions"] = bool(router.get("log_decisions", True))
    router["enable_prompt_compaction"] = bool(router.get("enable_prompt_compaction", True))
    for int_key, default_value in {
        "reserve_output_tokens": 1024,
        "min_compaction_tokens": 256,
        "compaction_margin_tokens": 128,
    }.items():
        try:
            router[int_key] = max(0, int(router.get(int_key, default_value)))
        except (TypeError, ValueError):
            router[int_key] = default_value
    try:
        chars_per_token = float(router.get("estimate_chars_per_token", APPROX_CHARS_PER_TOKEN))
    except (TypeError, ValueError):
        chars_per_token = APPROX_CHARS_PER_TOKEN
    router["estimate_chars_per_token"] = max(1.0, chars_per_token)
    routes = router.get("routes", router_defaults["routes"])
    if not isinstance(routes, list) or not routes:
        routes = router_defaults["routes"]
    normalized_routes: list[dict[str, Any]] = []
    default_routes_by_name = {
        str(route.get("name")): route
        for route in router_defaults.get("routes", [])
        if isinstance(route, dict) and route.get("name")
    }
    for index, route in enumerate(routes):
        if not isinstance(route, dict):
            continue
        route_name = str(route.get("name") or f"route_{index + 1}")
        route_defaults = default_routes_by_name.get(route_name, {})
        normalized = {
            "name": route_name,
            "max_input_tokens": route.get("max_input_tokens", route_defaults.get("max_input_tokens")),
            "input_token_budget": route.get("input_token_budget", route_defaults.get("input_token_budget")),
            "provider": str(route.get("provider", route_defaults.get("provider", "")) or ""),
            "model": str(route.get("model", route_defaults.get("model", "")) or ""),
            "temperature": route.get("temperature", route_defaults.get("temperature")),
            "reason": str(route.get("reason", route_defaults.get("reason", "")) or ""),
        }
        for token_key in ("max_input_tokens", "input_token_budget"):
            if normalized[token_key] is not None:
                try:
                    normalized[token_key] = max(1, int(normalized[token_key]))
                except (TypeError, ValueError):
                    normalized[token_key] = None
        if normalized["temperature"] is not None:
            try:
                normalized["temperature"] = float(normalized["temperature"])
            except (TypeError, ValueError):
                normalized["temperature"] = None
        normalized_routes.append(normalized)
    if not normalized_routes:
        normalized_routes = router_defaults["routes"]
    normalized_routes.sort(
        key=lambda item: (
            item.get("max_input_tokens") is None,
            int(item.get("max_input_tokens") or 10**12),
        )
    )
    router["routes"] = normalized_routes
    config["model_router"] = router

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
        or "model_router" not in parsed
        or "control_server" not in parsed
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


SENSITIVE_ARGUMENT_KEYWORDS = {
    "api_key",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "key_b64",
    "passphrase",
    "password",
    "private_key",
    "secret",
    "token",
}

SENSITIVE_OUTPUT_TOOL_NAMES = {"decrypt_text"}


def redact_sensitive_payload(value: Any) -> Any:
    """Return a log-safe copy of a value by redacting secret-bearing keys."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if "public" not in lowered and any(marker in lowered for marker in SENSITIVE_ARGUMENT_KEYWORDS):
                redacted[key_text] = "<redacted>"
            else:
                redacted[key_text] = redact_sensitive_payload(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_payload(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive_payload(item) for item in value]
    return value


def redact_sensitive_text(text: str) -> str:
    """Best-effort redaction for secret-looking labels in logs and previews."""
    safe = str(text or "")
    safe = re.sub(
        r"(?i)(\b(?:api[_-]?key|authorization|bearer|client[_-]?secret|credential|key[_-]?b64|passphrase|password|private[_-]?key|secret|token)\b\s*[:=]\s*)([^\s,}]+)",
        r"\1<redacted>",
        safe,
    )
    return safe


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



def estimate_token_count(text: str, *, chars_per_token: float = APPROX_CHARS_PER_TOKEN) -> int:
    """Approximate token count without requiring tokenizer-specific packages."""
    if not text:
        return 0
    chars = max(1, len(text))
    rough = int(chars / max(1.0, float(chars_per_token)))
    # Add a small lexical floor so symbol-heavy code and short JSON do not get
    # badly under-estimated by character count alone.
    lexical = len(re.findall(r"\w+|[^\w\s]", text)) // 2
    return max(1, rough, lexical)


def estimate_message_tokens(messages: list[dict[str, str]], *, chars_per_token: float = APPROX_CHARS_PER_TOKEN) -> int:
    total = 0
    for message in messages:
        role = str(message.get("role", ""))
        content = str(message.get("content", ""))
        total += 4  # lightweight per-message framing overhead
        total += estimate_token_count(role, chars_per_token=chars_per_token)
        total += estimate_token_count(content, chars_per_token=chars_per_token)
    return total + 2




def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def compact_text_middle(content: str, target_chars: int, *, reason: str = "prompt budget") -> tuple[str, dict[str, Any]]:
    """Preserve the beginning/end of content while removing the middle.

    This is intentionally deterministic and tokenizer-free so it works in a
    local-agent environment without extra dependencies.
    """
    target_chars = max(0, int(target_chars))
    if len(content) <= target_chars or target_chars <= 0:
        return content, {"compacted": False, "original_chars": len(content), "new_chars": len(content), "omitted_chars": 0}

    marker_template = "\n\n[...Cerebro compacted {omitted} characters from the middle for {reason}...]\n\n"
    marker = marker_template.format(omitted=0, reason=reason)
    if target_chars <= len(marker) + 40:
        compacted = content[: max(1, target_chars - 1)] + "…"
        return compacted, {
            "compacted": True,
            "original_chars": len(content),
            "new_chars": len(compacted),
            "omitted_chars": max(0, len(content) - len(compacted)),
            "strategy": "hard_tail_truncate",
        }

    available = max(1, target_chars - len(marker))
    head_chars = max(1, int(available * 0.6))
    tail_chars = max(1, available - head_chars)
    omitted_chars = max(0, len(content) - head_chars - tail_chars)
    marker = marker_template.format(omitted=omitted_chars, reason=reason)
    available = max(1, target_chars - len(marker))
    head_chars = max(1, int(available * 0.6))
    tail_chars = max(1, available - head_chars)
    omitted_chars = max(0, len(content) - head_chars - tail_chars)
    marker = marker_template.format(omitted=omitted_chars, reason=reason)
    compacted = content[:head_chars].rstrip() + marker + content[-tail_chars:].lstrip()
    if len(compacted) > target_chars:
        compacted = compacted[:target_chars - 1] + "…"
    return compacted, {
        "compacted": True,
        "original_chars": len(content),
        "new_chars": len(compacted),
        "omitted_chars": max(0, len(content) - len(compacted)),
        "strategy": "middle_out",
    }


def model_input_token_budget(
    decision: dict[str, Any],
    provider_config: dict[str, Any],
    config: dict[str, Any],
) -> int | None:
    """Resolve the safest known input-token budget for the chosen route."""
    router = config.get("model_router", default_model_router_config())
    if not bool(router.get("enable_prompt_compaction", True)):
        return None

    candidates: list[int] = []
    route_budget = safe_int(decision.get("input_token_budget"), 0)
    if route_budget > 0:
        candidates.append(route_budget)

    provider_window = max(
        safe_int(provider_config.get("context_window"), 0),
        safe_int(provider_config.get("max_context_tokens"), 0),
    )
    reserve = safe_int(router.get("reserve_output_tokens"), 1024)
    if provider_window > reserve:
        candidates.append(max(1, provider_window - reserve))

    explicit_default = safe_int(router.get("default_input_token_budget"), 0)
    if explicit_default > 0:
        candidates.append(explicit_default)

    if not candidates:
        return None
    min_budget = max(1, min(candidates))
    margin = safe_int(router.get("compaction_margin_tokens"), 128)
    return max(1, min_budget - margin)


def compact_messages_for_input_budget(
    messages: list[dict[str, str]],
    *,
    max_input_tokens: int,
    chars_per_token: float = APPROX_CHARS_PER_TOKEN,
    min_message_tokens: int = 256,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Return a compacted copy of messages if they exceed a model input budget."""
    original_tokens = estimate_message_tokens(messages, chars_per_token=chars_per_token)
    if max_input_tokens <= 0 or original_tokens <= max_input_tokens:
        return [dict(message) for message in messages], {
            "compacted": False,
            "original_estimated_tokens": original_tokens,
            "new_estimated_tokens": original_tokens,
            "max_input_tokens": max_input_tokens,
            "changed_messages": [],
        }

    compacted = [dict(message) for message in messages]
    changed: list[dict[str, Any]] = []
    iterations = 0
    min_chars = max(80, int(max(1, min_message_tokens) * max(1.0, chars_per_token)))

    def message_priority(index: int, message: dict[str, str]) -> tuple[int, int]:
        role = str(message.get("role", ""))
        content_len = len(str(message.get("content", "")))
        is_last = index == len(compacted) - 1
        # Prefer shrinking older assistant/user context first. Preserve system
        # prompts and the latest user request unless no other choice remains.
        if role == "system":
            priority = 2
        elif is_last and role == "user":
            priority = 1
        else:
            priority = 0
        return priority, -content_len

    while estimate_message_tokens(compacted, chars_per_token=chars_per_token) > max_input_tokens and iterations < 24:
        iterations += 1
        current_tokens = estimate_message_tokens(compacted, chars_per_token=chars_per_token)
        over_tokens = max(1, current_tokens - max_input_tokens)
        candidates = sorted(
            [
                (message_priority(index, message), index, str(message.get("content", "")))
                for index, message in enumerate(compacted)
                if len(str(message.get("content", ""))) > min_chars
            ],
            key=lambda item: item[0],
        )
        if not candidates:
            break
        _, index, content = candidates[0]
        remove_chars = max(int(over_tokens * chars_per_token * 1.35), int(512 * chars_per_token))
        target_chars = max(min_chars, len(content) - remove_chars)
        new_content, meta = compact_text_middle(content, target_chars, reason="model input budget")
        if new_content == content:
            break
        compacted[index]["content"] = new_content
        changed.append({"message_index": index, "role": compacted[index].get("role", ""), **meta})

    new_tokens = estimate_message_tokens(compacted, chars_per_token=chars_per_token)
    return compacted, {
        "compacted": bool(changed),
        "original_estimated_tokens": original_tokens,
        "new_estimated_tokens": new_tokens,
        "max_input_tokens": max_input_tokens,
        "changed_messages": changed,
        "iterations": iterations,
        "within_budget": new_tokens <= max_input_tokens,
    }

def model_route_decision_payload(
    *,
    messages: list[dict[str, str]],
    provider_name: str,
    selected_model: str,
    selected_temperature: float,
    config: dict[str, Any],
    explicit_model: bool = False,
) -> dict[str, Any]:
    router = config.get("model_router", default_model_router_config())
    chars_per_token = float(router.get("estimate_chars_per_token", APPROX_CHARS_PER_TOKEN))
    estimated_tokens = estimate_message_tokens(messages, chars_per_token=chars_per_token)
    payload: dict[str, Any] = {
        "enabled": bool(router.get("enabled", True)),
        "estimated_input_tokens": estimated_tokens,
        "chars_per_token": chars_per_token,
        "original_provider": provider_name,
        "original_model": selected_model,
        "original_temperature": selected_temperature,
        "provider": provider_name,
        "model": selected_model,
        "temperature": selected_temperature,
        "route_name": "disabled",
        "route_reason": "Model router disabled.",
        "explicit_model": explicit_model,
        "changed": False,
    }
    if not payload["enabled"]:
        return payload
    if explicit_model and bool(router.get("respect_explicit_model", True)):
        payload["route_name"] = "explicit_model"
        payload["route_reason"] = "Explicit model argument supplied; router preserved it."
        return payload

    routes = router.get("routes", [])
    selected_route: dict[str, Any] | None = None
    for route in routes if isinstance(routes, list) else []:
        if not isinstance(route, dict):
            continue
        max_tokens = route.get("max_input_tokens")
        if max_tokens is None or estimated_tokens <= int(max_tokens):
            selected_route = route
            break
    if selected_route is None and routes:
        selected_route = routes[-1]
    if selected_route is None:
        payload["route_name"] = "no_routes"
        payload["route_reason"] = "No usable model-router routes configured."
        return payload

    providers = config.get("llm_providers", {})
    route_provider = str(selected_route.get("provider", "") or provider_name)
    if route_provider not in providers:
        payload["route_name"] = str(selected_route.get("name", "invalid_provider"))
        payload["route_reason"] = f"Configured route provider `{route_provider}` is unknown; preserved original route."
        payload["invalid_provider"] = route_provider
        return payload

    route_model = str(selected_route.get("model", "") or selected_model or providers.get(route_provider, {}).get("model", MODEL))
    route_temperature = selected_route.get("temperature")
    if route_temperature is None:
        route_temperature = selected_temperature
    else:
        route_temperature = float(route_temperature)

    payload.update(
        {
            "provider": route_provider,
            "model": route_model,
            "temperature": route_temperature,
            "route_name": str(selected_route.get("name", "unnamed_route")),
            "route_reason": str(selected_route.get("reason", "") or "Matched by estimated input token count."),
            "max_input_tokens": selected_route.get("max_input_tokens"),
            "input_token_budget": selected_route.get("input_token_budget"),
        }
    )
    payload["changed"] = (payload["provider"], payload["model"], payload["temperature"]) != (
        provider_name,
        selected_model,
        selected_temperature,
    )
    return payload


def resolve_model_route(
    messages: list[dict[str, str]],
    *,
    provider_name: str,
    provider_config: dict[str, Any],
    selected_model: str,
    selected_temperature: float,
    config: dict[str, Any],
    explicit_model: bool = False,
    log_decision: bool = True,
) -> tuple[str, dict[str, Any], str, float, dict[str, Any]]:
    decision = model_route_decision_payload(
        messages=messages,
        provider_name=provider_name,
        selected_model=selected_model,
        selected_temperature=selected_temperature,
        config=config,
        explicit_model=explicit_model,
    )
    routed_provider = str(decision.get("provider", provider_name))
    if routed_provider != provider_name:
        routed_provider, routed_config = get_provider_config(routed_provider)
    else:
        routed_config = dict(provider_config)
    routed_model = str(decision.get("model", selected_model))
    routed_temperature = float(decision.get("temperature", selected_temperature))
    if log_decision and config.get("model_router", {}).get("log_decisions", True):
        log_run_event("model_route_decision", {k: v for k, v in decision.items() if k != "provider_config"})
    return routed_provider, routed_config, routed_model, routed_temperature, decision


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

    if msvcrt is None:
        return input(prompt).strip()

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
- Use show_config, list_llm_routes, list_available_models, discover_available_models, recommend_model_selection, build_model_portfolio, route_multi_model_task, show_model_router, recommend_model_route, audit_tool_coverage, recommend_tool_chain, build_execution_dossier, inspect_runtime_environment, audit_dependency_health, inspect_prompt_surface, build_context_budget_plan, simulate_tool_execution_plan, build_risk_register, map_repository_structure, inspect_project_entrypoints, extract_api_surface, trace_data_flow, inspect_error_log, inspect_config_surface, fetch_url_text, inspect_http_endpoint, fetch_json_api, extract_html_metadata, check_http_security_headers, crawl_url_map, infer_json_schema, extract_text_entities, generate_file_manifest, compare_workspace_files, inspect_python_environment, inspect_process_table, normalize_network_target, resolve_dns_records, reverse_dns_lookup, lookup_ip_rdap, lookup_ip_geolocation, get_public_ip_info, scan_tcp_ports, inspect_local_listening_ports, inspect_tls_certificate, inspect_local_network, build_network_intel_brief, ingest_network_traffic_file, analyze_network_traffic_file, build_ids_baseline, compare_network_baseline, capture_network_metadata_sample, build_ids_mode_plan, show_ids_alerts, lookup_cve, search_cves, check_cisa_kev, lookup_malware_hash, hash_workspace_file, add_malware_signature, scan_workspace_file_signatures, build_threat_intel_brief, build_toolbox_brief, show_workspace_stats, show_run_history, summarize_blackboard, and show_cycle_ledger when you need to understand the agent's own operating state, model catalog, provider/model choices, repository shape, tool affordances, execution plan, external documentation, or model-routing decisions.
- For direct network-information questions such as public IP, DNS, RDAP, GeoIP, ASN/ISP, TLS, local network, bounded port checks, traffic ingestion, or IDS-mode planning, call the smallest matching network/IDS tool once and then return a concise user-facing summary. Do not repeat the same network lookup and do not expose raw tool JSON unless the user asks for raw JSON. Live traffic capture must be bounded, metadata-only, and explicitly authorized.
- For direct defensive threat-intelligence questions such as CVE lookups, CISA KEV checks, malware hash enrichment, local file hash checks, or local malware-signature scans, call the smallest matching threat-intel tool once and then return a concise user-facing summary. Never download malware samples or execute suspect files.

Rules:
- Prefer evidence from tools over guessing.
- For substantial analysis, debugging, implementation, or refactoring, prefer build_context_pack, decompose_goal, and find_relevant_code_context before editing so the work starts from grounded situational context and exact code symbols.
- Keep file access inside the workspace.
- Do not run destructive or system-altering commands.
- Prefer file tools over shell commands for code changes.
- For ordinary informational answers, answer directly; do not call write_file, append_file, replace_in_file, or other write tools unless the user explicitly asks to save, export, edit, implement, or modify files.
- For short conversational follow-ups like "anything else?", "continue", "tell me more", or "go on", answer from the recent conversation instead of inspecting the workspace or calling tools unless the user explicitly asks for a workspace/tool action.
- When a user asks for a table, produce a standard Markdown pipe table in the final answer; the terminal renderer will convert it into a visual table.
- Store durable findings in memory when they may help later.
- Store explicit user facts such as name, contact details, birthday, preferences, and personal notes in the structured user profile, not in ad hoc memory.
- Respect the control file during autonomous loops so a human can ask the agent to wrap up or stop.
- Treat autonomous code changes as experiments: state the hypothesis, validate, record outcome, and roll back if policy or validation fails.
- Do not broaden scope just because more tools exist; choose the smallest reversible step that improves the selected opportunity.
- Never call self_improve_codebase from inside a self_improve_codebase cycle. During autonomous improvement, use concrete tools like read_file, replace_in_file, validate_python_file, git_diff, and run_internal_self_tests instead of recursively starting another autonomous improvement loop.

Registered tool specs are injected at runtime from the live tool registry.
Do not rely on stale hardcoded tool schemas; use the registered tool specs below.
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


SEARCH_STOPWORDS = {
    "about",
    "after",
    "again",
    "also",
    "and",
    "are",
    "because",
    "before",
    "but",
    "can",
    "could",
    "for",
    "from",
    "give",
    "have",
    "how",
    "into",
    "make",
    "more",
    "not",
    "now",
    "of",
    "on",
    "or",
    "please",
    "should",
    "show",
    "tell",
    "than",
    "that",
    "the",
    "this",
    "through",
    "to",
    "use",
    "what",
    "when",
    "where",
    "which",
    "with",
    "would",
    "you",
}


def search_terms(text: str, *, min_length: int = 2) -> list[str]:
    terms: list[str] = []
    for raw in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", text.lower()):
        term = raw.strip("._-")
        if len(term) < min_length or term in SEARCH_STOPWORDS:
            continue
        if term not in terms:
            terms.append(term)
    return terms


def score_text_relevance(query: str, text: str) -> tuple[float, list[str]]:
    query_normalized = re.sub(r"\s+", " ", query.lower()).strip()
    text_normalized = re.sub(r"\s+", " ", text.lower()).strip()
    if not query_normalized or not text_normalized:
        return 0.0, []

    terms = search_terms(query_normalized)
    score = 0.0
    reasons: list[str] = []

    if query_normalized and query_normalized in text_normalized:
        occurrences = text_normalized.count(query_normalized)
        score += 12.0 + min(occurrences, 5) * 2.0
        reasons.append("exact phrase")

    text_terms = set(search_terms(text_normalized))
    matched_terms: list[str] = []
    for term in terms:
        occurrences = text_normalized.count(term)
        if occurrences:
            matched_terms.append(term)
            score += 3.0 + min(occurrences, 4)
            if term in text_terms:
                score += 1.0

    if matched_terms:
        coverage = len(matched_terms) / max(1, len(terms))
        score += coverage * 10.0
        reasons.append("matched terms: " + ", ".join(matched_terms[:8]))

    for first, second in zip(terms, terms[1:]):
        phrase = f"{first} {second}"
        if phrase in text_normalized:
            score += 4.0
            reasons.append(f"ordered phrase: {phrase}")

    return score, reasons[:6]


def rank_relevant_text_items(
    query: str,
    items: list[dict[str, Any]],
    *,
    text_fields: tuple[str, ...] = ("content", "text", "value", "note", "title"),
    limit: int = 8,
) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for item in items:
        haystack = "\n".join(str(item.get(field, "")) for field in text_fields if item.get(field) is not None)
        score, reasons = score_text_relevance(query, haystack)
        if score <= 0:
            continue
        enriched = dict(item)
        enriched["relevance_score"] = round(score, 2)
        enriched["relevance_reasons"] = reasons
        ranked.append(enriched)
    ranked.sort(key=lambda entry: (-float(entry.get("relevance_score", 0)), str(entry.get("key") or entry.get("title") or entry.get("path") or "")))
    return ranked[: max(1, min(int(limit), 50))]


TEXT_FILE_SUFFIXES = {
    "",
    ".bat",
    ".cfg",
    ".css",
    ".csv",
    ".env",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".log",
    ".md",
    ".py",
    ".ps1",
    ".rst",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def looks_like_text_path(path: Path) -> bool:
    return path.suffix.lower() in TEXT_FILE_SUFFIXES


def read_text_sample(path: Path, max_chars: int = 12000) -> str:
    try:
        data = path.read_bytes()[: max(0, int(max_chars))]
    except OSError:
        return ""
    if b"\x00" in data:
        return ""
    return data.decode("utf-8", errors="replace")


def relevant_line_snippets(query: str, text: str, *, context_lines: int = 1, limit: int = 3) -> list[dict[str, Any]]:
    terms = search_terms(query)
    if not terms or not text:
        return []
    lines = text.splitlines()
    scored_lines: list[tuple[float, int, list[str]]] = []
    for index, line in enumerate(lines):
        score, reasons = score_text_relevance(query, line)
        if score > 0:
            scored_lines.append((score, index, reasons))
    scored_lines.sort(key=lambda item: (-item[0], item[1]))

    snippets: list[dict[str, Any]] = []
    used_ranges: list[range] = []
    for score, index, reasons in scored_lines:
        start = max(0, index - context_lines)
        end = min(len(lines), index + context_lines + 1)
        candidate_range = range(start, end)
        if any(set(candidate_range).intersection(existing) for existing in used_ranges):
            continue
        snippet_lines = [f"{line_number + 1}: {lines[line_number]}" for line_number in candidate_range]
        snippets.append(
            {
                "start_line": start + 1,
                "end_line": end,
                "score": round(score, 2),
                "reasons": reasons,
                "text": trim_text("\n".join(snippet_lines), 1200),
            }
        )
        used_ranges.append(candidate_range)
        if len(snippets) >= max(1, min(int(limit), 10)):
            break
    return snippets



def iter_python_source_files(target: Path, *, recursive: bool = True, max_files: int = 250) -> list[Path]:
    """Return bounded Python source files under a workspace target."""
    if target.is_file():
        candidates = [target]
    else:
        candidates = list(target.rglob("*.py") if recursive else target.glob("*.py"))
    files = [
        candidate
        for candidate in candidates
        if candidate.is_file()
        and candidate.suffix.lower() == ".py"
        and not should_skip_checkpoint_path(candidate)
    ]
    files.sort(key=lambda item: workspace_relative(item))
    return files[: max(1, min(int(max_files), 1000))]


def ast_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = ast_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def ast_decision_points(node: ast.AST) -> int:
    decision_nodes = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.ExceptHandler,
        ast.With,
        ast.AsyncWith,
        ast.BoolOp,
        ast.IfExp,
        ast.Match,
        ast.comprehension,
    )
    return sum(1 for child in ast.walk(node) if isinstance(child, decision_nodes))


def ast_node_source(source_lines: list[str], node: ast.AST, *, max_chars: int = 5000) -> str:
    start = max(0, int(getattr(node, "lineno", 1)) - 1)
    end = max(start + 1, int(getattr(node, "end_lineno", start + 1)))
    return trim_text("\n".join(source_lines[start:end]), max_chars)

def infer_task_profile(user_input: str) -> dict[str, Any]:
    text = re.sub(r"\s+", " ", user_input.lower()).strip()
    terms = search_terms(user_input)[:16]
    intents: list[str] = []

    def has_any(words: set[str]) -> bool:
        return any(word in text for word in words)

    if has_any({"fix", "bug", "error", "traceback", "crash", "broken", "wrong"}):
        intents.append("debug")
    if has_any({"improve", "advanced", "feature", "functionality", "intelligence", "implement", "build", "add"}):
        intents.append("implementation")
    if has_any({"refactor", "cleanup", "simplify", "modular", "architecture"}):
        intents.append("refactoring")
    if has_any({"test", "validate", "pytest", "ruff", "compile", "smoke"}):
        intents.append("validation")
    if has_any({"analyze", "inspect", "audit", "review", "summarize", "explain"}):
        intents.append("analysis")
    if has_any({"self-improve", "self improve", "autonomous", "autonomy", "agentic"}):
        intents.append("autonomy")
    if has_any({"model", "models", "provider", "openai", "anthropic", "xai", "grok", "claude", "llama", "meta", "gemini", "openrouter", "lm studio", "lmstudio", "ollama"}):
        intents.append("model_selection")
    if has_any({"network", "netstat", "dns", "domain", "hostname", "ip", "ip address", "asn", "isp", "geolocation", "geoip", "ports", "open port", "port scan", "rdap", "whois", "tls", "ssl", "certificate", "public ip", "traffic", "packet", "pcap", "ids", "intrusion", "suricata", "zeek", "flow", "flows", "beacon", "anomaly"}):
        intents.append("network_intelligence")
    if has_any({"cve", "cves", "cvss", "critical vulnerability", "critical vulnerabilities", "vulnerability", "vulnerabilities", "kev", "known exploited", "cisa kev", "malware", "malware signature", "malware signatures", "yara", "ioc", "indicator", "hash lookup", "threat intel", "threat intelligence", "malwarebazaar"}):
        intents.append("threat_intelligence")
    if has_any({"encrypt", "encryption", "decrypt", "decryption", "crypto", "cryptography", "cipher", "aes", "aes-gcm", "chacha20", "fernet", "pbkdf2", "hmac"}):
        intents.append("cryptography")
    if not intents:
        intents.append("conversation")

    risk_signals: list[str] = []
    if has_any({"delete", "remove", "wipe", "reset", "overwrite"}):
        risk_signals.append("destructive file operation")
    if has_any({"run", "command", "shell", "terminal", "subprocess", "powershell", "cmd"}):
        risk_signals.append("command execution")
    if has_any({"self-improve", "autonomous", "autonomy", "loop"}):
        risk_signals.append("autonomous loop")
    if has_any({"config", "provider", "api key", "memory", "control", "model", "models", "route"}):
        risk_signals.append("control-plane or persistent state")
    if has_any({"port scan", "scan ports", "open ports", "nmap", "external host", "public target"}):
        risk_signals.append("network scanning")

    risk_level = "high" if any("destructive" in item or "autonomous" in item for item in risk_signals) else "medium" if risk_signals else "low"

    suggested_tools: list[str] = []
    if "model_selection" in intents:
        suggested_tools.extend(["list_available_models", "discover_available_models", "recommend_model_selection", "build_model_portfolio", "set_model_selection", "list_llm_routes", "show_model_router"] )
    if "network_intelligence" in intents:
        suggested_tools.extend(["build_network_intel_brief", "build_ids_mode_plan", "ingest_network_traffic_file", "analyze_network_traffic_file", "build_ids_baseline", "compare_network_baseline", "show_ids_alerts", "capture_network_metadata_sample", "normalize_network_target", "resolve_dns_records", "reverse_dns_lookup", "lookup_ip_rdap", "lookup_ip_geolocation", "get_public_ip_info", "inspect_tls_certificate", "scan_tcp_ports", "inspect_local_listening_ports", "inspect_local_network"] )
    if "threat_intelligence" in intents:
        suggested_tools.extend(["build_threat_intel_brief", "lookup_cve", "search_cves", "check_cisa_kev", "lookup_malware_hash", "hash_workspace_file", "add_malware_signature", "scan_workspace_file_signatures"] )
    if "cryptography" in intents:
        suggested_tools.extend(["list_crypto_algorithms", "encrypt_text", "decrypt_text", "encrypt_file", "decrypt_file"] )
    if "implementation" in intents or "refactoring" in intents or "debug" in intents:
        suggested_tools.extend(["build_execution_dossier", "recommend_tool_chain", "plan_patch_strategy", "trace_goal_to_symbols", "build_validation_matrix", "score_execution_readiness", "build_context_pack", "decompose_goal", "find_relevant_code_context", "semantic_search_workspace", "read_file", "apply_unified_diff", "validate_python_file"] )
    elif "analysis" in intents:
        suggested_tools.extend(["build_execution_dossier", "recommend_tool_chain", "trace_goal_to_symbols", "map_tool_capability_graph", "build_context_pack", "find_relevant_code_context", "semantic_search_workspace", "search_files", "summarize_python_file"] )
    elif "validation" in intents:
        suggested_tools.extend(["build_execution_dossier", "recommend_tool_chain", "build_validation_matrix", "score_execution_readiness", "inspect_tool_schema_health", "run_internal_self_tests", "validate_workspace_python", "run_self_improvement_validation"] )
    else:
        suggested_tools.extend(["recommend_tool_chain", "map_tool_capability_graph", "search_memory", "build_context_pack"] )

    suggested_roles: list[str] = []
    if "implementation" in intents:
        suggested_roles.extend(["architect", "coder", "reviewer"] )
    if "refactoring" in intents:
        suggested_roles.extend(["architect", "refactorer", "tester"] )
    if "debug" in intents or "validation" in intents:
        suggested_roles.extend(["tester", "reviewer"] )
    if "analysis" in intents or "network_intelligence" in intents or "threat_intelligence" in intents or "cryptography" in intents:
        suggested_roles.extend(["researcher", "planner", "critic"] )
    if "autonomy" in intents or risk_level != "low":
        suggested_roles.extend(["safety", "maintainer"] )
    if not suggested_roles:
        suggested_roles = ["planner", "writer"]

    deduped_roles: list[str] = []
    for role in suggested_roles:
        if role in ROLE_CATALOG and role not in deduped_roles:
            deduped_roles.append(role)

    deduped_tools: list[str] = []
    for tool in suggested_tools:
        if tool not in deduped_tools:
            deduped_tools.append(tool)

    return {
        "intents": intents,
        "query_terms": terms,
        "estimated_input_tokens": estimate_token_count(user_input),
        "write_intent": user_explicitly_requested_file_write(user_input),
        "tool_intent": user_input_has_tool_intent(user_input),
        "risk_level": risk_level,
        "risk_signals": risk_signals,
        "suggested_roles": deduped_roles[:MAX_TEAM_ROLES],
        "suggested_tools": deduped_tools[:8],
    }


def build_task_intelligence_summary(user_input: str, state: "AgentState") -> str:
    profile = infer_task_profile(user_input)
    recent_failures = [item for item in state.tool_history[-8:] if not item.get("ok")]
    payload = {
        "turn_task_profile": profile,
        "recent_failure_count": len(recent_failures),
        "last_failed_tools": [item.get("tool") for item in recent_failures[-3:]],
        "active_plan_items": state.plan[:6],
        "instruction": (
            "Use this deterministic task profile as a routing hint only. "
            "Prefer evidence from tools and user instructions over the heuristic profile."
        ),
    }
    return "Task intelligence snapshot:\n" + json.dumps(payload, indent=2)


ANSI_PATTERN = re.compile(r"\033\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_PATTERN.sub("", text)


def strip_inline_markdown_for_width(text: str) -> str:
    # Width calculations should see the text as the user will see it after light
    # inline markdown rendering.
    return re.sub(r"\*\*([^*\n]+?)\*\*", r"\1", text)


def terminal_display_width(text: str) -> int:
    import unicodedata

    plain = strip_inline_markdown_for_width(strip_ansi(text))
    width = 0
    for char in plain:
        if unicodedata.combining(char):
            continue
        east_asian = unicodedata.east_asian_width(char)
        if east_asian in {"F", "W"}:
            width += 2
        elif ord(char) > 0xFFFF:
            width += 2
        else:
            width += 1
    return width


def truncate_display(text: str, max_width: int) -> str:
    if terminal_display_width(text) <= max_width:
        return text
    if max_width <= 1:
        return "…"[:max_width]
    output: list[str] = []
    used = 0
    for char in text:
        char_width = terminal_display_width(char)
        if used + char_width > max_width - 1:
            break
        output.append(char)
        used += char_width
    return "".join(output) + "…"


def pad_display(text: str, width: int, align: str = "left") -> str:
    visible_width = terminal_display_width(text)
    if visible_width > width:
        text = truncate_display(text, width)
        visible_width = terminal_display_width(text)
    padding = max(0, width - visible_width)
    if align == "right":
        return " " * padding + text
    if align == "center":
        left = padding // 2
        right = padding - left
        return " " * left + text + " " * right
    return text + " " * padding


def wrap_display_text(text: str, width: int) -> list[str]:
    text = text.strip()
    if not text:
        return [""]
    if terminal_display_width(text) <= width:
        return [text]

    words = re.split(r"(\s+)", text)
    lines: list[str] = []
    current = ""

    for token in words:
        if not token:
            continue
        candidate = current + token if current else token.strip()
        if terminal_display_width(candidate) <= width:
            current = candidate
            continue
        if current:
            lines.append(current.rstrip())
            current = token.strip()
            if terminal_display_width(current) <= width:
                continue
        # Very long token: hard-wrap by display width.
        while terminal_display_width(current) > width:
            chunk: list[str] = []
            used = 0
            rest: list[str] = []
            for char in current:
                char_width = terminal_display_width(char)
                if used + char_width <= width:
                    chunk.append(char)
                    used += char_width
                else:
                    rest.append(char)
            lines.append("".join(chunk))
            current = "".join(rest)
    if current:
        lines.append(current.rstrip())
    return lines or [""]


def split_markdown_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]

    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for char in stripped:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            current.append(char)
            continue
        if char == "|":
            cells.append("".join(current).strip().replace(r"\|", "|"))
            current = []
            continue
        current.append(char)
    cells.append("".join(current).strip().replace(r"\|", "|"))
    return cells


def is_markdown_table_separator(line: str) -> bool:
    cells = split_markdown_table_row(line)
    if len(cells) < 2:
        return False
    for cell in cells:
        normalized = cell.replace(" ", "")
        if not re.fullmatch(r":?-{3,}:?", normalized):
            return False
    return True


def markdown_table_alignments(separator_line: str, column_count: int) -> list[str]:
    alignments: list[str] = []
    for cell in split_markdown_table_row(separator_line)[:column_count]:
        normalized = cell.replace(" ", "")
        if normalized.startswith(":") and normalized.endswith(":"):
            alignments.append("center")
        elif normalized.endswith(":"):
            alignments.append("right")
        else:
            alignments.append("left")
    while len(alignments) < column_count:
        alignments.append("left")
    return alignments


def table_like_line(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and "|" in stripped and stripped.count("|") >= 2


def markdown_table_group(lines: list[str]) -> tuple[list[list[str]], list[str]] | None:
    parsed = [split_markdown_table_row(line) for line in lines]
    parsed = [row for row in parsed if len(row) >= 2]
    if len(parsed) < 2:
        return None

    separator_index = next((index for index, line in enumerate(lines) if is_markdown_table_separator(line)), -1)
    if separator_index >= 1:
        header = parsed[separator_index - 1]
        rows = parsed[separator_index + 1 :]
        column_count = max(len(header), *(len(row) for row in rows)) if rows else len(header)
        alignments = markdown_table_alignments(lines[separator_index], column_count)
        normalized_rows = [header] + rows
    else:
        # Loose pipe table fallback. Require at least three rows with stable column
        # counts so ordinary prose containing pipes is not over-formatted.
        counts = [len(row) for row in parsed]
        if len(parsed) < 3 or max(counts) < 2 or len(set(counts)) > 1:
            return None
        column_count = counts[0]
        alignments = ["left"] * column_count
        normalized_rows = parsed

    normalized: list[list[str]] = []
    for row in normalized_rows:
        cells = row[:column_count] + [""] * max(0, column_count - len(row))
        normalized.append(cells)
    return normalized, alignments[:column_count]


def compute_table_widths(rows: list[list[str]], max_width: int) -> list[int]:
    column_count = max((len(row) for row in rows), default=0)
    if column_count == 0:
        return []

    widths = [
        max(3, max(terminal_display_width(row[column]) for row in rows))
        for column in range(column_count)
    ]

    # Borders use: left/right + 2 spaces per cell + one separator between cells.
    border_overhead = 3 * column_count + 1
    available = max(8, max_width - border_overhead)
    if sum(widths) <= available:
        return widths

    min_widths = [min(max(3, terminal_display_width(rows[0][column])), 12) for column in range(column_count)]
    min_total = sum(min_widths)
    if min_total > available:
        min_widths = [max(3, available // column_count) for _ in range(column_count)]
    widths = [max(width, min_widths[index]) for index, width in enumerate(widths)]

    while sum(widths) > available:
        reducible = [
            (widths[index] - min_widths[index], index)
            for index in range(column_count)
            if widths[index] > min_widths[index]
        ]
        if not reducible:
            break
        _, index = max(reducible)
        widths[index] -= 1
    return widths


def render_box_table(rows: list[list[str]], alignments: list[str]) -> str:
    if not rows:
        return ""

    max_width = max(40, terminal_width() - 2)
    widths = compute_table_widths(rows, max_width)
    column_count = len(widths)

    def border(left: str, middle: str, right: str) -> str:
        return left + middle.join("─" * (width + 2) for width in widths) + right

    def render_row(row: list[str], *, header: bool = False) -> list[str]:
        wrapped_cells = [
            wrap_display_text(row[index] if index < len(row) else "", widths[index])
            for index in range(column_count)
        ]
        height = max(len(cell_lines) for cell_lines in wrapped_cells)
        lines: list[str] = []
        for line_index in range(height):
            rendered_cells = []
            for column_index, cell_lines in enumerate(wrapped_cells):
                cell_text = cell_lines[line_index] if line_index < len(cell_lines) else ""
                align = "left" if header else alignments[column_index]
                rendered_cells.append(" " + pad_display(cell_text, widths[column_index], align) + " ")
            lines.append("│" + "│".join(rendered_cells) + "│")
        return lines

    output: list[str] = [border("┌", "┬", "┐")]
    output.extend(render_row(rows[0], header=True))
    if len(rows) > 1:
        output.append(border("├", "┼", "┤"))
        for row in rows[1:]:
            output.extend(render_row(row))
    output.append(border("└", "┴", "┘"))
    return "\n".join(output)


def normalize_markdown_table(lines: list[str]) -> str | None:
    group = markdown_table_group(lines)
    if group is None:
        return None
    rows, alignments = group
    return render_box_table(rows, alignments)


def format_markdown_tables_for_terminal(text: str) -> str:
    lines = text.splitlines()
    output: list[str] = []
    pending: list[str] = []
    in_fence = False

    def flush_pending() -> None:
        nonlocal pending
        if not pending:
            return
        rendered = normalize_markdown_table(pending)
        if rendered:
            output.extend(rendered.splitlines())
        else:
            output.extend(pending)
        pending = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            flush_pending()
            in_fence = not in_fence
            output.append(line)
            continue
        if in_fence:
            output.append(line)
            continue
        if table_like_line(line):
            pending.append(line)
            continue
        flush_pending()
        output.append(line)

    flush_pending()
    return "\n".join(output)


def markdown_heading_match(line: str) -> re.Match[str] | None:
    return re.match(r"^(?P<marker>#{1,6})[ \t]+(?P<title>.+?)\s*$", line)


def render_markdown_heading_line(line: str) -> str:
    match = markdown_heading_match(line)
    if not match:
        return line

    marker = match.group("marker")
    level = len(marker)
    title = match.group("title").strip()
    if not title:
        return ""

    # Terminal output should look like a real heading, not raw Markdown.
    # The Markdown # / ## marker is a source-format hint, so strip it and
    # replace it with an underline style that still works in plain CMD output.
    max_width = max(12, min(terminal_width() - 4, 100))
    display_title = title.upper() if level == 1 else title
    display_title = truncate_display(display_title, max_width)
    rule_width = max(8, min(terminal_display_width(display_title), max_width))

    if level == 1:
        rule_char = "═"
        color = "96"
    elif level == 2:
        rule_char = "─"
        color = "94"
    else:
        rule_char = "┄"
        color = "90"

    rule = rule_char * rule_width
    if sys.stdout.isatty():
        styled_title = f"\033[1m{terminal_color(display_title, color)}\033[0m"
        styled_rule = terminal_color(rule, color)
        return f"{styled_title}\n{styled_rule}"
    return f"{display_title}\n{rule}"


def format_markdown_headers_for_terminal(text: str) -> str:
    lines = text.splitlines()
    output: list[str] = []
    in_fence = False
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            output.append(line)
            continue
        if in_fence:
            output.append(line)
            continue
        output.append(render_markdown_heading_line(line))
    return "\n".join(output)


def format_markdown_lists_for_terminal(text: str) -> str:
    lines = text.splitlines()
    output: list[str] = []
    in_fence = False
    unordered_pattern = re.compile(r"^(?P<indent>\s*)[-*+]\s+(?P<body>.+)$")
    ordered_pattern = re.compile(r"^(?P<indent>\s*)(?P<num>\d+)[.)]\s+(?P<body>.+)$")

    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            output.append(line)
            continue
        if in_fence:
            output.append(line)
            continue

        unordered = unordered_pattern.match(line)
        if unordered:
            body = unordered.group("body").strip()
            indent = unordered.group("indent")
            if body.startswith("[x] ") or body.startswith("[X] "):
                output.append(f"{indent}☑ {body[4:].strip()}")
            elif body.startswith("[ ] "):
                output.append(f"{indent}☐ {body[4:].strip()}")
            else:
                output.append(f"{indent}• {body}")
            continue

        ordered = ordered_pattern.match(line)
        if ordered:
            indent = ordered.group("indent")
            number = ordered.group("num")
            body = ordered.group("body").strip()
            output.append(f"{indent}{number}. {body}")
            continue

        output.append(line)

    return "\n".join(output)


def format_markdown_blockquotes_for_terminal(text: str) -> str:
    lines = text.splitlines()
    output: list[str] = []
    in_fence = False
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            output.append(line)
            continue
        if in_fence:
            output.append(line)
            continue
        quote = re.match(r"^\s*>\s?(?P<body>.*)$", line)
        if quote:
            output.append("│ " + quote.group("body"))
        else:
            output.append(line)
    return "\n".join(output)


def format_inline_markdown_for_terminal(text: str) -> str:
    lines = text.splitlines()
    output: list[str] = []
    in_fence = False

    def inline_code(match: re.Match[str]) -> str:
        code = match.group(1)
        return terminal_color(code, "93") if sys.stdout.isatty() else code

    def bold(match: re.Match[str]) -> str:
        content = match.group(1)
        return f"\033[1m{content}\033[0m" if sys.stdout.isatty() else content

    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            output.append(line)
            continue
        if in_fence:
            output.append(line)
            continue
        rendered = re.sub(r"`([^`\n]+?)`", inline_code, line)
        rendered = re.sub(r"\*\*([^\n]+?)\*\*", bold, rendered)
        output.append(rendered)

    return "\n".join(output)


def action_envelope_to_user_text(action: dict[str, Any], *, original_text: str = "") -> str:
    action_type = action.get("type")
    if action_type == "final" and isinstance(action.get("content"), str):
        return action["content"]

    if action_type == "tool":
        tool_name = str(action.get("tool", "unknown_tool"))
        return (
            f"[internal tool request suppressed: {tool_name}]\n"
            "The model returned a tool-action JSON envelope where user-facing text was expected. "
            "Cerebro kept the raw JSON out of the terminal."
        )

    if action_type == "batch":
        raw_actions = action.get("actions", [])
        tool_names: list[str] = []
        if isinstance(raw_actions, list):
            for item in raw_actions:
                if isinstance(item, dict) and isinstance(item.get("tool"), str):
                    tool_names.append(item["tool"])
        listed_tools = ", ".join(tool_names[:5]) or "no valid tools"
        extra = f" (+{len(tool_names) - 5} more)" if len(tool_names) > 5 else ""
        return (
            f"[internal batch request suppressed: {listed_tools}{extra}]\n"
            "The model returned a batch-action JSON envelope where user-facing text was expected. "
            "Cerebro kept the raw JSON out of the terminal."
        )

    if original_text:
        return original_text
    return "The model returned an unsupported action envelope."


def unwrap_final_action_text(text: str) -> str:
    stripped = strip_markdown_fences(text).strip()
    if not stripped.startswith("{"):
        return text
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return text
    if isinstance(parsed, dict) and parsed.get("type") in {"final", "tool", "batch"}:
        return action_envelope_to_user_text(parsed, original_text=text)
    return text


def render_terminal_markdown(text: str) -> str:
    def color_line_count(match: re.Match[str]) -> str:
        label = match.group("label")
        value = match.group("value")
        if not sys.stdout.isatty():
            return f"{label}{value}"
        if label.lower().startswith("lines added"):
            color = "32"
        elif label.lower().startswith("lines removed"):
            color = "31"
        else:
            numeric = int(value.replace("+", ""))
            color = "32" if numeric > 0 else "31" if numeric < 0 else "90"
        return f"{label}{terminal_color(value, color)}"

    rendered = unwrap_final_action_text(text)
    rendered = format_markdown_tables_for_terminal(rendered)
    rendered = format_markdown_headers_for_terminal(rendered)
    rendered = format_markdown_lists_for_terminal(rendered)
    rendered = format_markdown_blockquotes_for_terminal(rendered)
    rendered = format_inline_markdown_for_terminal(rendered)
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
    if RUNTIME_OUTPUT_SUPPRESSED:
        return False
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


def active_agent_file() -> str:
    active = Path(__file__).resolve()
    try:
        return str(active.relative_to(WORKSPACE_ROOT))
    except ValueError:
        return active.name


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
    if RUNTIME_OUTPUT_SUPPRESSED:
        return
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
    provider_name, provider_config, selected_model, selected_temperature, route_decision = resolve_model_route(
        messages,
        provider_name=provider_name,
        provider_config=provider_config,
        selected_model=selected_model,
        selected_temperature=float(selected_temperature),
        config=config,
        explicit_model=model is not None,
    )
    prompt_budget = model_input_token_budget(route_decision, provider_config, config)
    chars_per_token = float(config.get("model_router", {}).get("estimate_chars_per_token", APPROX_CHARS_PER_TOKEN))
    messages_for_model = messages
    compaction_meta: dict[str, Any] | None = None
    if prompt_budget:
        messages_for_model, compaction_meta = compact_messages_for_input_budget(
            messages,
            max_input_tokens=prompt_budget,
            chars_per_token=chars_per_token,
            min_message_tokens=safe_int(config.get("model_router", {}).get("min_compaction_tokens"), 256),
        )
        if compaction_meta.get("compacted"):
            log_run_event(
                "prompt_compacted_for_model_budget",
                {
                    "provider": provider_name,
                    "model": selected_model,
                    "route_name": route_decision.get("route_name"),
                    **compaction_meta,
                },
            )

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
                messages_for_model,
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
                messages_for_model,
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
        repaired_batch = repair_batch_candidate(candidate, tool_names=tool_names)
        if repaired_batch is not None:
            ok, repaired_reason = validate_action_shape(repaired_batch, tool_names=tool_names)
            if ok:
                log_run_event(
                    "repaired_batch_action",
                    {
                        "reason": reason,
                        "original_action_count": len(candidate.get("actions", [])) if isinstance(candidate.get("actions"), list) else 0,
                        "repaired_action_count": len(repaired_batch.get("actions", [])),
                    },
                )
                return repaired_batch
            reason = f"{reason}; repaired batch invalid: {repaired_reason}"
        log_run_event("invalid_action_shape", {"reason": reason, "candidate": candidate})

    action_like = next(
        (
            candidate
            for candidate in candidates
            if isinstance(candidate, dict) and candidate.get("type") in {"tool", "batch", "final"}
        ),
        None,
    )
    if action_like is not None:
        return {
            "type": "final",
            "content": action_envelope_to_user_text(action_like, original_text=reply),
            "summary": "Model returned an invalid action envelope; raw JSON was suppressed.",
        }

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


def normalize_batch_actions(actions: Any, tool_names: set[str] | None = None) -> list[dict[str, Any]]:
    if not isinstance(actions, list):
        return []
    normalized: list[dict[str, Any]] = []
    for action in actions[:configured_max_batch_actions()]:
        if not isinstance(action, dict):
            continue
        tool_name = action.get("tool")
        args = action.get("args", {})
        if not isinstance(tool_name, str) or not isinstance(args, dict):
            continue
        if tool_names is not None and tool_name not in tool_names:
            continue
        normalized.append({"tool": tool_name, "args": args})
    return normalized


def repair_batch_candidate(candidate: dict[str, Any], tool_names: set[str] | None = None) -> dict[str, Any] | None:
    if candidate.get("type") != "batch":
        return None
    normalized = normalize_batch_actions(candidate.get("actions"), tool_names=tool_names)
    if not normalized:
        return None
    repaired = dict(candidate)
    repaired["type"] = "batch"
    repaired["actions"] = normalized
    if len(candidate.get("actions", [])) != len(normalized):
        repaired["why"] = str(candidate.get("why") or "batch normalized to supported actions")
    return repaired


def log_run_event(event_type: str, payload: dict[str, Any]) -> None:
    entry = {
        "time": utc_now(),
        "event": event_type,
        "payload": payload,
    }
    try:
        with RUN_LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except OSError:
        # Logging should never break an agent turn, CLI command, parser repair,
        # or self-test. The workspace can be read-only in validation sandboxes.
        return


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
    conversation_history: list[dict[str, str]] = field(default_factory=list)
    consecutive_failures: int = 0
    turns_completed: int = 0

    def record_conversation_turn(self, user_input: str, assistant_output: str) -> None:
        self.conversation_history.append({"role": "user", "content": trim_text(user_input, 1200)})
        self.conversation_history.append({"role": "assistant", "content": trim_text(assistant_output, 1800)})
        self.conversation_history = self.conversation_history[-CONVERSATION_HISTORY_LIMIT:]

    def recent_conversation_messages(self) -> list[dict[str, str]]:
        return [dict(item) for item in self.conversation_history[-CONVERSATION_HISTORY_LIMIT:]]

    def record_tool_event(self, tool_name: str, args: dict[str, Any], result: ToolResult) -> None:
        self.consecutive_failures = 0 if result.ok else self.consecutive_failures + 1
        history_args = redact_sensitive_payload(args)
        if tool_name == "encrypt_text" and isinstance(history_args, dict) and "data" in history_args:
            history_args["data"] = "<redacted plaintext input>"
        self.tool_history.append(
            {
                "time": utc_now(),
                "tool": tool_name,
                "args": history_args,
                "ok": result.ok,
                "preview": "<redacted sensitive output>" if tool_name in SENSITIVE_OUTPUT_TOOL_NAMES else redact_sensitive_text(trim_text(result.content, 400)),
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
        conversation_text = "\n".join(
            f"- {item.get('role', 'unknown')}: {trim_text(item.get('content', ''), 180)}"
            for item in self.conversation_history[-4:]
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
            f"Recent autonomous runs:\n{auto_text}\n\n"
            f"Recent conversation:\n{conversation_text}"
        )


def _control_server_log(event_type: str, payload: dict[str, Any]) -> None:
    entry = {"time": utc_now(), "event": event_type, **payload}
    try:
        CONTROL_SERVER_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with CONTROL_SERVER_LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        pass
    log_run_event(f"control_server_{event_type}", payload)


def _control_server_safe_host(host: str) -> bool:
    cleaned = (host or "").strip().lower()
    if cleaned in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def _control_server_command_is_allowed(command_type: str, allowed: set[str] | None = None) -> bool:
    cleaned = str(command_type or "").strip().lower()
    if not cleaned:
        return False
    denied = {item.lower() for item in CONTROL_SERVER_DENIED_COMMAND_TYPES}
    if cleaned in denied:
        return False
    suspicious_fragments = {
        "shell",
        "exec",
        "payload",
        "persist",
        "exfil",
        "download",
        "upload",
        "keylog",
        "screenshot",
    }
    if any(fragment in cleaned for fragment in suspicious_fragments):
        return False
    allowed_set = {item.lower() for item in (allowed or CONTROL_SERVER_ALLOWED_COMMAND_TYPES)}
    return cleaned in allowed_set


def _json_dumps_line(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def _safe_client_id(value: str, fallback: str = "") -> str:
    candidate = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(value or "").strip())[:80].strip("._-:")
    return candidate or fallback or f"client-{uuid.uuid4().hex[:8]}"


class AgentControlServer:
    """Threaded local control plane for trusted agent clients.

    Protocol:
    1. Client sends one JSON line:
       {"type":"hello","client_id":"worker-1","token":"...","capabilities":["status"]}
    2. Server replies with a JSON-line welcome or error.
    3. Server may route allow-listed command envelopes to selected clients.
    4. Clients may reply with heartbeat, ack, status, or result JSON lines.

    This class deliberately routes high-level coordination messages only. It is
    not a remote shell, payload loader, persistence layer, or exfiltration path.
    """

    def __init__(
        self,
        host: str = CONTROL_SERVER_DEFAULT_HOST,
        port: int = CONTROL_SERVER_DEFAULT_PORT,
        *,
        token: str = "",
        require_token: bool = True,
        max_clients: int = 16,
        max_message_bytes: int = CONTROL_SERVER_MAX_PAYLOAD_BYTES,
        allowed_command_types: list[str] | None = None,
    ):
        self.host = host or CONTROL_SERVER_DEFAULT_HOST
        self.port = max(1, min(int(port or CONTROL_SERVER_DEFAULT_PORT), 65535))
        self.token = token
        self.require_token = bool(require_token)
        self.max_clients = max(1, min(int(max_clients), 128))
        self.max_message_bytes = max(1024, min(int(max_message_bytes), 1048576))
        self.allowed_command_types = {
            str(item).strip().lower()
            for item in (allowed_command_types or sorted(CONTROL_SERVER_ALLOWED_COMMAND_TYPES))
            if str(item).strip()
        }
        self.clients: dict[str, dict[str, Any]] = {}
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.started_at = ""
        self.last_error = ""

    def start(self) -> dict[str, Any]:
        with self.lock:
            if self.thread and self.thread.is_alive():
                return self.status()
            if not _control_server_safe_host(self.host):
                raise ValueError("Refusing to bind the control server to a non-loopback host without an explicit authorization gate.")
            self.stop_event.clear()
            listener = socket.socket(socket.AF_INET6 if ":" in self.host else socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self.port))
            listener.listen(self.max_clients)
            listener.settimeout(0.5)
            self.listener = listener
            self.port = int(listener.getsockname()[1])
            self.started_at = utc_now()
            self.thread = threading.Thread(target=self.listen_for_connections, name="cerebro-control-server", daemon=True)
            self.thread.start()
        _control_server_log("started", {"host": self.host, "port": self.port, "require_token": self.require_token})
        return self.status()

    def stop(self) -> dict[str, Any]:
        self.stop_event.set()
        with self.lock:
            listener = self.listener
            self.listener = None
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
            for client_id, record in list(self.clients.items()):
                sock = record.get("socket")
                try:
                    if sock is not None:
                        sock.close()
                except OSError:
                    pass
                self.clients.pop(client_id, None)
        _control_server_log("stopped", {"host": self.host, "port": self.port})
        return self.status()

    def listen_for_connections(self) -> None:
        while not self.stop_event.is_set():
            listener = self.listener
            if listener is None:
                break
            try:
                client_socket, address = listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop_event.is_set():
                    self.last_error = str(exc)
                    _control_server_log("accept_error", {"error": trim_text(str(exc), 500)})
                break

            with self.lock:
                too_many_clients = len(self.clients) >= self.max_clients
            if too_many_clients:
                self._send_error_and_close(client_socket, "server_full")
                continue

            provisional_id = f"pending-{uuid.uuid4().hex[:8]}"
            thread = threading.Thread(
                target=self.handle_client_connection,
                args=(provisional_id, client_socket, address),
                name=f"cerebro-client-{provisional_id}",
                daemon=True,
            )
            thread.start()

    def handle_client_connection(self, client_id: str, client_socket: socket.socket, address: Any = None) -> None:
        active_id = _safe_client_id(client_id)
        try:
            client_socket.settimeout(45)
            hello = self._recv_json_line(client_socket)
            if not isinstance(hello, dict) or hello.get("type") != "hello":
                self._send_error_and_close(client_socket, "expected_hello")
                return

            supplied_token = str(hello.get("token", ""))
            if self.require_token and not hmac.compare_digest(supplied_token, self.token):
                self._send_error_and_close(client_socket, "auth_failed")
                _control_server_log("auth_failed", {"address": repr(address)})
                return

            requested_id = _safe_client_id(str(hello.get("client_id", "")), fallback=active_id)
            capabilities = [
                str(item)[:80]
                for item in hello.get("capabilities", [])
                if isinstance(item, (str, int, float)) and str(item).strip()
            ][:40]

            with self.lock:
                active_id = requested_id
                if active_id in self.clients:
                    active_id = f"{active_id}-{uuid.uuid4().hex[:6]}"
                self.clients[active_id] = {
                    "socket": client_socket,
                    "address": repr(address),
                    "connected_at": utc_now(),
                    "last_seen": utc_now(),
                    "capabilities": capabilities,
                    "authenticated": True,
                    "received": 1,
                    "sent": 0,
                    "last_message": {"type": "hello"},
                }

            self._send_json(
                client_socket,
                {
                    "type": "welcome",
                    "client_id": active_id,
                    "server_time": utc_now(),
                    "allowed_command_types": sorted(self.allowed_command_types),
                },
            )
            _control_server_log("client_connected", {"client_id": active_id, "address": repr(address), "capabilities": capabilities})

            while not self.stop_event.is_set():
                message = self._recv_json_line(client_socket)
                if message is None:
                    break
                if not isinstance(message, dict):
                    self._send_json(client_socket, {"type": "error", "error": "message_must_be_json_object"})
                    continue
                message_type = str(message.get("type", "")).strip().lower()
                if message_type not in {"heartbeat", "ack", "status", "result", "error"}:
                    self._send_json(client_socket, {"type": "error", "error": "unsupported_client_message_type"})
                    continue
                with self.lock:
                    record = self.clients.get(active_id)
                    if record is not None:
                        record["last_seen"] = utc_now()
                        record["received"] = int(record.get("received", 0)) + 1
                        record["last_message"] = {
                            "type": message_type,
                            "message_id": message.get("message_id", ""),
                            "ok": message.get("ok", None),
                            "preview": trim_text(json.dumps(message, sort_keys=True), 500),
                        }
                if message_type == "heartbeat":
                    self._send_json(client_socket, {"type": "heartbeat_ack", "server_time": utc_now()})
        except Exception as exc:
            self.last_error = trim_text(str(exc), 500)
            _control_server_log("client_error", {"client_id": active_id, "error": self.last_error})
        finally:
            with self.lock:
                self.clients.pop(active_id, None)
            try:
                client_socket.close()
            except OSError:
                pass
            _control_server_log("client_disconnected", {"client_id": active_id})

    def route_command_to_clients(
        self,
        command_type: str,
        payload: dict[str, Any] | None,
        target_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        cleaned_command = str(command_type or "").strip().lower()
        if not _control_server_command_is_allowed(cleaned_command, self.allowed_command_types):
            raise ValueError(
                f"Refusing unsafe or unsupported command_type {command_type!r}. "
                f"Allowed types: {', '.join(sorted(self.allowed_command_types))}"
            )
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object/dict")
        serialized_payload = json.dumps(payload, sort_keys=True, default=str)
        if len(serialized_payload.encode("utf-8")) > self.max_message_bytes:
            raise ValueError(f"payload exceeds max_message_bytes={self.max_message_bytes}")

        target_filter = {_safe_client_id(item) for item in target_ids or [] if str(item).strip()}
        with self.lock:
            candidate_items = [
                (client_id, record)
                for client_id, record in self.clients.items()
                if not target_filter or client_id in target_filter
            ]

        message_id = uuid.uuid4().hex
        envelope = {
            "type": "command",
            "message_id": message_id,
            "command_type": cleaned_command,
            "payload": payload,
            "server_time": utc_now(),
        }
        delivered: list[str] = []
        failed: list[dict[str, str]] = []
        for client_id, record in candidate_items:
            sock = record.get("socket")
            if sock is None:
                failed.append({"client_id": client_id, "error": "missing_socket"})
                continue
            try:
                self._send_json(sock, envelope)
                delivered.append(client_id)
                with self.lock:
                    current = self.clients.get(client_id)
                    if current is not None:
                        current["sent"] = int(current.get("sent", 0)) + 1
                        current["last_sent"] = {"message_id": message_id, "command_type": cleaned_command}
            except OSError as exc:
                failed.append({"client_id": client_id, "error": trim_text(str(exc), 200)})

        result = {
            "ok": not failed,
            "message_id": message_id,
            "command_type": cleaned_command,
            "target_count": len(candidate_items),
            "delivered": delivered,
            "failed": failed,
        }
        _control_server_log("command_routed", {k: v for k, v in result.items() if k != "failed"} | {"failed_count": len(failed)})
        return result

    def status(self) -> dict[str, Any]:
        with self.lock:
            clients = {
                client_id: {
                    key: value
                    for key, value in record.items()
                    if key not in {"socket"}
                }
                for client_id, record in sorted(self.clients.items())
            }
            running = bool(self.thread and self.thread.is_alive() and self.listener is not None)
        return {
            "running": running,
            "host": self.host,
            "port": self.port,
            "started_at": self.started_at,
            "require_token": self.require_token,
            "max_clients": self.max_clients,
            "max_message_bytes": self.max_message_bytes,
            "allowed_command_types": sorted(self.allowed_command_types),
            "client_count": len(clients),
            "clients": clients,
            "last_error": self.last_error,
            "log_file": workspace_relative(CONTROL_SERVER_LOG_FILE),
        }

    def _recv_json_line(self, client_socket: socket.socket) -> Any:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = client_socket.recv(1)
            if not chunk:
                return None
            if chunk == b"\n":
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > self.max_message_bytes:
                raise ValueError(f"message exceeds max_message_bytes={self.max_message_bytes}")
        raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
        if not raw:
            return None
        return json.loads(raw)

    def _send_json(self, client_socket: socket.socket, payload: dict[str, Any]) -> None:
        client_socket.sendall(_json_dumps_line(payload))

    def _send_error_and_close(self, client_socket: socket.socket, error: str) -> None:
        try:
            self._send_json(client_socket, {"type": "error", "error": error, "server_time": utc_now()})
        except OSError:
            pass
        try:
            client_socket.close()
        except OSError:
            pass


CONTROL_SERVER: AgentControlServer | None = None
CONTROL_SERVER_LOCK = threading.RLock()


def control_server_config_from_agent_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or load_config()
    parsed = config.get("control_server", {})
    if not isinstance(parsed, dict):
        parsed = {}
    defaults = default_control_server_config()
    merged = defaults | parsed
    allowed = merged.get("allowed_command_types", sorted(CONTROL_SERVER_ALLOWED_COMMAND_TYPES))
    if not isinstance(allowed, list):
        allowed = sorted(CONTROL_SERVER_ALLOWED_COMMAND_TYPES)
    merged["allowed_command_types"] = [
        str(item).strip().lower()
        for item in allowed
        if str(item).strip() and _control_server_command_is_allowed(str(item).strip(), set(allowed))
    ]
    if not merged["allowed_command_types"]:
        merged["allowed_command_types"] = sorted(CONTROL_SERVER_ALLOWED_COMMAND_TYPES)
    return merged


def ensure_control_server_token(config: dict[str, Any] | None = None) -> str:
    server_config = control_server_config_from_agent_config(config)
    env_name = str(server_config.get("token_env", "CEREBRO_CONTROL_TOKEN")).strip()
    if env_name and os.environ.get(env_name):
        return str(os.environ[env_name])

    token_path_value = str(server_config.get("token_file", ".agent_control_server_token")).strip() or ".agent_control_server_token"
    token_path = resolve_workspace_path(token_path_value)
    if token_path.exists():
        try:
            token = token_path.read_text(encoding="utf-8").strip()
            if token:
                return token
        except OSError:
            pass

    token = secrets.token_urlsafe(32)
    try:
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(token + "\n", encoding="utf-8")
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            pass
    except OSError:
        # Last-resort in-memory token. The server can still run for this process.
        pass
    return token


def listen_for_connections(
    host: str = "",
    port: int = 0,
    token: str = "",
    authorized: bool = False,
) -> dict[str, Any]:
    """Start the safe local control server and listen for authenticated clients."""
    global CONTROL_SERVER
    config = load_config()
    server_config = control_server_config_from_agent_config(config)
    bind_host = host or str(server_config.get("bind_host") or CONTROL_SERVER_DEFAULT_HOST)
    bind_port = int(port or server_config.get("port") or CONTROL_SERVER_DEFAULT_PORT)
    if not _control_server_safe_host(bind_host) and not authorized:
        return {
            "ok": False,
            "error": "Refusing non-loopback bind without authorized=True.",
            "host": bind_host,
            "port": bind_port,
        }

    require_token = bool(server_config.get("require_token", True))
    resolved_token = token or (ensure_control_server_token(config) if require_token else "")

    with CONTROL_SERVER_LOCK:
        if CONTROL_SERVER and CONTROL_SERVER.status().get("running"):
            return {"ok": True, **CONTROL_SERVER.status()}
        CONTROL_SERVER = AgentControlServer(
            host=bind_host,
            port=bind_port,
            token=resolved_token,
            require_token=require_token,
            max_clients=int(server_config.get("max_clients", 16)),
            max_message_bytes=int(server_config.get("max_message_bytes", CONTROL_SERVER_MAX_PAYLOAD_BYTES)),
            allowed_command_types=list(server_config.get("allowed_command_types", sorted(CONTROL_SERVER_ALLOWED_COMMAND_TYPES))),
        )
        status = CONTROL_SERVER.start()
    return {"ok": True, **status, "token_hint": "Set CEREBRO_CONTROL_TOKEN or read .agent_control_server_token on this trusted host."}


def handle_client_connection(client_id: str, socket: socket.socket) -> dict[str, Any]:
    """Delegate one accepted client socket to the active control server."""
    with CONTROL_SERVER_LOCK:
        server = CONTROL_SERVER
    if server is None:
        return {"ok": False, "error": "control server is not running"}
    thread = threading.Thread(
        target=server.handle_client_connection,
        args=(_safe_client_id(client_id), socket, "manual"),
        daemon=True,
        name=f"cerebro-client-{_safe_client_id(client_id)}",
    )
    thread.start()
    return {"ok": True, "client_id": _safe_client_id(client_id)}


def route_command_to_clients(
    command_type: str,
    payload: dict[str, Any] | None,
    target_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Route one allow-listed coordination command to connected clients."""
    with CONTROL_SERVER_LOCK:
        server = CONTROL_SERVER
    if server is None or not server.status().get("running"):
        return {"ok": False, "error": "control server is not running"}
    return {"ok": True, **server.route_command_to_clients(command_type, payload or {}, target_ids)}


def stop_control_server() -> dict[str, Any]:
    global CONTROL_SERVER
    with CONTROL_SERVER_LOCK:
        server = CONTROL_SERVER
        if server is None:
            return {"ok": True, "running": False, "message": "control server was not running"}
        status = server.stop()
        CONTROL_SERVER = None
    return {"ok": True, **status}


def control_server_status() -> dict[str, Any]:
    with CONTROL_SERVER_LOCK:
        server = CONTROL_SERVER
    if server is None:
        return {
            "ok": True,
            "running": False,
            "host": CONTROL_SERVER_DEFAULT_HOST,
            "port": CONTROL_SERVER_DEFAULT_PORT,
            "client_count": 0,
            "clients": {},
        }
    return {"ok": True, **server.status()}



def build_tool_feedback(executed: list[tuple[str, ToolResult]], state: AgentState) -> str:
    sections = []
    for tool_name, result in executed:
        sections.append(f"Tool result for {tool_name}:\n{result.render()}")
    sections.append(f"Updated state:\n{state.context_summary()}")
    return "\n\n".join(sections)


NETWORK_INFORMATION_TOOLS = {
    "normalize_network_target",
    "resolve_dns_records",
    "reverse_dns_lookup",
    "lookup_ip_rdap",
    "lookup_ip_geolocation",
    "get_public_ip_info",
    "scan_tcp_ports",
    "inspect_local_listening_ports",
    "inspect_tls_certificate",
    "inspect_local_network",
    "build_network_intel_brief",
    "ingest_network_traffic_file",
    "analyze_network_traffic_file",
    "build_ids_baseline",
    "compare_network_baseline",
    "capture_network_metadata_sample",
    "build_ids_mode_plan",
    "show_ids_alerts",
}

THREAT_INTEL_TOOLS = {
    "lookup_cve",
    "search_cves",
    "check_cisa_kev",
    "lookup_malware_hash",
    "hash_workspace_file",
    "add_malware_signature",
    "scan_workspace_file_signatures",
    "build_threat_intel_brief",
}

NETWORK_QUERY_KEYWORDS = {
    "ip",
    "ip address",
    "public ip",
    "external ip",
    "wan ip",
    "geolocation",
    "geoip",
    "asn",
    "isp",
    "rdap",
    "whois",
    "dns",
    "reverse dns",
    "ptr",
    "open port",
    "open ports",
    "ports are open",
    "listening ports",
    "listening services",
    "netstat",
    "port scan",
    "tls",
    "certificate",
    "local network",
    "network info",
    "network traffic",
    "traffic capture",
    "packet capture",
    "packets",
    "pcap",
    "pcapng",
    "ids",
    "intrusion detection",
    "suricata",
    "zeek",
    "eve.json",
    "network flows",
    "flow logs",
    "beacon",
    "anomaly",
}


def _looks_like_network_information_request(user_input: str) -> bool:
    text = re.sub(r"\s+", " ", str(user_input or "").lower()).strip()
    if not text:
        return False
    return any(keyword in text for keyword in NETWORK_QUERY_KEYWORDS)


THREAT_INTEL_QUERY_KEYWORDS = {
    "cve",
    "cves",
    "cvss",
    "critical vulnerability",
    "critical vulnerabilities",
    "vulnerability",
    "vulnerabilities",
    "kev",
    "known exploited",
    "cisa kev",
    "malware",
    "malware signature",
    "malware signatures",
    "yara",
    "ioc",
    "indicator",
    "hash",
    "hash lookup",
    "threat intel",
    "threat intelligence",
    "malwarebazaar",
}


def _looks_like_threat_intel_request(user_input: str) -> bool:
    text = re.sub(r"\s+", " ", str(user_input or "").lower()).strip()
    if not text:
        return False
    return any(keyword in text for keyword in THREAT_INTEL_QUERY_KEYWORDS) or bool(re.search(r"CVE-\d{4}-\d{4,}", text, re.I)) or bool(re.search(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", text))


def _safe_join(values: Any, limit: int = 6) -> str:
    if not isinstance(values, list):
        return ""
    cleaned = [str(item) for item in values if str(item).strip()]
    if not cleaned:
        return ""
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + [f"+{len(values) - limit} more"]
    return ", ".join(cleaned)


def _network_payload(result: ToolResult) -> dict[str, Any]:
    if isinstance(result.meta, dict) and result.meta:
        return result.meta
    try:
        parsed = json.loads(result.content)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
HASH_PATTERN = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"


def _normalize_cve_id(value: str) -> str:
    candidate = str(value or "").strip().upper()
    candidate = candidate.replace(" ", "")
    return candidate


def _is_cve_id(value: str) -> bool:
    return bool(CVE_ID_PATTERN.match(_normalize_cve_id(value)))


def _is_hash_indicator(value: str) -> bool:
    return bool(HASH_PATTERN.match(str(value or "").strip()))


def _hash_algorithm_for_value(value: str) -> str:
    length = len(str(value or "").strip())
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(length, "unknown")


def _threat_cache_read() -> dict[str, Any]:
    if not THREAT_INTEL_CACHE_FILE.exists():
        return {"schema_version": 1, "updated_at": "", "cisa_kev": {}, "nvd": {}, "malware_hashes": {}}
    try:
        parsed = json.loads(THREAT_INTEL_CACHE_FILE.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {"schema_version": 1, "updated_at": "", "cisa_kev": {}, "nvd": {}, "malware_hashes": {}}
    if not isinstance(parsed, dict):
        return {"schema_version": 1, "updated_at": "", "cisa_kev": {}, "nvd": {}, "malware_hashes": {}}
    parsed.setdefault("schema_version", 1)
    parsed.setdefault("cisa_kev", {})
    parsed.setdefault("nvd", {})
    parsed.setdefault("malware_hashes", {})
    return parsed


def _threat_cache_write(cache: dict[str, Any]) -> None:
    cache = dict(cache)
    cache["updated_at"] = utc_now()
    try:
        THREAT_INTEL_CACHE_FILE.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        return


def _load_cisa_kev_catalog(*, refresh: bool = False, timeout: int = 12) -> tuple[dict[str, Any], list[str]]:
    cache = _threat_cache_read()
    warnings: list[str] = []
    cached = cache.get("cisa_kev") if isinstance(cache.get("cisa_kev"), dict) else {}
    if cached and not refresh:
        return cached, warnings
    headers = {"User-Agent": "Cerebro-Agent/1.0", "Accept": "application/json"}
    for url in CISA_KEV_URLS:
        try:
            payload = http_get_json(url, headers=headers, timeout=timeout)
        except Exception as exc:
            warnings.append(f"KEV fetch failed from {url}: {trim_text(str(exc), 300)}")
            continue
        if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
            payload["source_url"] = url
            payload["fetched_at"] = utc_now()
            cache["cisa_kev"] = payload
            _threat_cache_write(cache)
            return payload, warnings
        warnings.append(f"KEV fetch from {url} did not return expected catalog shape.")
    if cached:
        warnings.append("Using cached KEV catalog because live refresh failed.")
        return cached, warnings
    return {"vulnerabilities": []}, warnings


def _kev_index(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = catalog.get("vulnerabilities") if isinstance(catalog, dict) else []
    if not isinstance(rows, list):
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for item in rows:
        if not isinstance(item, dict):
            continue
        cve_id = _normalize_cve_id(str(item.get("cveID") or item.get("cve_id") or item.get("cve") or ""))
        if cve_id:
            indexed[cve_id] = item
    return indexed


def _nvd_headers() -> dict[str, str]:
    headers = {"User-Agent": "Cerebro-Agent/1.0", "Accept": "application/json"}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _nvd_get(params: dict[str, Any], *, timeout: int = 15) -> dict[str, Any]:
    clean_params = {str(k): v for k, v in params.items() if v not in (None, "", [])}
    query = urllib.parse.urlencode(clean_params, doseq=True)
    url = NVD_CVE_API_URL + (f"?{query}" if query else "")
    payload = http_get_json(url, headers=_nvd_headers(), timeout=timeout)
    if not isinstance(payload, dict):
        raise ValueError("NVD returned a non-object JSON payload.")
    return payload


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") if isinstance(cve, dict) else []
    if isinstance(descriptions, list):
        for item in descriptions:
            if isinstance(item, dict) and str(item.get("lang", "")).lower() == "en":
                return str(item.get("value") or "")
        for item in descriptions:
            if isinstance(item, dict) and item.get("value"):
                return str(item.get("value"))
    return ""


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    priority = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for key in priority:
        rows = metrics.get(key)
        if not isinstance(rows, list) or not rows:
            continue
        selected = rows[0] if isinstance(rows[0], dict) else {}
        cvss_data = selected.get("cvssData") if isinstance(selected.get("cvssData"), dict) else {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or selected.get("baseSeverity")
        vector = cvss_data.get("vectorString")
        if score is not None or severity or vector:
            return {
                "metric": key,
                "base_score": score,
                "base_severity": severity,
                "vector": vector,
                "exploitability_score": selected.get("exploitabilityScore"),
                "impact_score": selected.get("impactScore"),
                "source": selected.get("source"),
                "type": selected.get("type"),
            }
    return {}


def _extract_weaknesses(cve: dict[str, Any]) -> list[str]:
    weaknesses: list[str] = []
    for weakness in cve.get("weaknesses", []) if isinstance(cve.get("weaknesses"), list) else []:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description", []) if isinstance(weakness.get("description"), list) else []:
            if isinstance(desc, dict) and desc.get("value"):
                value = str(desc.get("value"))
                if value not in weaknesses:
                    weaknesses.append(value)
    return weaknesses[:20]


def _extract_cpes_from_nodes(nodes: Any, out: set[str]) -> None:
    if not isinstance(nodes, list):
        return
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for match in node.get("cpeMatch", []) if isinstance(node.get("cpeMatch"), list) else []:
            if isinstance(match, dict):
                criteria = str(match.get("criteria") or match.get("cpe23Uri") or "")
                if criteria:
                    out.add(criteria)
        _extract_cpes_from_nodes(node.get("children"), out)


def _extract_cpes(cve: dict[str, Any]) -> list[str]:
    cpes: set[str] = set()
    for config in cve.get("configurations", []) if isinstance(cve.get("configurations"), list) else []:
        if isinstance(config, dict):
            _extract_cpes_from_nodes(config.get("nodes"), cpes)
    return sorted(cpes)[:80]


def _normalize_nvd_vulnerability(item: dict[str, Any], kev: dict[str, Any] | None = None) -> dict[str, Any]:
    cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
    cve_id = _normalize_cve_id(str(cve.get("id") or cve.get("cveId") or ""))
    references = []
    for ref in cve.get("references", []) if isinstance(cve.get("references"), list) else []:
        if not isinstance(ref, dict):
            continue
        references.append({
            "url": ref.get("url"),
            "source": ref.get("source"),
            "tags": ref.get("tags") if isinstance(ref.get("tags"), list) else [],
        })
    return {
        "cve_id": cve_id,
        "source_identifier": cve.get("sourceIdentifier"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": _english_description(cve),
        "cvss": _extract_cvss(cve),
        "weaknesses": _extract_weaknesses(cve),
        "affected_cpes": _extract_cpes(cve),
        "reference_count": len(references),
        "references": references[:12],
        "kev": kev or None,
        "is_known_exploited": bool(kev),
    }


def _default_malware_signatures() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "updated_at": utc_now(),
        "signatures": [
            {
                "name": "EICAR Antivirus Test String",
                "signature_type": "string",
                "pattern": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                "severity": "test",
                "tags": ["eicar", "test-file", "antivirus-validation"],
                "description": "Benign EICAR test string used to validate malware-detection pipelines.",
                "source": "built-in",
                "created_at": utc_now(),
            },
            {
                "name": "Suspicious PowerShell Download Cradle",
                "signature_type": "regex",
                "pattern": r"(?i)(powershell|pwsh).{0,160}(downloadstring|downloadfile|invoke-webrequest|iwr|webclient)",
                "severity": "medium",
                "tags": ["powershell", "download-cradle", "script"],
                "description": "Detects common suspicious PowerShell web-download patterns in scripts/logs. This is heuristic and can false-positive.",
                "source": "built-in",
                "created_at": utc_now(),
            },
        ],
    }


def _load_malware_signatures(signature_path: str = "") -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    target = resolve_workspace_path(signature_path) if signature_path else MALWARE_SIGNATURES_FILE
    if not target.exists():
        catalog = _default_malware_signatures()
        if not signature_path:
            try:
                target.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")
            except OSError as exc:
                warnings.append(f"Could not initialize default signature file: {exc}")
        return catalog, warnings
    try:
        parsed = json.loads(target.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as exc:
        return _default_malware_signatures(), [f"Could not parse signature file {workspace_relative(target)}: {exc}; using built-ins."]
    if isinstance(parsed, list):
        parsed = {"schema_version": 1, "updated_at": "", "signatures": parsed}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("signatures"), list):
        return _default_malware_signatures(), [f"Signature file {workspace_relative(target)} has unsupported shape; using built-ins."]
    return parsed, warnings


def _save_malware_signatures(catalog: dict[str, Any], signature_path: str = "") -> Path:
    target = resolve_workspace_path(signature_path) if signature_path else MALWARE_SIGNATURES_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    catalog = dict(catalog)
    catalog["schema_version"] = int(catalog.get("schema_version", 1) or 1)
    catalog["updated_at"] = utc_now()
    if not isinstance(catalog.get("signatures"), list):
        catalog["signatures"] = []
    target.write_text(json.dumps(catalog, indent=2, sort_keys=True), encoding="utf-8")
    return target


def _file_hashes(path: Path) -> dict[str, str]:
    digesters = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}  # nosec: checksums are used as identifiers, not for trust decisions.
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for hasher in digesters.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in digesters.items()}


CRYPTO_ENVELOPE_PREFIX = "cerebro.crypto.v1:"
CRYPTO_DEFAULT_PBKDF2_ITERATIONS = 390_000
CRYPTO_MAX_FILE_BYTES_DEFAULT = 50 * 1024 * 1024
CRYPTO_SUPPORTED_ALGORITHMS = {
    "aesgcm": {
        "display": "AES-GCM",
        "requires": "cryptography",
        "authenticated": True,
        "recommended": True,
        "notes": "AEAD cipher; supports associated_data; derives a 256-bit key from passphrase by default.",
    },
    "chacha20poly1305": {
        "display": "ChaCha20-Poly1305",
        "requires": "cryptography",
        "authenticated": True,
        "recommended": True,
        "notes": "AEAD cipher; supports associated_data; derives a 256-bit key from passphrase by default.",
    },
    "fernet": {
        "display": "Fernet",
        "requires": "cryptography",
        "authenticated": True,
        "recommended": True,
        "notes": "High-level authenticated encryption token format; does not support associated_data.",
    },
    "xor_hmac_sha256": {
        "display": "XOR stream + HMAC-SHA256",
        "requires": "standard_library",
        "authenticated": True,
        "recommended": False,
        "notes": "Portable fallback for experimentation/offline use. Prefer AES-GCM or ChaCha20-Poly1305 for serious data protection.",
    },
}


def _crypto_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _crypto_b64decode(value: str) -> bytes:
    text = str(value or "").strip()
    if not text:
        return b""
    text = text.replace("\n", "").replace(" ", "")
    text += "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"Invalid base64 value: {exc}") from exc


def _crypto_normalize_algorithm(algorithm: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]", "", str(algorithm or "aesgcm").lower())
    aliases = {
        "aes": "aesgcm",
        "aes256": "aesgcm",
        "aes256gcm": "aesgcm",
        "aesgcm": "aesgcm",
        "chacha": "chacha20poly1305",
        "chacha20": "chacha20poly1305",
        "chacha20poly1305": "chacha20poly1305",
        "fernet": "fernet",
        "xor": "xor_hmac_sha256",
        "xorhmac": "xor_hmac_sha256",
        "xorhmacsha256": "xor_hmac_sha256",
    }
    normalized = aliases.get(cleaned, cleaned)
    if normalized not in CRYPTO_SUPPORTED_ALGORITHMS:
        supported = ", ".join(sorted(CRYPTO_SUPPORTED_ALGORITHMS))
        raise ValueError(f"Unsupported algorithm `{algorithm}`. Supported algorithms: {supported}.")
    return normalized


def _crypto_optional_primitives() -> tuple[dict[str, Any], str]:
    try:
        from cryptography.fernet import Fernet  # type: ignore
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305  # type: ignore
    except Exception as exc:
        return {}, str(exc)
    return {"AESGCM": AESGCM, "ChaCha20Poly1305": ChaCha20Poly1305, "Fernet": Fernet}, ""


def _crypto_availability() -> dict[str, Any]:
    primitives, error = _crypto_optional_primitives()
    algorithms: dict[str, Any] = {}
    for name, spec in CRYPTO_SUPPORTED_ALGORITHMS.items():
        requires = spec["requires"]
        available = requires == "standard_library" or bool(primitives)
        algorithms[name] = dict(spec) | {"available": available}
        if requires == "cryptography" and not available:
            algorithms[name]["unavailable_reason"] = "Install the optional `cryptography` package to enable this algorithm." if not error else f"cryptography import failed: {error}"
    return {
        "schema_version": 1,
        "default_algorithm": "aesgcm" if primitives else "xor_hmac_sha256",
        "cryptography_available": bool(primitives),
        "algorithms": algorithms,
        "formats": {
            "input": ["text", "base64", "hex"],
            "decrypted_output": ["text", "base64", "hex"],
            "encrypted_output": "armored envelope string prefixed with cerebro.crypto.v1:",
        },
        "keying": {
            "passphrase": "PBKDF2-HMAC-SHA256 with per-message random 128-bit salt.",
            "key_b64": "Raw URL-safe base64 key material. Do not paste long-term keys into prompts unless you accept local logging risk.",
        },
        "security_notes": [
            "AES-GCM and ChaCha20-Poly1305 are preferred when cryptography is installed.",
            "Fernet is a safe high-level option but does not support associated data.",
            "xor_hmac_sha256 is authenticated but is a fallback, not a modern AEAD replacement.",
            "The agent redacts passphrases/key_b64 values from tool-history arguments.",
        ],
    }


def _crypto_bytes_from_input(data: str, input_format: str = "text") -> bytes:
    fmt = str(input_format or "text").lower().strip()
    if fmt in {"text", "utf8", "utf-8"}:
        return str(data or "").encode("utf-8")
    if fmt in {"base64", "b64"}:
        return _crypto_b64decode(str(data or ""))
    if fmt == "hex":
        cleaned = re.sub(r"[^0-9a-fA-F]", "", str(data or ""))
        if len(cleaned) % 2:
            raise ValueError("Hex input has an odd number of digits.")
        return bytes.fromhex(cleaned)
    raise ValueError("input_format must be one of text, base64, or hex.")


def _crypto_bytes_to_output(data: bytes, output_format: str = "text") -> tuple[str, str]:
    fmt = str(output_format or "text").lower().strip()
    if fmt in {"text", "utf8", "utf-8"}:
        try:
            return data.decode("utf-8"), "text"
        except UnicodeDecodeError:
            return _crypto_b64encode(data), "base64"
    if fmt in {"base64", "b64"}:
        return _crypto_b64encode(data), "base64"
    if fmt == "hex":
        return data.hex(), "hex"
    raise ValueError("output_format must be one of text, base64, or hex.")


def _crypto_resolve_key(
    *,
    algorithm: str,
    passphrase: str = "",
    key_b64: str = "",
    salt: bytes = b"",
    iterations: int = CRYPTO_DEFAULT_PBKDF2_ITERATIONS,
) -> tuple[bytes, dict[str, Any]]:
    passphrase_text = str(passphrase or "")
    key_text = str(key_b64 or "").strip()
    if bool(passphrase_text) == bool(key_text):
        raise ValueError("Provide exactly one of passphrase or key_b64.")
    if passphrase_text:
        if not salt:
            raise ValueError("PBKDF2 salt is required when using a passphrase.")
        iterations = max(100_000, min(int(iterations or CRYPTO_DEFAULT_PBKDF2_ITERATIONS), 2_000_000))
        key = hashlib.pbkdf2_hmac("sha256", passphrase_text.encode("utf-8"), salt, iterations, dklen=32)
        return key, {"kdf": "pbkdf2_hmac_sha256", "iterations": iterations, "salt": _crypto_b64encode(salt)}

    key = _crypto_b64decode(key_text)
    if algorithm == "aesgcm" and len(key) not in {16, 24, 32}:
        raise ValueError("AES-GCM key_b64 must decode to 16, 24, or 32 bytes.")
    if algorithm in {"chacha20poly1305", "fernet", "xor_hmac_sha256"} and len(key) != 32:
        raise ValueError(f"{algorithm} key_b64 must decode to exactly 32 bytes.")
    return key, {"kdf": "raw_key_b64", "key_length_bytes": len(key)}


def _crypto_xor_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def _crypto_pack_envelope(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return CRYPTO_ENVELOPE_PREFIX + _crypto_b64encode(raw)


def _crypto_parse_envelope(envelope_text: str) -> dict[str, Any]:
    text = str(envelope_text or "").strip()
    if text.startswith(CRYPTO_ENVELOPE_PREFIX):
        raw = _crypto_b64decode(text[len(CRYPTO_ENVELOPE_PREFIX):])
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid crypto envelope JSON: {exc}") from exc
    else:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("Encrypted input must be a cerebro.crypto.v1 armored token or JSON envelope.") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Crypto envelope must decode to a JSON object.")
    if int(parsed.get("schema_version", 0) or 0) != 1:
        raise ValueError("Unsupported crypto envelope schema_version.")
    return parsed


def _crypto_encrypt_bytes(
    plaintext: bytes,
    *,
    algorithm: str = "aesgcm",
    passphrase: str = "",
    key_b64: str = "",
    associated_data: str = "",
    iterations: int = CRYPTO_DEFAULT_PBKDF2_ITERATIONS,
) -> tuple[str, dict[str, Any]]:
    normalized = _crypto_normalize_algorithm(algorithm)
    primitives, import_error = _crypto_optional_primitives()
    if CRYPTO_SUPPORTED_ALGORITHMS[normalized]["requires"] == "cryptography" and not primitives:
        raise RuntimeError(f"Algorithm `{normalized}` requires the optional `cryptography` package. Import error: {import_error}")
    salt = secrets.token_bytes(16) if passphrase else b""
    key, key_meta = _crypto_resolve_key(algorithm=normalized, passphrase=passphrase, key_b64=key_b64, salt=salt, iterations=iterations)
    aad = str(associated_data or "").encode("utf-8")
    payload: dict[str, Any] = {
        "schema_version": 1,
        "algorithm": normalized,
        "created_at": utc_now(),
        "plaintext_length": len(plaintext),
        "associated_data_sha256": hashlib.sha256(aad).hexdigest() if aad else "",
    } | key_meta

    if normalized == "aesgcm":
        nonce = secrets.token_bytes(12)
        ciphertext = primitives["AESGCM"](key).encrypt(nonce, plaintext, aad or None)
        payload |= {"nonce": _crypto_b64encode(nonce), "ciphertext": _crypto_b64encode(ciphertext)}
    elif normalized == "chacha20poly1305":
        nonce = secrets.token_bytes(12)
        ciphertext = primitives["ChaCha20Poly1305"](key).encrypt(nonce, plaintext, aad or None)
        payload |= {"nonce": _crypto_b64encode(nonce), "ciphertext": _crypto_b64encode(ciphertext)}
    elif normalized == "fernet":
        if aad:
            raise ValueError("Fernet does not support associated_data; use aesgcm or chacha20poly1305 when AAD is required.")
        fernet_key = base64.urlsafe_b64encode(key)
        token = primitives["Fernet"](fernet_key).encrypt(plaintext)
        payload |= {"token": token.decode("ascii")}
    elif normalized == "xor_hmac_sha256":
        nonce = secrets.token_bytes(16)
        stream = _crypto_xor_keystream(key, nonce, len(plaintext))
        ciphertext = bytes(left ^ right for left, right in zip(plaintext, stream))
        tag = hmac.new(key, b"cerebro-xor-hmac-sha256-v1" + nonce + aad + ciphertext, hashlib.sha256).digest()
        payload |= {"nonce": _crypto_b64encode(nonce), "ciphertext": _crypto_b64encode(ciphertext), "tag": _crypto_b64encode(tag)}
    else:
        raise ValueError(f"Unsupported algorithm: {normalized}")

    return _crypto_pack_envelope(payload), payload


def _crypto_decrypt_bytes(
    encrypted_text: str,
    *,
    passphrase: str = "",
    key_b64: str = "",
    associated_data: str = "",
) -> tuple[bytes, dict[str, Any]]:
    envelope = _crypto_parse_envelope(encrypted_text)
    normalized = _crypto_normalize_algorithm(str(envelope.get("algorithm") or ""))
    primitives, import_error = _crypto_optional_primitives()
    if CRYPTO_SUPPORTED_ALGORITHMS[normalized]["requires"] == "cryptography" and not primitives:
        raise RuntimeError(f"Algorithm `{normalized}` requires the optional `cryptography` package. Import error: {import_error}")
    kdf = str(envelope.get("kdf") or "")
    if kdf == "pbkdf2_hmac_sha256":
        if not passphrase:
            raise ValueError("This envelope was encrypted with a passphrase-derived key; passphrase is required.")
        salt = _crypto_b64decode(str(envelope.get("salt") or ""))
        iterations = int(envelope.get("iterations") or CRYPTO_DEFAULT_PBKDF2_ITERATIONS)
        key, _ = _crypto_resolve_key(algorithm=normalized, passphrase=passphrase, key_b64="", salt=salt, iterations=iterations)
    elif kdf == "raw_key_b64":
        if not key_b64:
            raise ValueError("This envelope was encrypted with raw key material; key_b64 is required.")
        key, _ = _crypto_resolve_key(algorithm=normalized, passphrase="", key_b64=key_b64, salt=b"")
    else:
        raise ValueError(f"Unsupported or missing kdf in envelope: {kdf!r}")

    aad = str(associated_data or "").encode("utf-8")
    expected_aad_hash = str(envelope.get("associated_data_sha256") or "")
    actual_aad_hash = hashlib.sha256(aad).hexdigest() if aad else ""
    if expected_aad_hash and expected_aad_hash != actual_aad_hash:
        raise ValueError("associated_data does not match this envelope.")

    if normalized == "aesgcm":
        nonce = _crypto_b64decode(str(envelope.get("nonce") or ""))
        ciphertext = _crypto_b64decode(str(envelope.get("ciphertext") or ""))
        plaintext = primitives["AESGCM"](key).decrypt(nonce, ciphertext, aad or None)
    elif normalized == "chacha20poly1305":
        nonce = _crypto_b64decode(str(envelope.get("nonce") or ""))
        ciphertext = _crypto_b64decode(str(envelope.get("ciphertext") or ""))
        plaintext = primitives["ChaCha20Poly1305"](key).decrypt(nonce, ciphertext, aad or None)
    elif normalized == "fernet":
        if aad:
            raise ValueError("Fernet envelopes do not accept associated_data.")
        token = str(envelope.get("token") or "").encode("ascii")
        plaintext = primitives["Fernet"](base64.urlsafe_b64encode(key)).decrypt(token)
    elif normalized == "xor_hmac_sha256":
        nonce = _crypto_b64decode(str(envelope.get("nonce") or ""))
        ciphertext = _crypto_b64decode(str(envelope.get("ciphertext") or ""))
        tag = _crypto_b64decode(str(envelope.get("tag") or ""))
        expected_tag = hmac.new(key, b"cerebro-xor-hmac-sha256-v1" + nonce + aad + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Ciphertext authentication failed; passphrase/key, AAD, or data may be wrong.")
        stream = _crypto_xor_keystream(key, nonce, len(ciphertext))
        plaintext = bytes(left ^ right for left, right in zip(ciphertext, stream))
    else:
        raise ValueError(f"Unsupported algorithm: {normalized}")

    meta = {
        "schema_version": envelope.get("schema_version"),
        "algorithm": normalized,
        "kdf": kdf,
        "plaintext_length": len(plaintext),
        "created_at": envelope.get("created_at"),
        "associated_data_used": bool(aad),
    }
    return plaintext, meta


def _default_encrypted_output_path(input_path: Path) -> Path:
    return input_path.with_name(input_path.name + ".cenc")


def _default_decrypted_output_path(input_path: Path) -> Path:
    name = input_path.name
    if name.endswith(".cenc"):
        return input_path.with_name(name[:-5] or "decrypted.bin")
    return input_path.with_name(name + ".decrypted")


def _scan_signature_against_bytes(signature: dict[str, Any], data: bytes, text: str, hashes: dict[str, str]) -> dict[str, Any] | None:
    name = str(signature.get("name") or "unnamed_signature")
    sig_type = str(signature.get("signature_type") or signature.get("type") or "string").lower().strip()
    pattern = str(signature.get("pattern") or "")
    if not pattern:
        return None
    evidence: dict[str, Any] = {"signature_type": sig_type}
    try:
        if sig_type in {"hash", "md5", "sha1", "sha256"}:
            expected = pattern.lower().strip()
            if expected in {value.lower() for value in hashes.values()}:
                evidence["hash_algorithm"] = _hash_algorithm_for_value(expected)
                evidence["hash"] = expected
            else:
                return None
        elif sig_type == "regex":
            match = re.search(pattern, text, flags=re.MULTILINE)
            if not match:
                return None
            evidence["offset"] = match.start()
            evidence["matched_preview"] = trim_text(match.group(0), 120)
        elif sig_type == "hex":
            hex_text = re.sub(r"[^0-9a-fA-F]", "", pattern)
            if len(hex_text) % 2:
                return None
            needle = bytes.fromhex(hex_text)
            offset = data.find(needle)
            if offset < 0:
                return None
            evidence["offset"] = offset
            evidence["byte_length"] = len(needle)
        elif sig_type == "string":
            offset = text.find(pattern)
            if offset < 0:
                return None
            evidence["offset"] = offset
            evidence["matched_preview"] = trim_text(pattern, 120)
        elif sig_type == "yara":
            try:
                import yara  # type: ignore
            except Exception as exc:
                return {"name": name, "matched": False, "warning": f"YARA signature skipped because yara-python is unavailable: {exc}"}
            try:
                rules = yara.compile(source=pattern)
                matches = rules.match(data=data)
            except Exception as exc:
                return {"name": name, "matched": False, "warning": f"YARA signature compile/match failed: {exc}"}
            if not matches:
                return None
            evidence["yara_matches"] = [str(match) for match in matches[:20]]
        else:
            return None
    except Exception as exc:
        return {"name": name, "matched": False, "warning": f"Signature scan error: {exc}"}
    return {
        "name": name,
        "matched": True,
        "severity": str(signature.get("severity") or "medium"),
        "tags": signature.get("tags") if isinstance(signature.get("tags"), list) else [],
        "description": signature.get("description", ""),
        "source": signature.get("source", ""),
        "evidence": evidence,
    }


IDS_SUSPICIOUS_PORTS: dict[int, str] = {
    21: "FTP cleartext service",
    23: "Telnet cleartext service",
    135: "Windows RPC exposure",
    139: "NetBIOS exposure",
    445: "SMB exposure",
    1433: "Microsoft SQL Server exposure",
    1521: "Oracle database exposure",
    3306: "MySQL exposure",
    3389: "Remote Desktop exposure",
    4444: "Common reverse-shell/metasploit listener port",
    5432: "PostgreSQL exposure",
    5900: "VNC exposure",
    6667: "IRC/C2-like port",
    6379: "Redis exposure",
    9200: "Elasticsearch exposure",
    11211: "Memcached exposure",
    2323: "Common IoT Telnet alternate port",
    31337: "Common backdoor-style port",
}


def _ids_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _ids_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, "", "-"):
            return default
        return int(float(str(value)))
    except (TypeError, ValueError):
        return default


def _ids_is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _ids_ip_scope(value: str) -> dict[str, Any]:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return {"valid": False, "scope": "unknown"}
    if ip.is_private:
        scope = "private"
    elif ip.is_loopback:
        scope = "loopback"
    elif ip.is_link_local:
        scope = "link_local"
    elif ip.is_multicast:
        scope = "multicast"
    elif ip.is_global:
        scope = "global"
    else:
        scope = "special"
    return {
        "valid": True,
        "version": ip.version,
        "scope": scope,
        "is_private": ip.is_private,
        "is_global": ip.is_global,
        "is_loopback": ip.is_loopback,
        "is_link_local": ip.is_link_local,
        "is_multicast": ip.is_multicast,
        "is_reserved": ip.is_reserved,
    }


def _ids_dns_entropy_like(query: str) -> float:
    lowered = re.sub(r"[^a-z0-9]", "", str(query or "").lower())
    if not lowered:
        return 0.0
    counts = collections.Counter(lowered)
    total = len(lowered)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * (0 if p <= 0 else __import__("math").log2(p))
    return round(entropy, 3)


def _ids_normalize_flow(raw: dict[str, Any], *, source: str = "unknown") -> dict[str, Any]:
    def pick(*keys: str) -> Any:
        for key in keys:
            if key in raw and raw.get(key) not in (None, "", "-"):
                return raw.get(key)
        return ""

    event_type = str(pick("event_type", "_path", "type", "kind") or "flow").lower()
    src_ip = str(pick("src_ip", "source.ip", "id.orig_h", "source_ip", "src", "saddr", "client_ip") or "")
    dst_ip = str(pick("dest_ip", "dst_ip", "destination.ip", "id.resp_h", "destination_ip", "dst", "daddr", "server_ip") or "")
    src_port = _ids_int(pick("src_port", "source.port", "id.orig_p", "sport", "source_port"), 0)
    dst_port = _ids_int(pick("dest_port", "dst_port", "destination.port", "id.resp_p", "dport", "destination_port"), 0)
    proto = str(pick("proto", "protocol", "trans_proto", "ip_proto") or "").upper()
    if not proto and dst_port:
        proto = "TCP/UDP"
    ts_raw = pick("timestamp", "ts", "@timestamp", "frame.time_epoch", "time")
    ts = _ids_float(ts_raw, 0.0)
    if not ts and isinstance(ts_raw, str):
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            ts = 0.0

    alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
    dns = raw.get("dns") if isinstance(raw.get("dns"), dict) else {}
    tls = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}
    http = raw.get("http") if isinstance(raw.get("http"), dict) else {}

    dns_query = str(pick("dns_query", "query") or dns.get("rrname") or dns.get("query") or "")
    tls_sni = str(pick("tls_sni", "server_name") or tls.get("sni") or tls.get("subject") or "")
    http_host = str(pick("http_host", "host") or http.get("hostname") or http.get("http_host") or "")

    flow = {
        "ts": ts,
        "source": source,
        "event_type": event_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "bytes": _ids_int(pick("bytes", "orig_bytes", "resp_bytes", "flow.bytes_toserver", "flow.bytes_toclient"), 0),
        "packets": _ids_int(pick("packets", "pkts", "orig_pkts", "resp_pkts"), 0),
        "dns_query": dns_query,
        "tls_sni": tls_sni,
        "http_host": http_host,
        "alert_signature": str(alert.get("signature") or pick("alert_signature", "signature") or ""),
        "alert_category": str(alert.get("category") or pick("alert_category", "category") or ""),
        "alert_severity": _ids_int(alert.get("severity") or pick("alert_severity", "severity"), 0),
    }
    flow["src_scope"] = _ids_ip_scope(src_ip).get("scope", "unknown") if src_ip else "unknown"
    flow["dst_scope"] = _ids_ip_scope(dst_ip).get("scope", "unknown") if dst_ip else "unknown"
    return flow


def _ids_parse_jsonl(text: str, *, limit: int, source: str) -> tuple[list[dict[str, Any]], list[str]]:
    flows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if len(flows) >= limit:
            break
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            if line_number <= 5:
                warnings.append(f"line {line_number}: not valid JSON")
            continue
        if isinstance(parsed, dict):
            flows.append(_ids_normalize_flow(parsed, source=source))
    return flows, warnings


def _ids_parse_csv(text: str, *, limit: int, source: str) -> tuple[list[dict[str, Any]], list[str]]:
    flows: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        reader = csv.DictReader(text.splitlines())
        for row in reader:
            if len(flows) >= limit:
                break
            if isinstance(row, dict):
                flows.append(_ids_normalize_flow(row, source=source))
    except csv.Error as exc:
        warnings.append(f"CSV parse warning: {exc}")
    return flows, warnings


def _ids_parse_zeek_conn(text: str, *, limit: int, source: str) -> tuple[list[dict[str, Any]], list[str]]:
    fields: list[str] = []
    flows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for line in text.splitlines():
        if len(flows) >= limit:
            break
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip():
            continue
        values = line.split("\t")
        if not fields or len(values) != len(fields):
            continue
        raw = dict(zip(fields, values))
        flows.append(_ids_normalize_flow(raw, source=source))
    if not fields:
        warnings.append("No Zeek #fields header found; parsed zero Zeek rows unless generic parsing succeeded.")
    return flows, warnings


def _ids_parse_generic_text(text: str, *, limit: int, source: str) -> tuple[list[dict[str, Any]], list[str]]:
    flows: list[dict[str, Any]] = []
    pattern = re.compile(r"(?P<src>\b(?:\d{1,3}\.){3}\d{1,3}\b)(?::(?P<src_port>\d{1,5}))?.{0,80}?(?:->|to|>|dst|dest|destination).{0,20}?(?P<dst>\b(?:\d{1,3}\.){3}\d{1,3}\b)(?::(?P<dst_port>\d{1,5}))?", re.I)
    for match in pattern.finditer(text):
        if len(flows) >= limit:
            break
        flows.append(_ids_normalize_flow({
            "src_ip": match.group("src"),
            "src_port": match.group("src_port") or 0,
            "dest_ip": match.group("dst"),
            "dest_port": match.group("dst_port") or 0,
            "proto": "UNKNOWN",
            "event_type": "text_match",
        }, source=source))
    return flows, [] if flows else ["Generic text parser found no IP-to-IP flow-like records."]


def _ids_parse_pcap_classic(data: bytes, *, limit: int, source: str) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    flows: list[dict[str, Any]] = []
    if len(data) < 24:
        return [], ["PCAP file is too small to contain a global header."]
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        return [], ["Not a classic PCAP file. PCAPNG requires tshark/Zeek/Suricata conversion before built-in parsing."]
    offset = 24
    while offset + 16 <= len(data) and len(flows) < limit:
        try:
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", data[offset:offset + 16])
        except struct.error:
            break
        offset += 16
        packet = data[offset:offset + incl_len]
        offset += incl_len
        if len(packet) < 14:
            continue
        eth_type = int.from_bytes(packet[12:14], "big")
        l3_offset = 14
        if eth_type == 0x8100 and len(packet) >= 18:
            eth_type = int.from_bytes(packet[16:18], "big")
            l3_offset = 18
        if eth_type != 0x0800 or len(packet) < l3_offset + 20:
            continue
        ip_header = packet[l3_offset:]
        version = ip_header[0] >> 4
        ihl = (ip_header[0] & 0x0F) * 4
        if version != 4 or len(ip_header) < ihl + 4:
            continue
        proto_num = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])
        l4 = ip_header[ihl:]
        src_port = dst_port = 0
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num))
        dns_query = ""
        if proto_num in {6, 17} and len(l4) >= 4:
            src_port = int.from_bytes(l4[0:2], "big")
            dst_port = int.from_bytes(l4[2:4], "big")
            if proto_num == 17 and (src_port == 53 or dst_port == 53) and len(l4) > 20:
                dns_query = _ids_decode_dns_query(l4[8:])
        flows.append(_ids_normalize_flow({
            "ts": float(ts_sec) + (float(ts_frac) / 1_000_000.0),
            "src_ip": src_ip,
            "dest_ip": dst_ip,
            "src_port": src_port,
            "dest_port": dst_port,
            "proto": proto,
            "bytes": len(packet),
            "packets": 1,
            "dns_query": dns_query,
            "event_type": "pcap_packet",
        }, source=source))
    return flows, warnings


def _ids_decode_dns_query(payload: bytes) -> str:
    if len(payload) < 12:
        return ""
    offset = 12
    labels: list[str] = []
    jumps = 0
    try:
        while offset < len(payload) and jumps < 20:
            length = payload[offset]
            if length == 0:
                break
            if length & 0xC0:
                break
            offset += 1
            if offset + length > len(payload):
                break
            label = payload[offset:offset + length].decode("ascii", errors="ignore")
            if label:
                labels.append(label)
            offset += length
            jumps += 1
    except Exception:
        return ""
    return ".".join(labels)


def _ids_read_traffic_records(path: str, *, input_format: str = "auto", limit: int = 5000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    target = resolve_workspace_path(path)
    if not target.exists() or not target.is_file():
        raise ValueError(f"Traffic source does not exist or is not a file: {path}")
    limit = max(1, min(int(limit), 50000))
    suffix = target.suffix.lower()
    fmt = str(input_format or "auto").lower().strip()
    source = workspace_relative(target)
    warnings: list[str] = []
    flows: list[dict[str, Any]] = []
    if fmt == "auto":
        if suffix in {".pcap", ".cap"}:
            fmt = "pcap"
        elif suffix in {".jsonl", ".eve"}:
            fmt = "jsonl"
        elif suffix == ".csv":
            fmt = "csv"
        elif suffix in {".log", ".txt", ""}:
            sample = target.read_text(encoding="utf-8", errors="replace")[:2000]
            fmt = "zeek" if "#fields" in sample and "id.orig_h" in sample else "text"
        else:
            fmt = "text"
    if fmt in {"pcap", "classic_pcap"}:
        data = target.read_bytes()[:64 * 1024 * 1024]
        flows, warnings = _ids_parse_pcap_classic(data, limit=limit, source=source)
    else:
        text = target.read_text(encoding="utf-8", errors="replace")
        if fmt in {"jsonl", "eve", "suricata"}:
            flows, warnings = _ids_parse_jsonl(text, limit=limit, source=source)
        elif fmt in {"zeek", "conn", "conn.log"}:
            flows, warnings = _ids_parse_zeek_conn(text, limit=limit, source=source)
        elif fmt == "csv":
            flows, warnings = _ids_parse_csv(text, limit=limit, source=source)
        else:
            flows, warnings = _ids_parse_generic_text(text, limit=limit, source=source)
    return flows, {"path": source, "format": fmt, "limit": limit, "warnings": warnings}


def _ids_alert(severity: str, category: str, title: str, evidence: dict[str, Any], recommendation: str) -> dict[str, Any]:
    return {
        "time": utc_now(),
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _ids_analyze_flows(flows: list[dict[str, Any]], *, baseline: dict[str, Any] | None = None, sensitivity: str = "medium") -> dict[str, Any]:
    baseline = baseline or {}
    sensitivity = str(sensitivity or "medium").lower()
    port_scan_threshold = {"low": 30, "medium": 18, "high": 10}.get(sensitivity, 18)
    fanout_threshold = {"low": 60, "medium": 35, "high": 20}.get(sensitivity, 35)
    beacon_min = {"low": 12, "medium": 8, "high": 5}.get(sensitivity, 8)
    alerts: list[dict[str, Any]] = []
    src_counter: collections.Counter[str] = collections.Counter()
    dst_counter: collections.Counter[str] = collections.Counter()
    port_counter: collections.Counter[int] = collections.Counter()
    proto_counter: collections.Counter[str] = collections.Counter()
    dns_counter: collections.Counter[str] = collections.Counter()
    per_src_ports: dict[str, set[int]] = collections.defaultdict(set)
    per_src_dsts: dict[str, set[str]] = collections.defaultdict(set)
    per_pair_times: dict[tuple[str, str, int, str], list[float]] = collections.defaultdict(list)
    external_dsts: set[str] = set()
    dst_ports_seen: set[int] = set()
    protocols_seen: set[str] = set()

    for flow in flows:
        src = str(flow.get("src_ip") or "")
        dst = str(flow.get("dst_ip") or "")
        port = _ids_int(flow.get("dst_port"), 0)
        proto = str(flow.get("proto") or "UNKNOWN").upper()
        if src:
            src_counter[src] += 1
        if dst:
            dst_counter[dst] += 1
        if port:
            port_counter[port] += 1
            dst_ports_seen.add(port)
        if proto:
            proto_counter[proto] += 1
            protocols_seen.add(proto)
        if src and port:
            per_src_ports[src].add(port)
        if src and dst:
            per_src_dsts[src].add(dst)
        if dst and _ids_ip_scope(dst).get("scope") == "global":
            external_dsts.add(dst)
        ts = _ids_float(flow.get("ts"), 0.0)
        if ts and src and dst:
            per_pair_times[(src, dst, port, proto)].append(ts)
        dns_query = str(flow.get("dns_query") or "")
        if dns_query:
            dns_counter[dns_query] += 1
        if flow.get("alert_signature"):
            severity_num = _ids_int(flow.get("alert_severity"), 2)
            severity = "high" if severity_num <= 1 else "medium" if severity_num <= 3 else "low"
            alerts.append(_ids_alert(
                severity,
                "upstream_ids_alert",
                str(flow.get("alert_signature")),
                {"src_ip": src, "dst_ip": dst, "dst_port": port, "category": flow.get("alert_category")},
                "Investigate the upstream IDS alert, then confirm host ownership and whether the destination service is expected.",
            ))
        if port in IDS_SUSPICIOUS_PORTS:
            src_scope = flow.get("src_scope")
            dst_scope = flow.get("dst_scope")
            severity = "high" if port in {23, 2323, 3389, 4444, 5900, 6667, 31337} and (src_scope == "global" or dst_scope == "global") else "medium"
            alerts.append(_ids_alert(
                severity,
                "suspicious_service_port",
                f"Traffic involving {IDS_SUSPICIOUS_PORTS[port]} ({port})",
                {"src_ip": src, "dst_ip": dst, "dst_port": port, "proto": proto},
                "Verify whether this service is expected. Restrict exposure, require strong authentication, or block if unauthorized.",
            ))
        if dns_query:
            entropy = _ids_dns_entropy_like(dns_query)
            if len(dns_query) > 80 or entropy >= 3.8:
                alerts.append(_ids_alert(
                    "medium",
                    "suspicious_dns",
                    "Long or high-entropy DNS query observed",
                    {"query": dns_query[:160], "length": len(dns_query), "entropy": entropy, "src_ip": src},
                    "Check whether the query belongs to legitimate software. High-entropy or unusually long domains can indicate tunneling, DGA, or tracking noise.",
                ))

    for src, ports in per_src_ports.items():
        if len(ports) >= port_scan_threshold:
            alerts.append(_ids_alert(
                "high" if len(ports) >= port_scan_threshold * 2 else "medium",
                "possible_port_scan",
                f"One source touched {len(ports)} destination ports",
                {"src_ip": src, "unique_dst_ports": sorted(ports)[:80]},
                "Validate whether this is an authorized scanner. If not, isolate/denylist the source and review target host logs.",
            ))
    for src, dsts in per_src_dsts.items():
        if len(dsts) >= fanout_threshold:
            alerts.append(_ids_alert(
                "medium",
                "possible_fanout_scan",
                f"One source contacted {len(dsts)} unique destinations",
                {"src_ip": src, "unique_dst_count": len(dsts), "sample_dst_ips": sorted(dsts)[:30]},
                "Check for discovery scans, malware propagation, or noisy inventory tooling.",
            ))
    for key, times in per_pair_times.items():
        if len(times) < beacon_min:
            continue
        ordered = sorted(times)
        intervals = [ordered[i + 1] - ordered[i] for i in range(len(ordered) - 1) if ordered[i + 1] > ordered[i]]
        if len(intervals) < beacon_min - 1:
            continue
        avg = sum(intervals) / len(intervals)
        if avg <= 0:
            continue
        variance = sum((item - avg) ** 2 for item in intervals) / len(intervals)
        jitter_ratio = (variance ** 0.5) / avg
        if 5 <= avg <= 3600 and jitter_ratio < 0.18:
            src, dst, port, proto = key
            alerts.append(_ids_alert(
                "medium",
                "possible_beaconing",
                "Regular repeated connection pattern observed",
                {"src_ip": src, "dst_ip": dst, "dst_port": port, "proto": proto, "samples": len(times), "avg_interval_seconds": round(avg, 2), "jitter_ratio": round(jitter_ratio, 3)},
                "Correlate with process/endpoint logs. Regular callbacks may be benign telemetry or command-and-control behavior.",
            ))

    if baseline:
        known_ports = {int(item) for item in baseline.get("dst_ports", []) if str(item).isdigit()}
        known_protocols = {str(item).upper() for item in baseline.get("protocols", [])}
        known_external = set(str(item) for item in baseline.get("external_destinations", []))
        new_ports = sorted(port for port in dst_ports_seen if port and port not in known_ports)
        new_protocols = sorted(proto for proto in protocols_seen if proto and proto not in known_protocols)
        new_external = sorted(dst for dst in external_dsts if dst not in known_external)
        if new_ports:
            alerts.append(_ids_alert("medium", "baseline_deviation", "New destination ports observed versus baseline", {"new_ports": new_ports[:80]}, "Review whether the new ports are expected for this host/network segment."))
        if new_protocols:
            alerts.append(_ids_alert("low", "baseline_deviation", "New protocols observed versus baseline", {"new_protocols": new_protocols}, "Confirm whether these protocol changes are expected."))
        if len(new_external) >= 5:
            alerts.append(_ids_alert("medium", "baseline_deviation", "New external destinations observed versus baseline", {"new_external_destinations": new_external[:50], "count": len(new_external)}, "Review new external destinations against application changes, updates, and threat intelligence."))

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    alerts.sort(key=lambda item: (-severity_rank.get(str(item.get("severity")), 0), str(item.get("category")), str(item.get("title"))))
    summary = {
        "flow_count": len(flows),
        "top_sources": src_counter.most_common(10),
        "top_destinations": dst_counter.most_common(10),
        "top_destination_ports": port_counter.most_common(20),
        "protocols": proto_counter.most_common(10),
        "top_dns_queries": dns_counter.most_common(10),
        "external_destination_count": len(external_dsts),
        "alerts": alerts[:100],
        "alert_count": len(alerts),
        "severity_counts": dict(collections.Counter(str(alert.get("severity", "info")) for alert in alerts)),
    }
    return summary


def _ids_baseline_from_flows(flows: list[dict[str, Any]], *, label: str = "baseline") -> dict[str, Any]:
    dst_ports = sorted({_ids_int(flow.get("dst_port"), 0) for flow in flows if _ids_int(flow.get("dst_port"), 0)})
    protocols = sorted({str(flow.get("proto") or "UNKNOWN").upper() for flow in flows if flow.get("proto")})
    external = sorted({str(flow.get("dst_ip")) for flow in flows if _ids_ip_scope(str(flow.get("dst_ip") or "")).get("scope") == "global"})
    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "label": label,
        "flow_count": len(flows),
        "dst_ports": dst_ports,
        "protocols": protocols,
        "external_destinations": external[:1000],
    }


def _ids_append_alerts(alerts: list[dict[str, Any]], *, source_path: str = "") -> int:
    if not alerts:
        return 0
    try:
        IDS_ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with IDS_ALERTS_FILE.open("a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(dict(alert) | {"source_path": source_path}, sort_keys=True) + "\n")
        return len(alerts)
    except OSError:
        return 0

def summarize_network_tool_result(tool_name: str, result: ToolResult) -> str:
    """Create a user-facing summary for network tools instead of dumping raw JSON/state."""
    payload = _network_payload(result)
    if not payload:
        status = "succeeded" if result.ok else "failed"
        return f"Network lookup {status}: {trim_text(result.content, 1200)}"

    lines: list[str] = []
    generated = payload.get("generated_at")
    if tool_name == "get_public_ip_info":
        public_ip = payload.get("public_ip") or payload.get("ip") or "unknown"
        lines.append(f"Your public IP address appears to be **{public_ip}**.")
        source = payload.get("source")
        if source:
            lines.append(f"Source: {source}.")
        classification = payload.get("classification")
        if isinstance(classification, dict):
            flags = [key for key in ("is_private", "is_global", "is_loopback", "is_reserved") if classification.get(key)]
            if flags:
                lines.append("Classification: " + ", ".join(flags).replace("is_", "") + ".")
        geo = payload.get("geolocation")
        if isinstance(geo, dict) and geo:
            city = geo.get("city")
            region = geo.get("region")
            country = geo.get("country")
            location = ", ".join(str(x) for x in (city, region, country) if x)
            org = geo.get("org") or geo.get("isp")
            asn = geo.get("asn")
            if location:
                lines.append(f"Approximate GeoIP location: {location}.")
            if org or asn:
                lines.append(f"Network/ISP hint: {org or 'unknown'}{f' ({asn})' if asn else ''}.")
        rdap = payload.get("rdap")
        if isinstance(rdap, dict) and rdap:
            name = rdap.get("name")
            start = rdap.get("start_address")
            end = rdap.get("end_address")
            handle = rdap.get("handle")
            if name or handle:
                lines.append(f"RDAP allocation: {name or handle}.")
            if start and end:
                lines.append(f"Registered range: {start} – {end}.")
        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            lines.append("Some enrichment sources failed, but the primary IP lookup succeeded.")
        lines.append("Note: GeoIP/ISP data is approximate and may reflect VPN, proxy, carrier-grade NAT, or ISP routing rather than your exact physical location.")
        return "\n".join(lines)

    if tool_name == "lookup_ip_geolocation":
        ip = payload.get("ip") or payload.get("target") or "unknown"
        if payload.get("skipped"):
            return f"GeoIP lookup skipped for **{ip}**: {payload.get('reason', 'target is not a public IP address')}."
        lines.append(f"GeoIP result for **{ip}**:")
        location = ", ".join(str(x) for x in (payload.get("city"), payload.get("region"), payload.get("country")) if x)
        if location:
            lines.append(f"Approximate location: {location}.")
        if payload.get("isp") or payload.get("org") or payload.get("asn"):
            lines.append(f"Network/ISP hint: {payload.get('isp') or payload.get('org') or 'unknown'}{f' ({payload.get('asn')})' if payload.get('asn') else ''}.")
        if payload.get("timezone"):
            lines.append(f"Timezone: {payload.get('timezone')}.")
        lines.append("GeoIP is approximate, not proof of a precise physical address.")
        return "\n".join(lines)

    if tool_name == "lookup_ip_rdap":
        if payload.get("skipped"):
            return f"RDAP lookup skipped: {payload.get('reason', 'target is not a public IP address')}."
        lines.append(f"RDAP result for **{payload.get('ip') or payload.get('target', 'target')}**:")
        for label, key in (("Name", "name"), ("Handle", "handle"), ("Type", "type"), ("Country", "country")):
            value = payload.get(key)
            if value:
                lines.append(f"{label}: {value}")
        if payload.get("start_address") and payload.get("end_address"):
            lines.append(f"Range: {payload.get('start_address')} – {payload.get('end_address')}")
        entities = _safe_join(payload.get("entity_handles"))
        if entities:
            lines.append(f"Entity handles: {entities}")
        return "\n".join(lines)

    if tool_name == "resolve_dns_records":
        target = payload.get("target") or payload.get("host") or "target"
        addresses = _safe_join(payload.get("addresses") or payload.get("records") or payload.get("ips"), limit=12)
        return f"DNS resolution for **{target}**: {addresses or 'no records returned'}."

    if tool_name == "reverse_dns_lookup":
        ip = payload.get("ip") or payload.get("target") or "target"
        names = _safe_join(payload.get("hostnames") or payload.get("names") or payload.get("ptr"), limit=8)
        if payload.get("hostname"):
            names = str(payload.get("hostname"))
        return f"Reverse DNS for **{ip}**: {names or 'no PTR record found'}."

    if tool_name == "scan_tcp_ports":
        target = payload.get("target") or payload.get("host") or "target"
        open_ports = payload.get("open_ports") or payload.get("open") or []
        closed_ports = payload.get("closed_ports") or payload.get("closed") or []
        filtered_ports = payload.get("filtered_ports") or payload.get("filtered") or []
        open_text = _safe_join(open_ports, limit=32) or "none detected"
        lines.append(f"TCP scan summary for **{target}**: open ports: {open_text}.")
        if isinstance(closed_ports, list):
            lines.append(f"Closed/refused ports checked: {len(closed_ports)}.")
        if isinstance(filtered_ports, list) and filtered_ports:
            lines.append(f"Timed out/filtered ports checked: {len(filtered_ports)}.")
        if payload.get("warnings"):
            lines.append("Warnings: " + _safe_join(payload.get("warnings"), limit=4))
        return "\n".join(lines)

    if tool_name == "inspect_local_listening_ports":
        entries = payload.get("entries") if isinstance(payload.get("entries"), list) else []
        tcp_entries = [row for row in entries if str(row.get("protocol", "")).upper().startswith("TCP")]
        udp_entries = [row for row in entries if str(row.get("protocol", "")).upper().startswith("UDP")]
        lines.append("Local listening-port summary for this machine:")
        if not entries:
            lines.append("No listening TCP/UDP ports were detected by the available local OS command.")
        else:
            lines.append(f"Detected {len(entries)} listening socket(s): {len(tcp_entries)} TCP and {len(udp_entries)} UDP.")
            for row in entries[:20]:
                protocol = str(row.get("protocol") or "?").upper()
                address = str(row.get("local_address") or row.get("address") or "?")
                port = row.get("port", "?")
                state = str(row.get("state") or "listening")
                exposure = str(row.get("exposure") or "unknown")
                pid = row.get("pid")
                process = row.get("process")
                owner = f" pid={pid}" if pid else ""
                if process:
                    owner += f" process={process}"
                lines.append(f"• {protocol} {address}:{port} — {state}, {exposure}{owner}")
            if len(entries) > 20:
                lines.append(f"…plus {len(entries) - 20} more socket(s).")
        if payload.get("command"):
            lines.append("Source: local OS listening-socket table.")
        if payload.get("warnings"):
            lines.append("Warnings: " + _safe_join(payload.get("warnings"), limit=4))
        lines.append("This is a local-host inventory, not a blind scan of every device on the LAN. For another device, provide a single authorized target IP/hostname and ports.")
        return "\n".join(lines)

    if tool_name == "inspect_tls_certificate":
        target = payload.get("target") or payload.get("host") or "target"
        lines.append(f"TLS certificate summary for **{target}**:")
        for label, key in (("Subject", "subject"), ("Issuer", "issuer"), ("Valid from", "not_before"), ("Valid until", "not_after"), ("SHA-256 fingerprint", "sha256_fingerprint"), ("TLS version", "tls_version"), ("Cipher", "cipher")):
            value = payload.get(key)
            if value:
                lines.append(f"{label}: {value}")
        sans = _safe_join(payload.get("subject_alt_names"), limit=8)
        if sans:
            lines.append(f"Subject alternative names: {sans}")
        return "\n".join(lines)

    if tool_name == "inspect_local_network":
        lines.append("Local network summary:")
        for label, key in (("Hostname", "hostname"), ("FQDN", "fqdn")):
            value = payload.get(key)
            if value:
                lines.append(f"{label}: {value}")
        local_ips = _safe_join(payload.get("local_ips") or payload.get("addresses"), limit=12)
        if local_ips:
            lines.append(f"Local IPs: {local_ips}")
        resolvers = _safe_join(payload.get("resolver_hints") or payload.get("dns_servers"), limit=8)
        if resolvers:
            lines.append(f"Resolver hints: {resolvers}")
        return "\n".join(lines)

    if tool_name in {"ingest_network_traffic_file", "analyze_network_traffic_file", "compare_network_baseline"}:
        source = payload.get("path") or payload.get("source_path") or "traffic source"
        flow_count = payload.get("flow_count", 0)
        lines.append(f"Network traffic analysis for **{source}**:")
        lines.append(f"Normalized flow/packet records: {flow_count}.")
        severity_counts = payload.get("severity_counts") or {}
        alert_count = payload.get("alert_count", 0)
        if alert_count:
            sev_text = ", ".join(f"{key}={value}" for key, value in severity_counts.items()) or str(alert_count)
            lines.append(f"IDS-style alerts: {alert_count} ({sev_text}).")
            for alert in (payload.get("alerts") or [])[:8]:
                lines.append(f"• {str(alert.get('severity', 'info')).upper()} — {alert.get('title')} [{alert.get('category')}]")
                evidence = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
                if evidence:
                    compact_evidence = json.dumps(evidence, sort_keys=True)
                    lines.append(f"  Evidence: {trim_text(compact_evidence, 220)}")
                if alert.get("recommendation"):
                    lines.append(f"  Next: {alert.get('recommendation')}")
            if alert_count > 8:
                lines.append(f"…plus {alert_count - 8} more alert(s).")
        else:
            lines.append("No IDS-style alerts were generated by the built-in heuristics.")
        top_ports = payload.get("top_destination_ports") or []
        if top_ports:
            lines.append("Top destination ports: " + ", ".join(f"{port}/{count}" for port, count in top_ports[:10]) + ".")
        top_sources = payload.get("top_sources") or []
        if top_sources:
            lines.append("Top sources: " + ", ".join(f"{ip} ({count})" for ip, count in top_sources[:6]) + ".")
        warnings = payload.get("warnings") or []
        if warnings:
            lines.append("Warnings: " + _safe_join(warnings, limit=4))
        if payload.get("alerts_recorded"):
            lines.append(f"Recorded alerts to `{workspace_relative(IDS_ALERTS_FILE)}`.")
        return "\n".join(lines)

    if tool_name == "build_ids_baseline":
        return (
            f"IDS baseline built for **{payload.get('label', 'baseline')}** from {payload.get('flow_count', 0)} flow(s).\n"
            f"Known destination ports: {_safe_join(payload.get('dst_ports'), limit=20) or 'none'}.\n"
            f"Known protocols: {_safe_join(payload.get('protocols'), limit=10) or 'none'}.\n"
            f"Saved baseline: `{payload.get('baseline_path', workspace_relative(IDS_BASELINE_FILE))}`."
        )

    if tool_name == "capture_network_metadata_sample":
        lines.append("Network metadata capture sample:")
        lines.append(f"Status: {'success' if result.ok else 'failed'}.")
        if payload.get("output_path"):
            lines.append(f"Metadata output: `{payload.get('output_path')}`.")
        if payload.get("packet_count") is not None:
            lines.append(f"Captured metadata rows: {payload.get('packet_count')}.")
        if payload.get("command"):
            lines.append("Capture adapter: tshark metadata-only fields.")
        if payload.get("warnings"):
            lines.append("Warnings: " + _safe_join(payload.get("warnings"), limit=5))
        lines.append("No packet payloads are intentionally retained by this tool.")
        return "\n".join(lines)

    if tool_name == "build_ids_mode_plan":
        lines.append("IDS mode plan:")
        lines.append(f"Mode: {payload.get('mode', 'offline')}.")
        for step in payload.get("recommended_sequence", [])[:12]:
            if isinstance(step, dict):
                lines.append(f"• {step.get('tool')}: {step.get('purpose')}")
        if payload.get("safety_rules"):
            lines.append("Safety rules: " + _safe_join(payload.get("safety_rules"), limit=6))
        return "\n".join(lines)

    if tool_name == "show_ids_alerts":
        alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
        lines.append(f"Stored IDS alerts: {len(alerts)} shown of {payload.get('total_alerts', len(alerts))} total.")
        for alert in alerts[:20]:
            lines.append(f"• {str(alert.get('severity', 'info')).upper()} — {alert.get('title')} [{alert.get('category')}] at {alert.get('time')}")
        return "\n".join(lines)

    # Fallback for normalize_network_target/build_network_intel_brief and future network tools.
    title = tool_name.replace("_", " ").title()
    compact = {k: v for k, v in payload.items() if k not in {"raw", "raw_keys"}}
    rendered = json.dumps(compact, indent=2)
    return f"{title}:\n```json\n{trim_text(rendered, 1800)}\n```"


def summarize_threat_intel_tool_result(tool_name: str, result: ToolResult) -> str:
    payload = _network_payload(result)
    lines: list[str] = []
    if not result.ok:
        return f"{tool_name} failed: {trim_text(result.content, 1000)}"

    if tool_name == "lookup_cve":
        cve = payload.get("cve") if isinstance(payload.get("cve"), dict) else {}
        lines.append(f"CVE lookup for **{cve.get('cve_id', payload.get('cve_id', 'unknown'))}**:")
        cvss = cve.get("cvss") if isinstance(cve.get("cvss"), dict) else {}
        if cvss:
            lines.append(f"CVSS: {cvss.get('base_severity', 'unknown')} {cvss.get('base_score', '')} ({cvss.get('metric', 'metric unknown')}).")
        if cve.get("is_known_exploited"):
            kev = cve.get("kev") if isinstance(cve.get("kev"), dict) else {}
            lines.append(f"CISA KEV: YES — added {kev.get('dateAdded', 'unknown date')}; due date {kev.get('dueDate', 'n/a')}.")
        else:
            lines.append("CISA KEV: not listed in the loaded KEV catalog.")
        if cve.get("description"):
            lines.append(f"Description: {trim_text(str(cve.get('description')), 700)}")
        if cve.get("weaknesses"):
            lines.append("Weaknesses: " + _safe_join(cve.get("weaknesses"), limit=8))
        if cve.get("reference_count"):
            lines.append(f"References: {cve.get('reference_count')} total; first {min(12, int(cve.get('reference_count') or 0))} retained in metadata.")
        return "\n".join(lines)

    if tool_name == "search_cves":
        rows = payload.get("results") if isinstance(payload.get("results"), list) else []
        lines.append(f"CVE search returned {len(rows)} shown of {payload.get('total_results', len(rows))} total result(s).")
        for row in rows[:10]:
            cvss = row.get("cvss") if isinstance(row.get("cvss"), dict) else {}
            kev = " KEV" if row.get("is_known_exploited") else ""
            lines.append(f"• {row.get('cve_id')}: {cvss.get('base_severity', 'unknown')} {cvss.get('base_score', '')}{kev} — {trim_text(str(row.get('description', '')), 180)}")
        return "\n".join(lines)

    if tool_name == "check_cisa_kev":
        rows = payload.get("matches") if isinstance(payload.get("matches"), list) else []
        lines.append(f"CISA KEV matches: {len(rows)} shown of {payload.get('match_count', len(rows))}.")
        for row in rows[:12]:
            lines.append(f"• {row.get('cveID')}: {row.get('vendorProject')} {row.get('product')} — added {row.get('dateAdded')}; due {row.get('dueDate')}")
        if payload.get("warnings"):
            lines.append("Warnings: " + _safe_join(payload.get("warnings"), limit=4))
        return "\n".join(lines)

    if tool_name == "lookup_malware_hash":
        status = payload.get("query_status") or payload.get("status")
        lines.append(f"Malware hash lookup for **{payload.get('hash', 'unknown')}**: {status}.")
        rows = payload.get("data") if isinstance(payload.get("data"), list) else []
        for row in rows[:5]:
            signatures = row.get("signature") or row.get("clamav") or row.get("file_name") or "unknown signature"
            tags = _safe_join(row.get("tags"), limit=8)
            lines.append(f"• {row.get('sha256_hash', row.get('md5_hash', 'sample'))}: {signatures}; file type={row.get('file_type', 'unknown')}; tags={tags or 'none'}")
        if not rows and status in {"hash_not_found", "file_not_found"}:
            lines.append("No known MalwareBazaar record was returned for that hash.")
        return "\n".join(lines)

    if tool_name == "hash_workspace_file":
        lines.append(f"File hashes for `{payload.get('path')}`:")
        hashes = payload.get("hashes") if isinstance(payload.get("hashes"), dict) else {}
        for name in ("md5", "sha1", "sha256"):
            if hashes.get(name):
                lines.append(f"{name.upper()}: `{hashes.get(name)}`")
        if payload.get("malware_lookup"):
            lookup = payload.get("malware_lookup") if isinstance(payload.get("malware_lookup"), dict) else {}
            lines.append(f"MalwareBazaar status: {lookup.get('query_status', lookup.get('status', 'unknown'))}.")
        return "\n".join(lines)

    if tool_name == "scan_workspace_file_signatures":
        lines.append(f"Signature scan for `{payload.get('path')}`: {payload.get('match_count', 0)} match(es) across {payload.get('file_count', 0)} file(s).")
        for match in payload.get("matches", [])[:12]:
            lines.append(f"• {match.get('severity', 'info').upper()} — {match.get('signature')} in `{match.get('path')}` ({match.get('signature_type')})")
        if payload.get("warnings"):
            lines.append("Warnings: " + _safe_join(payload.get("warnings"), limit=6))
        return "\n".join(lines)

    if tool_name == "add_malware_signature":
        return f"Saved malware signature `{payload.get('name')}` to `{payload.get('signature_path')}`. Total signatures: {payload.get('signature_count')}."

    if tool_name == "build_threat_intel_brief":
        lines.append(f"Threat-intel brief for `{payload.get('indicator')}`:")
        for finding in payload.get("findings", [])[:12]:
            if isinstance(finding, dict):
                lines.append(f"• {finding.get('type')}: {finding.get('summary')}")
        for step in payload.get("recommended_sequence", [])[:8]:
            if isinstance(step, dict):
                lines.append(f"Next tool: {step.get('tool')} — {step.get('purpose')}")
        return "\n".join(lines)

    return trim_text(result.content, 1200)



def _looks_like_tool_inventory_request(user_input: str) -> bool:
    """Detect direct requests for the agent's own tool inventory.

    These should be answered from the live registry, not from model memory, so
    the response cannot drift, omit newly added tools, or stop halfway through a
    hand-written capability overview.
    """
    text = re.sub(r"\s+", " ", str(user_input or "").lower()).strip()
    if not text:
        return False
    if not any(term in text for term in ("tool", "tools", "capabilities", "capability inventory")):
        return False

    inventory_phrases = (
        "tool inventory",
        "tools inventory",
        "list of tools",
        "list the tools",
        "table of tools",
        "table of the tools",
        "tools and what they do",
        "what tools",
        "which tools",
        "all tools",
        "available tools",
        "registered tools",
        "tools cerebro has access to",
        "tools do you have access to",
        "tools you have access to",
        "capabilities overview",
        "capability inventory",
    )
    if any(phrase in text for phrase in inventory_phrases):
        return True

    # Covers natural phrasing like: "give me a list of the tools CEREBRO has access to".
    asks_to_show = re.search(r"\b(?:give|show|list|display|print|return|make)\b", text) is not None
    asks_inventory = re.search(r"\btools?\b", text) is not None and re.search(
        r"\b(?:access|available|registered|have|has|do|does|what they do)\b",
        text,
    ) is not None
    return asks_to_show and asks_inventory


def _tool_inventory_category(name: str, description: str = "") -> str:
    token_text = f"{name} {description}".lower()

    if any(term in token_text for term in ("cve", "kev", "malware", "signature", "yara", "threat-intel", "threat intelligence", "malwarebazaar")):
        return "Threat Intelligence"
    if any(term in token_text for term in ("csv", "jsonl", "sqlite", "database", "archive", "zip", "tar", "pdf", "image", "json api", "html", "crawl", "security headers", "json schema", "entity", "manifest", "compare", "process", "environment", "external tool", "plugin", "media metadata")):
        return "Data, Documents & External Tools"
    if any(term in token_text for term in ("network", "dns", "rdap", "geoip", "geolocation", "tls", "ssl", "port", "traffic", "ids", "intrusion", "pcap", "suricata", "zeek", "packet", "baseline")):
        return "Network & IDS"
    if any(term in token_text for term in ("model", "llm", "provider", "router", "route", "runtime", "dependency", "prompt", "context budget", "token")):
        return "Models, Runtime & Context"
    if any(term in token_text for term in ("checkpoint", "self-improve", "self improvement", "improvement", "experiment", "autonomy", "cycle ledger", "rollback", "change impact", "control state", "control mode")):
        return "Self-Improvement & Change Control"
    if any(term in token_text for term in ("team", "subagent", "manager", "role", "meta", "quality gate", "execution dossier", "tool chain", "risk register", "validation matrix", "patch strategy", "readiness", "goal")):
        return "Planning & Multi-Agent Orchestration"
    if any(term in token_text for term in ("repository", "entrypoint", "api surface", "data flow", "error log", "python", "complexity", "import graph", "duplicate", "refactor", "code graph", "symbol", "callers", "orphan", "hotspot", "codebase", "function", "class")):
        return "Code Intelligence"
    if any(term in token_text for term in ("task", "blackboard", "memory", "profile", "plan", "history", "config", "run-log", "run history")):
        return "State, Memory & Tasks"
    if any(term in token_text for term in ("file", "workspace", "json", "write", "append", "replace", "diff", "search", "git", "pytest", "ruff", "smoke-test", "command", "path", "directory")):
        return "Workspace, Files & Validation"
    return "General Utilities"


def _escape_markdown_table_cell(value: Any, *, max_chars: int = 140) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = text.replace("|", r"\|")
    if len(text) > max_chars:
        text = text[: max(1, max_chars - 1)].rstrip() + "…"
    return text


def render_registered_tool_inventory(tools: "AgentTools", *, include_schemas: bool = False) -> str:
    """Render a complete, deterministic inventory from the live tool registry.

    The inventory is intentionally grouped into several narrow tables instead of
    one giant table. That keeps Windows Command Prompt from wrapping rows into a
    hard-to-read wall of borders when the registry grows past 100 tools.
    """
    specs = list(tools.tool_specs.values())
    categorized: dict[str, list[ToolSpec]] = collections.defaultdict(list)
    for spec in specs:
        categorized[_tool_inventory_category(spec.name, spec.description)].append(spec)

    category_order = [
        "Workspace, Files & Validation",
        "Code Intelligence",
        "Planning & Multi-Agent Orchestration",
        "Self-Improvement & Change Control",
        "Models, Runtime & Context",
        "Data, Documents & External Tools",
        "Network & IDS",
        "Threat Intelligence",
        "State, Memory & Tasks",
        "General Utilities",
    ]
    risk_labels = {
        TOOL_RISK_READ_ONLY: "read-only",
        TOOL_RISK_WRITE_FILE: "writes files",
        TOOL_RISK_RUN_COMMAND: "runs command",
        TOOL_RISK_AGENTIC: "agentic",
        TOOL_RISK_MEMORY: "memory/state",
        TOOL_RISK_CONTROL: "control",
    }

    lines: list[str] = []
    lines.append(f"CEREBRO TOOL INVENTORY — {len(specs)} registered tools")
    lines.append("")
    lines.append("This inventory is generated directly from the live tool registry, so it reflects the tools the agent can actually call.")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|---|---:|")
    for category in category_order:
        count = len(categorized.get(category, []))
        if count:
            lines.append(f"| {category} | {count} |")

    lines.append("")
    lines.append("Full tool list by category:")

    row_index = 0
    for category in category_order:
        category_specs = sorted(categorized.get(category, []), key=lambda item: item.name)
        if not category_specs:
            continue
        lines.append("")
        lines.append(f"### {category} ({len(category_specs)})")
        lines.append("")
        lines.append("| # | Tool | Risk | What it does |")
        lines.append("|---:|---|---|---|")
        for spec in category_specs:
            row_index += 1
            description = _escape_markdown_table_cell(spec.description, max_chars=95)
            risk = risk_labels.get(spec.risk, spec.risk)
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(row_index),
                        _escape_markdown_table_cell(spec.name, max_chars=38),
                        _escape_markdown_table_cell(risk, max_chars=18),
                        description,
                    ]
                )
                + " |"
            )

    if include_schemas:
        lines.append("")
        lines.append("Tool argument schemas:")
        lines.append("")
        for spec in sorted(specs, key=lambda item: item.name):
            schema_text = json.dumps(spec.schema, sort_keys=True)
            lines.append(f"- `{spec.name}`: `{_escape_markdown_table_cell(schema_text, max_chars=220)}`")

    return "\n".join(lines)

def build_direct_tool_inventory_response(user_input: str, tools: "AgentTools") -> str | None:
    if not _looks_like_tool_inventory_request(user_input):
        return None
    include_schemas = any(term in str(user_input or "").lower() for term in ("schema", "schemas", "arguments", "args", "parameters"))
    return render_registered_tool_inventory(tools, include_schemas=include_schemas)

def summarize_tool_results_for_user(user_input: str, executed: list[tuple[str, ToolResult]]) -> str:
    summaries: list[str] = []
    for tool_name, result in executed:
        if tool_name in NETWORK_INFORMATION_TOOLS:
            summaries.append(summarize_network_tool_result(tool_name, result))
        elif tool_name in THREAT_INTEL_TOOLS:
            summaries.append(summarize_threat_intel_tool_result(tool_name, result))
        elif result.ok:
            summaries.append(trim_text(result.content, 1200))
        else:
            summaries.append(f"{tool_name} failed: {trim_text(result.content, 800)}")
    return "\n\n".join(item for item in summaries if item.strip()) or "I ran the requested tool, but it returned no displayable output."


def should_finalize_after_tool_result(user_input: str, executed: list[tuple[str, ToolResult]]) -> bool:
    if not executed:
        return False
    tool_names = {name for name, _ in executed}
    if tool_names & NETWORK_INFORMATION_TOOLS and _looks_like_network_information_request(user_input):
        return True
    if tool_names & THREAT_INTEL_TOOLS and _looks_like_threat_intel_request(user_input):
        return True
    return False


def _looks_like_local_open_ports_request(user_input: str) -> bool:
    text = re.sub(r"\s+", " ", str(user_input or "").lower()).strip()
    if not text:
        return False
    port_phrases = ("open ports", "open port", "listening ports", "listening services", "netstat", "ports are open")
    local_scope = ("this network", "my network", "local network", "this computer", "my computer", "this machine", "localhost", "local host", "on this network")
    if any(phrase in text for phrase in port_phrases) and any(scope in text for scope in local_scope):
        return True
    # Treat short, target-less port questions as local-host diagnostics rather than hallucinating a shell command.
    if any(phrase in text for phrase in port_phrases) and not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[a-z0-9.-]+\.[a-z]{2,}", text):
        return True
    return False


def _looks_like_ids_mode_request(user_input: str) -> bool:
    text = re.sub(r"\s+", " ", str(user_input or "").lower()).strip()
    ids_terms = ("ids", "intrusion detection", "network traffic", "packet capture", "traffic capture", "pcap", "suricata", "zeek", "analyze traffic", "monitor traffic")
    return any(term in text for term in ids_terms)


def build_direct_network_tool_action(user_input: str) -> dict[str, Any] | None:
    """Return a deterministic one-tool action for simple network questions.

    This prevents the model from answering with an inert command like `netstat`
    when a safe, registered diagnostic tool already exists. Broad LAN scanning is
    intentionally not inferred from vague wording.
    """
    text = re.sub(r"\s+", " ", str(user_input or "").lower()).strip()
    if not _looks_like_network_information_request(text):
        return None
    if _looks_like_ids_mode_request(text) and not re.search(r"\b(?:analy[sz]e|ingest|parse)\b.*\b[\w./\\ -]+\.(?:pcap|cap|jsonl|eve|log|csv|txt)\b", text):
        live_requested = any(term in text for term in ("live", "start", "monitor", "capture"))
        return {
            "type": "tool",
            "tool": "build_ids_mode_plan",
            "args": {"mode": "live" if live_requested else "offline", "duration_seconds": 30, "authorized": False},
            "why": "Build a safe IDS-mode plan before capturing or analyzing network traffic.",
        }
    if _looks_like_local_open_ports_request(text):
        return {
            "type": "tool",
            "tool": "inspect_local_listening_ports",
            "args": {"include_udp": True, "include_process_names": True, "limit": 100},
            "why": "Inspect local listening ports with a bounded read-only OS diagnostic instead of emitting a shell command.",
        }
    if any(phrase in text for phrase in ("my ip", "ip address", "public ip", "external ip", "wan ip")) and not any(phrase in text for phrase in ("open port", "open ports", "port scan", "listening")):
        return {
            "type": "tool",
            "tool": "get_public_ip_info",
            "args": {"enrich": True, "timeout": 10},
            "why": "Answer the direct public-IP question with the public IP lookup tool.",
        }
    return None


def build_direct_threat_intel_tool_action(user_input: str) -> dict[str, Any] | None:
    """Return a deterministic one-tool action for simple CVE/hash/signature requests."""
    text = re.sub(r"\s+", " ", str(user_input or "")).strip()
    lowered = text.lower()
    if not _looks_like_threat_intel_request(text):
        return None
    cve_match = re.search(r"CVE-\d{4}-\d{4,}", text, re.I)
    if cve_match:
        cve_id = _normalize_cve_id(cve_match.group(0))
        if "kev" in lowered or "known exploited" in lowered:
            return {
                "type": "tool",
                "tool": "check_cisa_kev",
                "args": {"cve_id": cve_id, "limit": 10, "refresh": False, "timeout": 12},
                "why": "Check whether the supplied CVE is listed in CISA KEV.",
            }
        return {
            "type": "tool",
            "tool": "lookup_cve",
            "args": {"cve_id": cve_id, "include_kev": True, "timeout": 15},
            "why": "Look up the supplied CVE and enrich it with KEV status.",
        }
    hash_match = re.search(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", text)
    if hash_match:
        return {
            "type": "tool",
            "tool": "lookup_malware_hash",
            "args": {"file_hash": hash_match.group(0), "timeout": 15},
            "why": "Enrich the supplied file hash through a defensive malware-intelligence lookup.",
        }
    if any(term in lowered for term in ("signature", "signatures", "yara")):
        return {
            "type": "tool",
            "tool": "build_threat_intel_brief",
            "args": {"indicator": text, "include_cve": True, "include_malware": True},
            "why": "Build a safe threat-intelligence plan for malware signature work.",
        }
    return None


def user_explicitly_requested_file_write(user_input: str) -> bool:
    text = re.sub(r"\s+", " ", user_input.lower()).strip()
    if not text:
        return False
    return any(keyword in text for keyword in WRITE_INTENT_KEYWORDS)


def user_input_has_tool_intent(user_input: str) -> bool:
    text = re.sub(r"\s+", " ", user_input.lower()).strip()
    if not text:
        return False
    return any(keyword in text for keyword in TOOL_INTENT_KEYWORDS)


def build_turn_guidance(user_input: str, state: "AgentState") -> str:
    if user_input_looks_like_conversational_followup(user_input) and state.conversation_history:
        return (
            "Turn guidance: This user message is a short conversational follow-up. "
            "Use the recent conversation as context and return a final answer. "
            "Do not inspect the workspace or call tools unless the user explicitly asks for a tool/workspace/file action."
        )
    if not user_input_has_tool_intent(user_input) and not user_explicitly_requested_file_write(user_input):
        return (
            "Turn guidance: This looks like ordinary conversation or an informational question. "
            "Prefer a direct final answer. Do not call file/workspace/write tools unless necessary and clearly requested."
        )
    return (
        "Turn guidance: Tool use may be appropriate if it is the smallest safe way to satisfy the request. "
        "For write tools, require explicit user intent to save, export, edit, patch, refactor, or improve files."
    )


def should_block_write_action(tool_name: str, user_input: str) -> bool:
    if tool_name not in WRITE_TOOL_NAMES:
        return False
    return not user_explicitly_requested_file_write(user_input)


def user_input_looks_like_conversational_followup(user_input: str) -> bool:
    text = re.sub(r"\s+", " ", user_input.lower()).strip()
    if not text:
        return False
    if any(keyword in text for keyword in TOOL_INTENT_KEYWORDS):
        return False
    if text in CONVERSATIONAL_FOLLOWUP_PATTERNS:
        return True
    return len(text.split()) <= 4 and text.rstrip("?!.") in CONVERSATIONAL_FOLLOWUP_PATTERNS


def should_block_tool_for_conversational_followup(tool_name: str, user_input: str, state: AgentState) -> bool:
    if not state.conversation_history:
        return False
    if tool_name in {"remember", "recall", "search_memory"}:
        return False
    return user_input_looks_like_conversational_followup(user_input)


def blocked_conversational_tool_result(tool_name: str, user_input: str) -> ToolResult:
    message = (
        f"Blocked {tool_name}: the user message looks like a conversational follow-up. "
        "Answer directly from the recent conversation instead of inspecting the workspace or calling tools."
    )
    return ToolResult(
        False,
        message,
        meta={
            "blocked": True,
            "tool": tool_name,
            "reason": "conversational_followup_should_answer_directly",
            "user_input": trim_text(user_input, 500),
        },
    )


def blocked_write_tool_result(tool_name: str, user_input: str) -> ToolResult:
    message = (
        f"Blocked {tool_name}: this looks like an informational request, not an explicit request to save, export, edit, or modify files. "
        "Answer directly instead of writing to the workspace unless the user explicitly asks for a file change."
    )
    return ToolResult(
        False,
        message,
        meta={
            "blocked": True,
            "tool": tool_name,
            "reason": "missing_explicit_write_intent",
            "user_input": trim_text(user_input, 500),
        },
    )


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
        {"role": "system", "content": build_turn_guidance(user_input, state)},
        {"role": "system", "content": build_task_intelligence_summary(user_input, state)},
        *state.recent_conversation_messages(),
        {"role": "user", "content": user_input},
    ]
    log_run_event("turn_started", {"input": user_input, "turn": state.turns_completed, "depth": depth})

    direct_network_action = build_direct_network_tool_action(user_input)
    if direct_network_action is not None and direct_network_action.get("tool") in tools.tools:
        executed = execute_action(direct_network_action, tools, user_input=user_input)
        final_content = summarize_tool_results_for_user(user_input, executed)
        state.record_conversation_turn(user_input, final_content)
        log_run_event(
            "turn_finished_after_direct_network_tool",
            {
                "tools": [name for name, _ in executed],
                "final": trim_text(final_content, 2000),
                "depth": depth,
            },
        )
        return final_content

    direct_threat_action = build_direct_threat_intel_tool_action(user_input)
    if direct_threat_action is not None and direct_threat_action.get("tool") in tools.tools:
        executed = execute_action(direct_threat_action, tools, user_input=user_input)
        final_content = summarize_tool_results_for_user(user_input, executed)
        state.record_conversation_turn(user_input, final_content)
        log_run_event(
            "turn_finished_after_direct_threat_intel_tool",
            {
                "tools": [name for name, _ in executed],
                "final": trim_text(final_content, 2000),
                "depth": depth,
            },
        )
        return final_content

    direct_tool_inventory = build_direct_tool_inventory_response(user_input, tools)
    if direct_tool_inventory is not None:
        state.record_conversation_turn(user_input, direct_tool_inventory)
        log_run_event(
            "turn_finished_after_direct_tool_inventory",
            {
                "tool_count": len(tools.tool_specs),
                "final": trim_text(direct_tool_inventory, 2000),
                "depth": depth,
            },
        )
        return direct_tool_inventory

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
            final_content = str(action.get("content", ""))
            state.record_conversation_turn(user_input, final_content)
            log_run_event("turn_finished", {"step": step, "final": final_content, "depth": depth})
            return final_content

        executed = execute_action(action, tools, user_input=user_input)
        if any(not result.ok for _, result in executed):
            state.add_reflection("A tool failed; inspect the error and choose a narrower recovery step.")
        else:
            why = action.get("why")
            if isinstance(why, str):
                state.add_reflection(f"Successful action: {why}")

        if should_finalize_after_tool_result(user_input, executed):
            final_content = summarize_tool_results_for_user(user_input, executed)
            state.record_conversation_turn(user_input, final_content)
            log_run_event(
                "turn_finished_after_tool_summary",
                {
                    "step": step,
                    "tools": [name for name, _ in executed],
                    "final": trim_text(final_content, 2000),
                    "depth": depth,
                },
            )
            return final_content

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
        add("semantic_search_workspace", "Rank workspace text files and line snippets by semantic-ish term relevance without requiring ripgrep or a model.", {"query": "what to find", "path": ".", "limit": 8, "max_file_chars": 12000}, TOOL_RISK_READ_ONLY, self.semantic_search_workspace)
        add("find_relevant_code_context", "Rank Python symbols/functions/classes relevant to an objective with snippets and static risk signals.", {"objective": "change objective", "path": ".", "limit": 8}, TOOL_RISK_READ_ONLY, self.find_relevant_code_context)
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
        add("audit_tool_coverage", "Audit registered tool coverage, recent tool reliability, and capability gaps for a goal.", {"objective": "optional objective", "include_specs": False}, TOOL_RISK_READ_ONLY, self.audit_tool_coverage)
        add("recommend_tool_chain", "Recommend a safe ordered tool chain for an objective with gates, fallbacks, and validation steps.", {"objective": "user objective", "context": "optional context", "path": "."}, TOOL_RISK_READ_ONLY, self.recommend_tool_chain)
        add("build_execution_dossier", "Build a compact execution dossier: context, team, tool chain, model route, acceptance criteria, and risks.", {"objective": "user objective", "path": ".", "context": "optional context", "limit": 5}, TOOL_RISK_READ_ONLY, self.build_execution_dossier)
        add("inspect_tool_schema_health", "Audit registered tool schemas against callable signatures and flag schema/function drift.", {}, TOOL_RISK_READ_ONLY, self.inspect_tool_schema_health)
        add("map_tool_capability_graph", "Map tools into capabilities, entrypoints, and recommended edges for a goal.", {"objective": "optional objective", "include_edges": True}, TOOL_RISK_READ_ONLY, self.map_tool_capability_graph)
        add("mine_tool_usage_patterns", "Mine recent tool history and run logs for successful/failed tool-use patterns.", {"limit": 120}, TOOL_RISK_READ_ONLY, self.mine_tool_usage_patterns)
        add("trace_goal_to_symbols", "Trace a natural-language goal to likely files, Python symbols, call impact, and search evidence.", {"objective": "user objective", "path": ".", "limit": 5}, TOOL_RISK_READ_ONLY, self.trace_goal_to_symbols)
        add("build_validation_matrix", "Build a validation plan matrix for an objective and changed files without executing the checks.", {"objective": "user objective", "changed_files": [], "path": ".", "risk_level": ""}, TOOL_RISK_READ_ONLY, self.build_validation_matrix)
        add("plan_patch_strategy", "Plan the smallest reversible patch strategy with targets, checkpoints, validation, and rollback gates.", {"objective": "user objective", "target_path": ".", "context": "optional context", "max_files": 3}, TOOL_RISK_READ_ONLY, self.plan_patch_strategy)
        add("score_execution_readiness", "Score whether the agent has enough evidence, target clarity, validation, and rollback readiness to act.", {"objective": "user objective", "context": "optional context", "candidate": "", "changed_files": []}, TOOL_RISK_READ_ONLY, self.score_execution_readiness)
        add("decompose_goal", "Infer task intent, risk, roles, tools, acceptance criteria, and a first execution plan.", {"goal": "user objective", "context": "optional context"}, TOOL_RISK_READ_ONLY, self.decompose_goal)
        add("build_context_pack", "Build a compact situational context pack from memory, profile, blackboard, tasks, git, recent files, TODOs, and code intelligence.", {"objective": "user objective", "path": ".", "limit": 8}, TOOL_RISK_READ_ONLY, self.build_context_pack)
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
        add("show_model_router", "Show token-aware model-router thresholds and route targets.", {}, TOOL_RISK_READ_ONLY, self.show_model_router)
        add("validate_model_router_config", "Validate model-router routes, budgets, providers, and compaction settings.", {}, TOOL_RISK_READ_ONLY, self.validate_model_router_config)
        add("recommend_model_route", "Estimate prompt size and show which provider/model route would be used without calling a model.", {"prompt": "text to estimate", "path": "optional/file.py", "role": "optional role", "provider": "optional provider", "model": "optional model"}, TOOL_RISK_READ_ONLY, self.recommend_model_route)
        add("list_available_models", "List configured, cached, and static model options across providers without making live API calls unless refresh=true.", {"provider": "", "refresh": False, "include_static": True, "limit": 200}, TOOL_RISK_READ_ONLY, self.list_available_models)
        add("discover_available_models", "Call provider model-list APIs, cache live model ids, and report missing credentials or discovery errors.", {"provider": "", "save": True, "timeout": 12}, TOOL_RISK_READ_ONLY, self.discover_available_models)
        add("recommend_model_selection", "Score available models for a role/objective/context requirement and recommend the best provider/model choices.", {"objective": "task objective", "role": "", "provider": "", "required_context_tokens": 0, "prefer": "", "limit": 8, "refresh": False}, TOOL_RISK_READ_ONLY, self.recommend_model_selection)
        add("build_model_portfolio", "Recommend a multi-role model portfolio for fast, coding, reasoning, long-context, local, and open-weight needs.", {"objective": "overall workload", "refresh": False}, TOOL_RISK_READ_ONLY, self.build_model_portfolio)
        add("set_model_selection", "Persist a selected provider/model to the default route, a role route, or a model-router route.", {"provider": "openai", "model": "gpt-4.1", "scope": "default|role|router", "role": "", "route_name": "", "allow_unknown": False}, TOOL_RISK_CONTROL, self.set_model_selection)
        add("configure_llm_provider", "Add or update a configurable LLM provider, including OpenAI-compatible endpoints for new vendors.", {"name": "provider_name", "provider_type": "openai_compatible", "base_url": "https://...", "api_key_env": "PROVIDER_API_KEY", "model": "", "model_list_endpoint": "", "overwrite": False}, TOOL_RISK_CONTROL, self.configure_llm_provider)
        add("route_multi_model_task", "Plan a multi-model execution strategy by assigning providers/models to roles and execution phases.", {"objective": "task objective", "path": ".", "prefer": "", "required_context_tokens": 0, "refresh": False}, TOOL_RISK_READ_ONLY, self.route_multi_model_task)
        add("inspect_runtime_environment", "Inspect Python/runtime/provider environment readiness without exposing secret values.", {"include_packages": True, "include_env": True}, TOOL_RISK_READ_ONLY, self.inspect_runtime_environment)
        add("audit_dependency_health", "Audit Python imports, optional packages, and dependency-file health for the workspace.", {"path": ".", "recursive": True, "limit": 200}, TOOL_RISK_READ_ONLY, self.audit_dependency_health)
        add("inspect_prompt_surface", "Audit manager, role, quality, and self-improvement prompts for size, tool mentions, and instruction drift.", {"include_snippets": False}, TOOL_RISK_READ_ONLY, self.inspect_prompt_surface)
        add("build_context_budget_plan", "Plan prompt/context packing against a model input budget before sending large files or dossiers to an LLM.", {"objective": "task objective", "path": ".", "role": "planner", "provider": "", "model": "", "max_input_tokens": 0}, TOOL_RISK_READ_ONLY, self.build_context_budget_plan)
        add("propose_test_plan_for_symbol", "Propose targeted validation and regression tests for a Python symbol or file without writing tests.", {"symbol": "function_or_class", "path": ".", "objective": "optional objective", "limit": 8}, TOOL_RISK_READ_ONLY, self.propose_test_plan_for_symbol)
        add("simulate_tool_execution_plan", "Dry-run a recommended tool sequence and report preconditions, gates, fallbacks, and expected evidence.", {"objective": "task objective", "path": ".", "context": ""}, TOOL_RISK_READ_ONLY, self.simulate_tool_execution_plan)
        add("build_risk_register", "Build a risk register for an objective with likelihood, impact, mitigations, owners, and validation gates.", {"objective": "task objective", "path": ".", "context": "", "changed_files": []}, TOOL_RISK_READ_ONLY, self.build_risk_register)
        add("map_repository_structure", "Map repository directories, extension mix, important files, and likely architecture boundaries.", {"path": ".", "max_depth": 3, "include_hidden": False}, TOOL_RISK_READ_ONLY, self.map_repository_structure)
        add("inspect_project_entrypoints", "Find runnable entrypoints, CLI guards, scripts, app factories, and common project launch files.", {"path": ".", "recursive": True, "limit": 120}, TOOL_RISK_READ_ONLY, self.inspect_project_entrypoints)
        add("extract_api_surface", "Extract public functions/classes, signatures, docstrings, and module surface from Python files.", {"path": ".", "recursive": True, "include_private": False, "limit": 120}, TOOL_RISK_READ_ONLY, self.extract_api_surface)
        add("trace_data_flow", "Approximate data/control flow for a symbol or objective using static Python AST analysis.", {"objective": "task objective", "symbol": "", "path": ".", "limit": 8}, TOOL_RISK_READ_ONLY, self.trace_data_flow)
        add("inspect_error_log", "Parse a traceback or log file/text into exception, frames, missing modules, and likely next checks.", {"path": "", "text": "", "limit": 40}, TOOL_RISK_READ_ONLY, self.inspect_error_log)
        add("inspect_config_surface", "Inventory config/env/build files and redact secret-like values before previewing them.", {"path": ".", "include_preview": True, "preview_lines": 8}, TOOL_RISK_READ_ONLY, self.inspect_config_surface)
        add("fetch_url_text", "Fetch bounded text from an HTTP(S) URL for documentation/research, denying local/private hosts unless allowed.", {"url": "https://example.com", "max_chars": 6000, "timeout": 10, "allow_local": False}, TOOL_RISK_READ_ONLY, self.fetch_url_text)
        add("inspect_http_endpoint", "Inspect HTTP(S) endpoint status and headers without downloading the full body.", {"url": "https://example.com", "timeout": 10, "allow_local": False}, TOOL_RISK_READ_ONLY, self.inspect_http_endpoint)
        add("fetch_json_api", "Call a bounded JSON HTTP(S) API endpoint with SSRF guardrails, optional POST body, and parsed JSON output.", {"url": "https://api.example.com/data", "method": "GET", "headers": {}, "body": {}, "max_chars": 20000, "timeout": 10, "allow_local": False}, TOOL_RISK_READ_ONLY, self.fetch_json_api)
        add("extract_html_metadata", "Fetch bounded HTML and extract title, meta tags, canonical URL, headings, and normalized links with SSRF guardrails.", {"url": "https://example.com", "max_chars": 100000, "timeout": 10, "allow_local": False, "link_limit": 100}, TOOL_RISK_READ_ONLY, self.extract_html_metadata)
        add("check_http_security_headers", "Evaluate common HTTP security headers for an endpoint and return missing/weak controls.", {"url": "https://example.com", "timeout": 10, "allow_local": False}, TOOL_RISK_READ_ONLY, self.check_http_security_headers)
        add("crawl_url_map", "Perform a bounded same-host crawl and build a small URL/title/status/link map with SSRF guardrails.", {"start_url": "https://example.com", "max_pages": 10, "max_depth": 1, "timeout": 10, "allow_local": False, "same_host_only": True}, TOOL_RISK_READ_ONLY, self.crawl_url_map)
        add("infer_json_schema", "Infer a compact structural schema from a workspace JSON or JSONL file, or from provided JSON text.", {"path": "data.json", "json_text": "", "max_items": 1000, "max_depth": 6}, TOOL_RISK_READ_ONLY, self.infer_json_schema)
        add("extract_text_entities", "Extract URLs, emails, IPs, CVEs, hashes, and redacted secret-like strings from workspace text files.", {"path": ".", "recursive": True, "entity_types": [], "limit": 200, "max_file_chars": 200000}, TOOL_RISK_READ_ONLY, self.extract_text_entities)
        add("generate_file_manifest", "Generate a bounded file inventory with sizes, mtimes, MIME guesses, extensions, and optional SHA256 hashes.", {"path": ".", "recursive": True, "include_hashes": True, "max_files": 500, "max_bytes_per_hash": 10485760}, TOOL_RISK_READ_ONLY, self.generate_file_manifest)
        add("compare_workspace_files", "Compare two workspace files with hashes and a bounded unified diff for text files.", {"left_path": "old.txt", "right_path": "new.txt", "max_chars": 20000}, TOOL_RISK_READ_ONLY, self.compare_workspace_files)
        add("inspect_python_environment", "Inspect the active Python runtime, virtual environment, import path, and installed packages without exposing secrets.", {"include_packages": True, "include_env": False, "package_limit": 200}, TOOL_RISK_READ_ONLY, self.inspect_python_environment)
        add("inspect_process_table", "Inspect a bounded local process table using OS diagnostics, with optional filtering and command-line redaction.", {"filter": "", "limit": 100, "include_command": False}, TOOL_RISK_READ_ONLY, self.inspect_process_table)
        add("profile_csv_file", "Profile a workspace CSV/TSV file: columns, missing values, numeric ranges, samples, and row counts.", {"path": "data.csv", "delimiter": "", "sample_rows": 5, "max_rows": 10000}, TOOL_RISK_READ_ONLY, self.profile_csv_file)
        add("inspect_jsonl_file", "Inspect a JSONL/NDJSON log file and summarize keys, parse errors, samples, and value type frequencies.", {"path": "events.jsonl", "limit": 5000, "sample_rows": 5}, TOOL_RISK_READ_ONLY, self.inspect_jsonl_file)
        add("query_sqlite_database", "Run a read-only SELECT/WITH/PRAGMA query against a workspace SQLite database and return bounded rows.", {"path": "data.db", "query": "SELECT name FROM sqlite_master", "limit": 100, "timeout": 5}, TOOL_RISK_READ_ONLY, self.query_sqlite_database)
        add("inspect_archive_file", "Inventory a ZIP/TAR archive without extracting it, including size totals and path-traversal warnings.", {"path": "archive.zip", "limit": 200}, TOOL_RISK_READ_ONLY, self.inspect_archive_file)
        add("extract_pdf_text", "Extract bounded text from a workspace PDF using pypdf/PyPDF2 when available; no OCR or image parsing.", {"path": "document.pdf", "max_pages": 10, "max_chars": 20000}, TOOL_RISK_READ_ONLY, self.extract_pdf_text)
        add("inspect_image_metadata", "Inspect basic image metadata and optional EXIF using Pillow when available without modifying the image.", {"path": "image.png", "include_exif": False}, TOOL_RISK_READ_ONLY, self.inspect_image_metadata)
        add("list_external_tools", "List safe external command tools declared in .agent_external_tools.json so Cerebro can use local scanners and CLIs deliberately.", {"manifest_path": ".agent_external_tools.json"}, TOOL_RISK_READ_ONLY, self.list_external_tools)
        add("run_external_tool", "Run a manifest-declared external command tool with no shell, bounded timeout, workspace path guards, and authorization gates.", {"tool_name": "bandit_scan", "args": {"path": "."}, "manifest_path": ".agent_external_tools.json", "authorized": False, "timeout": 30}, TOOL_RISK_RUN_COMMAND, self.run_external_tool)
        add("normalize_network_target", "Normalize a hostname, URL, IP address, or CIDR and classify network safety properties.", {"target": "example.com", "resolve": False, "allow_private": False}, TOOL_RISK_READ_ONLY, self.normalize_network_target)
        add("resolve_dns_records", "Resolve A/AAAA records for a hostname with private-address guardrails.", {"target": "example.com", "record_type": "A", "allow_private": False, "timeout": 5}, TOOL_RISK_READ_ONLY, self.resolve_dns_records)
        add("reverse_dns_lookup", "Perform reverse DNS/PTR lookup for one IP address.", {"ip": "8.8.8.8", "allow_private": False}, TOOL_RISK_READ_ONLY, self.reverse_dns_lookup)
        add("lookup_ip_rdap", "Look up public IP network registration and ASN hints through RDAP.", {"target": "8.8.8.8", "timeout": 10}, TOOL_RISK_READ_ONLY, self.lookup_ip_rdap)
        add("lookup_ip_geolocation", "Look up public IP geolocation, ASN/org, and ISP-like metadata using bounded public APIs.", {"target": "8.8.8.8", "timeout": 10}, TOOL_RISK_READ_ONLY, self.lookup_ip_geolocation)
        add("get_public_ip_info", "Discover this machine's public IP and optionally enrich it with geolocation/ASN data.", {"enrich": True, "timeout": 10}, TOOL_RISK_READ_ONLY, self.get_public_ip_info)
        add("scan_tcp_ports", "Perform a bounded TCP connect scan against a single authorized host; public targets require allow_public=true.", {"target": "127.0.0.1", "ports": "22,80,443", "timeout": 0.5, "allow_public": False, "max_ports": 32}, TOOL_RISK_RUN_COMMAND, self.scan_tcp_ports)
        add("inspect_local_listening_ports", "Inspect TCP/UDP ports currently listening on this machine using bounded local OS diagnostics; this is not a LAN sweep.", {"include_udp": True, "include_process_names": True, "limit": 100}, TOOL_RISK_READ_ONLY, self.inspect_local_listening_ports)
        add("inspect_tls_certificate", "Inspect a TLS certificate and handshake metadata for a host/port without saving certificate material.", {"target": "example.com", "port": 443, "server_name": "", "timeout": 5, "allow_private": False}, TOOL_RISK_READ_ONLY, self.inspect_tls_certificate)
        add("inspect_local_network", "Inspect local hostname, addresses, resolver hints, and optional bounded OS network command output.", {"include_command_output": False}, TOOL_RISK_READ_ONLY, self.inspect_local_network)
        add("start_control_server", "Start a localhost-only authenticated control server for trusted agent clients; no shell or payload execution.", {"host": "", "port": 0, "authorized": False}, TOOL_RISK_CONTROL, self.start_control_server)
        add("show_control_server", "Show status, safe command types, and authenticated connected clients for the control server.", {}, TOOL_RISK_READ_ONLY, self.show_control_server)
        add("route_control_command", "Route an allow-listed JSON coordination command to connected trusted clients.", {"command_type": "ping", "payload": {}, "target_ids": []}, TOOL_RISK_CONTROL, self.route_control_command)
        add("stop_control_server", "Stop the control server and disconnect clients.", {}, TOOL_RISK_CONTROL, self.stop_control_server)
        add("build_network_intel_brief", "Build a safe network intelligence brief and recommended probe sequence for an IP/domain/URL.", {"target": "example.com", "include_scan_plan": True, "allow_public_scan": False}, TOOL_RISK_READ_ONLY, self.build_network_intel_brief)
        add("ingest_network_traffic_file", "Ingest a workspace PCAP/Suricata EVE/Zeek conn.log/CSV/JSONL/text traffic source into normalized metadata-only flow records.", {"path": "traffic.pcap", "input_format": "auto", "limit": 5000}, TOOL_RISK_READ_ONLY, self.ingest_network_traffic_file)
        add("analyze_network_traffic_file", "Analyze normalized network traffic records with IDS-style heuristics and optional baseline comparison.", {"path": "traffic.pcap", "input_format": "auto", "limit": 5000, "baseline_path": "", "sensitivity": "medium", "record_alerts": True}, TOOL_RISK_MEMORY, self.analyze_network_traffic_file)
        add("build_ids_baseline", "Build and save a simple IDS baseline from known-good traffic metadata.", {"path": "known_good.pcap", "input_format": "auto", "label": "home-network-baseline", "limit": 10000, "baseline_path": ".agent_ids_baseline.json"}, TOOL_RISK_MEMORY, self.build_ids_baseline)
        add("compare_network_baseline", "Compare a traffic source against a saved IDS baseline and report deviations.", {"path": "current.pcap", "input_format": "auto", "baseline_path": ".agent_ids_baseline.json", "limit": 10000, "sensitivity": "medium", "record_alerts": True}, TOOL_RISK_MEMORY, self.compare_network_baseline)
        add("capture_network_metadata_sample", "Capture a short live network metadata sample using tshark when explicitly authorized; stores metadata only, no payloads.", {"interface": "", "duration_seconds": 15, "max_packets": 200, "output_path": ".agent_ids_captures/sample.jsonl", "authorized": False}, TOOL_RISK_RUN_COMMAND, self.capture_network_metadata_sample)
        add("build_ids_mode_plan", "Build a defensive IDS-mode plan for offline log ingestion or explicitly authorized live metadata capture.", {"mode": "offline", "source_path": "", "duration_seconds": 30, "interface": "", "authorized": False}, TOOL_RISK_READ_ONLY, self.build_ids_mode_plan)
        add("show_ids_alerts", "Show recent IDS-style alerts recorded by network traffic analysis tools.", {"limit": 20, "min_severity": "info"}, TOOL_RISK_READ_ONLY, self.show_ids_alerts)
        add("lookup_cve", "Look up one CVE in NVD and optionally enrich it with CISA KEV known-exploited status.", {"cve_id": "CVE-2024-3094", "include_kev": True, "timeout": 15}, TOOL_RISK_READ_ONLY, self.lookup_cve)
        add("search_cves", "Search NVD CVEs by keyword, CPE, severity, publication window, or last-modified window with optional KEV enrichment.", {"keyword": "OpenSSH", "cpe_name": "", "cvss_severity": "", "published_days": 0, "modified_days": 0, "limit": 20, "include_kev": True, "timeout": 15}, TOOL_RISK_READ_ONLY, self.search_cves)
        add("check_cisa_kev", "Search the CISA Known Exploited Vulnerabilities catalog by CVE, vendor, product, or keyword.", {"cve_id": "", "vendor": "", "product": "", "keyword": "", "limit": 50, "refresh": False, "timeout": 12}, TOOL_RISK_READ_ONLY, self.check_cisa_kev)
        add("lookup_malware_hash", "Query MalwareBazaar for metadata about a file hash without downloading malware samples.", {"file_hash": "sha256/md5/sha1", "timeout": 15}, TOOL_RISK_READ_ONLY, self.lookup_malware_hash)
        add("hash_workspace_file", "Calculate MD5/SHA1/SHA256 for a workspace file and optionally look up the SHA256 in MalwareBazaar.", {"path": "sample.bin", "lookup_malware_bazaar": False, "timeout": 15}, TOOL_RISK_READ_ONLY, self.hash_workspace_file)
        add("list_crypto_algorithms", "List supported encryption/decryption algorithms, availability, formats, and security notes.", {}, TOOL_RISK_READ_ONLY, self.list_crypto_algorithms)
        add("encrypt_text", "Encrypt UTF-8 text, base64 data, or hex data into a portable authenticated crypto envelope.", {"data": "secret text", "algorithm": "aesgcm", "passphrase": "", "key_b64": "", "input_format": "text", "associated_data": "", "iterations": 390000}, TOOL_RISK_READ_ONLY, self.encrypt_text)
        add("decrypt_text", "Decrypt a Cerebro crypto envelope and return text, base64, or hex output.", {"encrypted_text": "cerebro.crypto.v1:...", "passphrase": "", "key_b64": "", "output_format": "text", "associated_data": ""}, TOOL_RISK_READ_ONLY, self.decrypt_text)
        add("encrypt_file", "Encrypt a workspace file into a portable authenticated crypto envelope file.", {"input_path": "secret.bin", "output_path": "", "algorithm": "aesgcm", "passphrase": "", "key_b64": "", "associated_data": "", "iterations": 390000, "overwrite": False, "max_bytes": 52428800}, TOOL_RISK_WRITE_FILE, self.encrypt_file)
        add("decrypt_file", "Decrypt a workspace crypto envelope file back to bytes.", {"input_path": "secret.bin.cenc", "output_path": "", "passphrase": "", "key_b64": "", "associated_data": "", "overwrite": False, "max_bytes": 52428800}, TOOL_RISK_WRITE_FILE, self.decrypt_file)
        add("add_malware_signature", "Add or update a local defensive malware signature for string, regex, hex, hash, or YARA matching.", {"name": "signature name", "pattern": "pattern", "signature_type": "string", "severity": "medium", "tags": [], "description": "", "source": "local", "overwrite": False, "signature_path": ""}, TOOL_RISK_MEMORY, self.add_malware_signature)
        add("scan_workspace_file_signatures", "Scan workspace file(s) with local malware signatures and optional yara-python support; never executes suspect files.", {"path": "sample.bin", "signature_path": "", "recursive": False, "max_files": 50, "max_bytes_per_file": 5242880, "use_yara": True}, TOOL_RISK_READ_ONLY, self.scan_workspace_file_signatures)
        add("build_threat_intel_brief", "Build a defensive threat-intelligence brief and recommended tool sequence for a CVE, hash, product, or malware-signature task.", {"indicator": "CVE/hash/product/signature goal", "include_cve": True, "include_malware": True}, TOOL_RISK_READ_ONLY, self.build_threat_intel_brief)
        add("build_toolbox_brief", "Recommend the most useful tool groups and next probes for a goal, including sub-agent usage guidance.", {"objective": "task objective", "path": "."}, TOOL_RISK_READ_ONLY, self.build_toolbox_brief)
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
        add("scan_workspace_secrets", "Scan workspace text files for likely exposed credentials, private keys, tokens, and high-entropy secret candidates with redacted evidence.", {"path": ".", "recursive": True, "max_files": 200, "max_bytes_per_file": 1048576, "include_low_confidence": False}, TOOL_RISK_READ_ONLY, self.scan_workspace_secrets)
        add("build_workspace_snapshot", "Build a compact operational snapshot of files, code surface, tool registry, config posture, and recent state without modifying files.", {"path": ".", "recursive": True, "max_files": 250, "include_hashes": False}, TOOL_RISK_READ_ONLY, self.build_workspace_snapshot)
        add("analyze_unified_diff_impact", "Analyze a unified diff or current git diff for changed files, risk signals, touched Python symbols, and recommended validation steps.", {"diff": "", "path": ".", "max_diff_chars": 40000}, TOOL_RISK_READ_ONLY, self.analyze_unified_diff_impact)
        add("create_diagnostic_bundle", "Write a redacted diagnostic JSON bundle with workspace snapshot, tool schema health, config posture, run history, and validation hints.", {"path": ".", "output_path": ".agent_diagnostics/latest_diagnostic_bundle.json", "max_files": 200}, TOOL_RISK_WRITE_FILE, self.create_diagnostic_bundle)
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
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

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

    def semantic_search_workspace(
        self,
        query: str,
        path: str = ".",
        limit: int = 8,
        max_file_chars: int = 12000,
    ) -> ToolResult:
        query = str(query).strip()
        if not query:
            return ToolResult(False, "Query cannot be empty.")
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")

        limit = max(1, min(int(limit), 30))
        max_file_chars = max(1000, min(int(max_file_chars), 100000))
        candidates = [target] if target.is_file() else list(target.rglob("*"))
        searched = 0
        skipped = 0
        file_items: list[dict[str, Any]] = []

        for candidate in candidates:
            if not candidate.is_file() or should_skip_checkpoint_path(candidate):
                continue
            if not looks_like_text_path(candidate):
                skipped += 1
                continue
            try:
                stat = candidate.stat()
            except OSError:
                skipped += 1
                continue
            text = read_text_sample(candidate, max_chars=max_file_chars)
            if not text:
                skipped += 1
                continue
            searched += 1
            score, reasons = score_text_relevance(query, text)
            if score <= 0:
                continue
            snippets = relevant_line_snippets(query, text, context_lines=1, limit=3)
            file_items.append(
                {
                    "path": workspace_relative(candidate),
                    "size": stat.st_size,
                    "score": round(score, 2),
                    "reasons": reasons,
                    "snippets": snippets,
                }
            )

        file_items.sort(key=lambda item: (-float(item.get("score", 0)), str(item.get("path", ""))))
        matches = file_items[:limit]
        payload = {
            "query": query,
            "path": workspace_relative(target),
            "searched_files": searched,
            "skipped_files": skipped,
            "match_count": len(file_items),
            "matches": matches,
        }
        if not matches:
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)

        lines: list[str] = []
        for item in matches:
            lines.append(f"{item['path']} (score={item['score']}): {', '.join(item.get('reasons', [])[:3])}")
            for snippet in item.get("snippets", [])[:2]:
                lines.append(f"  lines {snippet['start_line']}-{snippet['end_line']}: {trim_text(snippet['text'], 500)}")
        return ToolResult(True, "\n".join(lines), meta=payload)


    def find_relevant_code_context(self, objective: str, path: str = ".", limit: int = 8) -> ToolResult:
        objective = str(objective).strip()
        if not objective:
            return ToolResult(False, "Objective cannot be empty.")
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")

        limit = max(1, min(int(limit), 30))
        python_files = iter_python_source_files(target, recursive=target.is_dir(), max_files=250)
        terms = search_terms(objective)
        symbols: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        for candidate in python_files:
            relative = workspace_relative(candidate)
            try:
                source = candidate.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except (OSError, SyntaxError) as exc:
                errors.append({"path": relative, "error": str(exc)})
                continue

            source_lines = source.splitlines()
            parents: list[str] = []

            class Visitor(ast.NodeVisitor):
                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    self._capture_symbol(node, "class")
                    parents.append(node.name)
                    self.generic_visit(node)
                    parents.pop()

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    self._capture_symbol(node, "function")
                    parents.append(node.name)
                    self.generic_visit(node)
                    parents.pop()

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    self._capture_symbol(node, "async_function")
                    parents.append(node.name)
                    self.generic_visit(node)
                    parents.pop()

                def _capture_symbol(self, node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef, kind: str) -> None:
                    qualified = ".".join([*parents, node.name]) if parents else node.name
                    source_preview = ast_node_source(source_lines, node, max_chars=4500)
                    docstring = ast.get_docstring(node) or ""
                    signature = node.name
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        try:
                            signature = f"{node.name}({', '.join(arg.arg for arg in node.args.args)})"
                        except Exception:
                            signature = node.name
                    relevance_text = "\n".join(
                        [
                            kind,
                            node.name,
                            qualified,
                            signature,
                            docstring,
                            source_preview,
                        ]
                    )
                    score, reasons = score_text_relevance(objective, relevance_text)
                    normalized_name = re.sub(r"[_\.]+", " ", qualified).lower()
                    name_hits = [term for term in terms if term in normalized_name]
                    if name_hits:
                        score += len(name_hits) * 4
                        reasons.append("symbol name hits: " + ", ".join(name_hits[:6]))
                    if score <= 0:
                        return

                    end_line = int(getattr(node, "end_lineno", node.lineno))
                    line_count = max(1, end_line - int(node.lineno) + 1)
                    calls = [
                        ast_call_name(child.func)
                        for child in ast.walk(node)
                        if isinstance(child, ast.Call) and ast_call_name(child.func)
                    ]
                    unique_calls = sorted(set(calls))[:40]
                    decision_count = ast_decision_points(node)
                    complexity_score = decision_count * 3 + line_count // 8 + len(calls) // 6
                    risk_level = "high" if complexity_score >= 18 or line_count >= 180 else "medium" if complexity_score >= 8 or line_count >= 70 else "low"
                    snippet_start = max(1, int(node.lineno) - 2)
                    snippet_end = min(len(source_lines), int(node.lineno) + 8)
                    snippet = "\n".join(
                        f"{line_number}: {source_lines[line_number - 1]}"
                        for line_number in range(snippet_start, snippet_end + 1)
                    )
                    symbols.append(
                        {
                            "path": relative,
                            "kind": kind,
                            "name": node.name,
                            "qualified_name": qualified,
                            "signature": signature,
                            "line": int(node.lineno),
                            "end_line": end_line,
                            "line_count": line_count,
                            "score": round(score, 2),
                            "reasons": reasons[:8],
                            "decision_points": decision_count,
                            "call_count": len(calls),
                            "calls": unique_calls,
                            "risk_level": risk_level,
                            "docstring": trim_text(docstring, 500),
                            "snippet": trim_text(snippet, 1600),
                        }
                    )

            Visitor().visit(tree)

        symbols.sort(key=lambda item: (-float(item.get("score", 0)), -int(item.get("line_count", 0)), str(item.get("path", "")), int(item.get("line", 0))))
        top_symbols = symbols[:limit]
        recommendations: list[str] = []
        if top_symbols:
            first = top_symbols[0]
            recommendations.append(
                f"Start by inspecting {first.get('path')}:{first.get('line')} ({first.get('qualified_name')}) because it is the top objective match."
            )
            if any(item.get("risk_level") != "low" for item in top_symbols[:3]):
                recommendations.append("Top matches include medium/high-risk symbols; use a narrow patch and run self-tests after edits.")
            if len(python_files) >= 250:
                recommendations.append("Search was capped at 250 Python files; narrow the path if relevant code is missing.")
        else:
            recommendations.append("No relevant Python symbols matched; fall back to semantic_search_workspace or broaden the query.")

        payload = {
            "generated_at": utc_now(),
            "objective": objective,
            "path": workspace_relative(target),
            "searched_files": len(python_files),
            "match_count": len(symbols),
            "query_terms": terms,
            "symbols": top_symbols,
            "errors": errors[:25],
            "recommendations": recommendations,
        }
        if not top_symbols:
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)

        lines: list[str] = []
        for item in top_symbols:
            lines.append(
                f"{item['path']}:{item['line']} {item['qualified_name']} [{item['kind']}, risk={item['risk_level']}, score={item['score']}]"
            )
            if item.get("reasons"):
                lines.append("  " + "; ".join(item["reasons"][:3]))
            lines.append("  " + trim_text(str(item.get("snippet", "")).replace("\n", "\n  "), 900))
        return ToolResult(True, "\n".join(lines), meta=payload)

    def run_command(self, command: str) -> ToolResult:
        lowered = command.lower().strip()
        if not lowered:
            return ToolResult(False, "Command cannot be empty.")

        dangerous_patterns = [
            r"(^|\s)(del|erase|rd|rmdir|format|diskpart)(\s|$)",
            r"(^|\s)(shutdown|restart-computer|stop-computer)(\s|$)",
            r"(^|\s)reg\s+delete(\s|$)",
            r"(^|\s)sc\s+delete(\s|$)",
            r"(^|\s)mkfs(\.|\s|$)",
            r"remove-item",
        ]
        if any(re.search(pattern, lowered) for pattern in dangerous_patterns):
            return ToolResult(False, "Blocked: potentially destructive command.")

        shell_control_tokens = ["&&", "||", ";", "|", ">", ">>", "<", "`", "$("]
        if any(token in command for token in shell_control_tokens):
            return ToolResult(False, "Blocked: shell control operators are not allowed in run_command.")

        try:
            args = shlex.split(command, posix=not sys.platform.startswith("win"))
        except ValueError as exc:
            return ToolResult(False, f"Invalid command syntax: {exc}")
        if not args:
            return ToolResult(False, "Command cannot be empty.")

        windows_shell_builtins = {"dir", "cls", "copy", "move", "type"}
        use_shell = sys.platform.startswith("win") and args[0].lower() in windows_shell_builtins

        try:
            result = subprocess.run(
                command if use_shell else args,
                shell=use_shell,
                capture_output=True,
                text=True,
                timeout=15,
                cwd=WORKSPACE_ROOT,
            )
        except FileNotFoundError:
            return ToolResult(False, f"Command not found: {args[0]}")
        except subprocess.TimeoutExpired:
            return ToolResult(False, "Command timed out after 15 seconds.")
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

    def audit_tool_coverage(self, objective: str = "", include_specs: bool = False) -> ToolResult:
        objective_text = str(objective or "").strip()
        profile = infer_task_profile(objective_text) if objective_text else {}

        risk_counts: dict[str, int] = {}
        capability_keywords = {
            "workspace_io": {"file", "path", "read", "write", "append", "replace", "diff", "json"},
            "search_and_context": {"search", "context", "semantic", "relevant", "recent", "todo"},
            "code_intelligence": {"code", "symbol", "graph", "call", "complexity", "import", "duplicate", "hotspot", "orphan", "refactor"},
            "planning_and_strategy": {"plan", "dossier", "chain", "strategy", "decompose", "readiness", "matrix", "coverage"},
            "validation": {"validate", "test", "pytest", "ruff", "smoke", "policy", "readiness"},
            "tooling_intelligence": {"tool", "schema", "capability", "coverage", "usage", "chain", "dossier"},
            "autonomy": {"self", "improve", "cycle", "checkpoint", "rollback", "experiment", "learning", "planning", "health"},
            "collaboration": {"team", "role", "subagent", "manager", "meta", "quality", "disagreement"},
            "state_and_memory": {"memory", "profile", "task", "blackboard", "history", "ledger", "config"},
            "model_routing": {"model", "provider", "route", "router", "llm", "token"},
        }
        capabilities: dict[str, list[str]] = {name: [] for name in capability_keywords}
        tool_rows: list[dict[str, Any]] = []
        for name, spec in sorted(self.tool_specs.items()):
            risk_counts[spec.risk] = risk_counts.get(spec.risk, 0) + 1
            haystack = f"{name} {spec.description}".lower()
            matched_caps: list[str] = []
            for capability, keywords in capability_keywords.items():
                if any(keyword in haystack for keyword in keywords):
                    capabilities[capability].append(name)
                    matched_caps.append(capability)
            row = {
                "name": name,
                "risk": spec.risk,
                "capabilities": matched_caps,
            }
            if include_specs:
                row["description"] = spec.description
                row["schema"] = spec.schema
            tool_rows.append(row)

        recent = self.state.tool_history[-80:]
        by_tool: dict[str, dict[str, Any]] = {}
        for event in recent:
            tool_name = str(event.get("tool", ""))
            if not tool_name:
                continue
            stats = by_tool.setdefault(tool_name, {"calls": 0, "successes": 0, "failures": 0, "last_ok": None, "last_preview": ""})
            stats["calls"] += 1
            if event.get("ok"):
                stats["successes"] += 1
            else:
                stats["failures"] += 1
            stats["last_ok"] = bool(event.get("ok"))
            stats["last_preview"] = trim_text(str(event.get("preview", "")), 180)
        for stats in by_tool.values():
            stats["success_rate"] = round(stats["successes"] / max(1, stats["calls"]), 3)

        suggested_tools = profile.get("suggested_tools", []) if profile else []
        missing_suggested_tools = [tool for tool in suggested_tools if tool not in self.tools]
        capability_gaps = [name for name, tools in capabilities.items() if not tools]

        recommendations: list[str] = []
        if objective_text:
            recommendations.append("Use recommend_tool_chain for the concrete ordered tool sequence before acting.")
        if any(item.get("failures", 0) for item in by_tool.values()):
            recommendations.append("Recent tool failures exist; prefer lower-risk read-only probes before write or command tools.")
        if "validation" not in capability_gaps:
            recommendations.append("Validation coverage is available; every code edit should finish with a compile/smoke/policy check.")
        if "code_intelligence" not in capability_gaps:
            recommendations.append("Code intelligence tools are available; use symbol impact and hotspots before refactoring shared helpers.")
        if not recommendations:
            recommendations.append("Tool registry looks broad enough for normal agentic coding and analysis work.")

        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "task_profile": profile,
            "tool_count": len(self.tool_specs),
            "risk_counts": risk_counts,
            "capabilities": {name: sorted(tools) for name, tools in capabilities.items()},
            "capability_gaps": capability_gaps,
            "suggested_tools": suggested_tools,
            "missing_suggested_tools": missing_suggested_tools,
            "recent_tool_reliability": by_tool,
            "least_recent_or_unused_tools": [name for name in sorted(self.tools) if name not in by_tool][:20],
            "recommendations": recommendations,
            "tools": tool_rows if include_specs else [row["name"] for row in tool_rows],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def recommend_tool_chain(self, objective: str, context: str = "", path: str = ".") -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        context_text = str(context or "")
        scope = workspace_relative(resolve_workspace_path(path))
        profile = infer_task_profile(f"{objective_text}\n{context_text}")
        intents = set(profile.get("intents", []))
        write_intent = bool(profile.get("write_intent"))
        risk_level = str(profile.get("risk_level", "low"))

        phases: list[dict[str, Any]] = []

        def add_phase(name: str, purpose: str, tools: list[str], gate: str = "", fallback: str = "") -> None:
            available_tools = [tool for tool in tools if tool in self.tools]
            missing_tools = [tool for tool in tools if tool not in self.tools]
            phases.append(
                {
                    "phase": len(phases) + 1,
                    "name": name,
                    "purpose": purpose,
                    "tools": available_tools,
                    "missing_tools": missing_tools,
                    "gate": gate,
                    "fallback": fallback,
                }
            )

        add_phase(
            "profile_and_scope",
            "Classify intent, estimate risk, and gather a compact workspace briefing before choosing edits.",
            ["decompose_goal", "audit_tool_coverage", "map_tool_capability_graph", "mine_tool_usage_patterns", "build_context_pack"],
            "Proceed only after the objective, path scope, and risk level are explicit.",
        )

        if "analysis" in intents or "conversation" in intents:
            add_phase(
                "evidence_search",
                "Find relevant files, memory, code symbols, TODOs, and recent workspace evidence.",
                ["semantic_search_workspace", "find_relevant_code_context", "trace_goal_to_symbols", "search_files", "summarize_python_file"],
                "Cite exact files/symbols in the next decision; do not guess from filenames alone.",
            )

        if "network_intelligence" in intents:
            add_phase(
                "network_reconnaissance",
                "Classify the network target, resolve addresses, enrich public IP ownership/context, and gate any active checks.",
                ["build_network_intel_brief", "normalize_network_target", "resolve_dns_records", "reverse_dns_lookup", "lookup_ip_rdap", "lookup_ip_geolocation", "inspect_tls_certificate", "scan_tcp_ports"],
                "Active port checks require clear authorization; public targets require allow_public=true and bounded port lists.",
                "If active checks are not authorized, return a passive DNS/RDAP/GeoIP brief only.",
            )
            if any(term in objective_text.lower() for term in ["ids", "traffic", "packet", "pcap", "suricata", "zeek", "flow", "flows", "intrusion", "beacon", "anomaly"]):
                add_phase(
                    "ids_traffic_analysis",
                    "Ingest traffic metadata, normalize flows, generate IDS-style alerts, and optionally compare against a known-good baseline.",
                    ["build_ids_mode_plan", "ingest_network_traffic_file", "analyze_network_traffic_file", "build_ids_baseline", "compare_network_baseline", "show_ids_alerts", "capture_network_metadata_sample"],
                    "Live capture requires explicit authorization and remains bounded, metadata-only, and local to owned/authorized networks.",
                    "If live capture is unavailable, analyze PCAP/Suricata EVE/Zeek/CSV/JSONL files offline.",
                )

        if "debug" in intents:
            add_phase(
                "failure_localization",
                "Localize the failure before editing by combining static symbol context with safe validation.",
                ["trace_goal_to_symbols", "find_relevant_code_context", "analyze_symbol_impact", "run_python_smoke_test", "validate_python_file"],
                "A fix is not ready until the failure surface or likely failing symbol is named.",
                "If the bug cannot be reproduced, produce a minimal diagnostic plan instead of editing broadly.",
            )

        if "implementation" in intents:
            add_phase(
                "feature_slice",
                "Select the smallest useful implementation slice and identify impacted symbols.",
                ["trace_goal_to_symbols", "find_relevant_code_context", "analyze_symbol_impact", "plan_patch_strategy", "recommend_team"],
                "Only edit after the target file and acceptance criteria are known.",
            )

        if "refactoring" in intents:
            add_phase(
                "refactor_safety",
                "Measure blast radius and hotspot risk before moving or rewriting code.",
                ["build_code_graph", "rank_code_hotspots", "trace_goal_to_symbols", "analyze_symbol_impact", "find_callers"],
                "Do not refactor a high fan-in helper without a validation plan and rollback point.",
            )

        if write_intent:
            add_phase(
                "rollback_and_patch",
                "Create rollback readiness, then apply the smallest reversible edit.",
                ["plan_patch_strategy", "create_checkpoint", "read_file", "apply_unified_diff", "replace_in_file"],
                "Use apply_unified_diff or exact replacement; avoid broad rewrites unless explicitly requested.",
                "If a patch fails, read the file around the target and retry with a narrower diff.",
            )

        if "autonomy" in intents:
            add_phase(
                "autonomy_governance",
                "Use health, planning, cycle ledger, and policy before starting or continuing self-improvement loops.",
                ["generate_health_report", "generate_planning_brief", "show_cycle_ledger", "self_improve_codebase"],
                "Autonomous loops must remain interruptible and cannot recursively call self_improve_codebase.",
            )

        if "validation" in intents or write_intent or risk_level != "low":
            add_phase(
                "validation_and_policy",
                "Validate behavior, summarize change impact, and check autonomy policy when risk is elevated.",
                ["build_validation_matrix", "validate_python_file", "validate_workspace_python", "run_self_improvement_validation", "analyze_change_impact", "evaluate_autonomy_policy", "git_diff", "score_execution_readiness"],
                "Final answer must report what validation proves and what remains untested.",
                "If validation or policy fails, restore checkpoint or report the exact blocking condition.",
            )

        add_phase(
            "final_synthesis",
            "Produce a concise final result with files changed, evidence, risks, and next action.",
            ["score_execution_readiness", "quality_gate", "meta_review", "show_history"],
            "Finish with a user-visible answer, not raw tool JSON.",
        )

        flattened_tools: list[str] = []
        for phase in phases:
            for tool in phase.get("tools", []):
                if tool not in flattened_tools:
                    flattened_tools.append(tool)

        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "scope": scope,
            "task_profile": profile,
            "phases": phases,
            "tool_sequence": flattened_tools,
            "risk_controls": {
                "write_intent": write_intent,
                "risk_level": risk_level,
                "requires_checkpoint": write_intent or "autonomy" in intents,
                "requires_policy_check": write_intent or risk_level != "low" or "autonomy" in intents,
                "requires_validation": write_intent or bool({"debug", "implementation", "refactoring", "validation", "autonomy"}.intersection(intents)),
            },
            "decision_rules": [
                "Use read-only probes first unless the user explicitly requested file changes.",
                "Escalate from direct execution to team execution when architecture, policy, or validation could disagree.",
                "Prefer one small patch plus validation over a large patch with uncertain blast radius.",
                "After any failed tool call, retry with a narrower input or switch to a lower-risk diagnostic tool.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def build_execution_dossier(self, objective: str, path: str = ".", context: str = "", limit: int = 5) -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        limit = max(1, min(int(limit), 12))
        scope = workspace_relative(resolve_workspace_path(path))

        decomposition = self.decompose_goal(goal=objective_text, context=context)
        tool_chain = self.recommend_tool_chain(objective=objective_text, context=context, path=scope)
        team = self.recommend_team(task=objective_text, context=context)
        context_pack = self.build_context_pack(objective=objective_text, path=scope, limit=limit)
        audit = self.audit_tool_coverage(objective=objective_text, include_specs=False)
        tool_schema_health = self.inspect_tool_schema_health()
        capability_graph = self.map_tool_capability_graph(objective=objective_text, include_edges=True)
        symbol_trace = self.trace_goal_to_symbols(objective=objective_text, path=scope, limit=limit)
        patch_strategy = self.plan_patch_strategy(objective=objective_text, target_path=scope, context=context, max_files=limit)
        validation_matrix = self.build_validation_matrix(objective=objective_text, changed_files=patch_strategy.meta.get("candidate_files", []) if patch_strategy.ok else [], path=scope)
        readiness = self.score_execution_readiness(objective=objective_text, context=context, changed_files=patch_strategy.meta.get("candidate_files", []) if patch_strategy.ok else [])

        role = "planner"
        if team.ok and team.meta.get("roles"):
            role = str(team.meta["roles"][0])
        route_probe_prompt = "\n\n".join(
            [
                objective_text,
                trim_text(context, 1200),
                trim_text(context_pack.content if context_pack.ok else "", 2400),
            ]
        )
        model_route = self.recommend_model_route(prompt=route_probe_prompt, role=role)
        model_selection = self.recommend_model_selection(objective=objective_text, role=role, required_context_tokens=safe_int(model_route.meta.get("estimated_input_tokens"), 0) if model_route.ok else 0, limit=5)

        risks: list[str] = []
        profile = decomposition.meta.get("task_profile", {}) if decomposition.ok else infer_task_profile(objective_text)
        if profile.get("write_intent"):
            risks.append("File-write intent detected; checkpoint and validation are required before finalizing.")
        if profile.get("risk_level") != "low":
            risks.append(f"Risk level is {profile.get('risk_level')}; policy and rollback evidence should be explicit.")
        if context_pack.ok and context_pack.meta.get("workspace", {}).get("code_hotspots", {}).get("hotspots"):
            risks.append("Code hotspots exist; avoid broad edits to high-blast-radius symbols without call impact analysis.")
        if not risks:
            risks.append("No elevated deterministic risk signals found; still validate any code changes.")

        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "scope": scope,
            "decomposition": decomposition.meta if decomposition.ok else {"error": decomposition.content},
            "recommended_team": team.meta if team.ok else {"error": team.content},
            "tool_chain": tool_chain.meta if tool_chain.ok else {"error": tool_chain.content},
            "context_pack_summary": {
                "ok": context_pack.ok,
                "semantic_matches": context_pack.meta.get("workspace", {}).get("semantic_matches", [])[:limit] if context_pack.ok else [],
                "relevant_code_symbols": context_pack.meta.get("workspace", {}).get("relevant_code_symbols", [])[:limit] if context_pack.ok else [],
                "relevant_todos": context_pack.meta.get("workspace", {}).get("relevant_todos", [])[:limit] if context_pack.ok else [],
                "recommendations": context_pack.meta.get("recommendations", []) if context_pack.ok else [],
            },
            "tool_coverage": {
                "tool_count": audit.meta.get("tool_count") if audit.ok else None,
                "capability_gaps": audit.meta.get("capability_gaps", []) if audit.ok else [],
                "risk_counts": audit.meta.get("risk_counts", {}) if audit.ok else {},
                "schema_health_ok": tool_schema_health.meta.get("schema_health_ok") if tool_schema_health.ok else None,
            },
            "capability_graph_summary": {
                "node_count": capability_graph.meta.get("node_count") if capability_graph.ok else None,
                "edge_count": capability_graph.meta.get("edge_count") if capability_graph.ok else None,
                "entrypoints": capability_graph.meta.get("entrypoints", {}) if capability_graph.ok else {},
            },
            "symbol_trace_summary": {
                "ok": symbol_trace.ok,
                "candidate_files": symbol_trace.meta.get("candidate_files", [])[:limit] if symbol_trace.ok else [],
                "candidate_symbols": symbol_trace.meta.get("candidate_symbols", [])[:limit] if symbol_trace.ok else [],
                "recommendations": symbol_trace.meta.get("recommendations", []) if symbol_trace.ok else [symbol_trace.content],
            },
            "patch_strategy_summary": {
                "ok": patch_strategy.ok,
                "candidate_files": patch_strategy.meta.get("candidate_files", []) if patch_strategy.ok else [],
                "patch_steps": patch_strategy.meta.get("patch_steps", []) if patch_strategy.ok else [],
                "rollback_plan": patch_strategy.meta.get("rollback_plan", []) if patch_strategy.ok else [],
            },
            "validation_matrix_summary": {
                "ok": validation_matrix.ok,
                "minimum_pass_set": validation_matrix.meta.get("minimum_pass_set", []) if validation_matrix.ok else [],
                "missing_tools": validation_matrix.meta.get("missing_tools", []) if validation_matrix.ok else [],
            },
            "readiness": readiness.meta if readiness.ok else {"error": readiness.content},
            "model_route": model_route.meta if model_route.ok else {"error": model_route.content},
            "model_selection": model_selection.meta if model_selection.ok else {"error": model_selection.content},
            "risks": risks,
            "acceptance_criteria": decomposition.meta.get("acceptance_criteria", []) if decomposition.ok else [],
            "next_best_action": (
                "Run the first read-only phase in the recommended tool chain, then patch only after the dossier evidence identifies a narrow target."
                if profile.get("tool_intent")
                else "Answer directly unless the user asks to inspect or modify files."
            ),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_tool_schema_health(self) -> ToolResult:
        rows: list[dict[str, Any]] = []
        issues: list[dict[str, Any]] = []
        risk_by_tool = {name: spec.risk for name, spec in self.tool_specs.items()}
        valid_risks = {
            TOOL_RISK_READ_ONLY,
            TOOL_RISK_WRITE_FILE,
            TOOL_RISK_RUN_COMMAND,
            TOOL_RISK_AGENTIC,
            TOOL_RISK_MEMORY,
            TOOL_RISK_CONTROL,
        }

        for name, spec in sorted(self.tool_specs.items()):
            try:
                signature = inspect.signature(spec.function)
                parameters = signature.parameters
            except (TypeError, ValueError) as exc:
                row = {
                    "tool": name,
                    "risk": spec.risk,
                    "schema_keys": sorted(spec.schema),
                    "signature_error": str(exc),
                    "issues": ["signature_unavailable"],
                }
                rows.append(row)
                issues.append({"tool": name, "issue": "signature_unavailable", "detail": str(exc)})
                continue

            param_names = [
                param_name
                for param_name, param in parameters.items()
                if param_name != "self" and param.kind not in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
            ]
            accepts_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters.values())
            required_params = [
                param_name
                for param_name, param in parameters.items()
                if param_name != "self"
                and param.default is inspect._empty
                and param.kind in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
            ]
            schema_keys = sorted(str(key) for key in spec.schema.keys())
            missing_required = [param for param in required_params if param not in spec.schema]
            extra_schema = [key for key in schema_keys if key not in param_names and not accepts_kwargs]
            row_issues: list[str] = []
            if missing_required:
                row_issues.append("missing_required_schema_keys")
                for param in missing_required:
                    issues.append({"tool": name, "issue": "missing_required_schema_key", "detail": param})
            if extra_schema:
                row_issues.append("extra_schema_keys")
                for key in extra_schema:
                    issues.append({"tool": name, "issue": "extra_schema_key", "detail": key})
            if spec.risk not in valid_risks:
                row_issues.append("unknown_risk_level")
                issues.append({"tool": name, "issue": "unknown_risk_level", "detail": spec.risk})
            if not spec.description.strip():
                row_issues.append("missing_description")
                issues.append({"tool": name, "issue": "missing_description", "detail": "description is empty"})
            rows.append(
                {
                    "tool": name,
                    "risk": spec.risk,
                    "parameters": param_names,
                    "required_parameters": required_params,
                    "schema_keys": schema_keys,
                    "accepts_kwargs": accepts_kwargs,
                    "issues": row_issues,
                }
            )

        severe_issues = [item for item in issues if item.get("issue") in {"missing_required_schema_key", "unknown_risk_level", "signature_unavailable"}]
        payload = {
            "generated_at": utc_now(),
            "tool_count": len(self.tool_specs),
            "schema_health_ok": not severe_issues,
            "issue_count": len(issues),
            "severe_issue_count": len(severe_issues),
            "issues": issues,
            "tools": rows,
            "risk_by_tool": risk_by_tool,
            "recommendations": [
                "Fix missing required schema keys before delegating that tool to a model."
                if severe_issues
                else "Tool schemas are aligned well enough for deterministic JSON tool calling.",
                "Treat extra schema keys as documentation drift unless the callable accepts **kwargs.",
                "Run this after adding or renaming any tool method.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def map_tool_capability_graph(self, objective: str = "", include_edges: bool = True) -> ToolResult:
        objective_text = str(objective or "").strip()
        capability_keywords = {
            "workspace_io": {"file", "path", "read", "write", "append", "replace", "diff", "json", "checkpoint", "restore"},
            "search_and_context": {"search", "context", "semantic", "relevant", "recent", "todo", "trace", "scope"},
            "code_intelligence": {"code", "symbol", "graph", "call", "complexity", "import", "duplicate", "hotspot", "orphan", "refactor"},
            "planning_and_strategy": {"plan", "dossier", "chain", "strategy", "decompose", "readiness", "matrix", "coverage"},
            "validation": {"validate", "test", "pytest", "ruff", "smoke", "policy", "quality", "readiness"},
            "autonomy": {"self", "improve", "cycle", "checkpoint", "rollback", "experiment", "learning", "planning", "health"},
            "collaboration": {"team", "role", "subagent", "manager", "meta", "quality", "disagreement"},
            "state_and_memory": {"memory", "profile", "task", "blackboard", "history", "ledger", "config", "usage"},
            "model_routing": {"model", "provider", "route", "router", "llm", "token"},
            "tooling_intelligence": {"tool", "schema", "capability", "coverage", "usage", "chain", "dossier"},
        }
        nodes: dict[str, dict[str, Any]] = {}
        capabilities: dict[str, list[str]] = {capability: [] for capability in capability_keywords}
        for name, spec in sorted(self.tool_specs.items()):
            haystack = f"{name} {spec.description} {' '.join(map(str, spec.schema.keys()))}".lower()
            matched = [
                capability
                for capability, keywords in capability_keywords.items()
                if any(keyword in haystack for keyword in keywords)
            ]
            if not matched:
                matched = ["uncategorized"]
            for capability in matched:
                capabilities.setdefault(capability, []).append(name)
            nodes[name] = {
                "risk": spec.risk,
                "capabilities": matched,
                "description": spec.description,
            }

        chain_tools: list[str] = []
        phases: list[dict[str, Any]] = []
        if objective_text:
            chain = self.recommend_tool_chain(objective=objective_text, path=".")
            if chain.ok:
                chain_tools = list(chain.meta.get("tool_sequence", []))
                phases = list(chain.meta.get("phases", []))

        edges: list[dict[str, Any]] = []
        if include_edges:
            for first, second in zip(chain_tools, chain_tools[1:]):
                edges.append({"from": first, "to": second, "kind": "recommended_sequence", "objective": objective_text})
            default_edges = [
                ("decompose_goal", "build_context_pack", "scope_to_context"),
                ("build_context_pack", "trace_goal_to_symbols", "context_to_targets"),
                ("trace_goal_to_symbols", "plan_patch_strategy", "targets_to_patch_plan"),
                ("plan_patch_strategy", "create_checkpoint", "patch_plan_to_rollback"),
                ("create_checkpoint", "apply_unified_diff", "rollback_to_patch"),
                ("apply_unified_diff", "build_validation_matrix", "patch_to_validation_plan"),
                ("build_validation_matrix", "run_self_improvement_validation", "validation_plan_to_execution"),
                ("run_self_improvement_validation", "score_execution_readiness", "validation_to_readiness"),
                ("score_execution_readiness", "quality_gate", "readiness_to_final_gate"),
            ]
            for source, target, kind in default_edges:
                if source in self.tools and target in self.tools:
                    edge = {"from": source, "to": target, "kind": kind}
                    if edge not in edges:
                        edges.append(edge)

        entrypoints = {
            "analysis": [tool for tool in ["build_execution_dossier", "decompose_goal", "build_context_pack", "semantic_search_workspace"] if tool in self.tools],
            "implementation": [tool for tool in ["build_execution_dossier", "trace_goal_to_symbols", "plan_patch_strategy", "create_checkpoint"] if tool in self.tools],
            "debug": [tool for tool in ["trace_goal_to_symbols", "analyze_symbol_impact", "run_python_smoke_test", "build_validation_matrix"] if tool in self.tools],
            "validation": [tool for tool in ["build_validation_matrix", "run_self_improvement_validation", "score_execution_readiness", "quality_gate"] if tool in self.tools],
            "autonomy": [tool for tool in ["generate_health_report", "generate_planning_brief", "show_cycle_ledger", "evaluate_autonomy_policy"] if tool in self.tools],
        }
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "capabilities": {name: sorted(values) for name, values in capabilities.items()},
            "uncategorized": capabilities.get("uncategorized", []),
            "entrypoints": entrypoints,
            "objective_tool_sequence": chain_tools,
            "objective_phases": phases,
            "edges": edges,
            "nodes": nodes,
            "recommendations": [
                "Start with an entrypoint tool instead of ad hoc file reads for complex goals.",
                "Use capability graph edges as a default route, not as a hard rule; user instructions still dominate.",
                "Prefer read-only planning and tracing tools before write-file or shell-command tools.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def mine_tool_usage_patterns(self, limit: int = 120) -> ToolResult:
        limit = max(1, min(int(limit), 500))
        history_events = [
            {
                "time": item.get("time"),
                "tool": item.get("tool"),
                "ok": bool(item.get("ok")),
                "source": "state.tool_history",
                "preview": item.get("preview", ""),
            }
            for item in self.state.tool_history[-limit:]
            if item.get("tool")
        ]
        run_events: list[dict[str, Any]] = []
        for event in load_run_events(limit=limit):
            payload = event.get("payload", {}) if isinstance(event.get("payload"), dict) else {}
            if event.get("event") == "tool_executed" and payload.get("tool"):
                run_events.append(
                    {
                        "time": event.get("time"),
                        "tool": payload.get("tool"),
                        "ok": bool(payload.get("ok")),
                        "source": "run_log",
                        "preview": payload.get("preview", ""),
                    }
                )
        events = sorted([*history_events, *run_events], key=lambda item: str(item.get("time") or ""))[-limit:]
        stats: dict[str, dict[str, Any]] = {}
        transitions: dict[str, dict[str, Any]] = {}
        for event in events:
            tool = str(event.get("tool", ""))
            if not tool:
                continue
            bucket = stats.setdefault(tool, {"calls": 0, "successes": 0, "failures": 0, "sources": set()})
            bucket["calls"] += 1
            bucket["sources"].add(str(event.get("source", "")))
            if event.get("ok"):
                bucket["successes"] += 1
            else:
                bucket["failures"] += 1
        for first, second in zip(events, events[1:]):
            first_tool = str(first.get("tool", ""))
            second_tool = str(second.get("tool", ""))
            if not first_tool or not second_tool:
                continue
            key = f"{first_tool} -> {second_tool}"
            bucket = transitions.setdefault(key, {"from": first_tool, "to": second_tool, "count": 0, "success_after": 0, "failure_after": 0})
            bucket["count"] += 1
            if second.get("ok"):
                bucket["success_after"] += 1
            else:
                bucket["failure_after"] += 1

        normalized_stats = []
        for tool, bucket in stats.items():
            calls = max(1, int(bucket.get("calls", 0)))
            normalized_stats.append(
                {
                    "tool": tool,
                    "calls": bucket["calls"],
                    "successes": bucket["successes"],
                    "failures": bucket["failures"],
                    "success_rate": round(bucket["successes"] / calls, 3),
                    "sources": sorted(bucket.get("sources", [])),
                }
            )
        normalized_stats.sort(key=lambda item: (-int(item["calls"]), item["tool"]))
        transition_rows = list(transitions.values())
        for row in transition_rows:
            row["success_after_rate"] = round(row["success_after"] / max(1, row["count"]), 3)
        transition_rows.sort(key=lambda item: (-int(item["count"]), -float(item["success_after_rate"]), item["from"], item["to"]))

        unreliable = [row for row in normalized_stats if row["calls"] >= 2 and row["success_rate"] < 0.75]
        reliable = [row for row in normalized_stats if row["calls"] >= 2 and row["success_rate"] >= 0.9]
        payload = {
            "generated_at": utc_now(),
            "event_count": len(events),
            "tool_stats": normalized_stats,
            "top_transitions": transition_rows[:20],
            "reliable_tools": reliable[:15],
            "unreliable_tools": unreliable[:15],
            "recommendations": [
                "Prefer reliable read-only tools early in a turn; reserve unreliable or high-risk tools for after narrowing context.",
                "Repeated failed transitions indicate a prompt/tool schema mismatch or overly broad task decomposition."
                if unreliable
                else "No recurring unreliable tool pattern detected in the sampled history.",
                "Use this together with inspect_tool_schema_health when a model keeps calling tools incorrectly.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def trace_goal_to_symbols(self, objective: str, path: str = ".", limit: int = 5) -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        limit = max(1, min(int(limit), 12))
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")

        semantic = self.semantic_search_workspace(objective_text, workspace_relative(target), limit=limit, max_file_chars=16000)
        code = self.find_relevant_code_context(objective_text, workspace_relative(target), limit=limit)
        graph = self.build_code_graph(workspace_relative(target), recursive=target.is_dir())
        symbol_rows: list[dict[str, Any]] = []
        if code.ok:
            for symbol in code.meta.get("symbols", [])[:limit]:
                name = str(symbol.get("name") or symbol.get("qualified_name") or "")
                qualified_name = str(symbol.get("qualified_name") or name)
                impact = self.analyze_symbol_impact(name) if name else ToolResult(False, "No symbol name.")
                symbol_rows.append(
                    {
                        "path": symbol.get("path"),
                        "line": symbol.get("line"),
                        "kind": symbol.get("kind"),
                        "name": name,
                        "qualified_name": qualified_name,
                        "score": symbol.get("score"),
                        "risk_level": symbol.get("risk_level"),
                        "line_count": symbol.get("line_count"),
                        "decision_points": symbol.get("decision_points"),
                        "call_count": symbol.get("call_count"),
                        "impact": impact.meta if impact.ok else {"ok": False, "error": impact.content},
                        "reasons": symbol.get("reasons", []),
                    }
                )

        candidate_files: dict[str, dict[str, Any]] = {}
        if semantic.ok:
            for match in semantic.meta.get("matches", [])[:limit]:
                rel = str(match.get("path", ""))
                if rel:
                    candidate_files.setdefault(rel, {"path": rel, "semantic_score": match.get("score"), "snippets": []})
                    candidate_files[rel]["snippets"] = match.get("snippets", [])[:2]
        for symbol in symbol_rows:
            rel = str(symbol.get("path", ""))
            if rel:
                row = candidate_files.setdefault(rel, {"path": rel, "semantic_score": None, "snippets": []})
                row.setdefault("symbols", []).append(
                    {
                        "name": symbol.get("qualified_name"),
                        "line": symbol.get("line"),
                        "score": symbol.get("score"),
                        "risk_level": symbol.get("risk_level"),
                    }
                )

        recommendations: list[str] = []
        if symbol_rows:
            top = symbol_rows[0]
            recommendations.append(f"Inspect {top.get('path')}:{top.get('line')} ({top.get('qualified_name')}) first; it is the top code-symbol match.")
            if any(str(row.get("impact", {}).get("risk_level", row.get("risk_level"))) in {"medium", "high"} for row in symbol_rows[:3]):
                recommendations.append("At least one top target has non-low impact; use plan_patch_strategy before editing.")
        elif candidate_files:
            top_path = next(iter(candidate_files))
            recommendations.append(f"No Python symbol dominated; inspect semantically matched file {top_path} first.")
        else:
            recommendations.append("No strong workspace target found; broaden the query or ask for a more specific file/path.")
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "path": workspace_relative(target),
            "semantic_search_ok": semantic.ok,
            "code_context_ok": code.ok,
            "code_graph_ok": graph.ok,
            "candidate_files": list(candidate_files.values())[:limit],
            "candidate_symbols": symbol_rows,
            "recommendations": recommendations,
            "errors": [
                {"tool": "semantic_search_workspace", "error": semantic.content} if not semantic.ok else {},
                {"tool": "find_relevant_code_context", "error": code.content} if not code.ok else {},
                {"tool": "build_code_graph", "error": graph.content} if not graph.ok else {},
            ],
        }
        ok = bool(candidate_files or symbol_rows)
        return ToolResult(ok, json.dumps(payload, indent=2), meta=payload)

    def build_validation_matrix(
        self,
        objective: str = "",
        changed_files: list[str] | str | None = None,
        path: str = ".",
        risk_level: str = "",
    ) -> ToolResult:
        objective_text = str(objective or "").strip()
        profile = infer_task_profile(objective_text) if objective_text else {"intents": [], "risk_level": "low", "write_intent": False}
        resolved_risk = str(risk_level or profile.get("risk_level") or "low")
        if isinstance(changed_files, str):
            raw_files = [item.strip() for item in re.split(r"[,\n]", changed_files) if item.strip()]
        else:
            raw_files = [str(item).strip() for item in (changed_files or []) if str(item).strip()]
        target = resolve_workspace_path(path)
        scoped_path = workspace_relative(target)

        file_rows: list[dict[str, Any]] = []
        suffixes: set[str] = set()
        for raw in raw_files:
            try:
                resolved = resolve_workspace_path(raw)
                rel = workspace_relative(resolved)
            except Exception:
                rel = raw
                resolved = WORKSPACE_ROOT / raw
            suffix = Path(rel).suffix.lower()
            suffixes.add(suffix)
            file_rows.append(
                {
                    "path": rel,
                    "suffix": suffix,
                    "exists": resolved.exists(),
                    "is_python": suffix == ".py",
                    "is_json": suffix == ".json",
                    "is_agent_control_plane": Path(rel).name.startswith(".agent_") or Path(rel).name == Path(active_agent_file()).name,
                }
            )

        matrix: list[dict[str, Any]] = []

        def add_check(name: str, tool: str, purpose: str, when: str, blocking: bool, evidence_strength: str, args: dict[str, Any]) -> None:
            matrix.append(
                {
                    "order": len(matrix) + 1,
                    "name": name,
                    "tool": tool,
                    "purpose": purpose,
                    "when": when,
                    "blocking": blocking,
                    "evidence_strength": evidence_strength,
                    "args": args,
                    "available": tool in self.tools,
                }
            )

        python_files = [row["path"] for row in file_rows if row.get("is_python")]
        json_files = [row["path"] for row in file_rows if row.get("is_json")]
        add_check("inspect_status", "git_status", "Capture current workspace state before trusting validation.", "always", False, "low", {})
        if python_files:
            for file_path in python_files[:8]:
                add_check("compile_python_file", "validate_python_file", f"Compile-check {file_path}.", "changed Python file", True, "medium", {"path": file_path})
        elif ".py" in suffixes or target.suffix.lower() == ".py" or target.is_dir():
            add_check("compile_python_scope", "validate_workspace_python", "Compile-check Python files in scope.", "Python scope or unknown changed Python set", True, "medium", {"path": scoped_path, "recursive": target.is_dir()})
        if json_files:
            for file_path in json_files[:8]:
                add_check("validate_json_file", "validate_json_file", f"Parse-check {file_path}.", "changed JSON file", True, "medium", {"path": file_path})
        if any(Path(row["path"]).name.startswith("agent") and row["suffix"] == ".py" for row in file_rows) or "implementation" in profile.get("intents", []) or "refactoring" in profile.get("intents", []):
            add_check("internal_self_tests", "run_internal_self_tests", "Run deterministic control-plane tests after agent changes.", "agent/control-plane change", True, "high", {})
        if profile.get("write_intent") or raw_files:
            add_check("self_improvement_validation", "run_self_improvement_validation", "Run compile/smoke/optional pytest/ruff and diff status.", "after file edits", True, "high", {"path": scoped_path})
            add_check("diff_review", "git_diff", "Review exact patch before final answer.", "after file edits", True, "medium", {"path": scoped_path})
        if resolved_risk != "low" or profile.get("write_intent"):
            add_check("policy_check", "evaluate_autonomy_policy", "Check change impact against autonomy risk budget.", "medium/high risk or file-write intent", True, "high", {"impact": {"risk_level": resolved_risk}, "changed_files": raw_files})
        add_check("final_readiness", "score_execution_readiness", "Verify evidence, target clarity, validation, and rollback readiness before finalizing.", "before final answer", True, "medium", {"objective": objective_text, "changed_files": raw_files})

        missing_tools = sorted({row["tool"] for row in matrix if not row["available"]})
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "path": scoped_path,
            "risk_level": resolved_risk,
            "changed_files": file_rows,
            "matrix": matrix,
            "missing_tools": missing_tools,
            "minimum_pass_set": [row["name"] for row in matrix if row["blocking"]],
            "recommendations": [
                "Execute blocking checks after patching and before summarizing success.",
                "For Python agent changes, compile plus run_internal_self_tests is the minimum useful validation.",
                "If policy_check fails, restore checkpoint or reduce the patch scope before continuing.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def plan_patch_strategy(self, objective: str, target_path: str = ".", context: str = "", max_files: int = 3) -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        max_files = max(1, min(int(max_files), 10))
        target = resolve_workspace_path(target_path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {target_path}")
        profile = infer_task_profile(f"{objective_text}\n{context}")
        trace = self.trace_goal_to_symbols(objective_text, workspace_relative(target), limit=max_files)
        chain = self.recommend_tool_chain(objective_text, context=context, path=workspace_relative(target))

        candidate_files: list[str] = []
        if trace.ok:
            for row in trace.meta.get("candidate_symbols", []):
                rel = str(row.get("path", ""))
                if rel and rel not in candidate_files:
                    candidate_files.append(rel)
            for row in trace.meta.get("candidate_files", []):
                rel = str(row.get("path", ""))
                if rel and rel not in candidate_files:
                    candidate_files.append(rel)
        if not candidate_files and target.is_file():
            candidate_files.append(workspace_relative(target))
        candidate_files = candidate_files[:max_files]
        validation = self.build_validation_matrix(objective_text, changed_files=candidate_files, path=workspace_relative(target), risk_level=str(profile.get("risk_level", "low")))

        patch_steps: list[dict[str, Any]] = [
            {
                "step": 1,
                "action": "create_checkpoint",
                "tool": "create_checkpoint",
                "args": {"label": "before-targeted-patch"},
                "reason": "Make rollback concrete before any write.",
            },
            {
                "step": 2,
                "action": "read_targets",
                "tool": "read_file",
                "args": {"path": candidate_files[0] if candidate_files else workspace_relative(target)},
                "reason": "Inspect exact current content around the intended edit.",
            },
            {
                "step": 3,
                "action": "patch_minimal_slice",
                "tool": "apply_unified_diff",
                "args": {"diff": "<minimal unified diff against selected target files>"},
                "reason": "Prefer a reviewable diff over full-file overwrite.",
            },
            {
                "step": 4,
                "action": "validate_blocking_checks",
                "tool": "build_validation_matrix",
                "args": {"objective": objective_text, "changed_files": candidate_files, "path": workspace_relative(target)},
                "reason": "Run the blocking checks from the returned matrix, not just the easiest check.",
            },
            {
                "step": 5,
                "action": "review_diff_and_readiness",
                "tool": "score_execution_readiness",
                "args": {"objective": objective_text, "changed_files": candidate_files},
                "reason": "Confirm evidence and validation are sufficient before finalizing.",
            },
        ]
        rollback_plan = [
            "Use restore_checkpoint with preserve_agent_state=True if compile/tests fail after the patch.",
            "If a tool call fails because the target was too broad, retry against one file or symbol at a time.",
            "Report partial progress honestly if validation cannot be executed.",
        ]
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "target_path": workspace_relative(target),
            "task_profile": profile,
            "candidate_files": candidate_files,
            "candidate_symbols": trace.meta.get("candidate_symbols", [])[:max_files] if trace.ok else [],
            "tool_chain": chain.meta if chain.ok else {"error": chain.content},
            "validation_matrix": validation.meta if validation.ok else {"error": validation.content},
            "patch_steps": patch_steps,
            "rollback_plan": rollback_plan,
            "edit_policy": {
                "max_files": max_files,
                "prefer_unified_diff": True,
                "avoid_full_rewrite": True,
                "requires_checkpoint": bool(profile.get("write_intent", True)),
                "requires_validation": True,
            },
            "recommendations": [
                "Patch only the first target unless evidence proves multiple files must change.",
                "Name the acceptance criterion that each edit satisfies before applying the diff.",
                "Do not claim success until the validation matrix blocking checks have passed or their limits are disclosed.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def score_execution_readiness(
        self,
        objective: str,
        context: str = "",
        candidate: str = "",
        changed_files: list[str] | str | None = None,
    ) -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        profile = infer_task_profile(f"{objective_text}\n{context}")
        if isinstance(changed_files, str):
            changed = [item.strip() for item in re.split(r"[,\n]", changed_files) if item.strip()]
        else:
            changed = [str(item).strip() for item in (changed_files or []) if str(item).strip()]
        context_text = str(context or "")
        candidate_text = str(candidate or "")
        tool_names_in_context = {name for name in self.tools if name in context_text or name in candidate_text}
        validation_terms = {"validated", "validation", "compile", "py_compile", "pytest", "ruff", "smoke", "self-tests", "self tests", "passed"}
        rollback_terms = {"checkpoint", "rollback", "restore", "reversible", "diff"}
        target_terms = {"file", "path", "symbol", "function", "class", ".py", ".json"}

        gates: list[dict[str, Any]] = []

        def add_gate(name: str, passed: bool, weight: int, detail: str) -> None:
            gates.append({"name": name, "passed": bool(passed), "weight": weight, "detail": detail})

        add_gate("objective_present", bool(objective_text), 2, "A concrete objective is required.")
        add_gate("tool_intent_routed", (not profile.get("tool_intent")) or bool(tool_names_in_context) or bool(changed), 1, "Complex/tool tasks should show evidence of tool routing or changed targets.")
        add_gate("target_clarity", bool(changed) or any(term in context_text.lower() or term in candidate_text.lower() for term in target_terms), 2, "Implementation work needs named files, paths, or symbols.")
        add_gate("rollback_readiness", (not profile.get("write_intent")) or any(term in context_text.lower() or term in candidate_text.lower() for term in rollback_terms), 2, "Write work should mention checkpoint/diff/rollback readiness.")
        add_gate("validation_evidence", (not profile.get("write_intent")) or any(term in context_text.lower() or term in candidate_text.lower() for term in validation_terms), 3, "Write work should include validation evidence or an explicit limitation.")
        add_gate("scope_control", len(changed) <= load_autonomy_policy().get("max_changed_files_per_cycle", 4), 2, "Changed-file count should stay inside policy budget.")
        add_gate("final_candidate_present", bool(candidate_text) or bool(changed) or not profile.get("write_intent"), 1, "A final answer or concrete change evidence should exist before finalizing.")

        possible = sum(int(gate["weight"]) for gate in gates)
        earned = sum(int(gate["weight"]) for gate in gates if gate["passed"])
        score = round(earned / max(1, possible), 3)
        failed_gates = [gate for gate in gates if not gate["passed"]]
        if score >= 0.85 and not failed_gates:
            decision = "ready"
        elif score >= 0.65:
            decision = "proceed_with_caution"
        else:
            decision = "not_ready"
        next_actions: list[str] = []
        for gate in failed_gates:
            if gate["name"] == "target_clarity":
                next_actions.append("Run trace_goal_to_symbols or build_context_pack to identify concrete files/symbols.")
            elif gate["name"] == "rollback_readiness":
                next_actions.append("Create a checkpoint and prefer apply_unified_diff before editing.")
            elif gate["name"] == "validation_evidence":
                next_actions.append("Run the blocking checks from build_validation_matrix.")
            elif gate["name"] == "tool_intent_routed":
                next_actions.append("Run build_execution_dossier or recommend_tool_chain before acting.")
            elif gate["name"] == "scope_control":
                next_actions.append("Reduce changed files or update autonomy policy intentionally.")
        if not next_actions:
            next_actions.append("Proceed to quality_gate or final synthesis with explicit validation notes.")
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "task_profile": profile,
            "changed_files": changed,
            "score": score,
            "decision": decision,
            "gates": gates,
            "failed_gates": failed_gates,
            "observed_tool_names": sorted(tool_names_in_context),
            "next_actions": next_actions,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)


    def route_multi_model_task(
        self,
        objective: str,
        path: str = ".",
        prefer: str = "",
        required_context_tokens: int = 0,
        refresh: bool = False,
    ) -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        scope = workspace_relative(resolve_workspace_path(path))
        profile = infer_task_profile(objective_text)
        team = self.recommend_team(task=objective_text, context=f"scope={scope}\nprefer={prefer}")
        roles = [role for role in team.meta.get("roles", []) if role in ROLE_CATALOG] if team.ok else []
        if not roles:
            roles = ["planner", "coder", "reviewer"]
        chain = self.recommend_tool_chain(objective=objective_text, context=prefer, path=scope)
        phases = chain.meta.get("phases", []) if chain.ok else []
        required_context = safe_int(required_context_tokens, 0)
        if required_context <= 0:
            probe = self.recommend_model_route(prompt=objective_text + "\n" + prefer, role=roles[0])
            required_context = safe_int(probe.meta.get("estimated_input_tokens"), 0) if probe.ok else 0

        role_routes: dict[str, Any] = {}
        for role in roles:
            role_prefer_terms = " ".join([prefer, "coding" if role in {"coder", "refactorer", "tester", "reviewer"} else "reasoning"]).strip()
            recommendation = self.recommend_model_selection(
                objective=objective_text,
                role=role,
                required_context_tokens=required_context,
                prefer=role_prefer_terms,
                limit=5,
                refresh=refresh,
            )
            role_routes[role] = recommendation.meta if recommendation.ok else {"error": recommendation.content}

        phase_routes: list[dict[str, Any]] = []
        for phase in phases:
            phase_name = str(phase.get("phase", phase.get("name", "phase")))
            phase_tools = [str(tool) for tool in phase.get("tools", [])]
            phase_role = "planner"
            if any(tool in phase_tools for tool in ["apply_unified_diff", "replace_in_file", "write_file"]):
                phase_role = "coder"
            elif any(tool in phase_tools for tool in ["run_self_improvement_validation", "build_validation_matrix", "quality_gate"]):
                phase_role = "tester"
            elif any(tool in phase_tools for tool in ["evaluate_autonomy_policy", "create_checkpoint", "restore_checkpoint"]):
                phase_role = "safety"
            elif any(tool in phase_tools for tool in ["semantic_search_workspace", "find_relevant_code_context", "trace_goal_to_symbols"]):
                phase_role = "researcher"
            if phase_role not in roles:
                phase_role = roles[0]
            chosen = role_routes.get(phase_role, {})
            rec = chosen.get("recommendation", {}) if isinstance(chosen, dict) else {}
            phase_routes.append(
                {
                    "phase": phase_name,
                    "tools": phase_tools,
                    "assigned_role": phase_role,
                    "provider": rec.get("provider"),
                    "model": rec.get("model"),
                    "model_score": rec.get("score"),
                    "why": rec.get("reasons", [])[:4] if isinstance(rec, dict) else [],
                }
            )

        portfolio = self.build_model_portfolio(objective=objective_text, refresh=refresh)
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "scope": scope,
            "task_profile": profile,
            "recommended_team": team.meta if team.ok else {"error": team.content},
            "required_context_tokens": required_context,
            "role_routes": role_routes,
            "phase_routes": phase_routes,
            "portfolio": portfolio.meta.get("portfolio", {}) if portfolio.ok else {"error": portfolio.content},
            "execution_policy": [
                "Use the strongest reasoning model for planning, safety, and final synthesis.",
                "Use coding-specialized models for patch generation and code review.",
                "Use fast/cheap/local models for broad search, summaries, and low-risk drafting.",
                "Keep provider/model selection explicit in the run log when a route changes.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_runtime_environment(self, include_packages: bool = True, include_env: bool = True) -> ToolResult:
        import importlib.util
        import platform

        config = load_config()
        provider_env: dict[str, Any] = {}
        if include_env:
            for provider, settings in config.get("llm_providers", {}).items():
                if not isinstance(settings, dict):
                    continue
                env_name = str(settings.get("api_key_env", "")).strip()
                inline_key = bool(str(settings.get("api_key", "")).strip())
                provider_env[str(provider)] = {
                    "api_key_env": env_name,
                    "env_present": bool(env_name and os.environ.get(env_name)),
                    "inline_key_present": inline_key,
                    "base_url": settings.get("base_url", ""),
                    "type": settings.get("type", ""),
                    "model": settings.get("model", ""),
                }

        package_names = [
            "openai",
            "anthropic",
            "pytest",
            "ruff",
            "requests",
            "pydantic",
            "numpy",
            "tiktoken",
            "rich",
        ]
        packages = {}
        if include_packages:
            for name in package_names:
                spec = importlib.util.find_spec(name)
                packages[name] = {
                    "available": spec is not None,
                    "origin": trim_text(str(getattr(spec, "origin", "") or ""), 200) if spec else "",
                }

        payload = {
            "generated_at": utc_now(),
            "python": {
                "version": sys.version,
                "executable": sys.executable,
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
            },
            "workspace": {
                "root": str(WORKSPACE_ROOT),
                "cwd": str(Path.cwd()),
                "config_file_exists": CONFIG_FILE.exists(),
                "memory_file_exists": MEMORY_FILE.exists(),
                "model_catalog_file_exists": MODEL_CATALOG_FILE.exists(),
                "git_dir_exists": (WORKSPACE_ROOT / ".git").exists(),
            },
            "providers": provider_env,
            "packages": packages,
            "recommendations": [
                "Set provider API keys as environment variables rather than inline config values.",
                "Install optional provider SDKs only for providers you actively route to.",
                "Use discover_available_models after setting provider credentials to refresh the model catalog.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def audit_dependency_health(self, path: str = ".", recursive: bool = True, limit: int = 200) -> ToolResult:
        import importlib.util

        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        limit = max(1, min(int(limit), 1000))
        files = iter_python_source_files(target, recursive=bool(recursive), max_files=limit)
        local_modules = {file.stem for file in iter_python_source_files(WORKSPACE_ROOT, recursive=True, max_files=1000)}
        stdlib = set(getattr(sys, "stdlib_module_names", set()))
        imports: dict[str, dict[str, Any]] = {}
        parse_errors: list[dict[str, Any]] = []
        for file in files:
            text = read_text_sample(file, 400000)
            try:
                tree = ast.parse(text)
            except SyntaxError as exc:
                parse_errors.append({"path": workspace_relative(file), "line": exc.lineno, "error": str(exc)})
                continue
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.level and node.level > 0:
                        continue
                    names = [node.module.split(".")[0]]
                for name in names:
                    if not name:
                        continue
                    entry = imports.setdefault(name, {"count": 0, "files": set()})
                    entry["count"] += 1
                    entry["files"].add(workspace_relative(file))

        rows: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []
        for name, data in sorted(imports.items()):
            is_local = name in local_modules
            is_stdlib = name in stdlib or name in {"__future__"}
            available = is_local or is_stdlib or importlib.util.find_spec(name) is not None
            row = {
                "module": name,
                "count": data["count"],
                "files": sorted(data["files"])[:20],
                "classification": "local" if is_local else "stdlib" if is_stdlib else "third_party",
                "available": available,
            }
            rows.append(row)
            if not available:
                missing.append(row)

        dependency_files = []
        for filename in ["requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "uv.lock", "environment.yml"]:
            candidate = WORKSPACE_ROOT / filename
            if candidate.exists():
                dependency_files.append({"path": filename, "size": candidate.stat().st_size})
        optional_missing = [name for name in ["openai", "anthropic", "pytest", "ruff", "tiktoken"] if importlib.util.find_spec(name) is None]
        payload = {
            "generated_at": utc_now(),
            "scope": workspace_relative(target),
            "files_scanned": len(files),
            "import_count": len(rows),
            "imports": rows,
            "missing_modules": missing,
            "parse_errors": parse_errors,
            "dependency_files": dependency_files,
            "optional_missing": optional_missing,
            "health": "needs_attention" if missing or parse_errors else "ok",
            "recommendations": [
                "If a missing module is intentional because it is optional, keep the guarded import and improve the error message.",
                "For local-agent portability, prefer standard-library fallbacks for optional validation tools.",
                "Keep dependency declarations aligned with imports used by default execution paths.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_prompt_surface(self, include_snippets: bool = False) -> ToolResult:
        prompt_sources = {
            "SYSTEM_PROMPT": SYSTEM_PROMPT,
            "MANAGER_POLICY_PROMPT": MANAGER_POLICY_PROMPT,
            "META_AGENT_PROMPT": META_AGENT_PROMPT,
            "DISAGREEMENT_AGENT_PROMPT": DISAGREEMENT_AGENT_PROMPT,
            "QUALITY_GATE_PROMPT": QUALITY_GATE_PROMPT,
            "SELF_IMPROVEMENT_REVIEW_PROMPT": SELF_IMPROVEMENT_REVIEW_PROMPT,
        }
        for role in ROLE_CATALOG:
            prompt_sources[f"ROLE_PROMPT::{role}"] = build_role_system_prompt(role)

        tool_mentions: dict[str, list[str]] = {name: [] for name in self.tool_specs}
        rows: list[dict[str, Any]] = []
        issues: list[str] = []
        for name, prompt in prompt_sources.items():
            mentioned = [tool for tool in self.tool_specs if tool in prompt]
            for tool in mentioned:
                tool_mentions[tool].append(name)
            tokens = estimate_token_count(prompt)
            row = {
                "prompt": name,
                "chars": len(prompt),
                "estimated_tokens": tokens,
                "tool_mentions": mentioned[:40],
                "json_only_mentions": prompt.lower().count("json"),
                "workspace_mentions": prompt.lower().count("workspace"),
            }
            if include_snippets:
                row["snippet"] = trim_text(prompt, 700)
            rows.append(row)
            if tokens > 6000:
                issues.append(f"{name} is large ({tokens} estimated tokens); consider compacting or moving details into tools.")
            if "json" not in prompt.lower() and name != "SELF_IMPROVEMENT_REVIEW_PROMPT":
                issues.append(f"{name} may not clearly reinforce JSON tool-call format.")

        unmentioned_tools = sorted(tool for tool, prompts in tool_mentions.items() if not prompts)
        high_risk_unmentioned = [tool for tool in unmentioned_tools if self.tool_specs[tool].risk != TOOL_RISK_READ_ONLY]
        payload = {
            "generated_at": utc_now(),
            "prompt_count": len(rows),
            "prompts": rows,
            "unmentioned_tools": unmentioned_tools,
            "high_risk_unmentioned_tools": high_risk_unmentioned,
            "issues": issues,
            "recommendations": [
                "Keep high-risk tool guidance explicit in manager/system prompts.",
                "Mention new high-level planning tools in the system prompt so the manager discovers them before low-level writes.",
                "When prompt size grows, move repeated policy text into deterministic tools and cite tool outputs instead.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def build_context_budget_plan(
        self,
        objective: str,
        path: str = ".",
        role: str = "planner",
        provider: str = "",
        model: str = "",
        max_input_tokens: int = 0,
    ) -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        scope = workspace_relative(resolve_workspace_path(path))
        role = str(role or "planner")
        if role not in ROLE_CATALOG:
            role = "planner"
        context_pack = self.build_context_pack(objective=objective_text, path=scope, limit=6)
        route_probe = self.recommend_model_route(
            prompt=objective_text + "\n\n" + (context_pack.content if context_pack.ok else ""),
            role=role,
            provider=provider,
            model=model,
        )
        estimated_tokens = safe_int(route_probe.meta.get("estimated_input_tokens"), 0) if route_probe.ok else estimate_token_count(objective_text)
        budget = safe_int(max_input_tokens, 0) or safe_int(route_probe.meta.get("input_token_budget"), 0) if route_probe.ok else 0
        if budget <= 0:
            budget = 7600
        reserve = max(512, int(budget * 0.15))
        available_for_context = max(256, budget - reserve - estimate_token_count(objective_text))
        sections = [
            {"name": "system_and_tool_prompt", "priority": 1, "estimated_tokens": 1200, "strategy": "keep stable; do not duplicate tool specs inside user context"},
            {"name": "objective_and_acceptance_criteria", "priority": 1, "estimated_tokens": estimate_token_count(objective_text) + 120, "strategy": "keep verbatim"},
            {"name": "target_symbols_and_files", "priority": 2, "estimated_tokens": min(1200, max(300, available_for_context // 3)), "strategy": "use trace_goal_to_symbols snippets first"},
            {"name": "workspace_context_pack", "priority": 3, "estimated_tokens": min(2400, max(500, available_for_context // 2)), "strategy": "compact middle; keep recommendations and top matches"},
            {"name": "recent_history_and_state", "priority": 4, "estimated_tokens": min(1000, max(200, available_for_context // 6)), "strategy": "summarize rather than include raw logs"},
            {"name": "validation_and_risk", "priority": 2, "estimated_tokens": min(1000, max(300, available_for_context // 5)), "strategy": "include only blocking checks and risk register top items"},
        ]
        section_total = sum(item["estimated_tokens"] for item in sections)
        over_budget = section_total + reserve > budget
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "scope": scope,
            "role": role,
            "route_probe": route_probe.meta if route_probe.ok else {"error": route_probe.content},
            "budget": {
                "max_input_tokens": budget,
                "estimated_full_prompt_tokens": estimated_tokens,
                "reserved_output_and_margin_tokens": reserve,
                "available_for_context_tokens": available_for_context,
                "section_total_tokens": section_total,
                "over_budget": over_budget,
            },
            "sections": sections,
            "compaction_plan": [
                "Keep objective, acceptance criteria, and selected file paths verbatim.",
                "Use top-ranked snippets rather than full files unless the target is small.",
                "Collapse run history, blackboard, and memory into bullet summaries.",
                "If still over budget, run compact_messages_for_input_budget before model call.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def propose_test_plan_for_symbol(self, symbol: str, path: str = ".", objective: str = "", limit: int = 8) -> ToolResult:
        symbol_text = str(symbol or "").strip()
        if not symbol_text:
            return ToolResult(False, "Symbol cannot be empty.")
        limit = max(1, min(int(limit), 25))
        scope = workspace_relative(resolve_workspace_path(path))
        symbol_result = self.find_symbol(symbol_text)
        impact = self.analyze_symbol_impact(symbol_text)
        semantic = self.semantic_search_workspace(query=f"{symbol_text} {objective}", path=scope, limit=limit)
        candidate_files = []
        for item in symbol_result.meta.get("matches", []) if symbol_result.ok else []:
            candidate_files.append(item.get("path"))
        for item in semantic.meta.get("matches", []) if semantic.ok else []:
            candidate_files.append(item.get("path"))
        candidate_files = [file for file in dict.fromkeys(str(item) for item in candidate_files if item)][:limit]
        test_cases = [
            {"case": "happy_path", "purpose": f"Call {symbol_text} with representative valid input and assert the expected output shape."},
            {"case": "empty_or_minimal_input", "purpose": f"Verify {symbol_text} handles empty strings, empty lists, None, or missing optional values as intended."},
            {"case": "invalid_input", "purpose": f"Confirm {symbol_text} fails safely or returns a clear ToolResult error for invalid inputs."},
            {"case": "regression_context", "purpose": "Use the objective-specific scenario as a regression fixture once the bug/feature is understood."},
        ]
        if impact.ok and impact.meta.get("risk_level") in {"medium", "high"}:
            test_cases.append({"case": "call_graph_regression", "purpose": "Exercise at least one caller because impact analysis shows non-trivial fan-in/fan-out."})
        commands = []
        if candidate_files:
            commands.append(f"python -m py_compile {shlex.quote(candidate_files[0])}")
        commands.extend([
            "python -m pytest -q  # if tests exist",
            "python -m ruff check .  # optional style/static check when ruff is installed",
            "python agent.py --self-test  # if this script exposes the internal test flag in your local copy",
        ])
        payload = {
            "generated_at": utc_now(),
            "symbol": symbol_text,
            "objective": str(objective or ""),
            "scope": scope,
            "candidate_files": candidate_files,
            "symbol_matches": symbol_result.meta.get("matches", []) if symbol_result.ok else [],
            "impact": impact.meta if impact.ok else {"error": impact.content},
            "test_cases": test_cases,
            "validation_commands": commands,
            "recommendations": [
                "Start with a compile/smoke check before writing a full test harness.",
                "Prefer regression tests around public tool methods and parser/control-plane helpers.",
                "For agent tools, assert ToolResult.ok, important meta keys, and stable error behavior.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def simulate_tool_execution_plan(self, objective: str, path: str = ".", context: str = "") -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        scope = workspace_relative(resolve_workspace_path(path))
        chain = self.recommend_tool_chain(objective=objective_text, context=context, path=scope)
        phases = chain.meta.get("phases", []) if chain.ok else []
        schema_health = self.inspect_tool_schema_health()
        schema_issues_by_tool: dict[str, list[str]] = {}
        for issue in schema_health.meta.get("issues", []) if schema_health.ok else []:
            schema_issues_by_tool.setdefault(str(issue.get("tool", "")), []).append(str(issue.get("issue", "")))
        simulated_steps: list[dict[str, Any]] = []
        step = 0
        for phase in phases:
            for tool in phase.get("tools", []):
                tool = str(tool)
                spec = self.tool_specs.get(tool)
                step += 1
                simulated_steps.append(
                    {
                        "step": step,
                        "phase": phase.get("phase", phase.get("name", "")),
                        "tool": tool,
                        "risk": spec.risk if spec else "unknown",
                        "schema": spec.schema if spec else {},
                        "preconditions": [
                            "Tool is registered and schema is healthy." if not schema_issues_by_tool.get(tool) else f"Resolve schema issues: {schema_issues_by_tool[tool]}",
                            "Use workspace-relative paths only." if spec and "path" in spec.schema else "No path precondition detected.",
                            "Checkpoint exists before write/control action." if spec and spec.risk in {TOOL_RISK_WRITE_FILE, TOOL_RISK_CONTROL} else "Read-only or non-write step.",
                        ],
                        "expected_evidence": "Structured ToolResult with ok/content/meta; preserve important meta keys for the next step.",
                        "fallback": "Retry with narrower args, inspect schema, or switch to read-only diagnostic tool if this fails.",
                    }
                )
        risk_counts: dict[str, int] = {}
        for item in simulated_steps:
            risk_counts[item["risk"]] = risk_counts.get(item["risk"], 0) + 1
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "scope": scope,
            "context_preview": trim_text(context, 800),
            "source_chain": chain.meta if chain.ok else {"error": chain.content},
            "risk_counts": risk_counts,
            "simulated_steps": simulated_steps,
            "stop_conditions": [
                "Stop before write/control tools if checkpoint or target clarity is missing.",
                "Stop after validation failure and either roll back or narrow the patch.",
                "Stop if tool schema health reports severe issues for a planned tool.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def build_risk_register(
        self,
        objective: str,
        path: str = ".",
        context: str = "",
        changed_files: list[str] | str | None = None,
    ) -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        scope = workspace_relative(resolve_workspace_path(path))
        if isinstance(changed_files, str):
            changed = [item.strip() for item in re.split(r"[,\n]", changed_files) if item.strip()]
        else:
            changed = [str(item).strip() for item in (changed_files or []) if str(item).strip()]
        profile = infer_task_profile(f"{objective_text}\n{context}")
        policy = self.evaluate_autonomy_policy({"risk_level": profile.get("risk_level", "low")}, changed or [scope])
        validation = self.build_validation_matrix(objective=objective_text, changed_files=changed, path=scope, risk_level=str(profile.get("risk_level", "low")))
        hotspots = self.rank_code_hotspots(path=scope, recursive=Path(scope).suffix == "")
        risks: list[dict[str, Any]] = []

        def add_risk(name: str, category: str, likelihood: str, impact: str, trigger: str, mitigation: str, owner: str, gate: str) -> None:
            risks.append(
                {
                    "name": name,
                    "category": category,
                    "likelihood": likelihood,
                    "impact": impact,
                    "trigger": trigger,
                    "mitigation": mitigation,
                    "owner": owner,
                    "validation_gate": gate,
                }
            )

        if profile.get("write_intent"):
            add_risk("Unreversible edit", "rollback", "medium", "high", "write intent detected", "Create checkpoint and prefer unified diff", "safety", "checkpoint exists before write")
            add_risk("Behavior regression", "correctness", "medium", "high", "code modification", "Run compile/smoke/self-tests and inspect diff", "tester", "blocking validation matrix passes")
        if profile.get("risk_level") != "low":
            add_risk("Scope creep", "autonomy", "medium", "medium", f"task risk={profile.get('risk_level')}", "Limit changed files and ask policy gate to approve", "planner", "evaluate_autonomy_policy returns allow")
        if changed and len(changed) > load_autonomy_policy().get("max_changed_files_per_cycle", 4):
            add_risk("Changed-file budget exceeded", "policy", "high", "high", f"changed_files={len(changed)}", "Split into separate cycles", "maintainer", "changed file count within policy")
        hotspot_items = hotspots.meta.get("hotspots", []) if hotspots.ok else []
        if hotspot_items:
            add_risk("High-blast-radius symbol", "code_hotspot", "medium", "medium", "hotspots detected in target scope", "Run analyze_symbol_impact before editing shared helpers", "architect", "call impact understood")
        if not risks:
            add_risk("Unknown unknowns", "general", "low", "medium", "no deterministic risk signals", "Use read-only probes and state residual uncertainty", "reviewer", "quality_gate records residual risk")
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "scope": scope,
            "changed_files": changed,
            "task_profile": profile,
            "policy_decision": policy.meta if policy.ok else {"error": policy.content},
            "validation_matrix": validation.meta if validation.ok else {"error": validation.content},
            "hotspot_preview": hotspot_items[:5],
            "risks": risks,
            "top_mitigations": [
                "Checkpoint before write/control actions.",
                "Keep the patch to the smallest target file/symbol.",
                "Run the validation matrix and report any unexecuted checks.",
                "Use quality_gate before finalizing high-risk or autonomous work.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)


    def map_repository_structure(self, path: str = ".", max_depth: int = 3, include_hidden: bool = False) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        max_depth = max(0, min(safe_int(max_depth, 3), 12))
        root = target if target.is_dir() else target.parent
        root_depth = len(root.relative_to(WORKSPACE_ROOT).parts) if root != WORKSPACE_ROOT else 0
        extension_counts: dict[str, int] = {}
        directory_counts: dict[str, int] = {}
        important_files: list[dict[str, Any]] = []
        tree: list[dict[str, Any]] = []
        important_names = {
            "pyproject.toml", "requirements.txt", "requirements-dev.txt", "setup.py", "setup.cfg",
            "package.json", "tsconfig.json", "dockerfile", "docker-compose.yml", "compose.yml",
            "makefile", "readme.md", "license", ".env", ".env.example", ".gitignore",
            "pytest.ini", "tox.ini", "ruff.toml", ".pre-commit-config.yaml", "agent.py",
        }

        def hidden_or_generated(item: Path) -> bool:
            parts = item.relative_to(WORKSPACE_ROOT).parts if item.is_relative_to(WORKSPACE_ROOT) else item.parts
            if any(part.startswith(".") for part in parts if part not in {"."}):
                return True
            return any(part in {"__pycache__", "node_modules", "dist", "build", ".venv", "venv", ".git"} for part in parts)

        candidates = [target] if target.is_file() else list(target.rglob("*"))
        for item in sorted(candidates, key=lambda value: workspace_relative(value)):
            if should_skip_checkpoint_path(item):
                continue
            rel = workspace_relative(item)
            if not include_hidden and hidden_or_generated(item):
                continue
            item_depth = max(0, len(item.relative_to(WORKSPACE_ROOT).parts) - root_depth - (0 if item.is_dir() else 1))
            if item_depth > max_depth:
                continue
            if item.is_dir():
                try:
                    child_count = sum(1 for _ in item.iterdir())
                except OSError:
                    child_count = 0
                directory_counts[rel] = child_count
                tree.append({"path": rel, "type": "dir", "depth": item_depth, "children": child_count})
            elif item.is_file():
                suffix = item.suffix.lower() or "[no extension]"
                extension_counts[suffix] = extension_counts.get(suffix, 0) + 1
                try:
                    size = item.stat().st_size
                except OSError:
                    size = 0
                row = {"path": rel, "type": "file", "depth": item_depth, "size": size, "extension": suffix}
                tree.append(row)
                lowered_name = item.name.lower()
                if lowered_name in important_names or lowered_name.startswith(("readme", "license")):
                    important_files.append(row)
        architecture_hints: list[str] = []
        top_dirs = sorted(directory_counts.items(), key=lambda item: (-item[1], item[0]))[:10]
        if extension_counts.get(".py", 0):
            architecture_hints.append("Python codebase detected; use extract_api_surface, inspect_project_entrypoints, and trace_data_flow before refactors.")
        if any(item["path"].endswith("pyproject.toml") for item in important_files):
            architecture_hints.append("pyproject.toml present; inspect_config_surface can reveal packaging, tooling, and script metadata.")
        if any("test" in item["path"].lower() for item in tree):
            architecture_hints.append("Test-like paths detected; use propose_test_plan_for_symbol and run_pytest for validation planning/execution.")
        if not architecture_hints:
            architecture_hints.append("No strong architecture signal found; start with read-only mapping and semantic search.")
        payload = {
            "generated_at": utc_now(),
            "root": workspace_relative(root),
            "max_depth": max_depth,
            "include_hidden": bool(include_hidden),
            "extension_counts": dict(sorted(extension_counts.items(), key=lambda item: (-item[1], item[0]))),
            "top_directories": [{"path": key, "children": value} for key, value in top_dirs],
            "important_files": important_files[:40],
            "tree": tree[:300],
            "tree_truncated": len(tree) > 300,
            "architecture_hints": architecture_hints,
            "recommended_next_tools": ["inspect_project_entrypoints", "extract_api_surface", "inspect_config_surface", "build_context_pack"],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_project_entrypoints(self, path: str = ".", recursive: bool = True, limit: int = 120) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        limit = max(1, min(safe_int(limit, 120), 500))
        py_files = iter_python_source_files(target, recursive=bool(recursive), max_files=limit)
        entrypoints: list[dict[str, Any]] = []
        common_launch_files: list[dict[str, Any]] = []
        for name in ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Makefile", "Dockerfile", "docker-compose.yml", "compose.yml", "package.json"]:
            for candidate in (target.rglob(name) if target.is_dir() else [target] if target.name == name else []):
                if candidate.is_file() and not should_skip_checkpoint_path(candidate):
                    common_launch_files.append({"path": workspace_relative(candidate), "kind": name})
        script_hints: list[str] = []
        for config_file in common_launch_files[:20]:
            file_path = resolve_workspace_path(config_file["path"])
            sample = read_text_sample(file_path, max_chars=5000)
            if file_path.name == "pyproject.toml":
                for line in sample.splitlines():
                    stripped = line.strip()
                    if stripped and "=" in stripped and not stripped.startswith("#") and any(section in sample for section in ["[project.scripts]", "[tool.poetry.scripts]"]):
                        if re.match(r"[A-Za-z0-9_.-]+\s*=", stripped):
                            script_hints.append(f"{workspace_relative(file_path)}: {stripped}")
            elif file_path.name in {"Makefile", "setup.py", "package.json"}:
                for line in sample.splitlines()[:80]:
                    if any(term in line.lower() for term in ["script", "entry", "console", "python", "pytest", "run"]):
                        script_hints.append(f"{workspace_relative(file_path)}: {line.strip()}")
        for file_path in py_files:
            source = read_text_sample(file_path, max_chars=80000)
            try:
                tree = ast.parse(source)
            except SyntaxError as exc:
                entrypoints.append({"path": workspace_relative(file_path), "kind": "syntax_error", "line": exc.lineno, "detail": exc.msg})
                continue
            lines = source.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in {"main", "cli", "run", "app", "create_app"}:
                    entrypoints.append({
                        "path": workspace_relative(file_path),
                        "kind": "function",
                        "name": node.name,
                        "line": getattr(node, "lineno", 0),
                        "signature": f"{node.name}(...)" if not hasattr(ast, "unparse") else trim_text(f"{node.name}{ast.unparse(node.args)}", 200),
                    })
                if isinstance(node, ast.If):
                    test_src = ""
                    try:
                        test_src = ast.unparse(node.test)
                    except Exception:
                        test_src = ""
                    if "__name__" in test_src and "__main__" in test_src:
                        calls = sorted({ast_call_name(child.func) for child in ast.walk(node) if isinstance(child, ast.Call) and ast_call_name(child.func)})
                        snippet = trim_text("\n".join(lines[max(0, getattr(node, "lineno", 1)-1): min(len(lines), getattr(node, "lineno", 1)+8)]), 800)
                        entrypoints.append({
                            "path": workspace_relative(file_path),
                            "kind": "main_guard",
                            "line": getattr(node, "lineno", 0),
                            "calls": calls[:20],
                            "snippet": snippet,
                        })
        recommendations = [
            "Use inspect_config_surface to verify script metadata before changing CLI behavior.",
            "Use trace_data_flow on main/cli/run_agent before touching execution flow.",
        ]
        payload = {
            "generated_at": utc_now(),
            "scope": workspace_relative(target),
            "python_files_scanned": len(py_files),
            "entrypoints": entrypoints[:limit],
            "common_launch_files": common_launch_files[:80],
            "script_hints": script_hints[:80],
            "recommendations": recommendations,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def extract_api_surface(self, path: str = ".", recursive: bool = True, include_private: bool = False, limit: int = 120) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        limit = max(1, min(safe_int(limit, 120), 1000))
        files = iter_python_source_files(target, recursive=bool(recursive), max_files=limit)
        modules: list[dict[str, Any]] = []
        total_symbols = 0

        def arg_signature(node: ast.arguments) -> str:
            if not hasattr(ast, "unparse"):
                return "(...)"
            try:
                return "(" + ", ".join(ast.unparse(arg) for arg in node.args) + (
                    (", *" + node.vararg.arg) if node.vararg else ""
                ) + (
                    (", **" + node.kwarg.arg) if node.kwarg else ""
                ) + ")"
            except Exception:
                return "(...)"

        for file_path in files:
            source = read_text_sample(file_path, max_chars=200000)
            try:
                tree = ast.parse(source)
            except SyntaxError as exc:
                modules.append({"path": workspace_relative(file_path), "error": f"SyntaxError line {exc.lineno}: {exc.msg}", "symbols": []})
                continue
            symbols: list[dict[str, Any]] = []
            imports: list[str] = []
            for node in tree.body:
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    imports.extend(f"{module}.{alias.name}" if module else alias.name for alias in node.names)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not include_private and node.name.startswith("_"):
                        continue
                    symbols.append({
                        "kind": "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                        "name": node.name,
                        "line": getattr(node, "lineno", 0),
                        "signature": f"{node.name}{arg_signature(node.args)}",
                        "doc": trim_text((ast.get_docstring(node) or "").splitlines()[0] if ast.get_docstring(node) else "", 200),
                        "decision_points": ast_decision_points(node),
                        "public": not node.name.startswith("_"),
                    })
                elif isinstance(node, ast.ClassDef):
                    if not include_private and node.name.startswith("_"):
                        continue
                    methods: list[dict[str, Any]] = []
                    for child in node.body:
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if not include_private and child.name.startswith("_") and child.name not in {"__init__", "__call__"}:
                                continue
                            methods.append({
                                "name": child.name,
                                "line": getattr(child, "lineno", 0),
                                "signature": f"{child.name}{arg_signature(child.args)}",
                                "doc": trim_text((ast.get_docstring(child) or "").splitlines()[0] if ast.get_docstring(child) else "", 160),
                                "decision_points": ast_decision_points(child),
                            })
                    symbols.append({
                        "kind": "class",
                        "name": node.name,
                        "line": getattr(node, "lineno", 0),
                        "bases": [ast_call_name(base) if not hasattr(ast, "unparse") else ast.unparse(base) for base in node.bases],
                        "doc": trim_text((ast.get_docstring(node) or "").splitlines()[0] if ast.get_docstring(node) else "", 200),
                        "methods": methods,
                        "method_count": len(methods),
                        "public": not node.name.startswith("_"),
                    })
            total_symbols += len(symbols)
            modules.append({
                "path": workspace_relative(file_path),
                "imports": sorted(set(imports))[:80],
                "symbol_count": len(symbols),
                "symbols": symbols[:80],
            })
        payload = {
            "generated_at": utc_now(),
            "scope": workspace_relative(target),
            "files_scanned": len(files),
            "symbol_count": total_symbols,
            "include_private": bool(include_private),
            "modules": modules[:limit],
            "recommended_next_tools": ["find_symbol", "analyze_symbol_impact", "trace_data_flow", "propose_test_plan_for_symbol"],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def trace_data_flow(self, objective: str, symbol: str = "", path: str = ".", limit: int = 8) -> ToolResult:
        objective_text = str(objective or "").strip()
        symbol_text = str(symbol or "").strip()
        if not objective_text and not symbol_text:
            return ToolResult(False, "Objective or symbol is required.")
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        limit = max(1, min(safe_int(limit, 8), 50))
        terms = set(search_terms(" ".join([objective_text, symbol_text])))
        files = iter_python_source_files(target, recursive=target.is_dir(), max_files=250)
        flows: list[dict[str, Any]] = []
        for file_path in files:
            source = read_text_sample(file_path, max_chars=220000)
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            imports: list[str] = []
            for node in tree.body:
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.extend(f"{node.module or ''}.{alias.name}".strip(".") for alias in node.names)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                name = getattr(node, "name", "")
                haystack = f"{name} {workspace_relative(file_path)} {ast.get_docstring(node) or ''}".lower()
                if symbol_text and name != symbol_text and symbol_text.lower() not in haystack:
                    continue
                if not symbol_text and terms and not any(term in haystack for term in terms):
                    continue
                args: list[str] = []
                assignments: list[str] = []
                returns: list[str] = []
                calls: list[str] = []
                raises: list[str] = []
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = [arg.arg for arg in node.args.args]
                for child in ast.walk(node):
                    if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                        targets = []
                        raw_targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                        for target_node in raw_targets:
                            if isinstance(target_node, ast.Name):
                                targets.append(target_node.id)
                            elif isinstance(target_node, ast.Attribute):
                                targets.append(ast_call_name(target_node))
                        assignments.extend(targets)
                    elif isinstance(child, ast.Return):
                        try:
                            returns.append(trim_text(ast.unparse(child.value), 160) if child.value is not None and hasattr(ast, "unparse") else "return")
                        except Exception:
                            returns.append("return")
                    elif isinstance(child, ast.Call):
                        call_name = ast_call_name(child.func)
                        if call_name:
                            calls.append(call_name)
                    elif isinstance(child, ast.Raise):
                        try:
                            raises.append(trim_text(ast.unparse(child.exc), 160) if child.exc is not None and hasattr(ast, "unparse") else "raise")
                        except Exception:
                            raises.append("raise")
                flows.append({
                    "path": workspace_relative(file_path),
                    "kind": "class" if isinstance(node, ast.ClassDef) else "function",
                    "name": name,
                    "line": getattr(node, "lineno", 0),
                    "inputs": args[:20],
                    "assignments": sorted(set(assignments))[:40],
                    "returns": returns[:20],
                    "calls": sorted(set(calls))[:80],
                    "raises": raises[:20],
                    "imports": sorted(set(imports))[:40],
                    "decision_points": ast_decision_points(node),
                })
                if len(flows) >= limit:
                    break
            if len(flows) >= limit:
                break
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "symbol": symbol_text,
            "scope": workspace_relative(target),
            "flows": flows,
            "recommendations": [
                "Use analyze_symbol_impact for call-graph blast radius before editing a shared function.",
                "Use propose_test_plan_for_symbol to turn observed inputs/returns/raises into regression cases.",
                "Treat this as an approximate static trace; dynamic behavior still needs tests or smoke runs.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_error_log(self, path: str = "", text: str = "", limit: int = 40) -> ToolResult:
        source_label = "inline_text"
        body = str(text or "")
        if path:
            target = resolve_workspace_path(path)
            if not target.is_file():
                return ToolResult(False, f"File not found: {path}")
            body = target.read_text(encoding="utf-8", errors="replace")
            source_label = workspace_relative(target)
        if not body.strip():
            return ToolResult(False, "Provide either path or text containing a traceback/log.")
        limit = max(1, min(safe_int(limit, 40), 200))
        lines = body.splitlines()
        exception_matches = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Warning|Interrupt|Exit)):\s*(.*)$", body)
        frames: list[dict[str, Any]] = []
        frame_re = re.compile(r'^\s*File "([^"]+)", line (\d+), in ([^\s]+)')
        for index, line in enumerate(lines):
            match = frame_re.search(line)
            if match:
                snippet = lines[index + 1].strip() if index + 1 < len(lines) else ""
                frames.append({"file": match.group(1), "line": int(match.group(2)), "function": match.group(3), "snippet": snippet})
        missing_modules = sorted(set(re.findall(r"No module named ['\"]([^'\"]+)['\"]", body)))
        file_not_found = sorted(set(re.findall(r"No such file or directory: ['\"]([^'\"]+)['\"]", body)))
        permission_denied = "Permission denied" in body or "Access is denied" in body
        recommendations: list[str] = []
        if missing_modules:
            recommendations.append("Install or route around missing modules, then rerun audit_dependency_health.")
        if frames:
            recommendations.append("Use trace_data_flow or propose_test_plan_for_symbol on the deepest project frame.")
        if file_not_found:
            recommendations.append("Inspect path assumptions with inspect_path and list_files.")
        if permission_denied:
            recommendations.append("Avoid privilege escalation; choose a workspace-safe path or narrower command.")
        if not recommendations:
            recommendations.append("Search the log terms with semantic_search_workspace and reproduce with a smoke test.")
        payload = {
            "generated_at": utc_now(),
            "source": source_label,
            "line_count": len(lines),
            "exceptions": [{"type": kind, "message": message} for kind, message in exception_matches[-limit:]],
            "frames": frames[-limit:],
            "deepest_frame": frames[-1] if frames else None,
            "missing_modules": missing_modules,
            "missing_files": file_not_found,
            "permission_denied": permission_denied,
            "recommendations": recommendations,
            "preview_tail": "\n".join(lines[-min(len(lines), 30):]),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_config_surface(self, path: str = ".", include_preview: bool = True, preview_lines: int = 8) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        preview_lines = max(0, min(safe_int(preview_lines, 8), 40))
        config_names = {
            ".env", ".env.example", ".env.local", ".gitignore", ".pre-commit-config.yaml",
            "pyproject.toml", "requirements.txt", "requirements-dev.txt", "setup.py", "setup.cfg",
            "tox.ini", "pytest.ini", "ruff.toml", "mypy.ini", "package.json", "tsconfig.json",
            "Dockerfile", "docker-compose.yml", "compose.yml", "Makefile", "README.md",
        }
        config_suffixes = {".toml", ".ini", ".cfg", ".yaml", ".yml", ".json", ".env"}
        secret_re = re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|authorization|bearer|private[_-]?key)\s*([:=])\s*([^\s#]+)")
        files = [target] if target.is_file() else list(target.rglob("*"))
        rows: list[dict[str, Any]] = []
        for item in sorted(files, key=lambda value: workspace_relative(value)):
            if not item.is_file() or should_skip_checkpoint_path(item):
                continue
            name = item.name
            suffix = item.suffix.lower()
            if name not in config_names and suffix not in config_suffixes:
                continue
            sample = read_text_sample(item, max_chars=12000)
            redacted = secret_re.sub(lambda match: f"{match.group(1)}{match.group(2)}<redacted>", sample)
            row = {
                "path": workspace_relative(item),
                "size": item.stat().st_size if item.exists() else 0,
                "kind": name if name in config_names else suffix,
                "line_count": len(sample.splitlines()),
                "secret_like_values_redacted": sample != redacted,
            }
            if include_preview:
                row["preview"] = "\n".join(redacted.splitlines()[:preview_lines])
            rows.append(row)
        payload = {
            "generated_at": utc_now(),
            "scope": workspace_relative(target),
            "config_file_count": len(rows),
            "files": rows[:160],
            "truncated": len(rows) > 160,
            "recommendations": [
                "Use this before changing provider, model, package, or test configuration.",
                "Secret-like values are redacted in previews, but avoid pasting full config into model prompts when unnecessary.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def _url_is_allowed_for_fetch(self, url: str, allow_local: bool = False) -> tuple[bool, str, urllib.parse.ParseResult | None]:
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as exc:
            return False, f"Invalid URL: {exc}", None
        if parsed.scheme not in {"http", "https"}:
            return False, "Only http and https URLs are allowed.", parsed
        host = parsed.hostname or ""
        if not host:
            return False, "URL must include a host.", parsed
        if allow_local:
            return True, "allowed", parsed
        lowered = host.lower()
        if lowered in {"localhost", "127.0.0.1", "0.0.0.0", "::1"} or lowered.endswith(".local"):
            return False, "Local/private hosts are denied unless allow_local=true.", parsed
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                address = info[4][0]
                ip = ipaddress.ip_address(address)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    return False, "Local/private network addresses are denied unless allow_local=true.", parsed
        except Exception:
            # DNS failures will be reported by the actual request; do not leak resolver detail here.
            pass
        return True, "allowed", parsed

    def fetch_url_text(self, url: str, max_chars: int = 6000, timeout: int = 10, allow_local: bool = False) -> ToolResult:
        url_text = str(url or "").strip()
        allowed, reason, parsed = self._url_is_allowed_for_fetch(url_text, allow_local=bool(allow_local))
        if not allowed:
            return ToolResult(False, reason)
        max_chars = max(200, min(safe_int(max_chars, 6000), 50000))
        timeout = max(1, min(safe_int(timeout, 10), 30))
        headers = {"User-Agent": "Cerebro-Agent/1.0 (+bounded-text-fetch)", "Accept": "text/*, application/json, application/xml;q=0.8, */*;q=0.2"}
        try:
            request = urllib.request.Request(url_text, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content_type = response.headers.get("content-type", "")
                raw = response.read(max_chars + 1)
                status = getattr(response, "status", None)
        except urllib.error.HTTPError as exc:
            detail = exc.read(min(max_chars, 2000)).decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
            return ToolResult(False, f"HTTP {exc.code}: {trim_text(detail, 1000)}")
        except Exception as exc:
            return ToolResult(False, f"URL fetch failed: {trim_text(str(exc), 600)}")
        truncated = len(raw) > max_chars
        raw = raw[:max_chars]
        text = raw.decode("utf-8", errors="replace")
        payload = {
            "generated_at": utc_now(),
            "url": url_text,
            "host": parsed.hostname if parsed else "",
            "status": status,
            "content_type": content_type,
            "chars_returned": len(text),
            "truncated": truncated,
            "text": text,
            "recommendations": ["Summarize or cite only the relevant portions; do not paste large pages into follow-up prompts unnecessarily."],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_http_endpoint(self, url: str, timeout: int = 10, allow_local: bool = False) -> ToolResult:
        url_text = str(url or "").strip()
        allowed, reason, parsed = self._url_is_allowed_for_fetch(url_text, allow_local=bool(allow_local))
        if not allowed:
            return ToolResult(False, reason)
        timeout = max(1, min(safe_int(timeout, 10), 30))
        headers = {"User-Agent": "Cerebro-Agent/1.0 (+endpoint-inspection)", "Accept": "*/*"}
        try:
            request = urllib.request.Request(url_text, headers=headers, method="HEAD")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = {
                    "generated_at": utc_now(),
                    "url": url_text,
                    "host": parsed.hostname if parsed else "",
                    "status": getattr(response, "status", None),
                    "reason": getattr(response, "reason", ""),
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                    "method": "HEAD",
                }
        except urllib.error.HTTPError as exc:
            payload = {
                "generated_at": utc_now(),
                "url": url_text,
                "host": parsed.hostname if parsed else "",
                "status": exc.code,
                "reason": str(exc.reason),
                "headers": {key.lower(): value for key, value in exc.headers.items()} if exc.headers else {},
                "method": "HEAD",
                "error": trim_text(str(exc), 600),
            }
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)
        except Exception as exc:
            return ToolResult(False, f"Endpoint inspection failed: {trim_text(str(exc), 600)}")
        payload["recommendations"] = ["Use fetch_url_text only when body content is needed and keep max_chars bounded."]
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)


    def fetch_json_api(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, Any] | None = None,
        body: Any = None,
        max_chars: int = 20000,
        timeout: int = 10,
        allow_local: bool = False,
    ) -> ToolResult:
        url_text = str(url or "").strip()
        allowed, reason, parsed = self._url_is_allowed_for_fetch(url_text, allow_local=bool(allow_local))
        if not allowed:
            return ToolResult(False, reason)

        method_text = str(method or "GET").upper().strip()
        if method_text not in {"GET", "POST"}:
            return ToolResult(False, "Only GET and POST JSON API calls are supported.")
        max_chars = max(200, min(safe_int(max_chars, 20000), 250000))
        timeout = max(1, min(safe_int(timeout, 10), 30))

        request_headers = {
            "User-Agent": "Cerebro-Agent/1.0 (+bounded-json-api)",
            "Accept": "application/json, text/json;q=0.9, */*;q=0.2",
        }
        if isinstance(headers, dict):
            for key, value in headers.items():
                key_text = str(key).strip()
                if not key_text:
                    continue
                if key_text.lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
                    request_headers[key_text] = "<redacted>"
                else:
                    request_headers[key_text] = str(value)

        data: bytes | None = None
        body_preview: Any = None
        if method_text == "POST":
            request_headers.setdefault("Content-Type", "application/json")
            body_value = {} if body is None else body
            try:
                data = json.dumps(body_value).encode("utf-8")
                body_preview = body_value if len(data) <= 2000 else "<body too large to preview>"
            except TypeError as exc:
                return ToolResult(False, f"Body is not JSON-serializable: {exc}")

        send_headers = {
            key: (str(value) if value != "<redacted>" else "")
            for key, value in request_headers.items()
        }
        try:
            request = urllib.request.Request(url_text, data=data, headers=send_headers, method=method_text)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content_type = response.headers.get("content-type", "")
                raw = response.read(max_chars + 1)
                status = getattr(response, "status", None)
        except urllib.error.HTTPError as exc:
            raw = exc.read(min(max_chars + 1, 50000)) if hasattr(exc, "read") else b""
            text = raw[:max_chars].decode("utf-8", errors="replace")
            payload = {
                "generated_at": utc_now(),
                "url": url_text,
                "host": parsed.hostname if parsed else "",
                "method": method_text,
                "status": exc.code,
                "reason": str(exc.reason),
                "headers": {key.lower(): value for key, value in exc.headers.items()} if exc.headers else {},
                "text_preview": trim_text(text, 4000),
                "truncated": len(raw) > max_chars,
            }
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)
        except Exception as exc:
            return ToolResult(False, f"JSON API request failed: {trim_text(str(exc), 600)}")

        truncated = len(raw) > max_chars
        text = raw[:max_chars].decode("utf-8", errors="replace")
        parsed_json: Any = None
        parse_error = ""
        try:
            parsed_json = json.loads(text)
        except json.JSONDecodeError as exc:
            parse_error = f"line {exc.lineno}, column {exc.colno}: {exc.msg}"

        payload = {
            "generated_at": utc_now(),
            "url": url_text,
            "host": parsed.hostname if parsed else "",
            "method": method_text,
            "status": status,
            "content_type": content_type,
            "request_headers": request_headers,
            "body_preview": body_preview,
            "chars_returned": len(text),
            "truncated": truncated,
            "json": parsed_json,
            "json_parse_error": parse_error,
            "text_preview": "" if parsed_json is not None else trim_text(text, 8000),
            "recommendations": [
                "Use this for small documentation, status, metadata, and OSINT APIs.",
                "Do not send secrets in headers or body; authorization-like headers are redacted from logs.",
            ],
        }
        return ToolResult(parsed_json is not None, json.dumps(payload, indent=2), meta=payload)


    def extract_html_metadata(
        self,
        url: str,
        max_chars: int = 100000,
        timeout: int = 10,
        allow_local: bool = False,
        link_limit: int = 100,
    ) -> ToolResult:
        url_text = str(url or "").strip()
        allowed, reason, parsed = self._url_is_allowed_for_fetch(url_text, allow_local=bool(allow_local))
        if not allowed:
            return ToolResult(False, reason)
        max_chars = max(1000, min(safe_int(max_chars, 100000), 500000))
        timeout = max(1, min(safe_int(timeout, 10), 30))
        link_limit = max(0, min(safe_int(link_limit, 100), 1000))

        headers = {
            "User-Agent": "Cerebro-Agent/1.0 (+bounded-html-metadata)",
            "Accept": "text/html, application/xhtml+xml;q=0.9, */*;q=0.1",
        }
        try:
            request = urllib.request.Request(url_text, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content_type = response.headers.get("content-type", "")
                status = getattr(response, "status", None)
                final_url = response.geturl()
                raw = response.read(max_chars + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(min(max_chars, 4000)).decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
            return ToolResult(False, f"HTTP {exc.code}: {trim_text(detail, 1000)}")
        except Exception as exc:
            return ToolResult(False, f"HTML metadata fetch failed: {trim_text(str(exc), 600)}")

        truncated = len(raw) > max_chars
        text = raw[:max_chars].decode("utf-8", errors="replace")

        class MetadataParser(html.parser.HTMLParser):
            def __init__(self) -> None:
                super().__init__(convert_charrefs=True)
                self.title_parts: list[str] = []
                self.in_title = False
                self.links: list[dict[str, str]] = []
                self.metas: list[dict[str, str]] = []
                self.headings: list[dict[str, str]] = []
                self.canonical = ""
                self._heading_tag = ""
                self._heading_parts: list[str] = []

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                tag = tag.lower()
                attr = {str(k).lower(): str(v or "") for k, v in attrs}
                if tag == "title":
                    self.in_title = True
                elif tag == "meta":
                    key = attr.get("name") or attr.get("property") or attr.get("http-equiv")
                    content = attr.get("content", "")
                    if key and content:
                        self.metas.append({"key": key, "content": trim_text(content, 500)})
                elif tag == "link" and attr.get("rel", "").lower() == "canonical" and attr.get("href"):
                    self.canonical = attr.get("href", "")
                elif tag == "a" and attr.get("href"):
                    self.links.append({"href": attr.get("href", ""), "text": ""})
                elif tag in {"h1", "h2", "h3"}:
                    self._heading_tag = tag
                    self._heading_parts = []

            def handle_endtag(self, tag: str) -> None:
                tag = tag.lower()
                if tag == "title":
                    self.in_title = False
                if self._heading_tag and tag == self._heading_tag:
                    text_value = re.sub(r"\s+", " ", " ".join(self._heading_parts)).strip()
                    if text_value:
                        self.headings.append({"level": self._heading_tag, "text": trim_text(text_value, 300)})
                    self._heading_tag = ""
                    self._heading_parts = []

            def handle_data(self, data: str) -> None:
                if self.in_title:
                    self.title_parts.append(data)
                if self._heading_tag:
                    self._heading_parts.append(data)
                if self.links and not self.links[-1].get("text"):
                    cleaned = re.sub(r"\s+", " ", data).strip()
                    if cleaned:
                        self.links[-1]["text"] = trim_text(cleaned, 200)

        parser_obj = MetadataParser()
        try:
            parser_obj.feed(text)
        except Exception:
            # HTML in the wild is often malformed; keep partial parse results.
            pass

        base_url = final_url or url_text
        host = urllib.parse.urlparse(base_url).hostname or (parsed.hostname if parsed else "")
        normalized_links: list[dict[str, Any]] = []
        seen: set[str] = set()
        for link in parser_obj.links:
            href = str(link.get("href") or "").strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            absolute = urllib.parse.urljoin(base_url, href)
            parsed_link = urllib.parse.urlparse(absolute)
            if parsed_link.scheme not in {"http", "https"} or not parsed_link.netloc:
                continue
            normalized = urllib.parse.urlunparse((parsed_link.scheme, parsed_link.netloc, parsed_link.path or "/", "", parsed_link.query, ""))
            if normalized in seen:
                continue
            seen.add(normalized)
            normalized_links.append(
                {
                    "url": normalized,
                    "host": parsed_link.hostname or "",
                    "same_host": (parsed_link.hostname or "").lower() == str(host or "").lower(),
                    "text": link.get("text", ""),
                }
            )
            if len(normalized_links) >= link_limit:
                break

        title = re.sub(r"\s+", " ", " ".join(parser_obj.title_parts)).strip()
        payload = {
            "generated_at": utc_now(),
            "url": url_text,
            "final_url": base_url,
            "host": host,
            "status": status,
            "content_type": content_type,
            "chars_scanned": len(text),
            "truncated": truncated,
            "title": trim_text(title, 500),
            "canonical": urllib.parse.urljoin(base_url, parser_obj.canonical) if parser_obj.canonical else "",
            "meta_tags": parser_obj.metas[:100],
            "headings": parser_obj.headings[:80],
            "link_count_returned": len(normalized_links),
            "links": normalized_links,
            "recommendations": [
                "Use crawl_url_map for a bounded same-host crawl when a page's link graph matters.",
                "Use check_http_security_headers for a security-header-focused view of the same endpoint.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def check_http_security_headers(self, url: str, timeout: int = 10, allow_local: bool = False) -> ToolResult:
        endpoint = self.inspect_http_endpoint(url=url, timeout=timeout, allow_local=allow_local)
        if endpoint.meta:
            payload = dict(endpoint.meta)
        else:
            try:
                payload = json.loads(endpoint.content)
            except (json.JSONDecodeError, TypeError):
                return endpoint
        headers = {str(k).lower(): str(v) for k, v in (payload.get("headers") or {}).items()}
        parsed = urllib.parse.urlparse(str(url or ""))
        checks: list[dict[str, Any]] = []

        def add_check(name: str, header: str, ok: bool, severity: str, detail: str) -> None:
            checks.append(
                {
                    "name": name,
                    "header": header,
                    "ok": bool(ok),
                    "severity": severity if not ok else "info",
                    "detail": detail,
                    "value": headers.get(header, ""),
                }
            )

        add_check(
            "Strict Transport Security",
            "strict-transport-security",
            parsed.scheme == "http" or "strict-transport-security" in headers,
            "medium",
            "Missing HSTS on HTTPS can allow downgrade or cookie exposure on repeat visits.",
        )
        csp = headers.get("content-security-policy", "")
        add_check(
            "Content Security Policy",
            "content-security-policy",
            bool(csp),
            "medium",
            "Missing CSP weakens browser-side mitigation for XSS and content injection.",
        )
        add_check(
            "X-Content-Type-Options",
            "x-content-type-options",
            headers.get("x-content-type-options", "").lower() == "nosniff",
            "low",
            "Expected x-content-type-options: nosniff.",
        )
        xfo = headers.get("x-frame-options", "").lower()
        has_frame_ancestors = "frame-ancestors" in csp.lower()
        add_check(
            "Clickjacking Protection",
            "x-frame-options/content-security-policy",
            xfo in {"deny", "sameorigin"} or has_frame_ancestors,
            "medium",
            "Expected X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors.",
        )
        add_check(
            "Referrer Policy",
            "referrer-policy",
            bool(headers.get("referrer-policy")),
            "low",
            "Missing Referrer-Policy can leak URL data through outbound requests.",
        )
        add_check(
            "Permissions Policy",
            "permissions-policy",
            bool(headers.get("permissions-policy")),
            "low",
            "Missing Permissions-Policy leaves browser feature access less explicit.",
        )
        add_check(
            "Cross-Origin Opener Policy",
            "cross-origin-opener-policy",
            bool(headers.get("cross-origin-opener-policy")),
            "low",
            "Missing COOP can weaken cross-origin isolation for some applications.",
        )
        cookie_headers = [value for key, value in headers.items() if key == "set-cookie"]
        if cookie_headers:
            joined = "\n".join(cookie_headers).lower()
            add_check(
                "Cookie Secure Flag",
                "set-cookie",
                "secure" in joined,
                "medium",
                "Cookies should generally use Secure on HTTPS.",
            )
            add_check(
                "Cookie HttpOnly Flag",
                "set-cookie",
                "httponly" in joined,
                "medium",
                "Sensitive cookies should generally use HttpOnly.",
            )

        missing_or_weak = [check for check in checks if not check["ok"]]
        severity_score = sum({"info": 0, "low": 1, "medium": 2, "high": 3}.get(str(item.get("severity")), 1) for item in missing_or_weak)
        grade = "A" if severity_score == 0 else "B" if severity_score <= 2 else "C" if severity_score <= 5 else "D"
        result_payload = {
            "generated_at": utc_now(),
            "url": url,
            "status": payload.get("status"),
            "grade": grade,
            "missing_or_weak_count": len(missing_or_weak),
            "checks": checks,
            "recommendations": [
                "Treat this as a heuristic header review, not a full web-application security assessment.",
                "Confirm intentional omissions with the application architecture before changing production headers.",
            ],
        }
        return ToolResult(endpoint.ok or bool(checks), json.dumps(result_payload, indent=2), meta=result_payload)

    def crawl_url_map(
        self,
        start_url: str,
        max_pages: int = 10,
        max_depth: int = 1,
        timeout: int = 10,
        allow_local: bool = False,
        same_host_only: bool = True,
    ) -> ToolResult:
        start = str(start_url or "").strip()
        allowed, reason, parsed = self._url_is_allowed_for_fetch(start, allow_local=bool(allow_local))
        if not allowed:
            return ToolResult(False, reason)
        max_pages = max(1, min(safe_int(max_pages, 10), 50))
        max_depth = max(0, min(safe_int(max_depth, 1), 3))
        timeout = max(1, min(safe_int(timeout, 10), 30))
        start_host = (parsed.hostname if parsed else "") or ""
        queue: collections.deque[tuple[str, int]] = collections.deque([(start, 0)])
        visited: set[str] = set()
        pages: list[dict[str, Any]] = []
        edges: list[dict[str, str]] = []
        errors: list[dict[str, str]] = []

        while queue and len(visited) < max_pages:
            current, depth = queue.popleft()
            current_norm = urllib.parse.urlunparse(urllib.parse.urlparse(current)._replace(fragment=""))
            if current_norm in visited:
                continue
            current_host = urllib.parse.urlparse(current_norm).hostname or ""
            if same_host_only and current_host.lower() != start_host.lower():
                continue
            visited.add(current_norm)
            meta_result = self.extract_html_metadata(current_norm, max_chars=120000, timeout=timeout, allow_local=allow_local, link_limit=200)
            if not meta_result.ok:
                errors.append({"url": current_norm, "error": trim_text(meta_result.content, 500)})
                pages.append({"url": current_norm, "depth": depth, "ok": False, "error": trim_text(meta_result.content, 500)})
                continue
            meta = meta_result.meta
            page_links = meta.get("links", []) if isinstance(meta.get("links"), list) else []
            pages.append(
                {
                    "url": current_norm,
                    "depth": depth,
                    "ok": True,
                    "status": meta.get("status"),
                    "title": meta.get("title", ""),
                    "canonical": meta.get("canonical", ""),
                    "link_count": len(page_links),
                }
            )
            for link in page_links:
                target_url = str(link.get("url") or "")
                if not target_url:
                    continue
                target_host = urllib.parse.urlparse(target_url).hostname or ""
                if same_host_only and target_host.lower() != start_host.lower():
                    continue
                edges.append({"source": current_norm, "target": target_url, "text": trim_text(str(link.get("text") or ""), 100)})
                if depth < max_depth and target_url not in visited and len(visited) + len(queue) < max_pages:
                    queue.append((target_url, depth + 1))

        payload = {
            "generated_at": utc_now(),
            "start_url": start,
            "same_host_only": bool(same_host_only),
            "max_pages": max_pages,
            "max_depth": max_depth,
            "visited_count": len(visited),
            "page_count": len(pages),
            "edge_count": len(edges),
            "pages": pages,
            "edges": edges[:1000],
            "errors": errors[:50],
            "recommendations": [
                "Keep max_depth low for reconnaissance; this crawler is designed for maps, not mirroring sites.",
                "Use extract_html_metadata on a specific page when you need richer headings/meta/link details.",
            ],
        }
        return ToolResult(bool(pages), json.dumps(payload, indent=2), meta=payload)

    def infer_json_schema(
        self,
        path: str = "",
        json_text: str = "",
        max_items: int = 1000,
        max_depth: int = 6,
    ) -> ToolResult:
        max_items = max(1, min(safe_int(max_items, 1000), 20000))
        max_depth = max(1, min(safe_int(max_depth, 6), 12))
        source = ""
        samples: list[Any] = []
        parse_errors: list[str] = []

        if str(json_text or "").strip():
            source = "json_text"
            try:
                samples = [json.loads(str(json_text))]
            except json.JSONDecodeError as exc:
                return ToolResult(False, f"Invalid json_text: line {exc.lineno}, column {exc.colno}: {exc.msg}")
        else:
            target = resolve_workspace_path(path or "")
            if not target.is_file():
                return ToolResult(False, f"JSON/JSONL file not found: {path}")
            source = workspace_relative(target)
            suffix = target.suffix.lower()
            try:
                if suffix == ".jsonl" or suffix == ".ndjson":
                    with target.open("r", encoding="utf-8", errors="replace") as handle:
                        for line_number, line in enumerate(handle, start=1):
                            if len(samples) >= max_items:
                                break
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                samples.append(json.loads(line))
                            except json.JSONDecodeError as exc:
                                parse_errors.append(f"line {line_number}: {exc.msg}")
                else:
                    parsed_value = json.loads(target.read_text(encoding="utf-8", errors="replace"))
                    if isinstance(parsed_value, list):
                        samples = parsed_value[:max_items]
                    else:
                        samples = [parsed_value]
            except json.JSONDecodeError as exc:
                return ToolResult(False, f"Invalid JSON in {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}")
            except OSError as exc:
                return ToolResult(False, f"Could not read {path}: {exc}")

        def merge_schema(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
            if not left:
                return right
            types = sorted(set(left.get("types", [])) | set(right.get("types", [])))
            merged: dict[str, Any] = {"types": types, "count": int(left.get("count", 0)) + int(right.get("count", 0))}
            if "properties" in left or "properties" in right:
                props: dict[str, Any] = {}
                all_keys = set((left.get("properties") or {}).keys()) | set((right.get("properties") or {}).keys())
                for key in sorted(all_keys):
                    props[key] = merge_schema((left.get("properties") or {}).get(key, {}), (right.get("properties") or {}).get(key, {}))
                merged["properties"] = props
            if "items" in left or "items" in right:
                merged["items"] = merge_schema(left.get("items", {}), right.get("items", {}))
            examples = []
            for value in list(left.get("examples", [])) + list(right.get("examples", [])):
                if value not in examples and len(examples) < 5:
                    examples.append(value)
            if examples:
                merged["examples"] = examples
            return merged

        def schema_for(value: Any, depth: int = 0) -> dict[str, Any]:
            if value is None:
                return {"types": ["null"], "count": 1, "examples": [None]}
            if isinstance(value, bool):
                return {"types": ["boolean"], "count": 1, "examples": [value]}
            if isinstance(value, int) and not isinstance(value, bool):
                return {"types": ["integer"], "count": 1, "examples": [value]}
            if isinstance(value, float):
                return {"types": ["number"], "count": 1, "examples": [value]}
            if isinstance(value, str):
                return {"types": ["string"], "count": 1, "examples": [trim_text(value, 120)]}
            if isinstance(value, list):
                item_schema: dict[str, Any] = {}
                if depth < max_depth:
                    for item in value[: min(len(value), 100)]:
                        item_schema = merge_schema(item_schema, schema_for(item, depth + 1))
                return {"types": ["array"], "count": 1, "length_min": len(value), "length_max": len(value), "items": item_schema}
            if isinstance(value, dict):
                props: dict[str, Any] = {}
                if depth < max_depth:
                    for key, item in list(value.items())[:500]:
                        props[str(key)] = schema_for(item, depth + 1)
                return {"types": ["object"], "count": 1, "properties": props}
            return {"types": [type(value).__name__], "count": 1, "examples": [trim_text(repr(value), 120)]}

        schema: dict[str, Any] = {}
        for sample in samples[:max_items]:
            sample_schema = schema_for(sample, 0)
            if isinstance(sample, list) and "length_min" in sample_schema and "length_max" in sample_schema:
                pass
            schema = merge_schema(schema, sample_schema)

        # Add object key presence counts for common tabular JSON/JSONL records.
        key_presence: dict[str, int] = collections.Counter()
        object_samples = [item for item in samples if isinstance(item, dict)]
        for item in object_samples:
            for key in item:
                key_presence[str(key)] += 1
        required_keys = sorted(key for key, count in key_presence.items() if object_samples and count == len(object_samples))
        payload = {
            "generated_at": utc_now(),
            "source": source,
            "sample_count": len(samples),
            "parse_errors": parse_errors[:50],
            "schema": schema,
            "object_key_presence": dict(sorted(key_presence.items())),
            "required_keys_in_sample": required_keys,
            "recommendations": [
                "Schema is inferred from bounded samples, not a formal contract.",
                "Use query_sqlite_database/profile_csv_file for tabular stores, and inspect_jsonl_file for log-specific key frequencies.",
            ],
        }
        return ToolResult(bool(samples) and not (parse_errors and not samples), json.dumps(payload, indent=2), meta=payload)

    def extract_text_entities(
        self,
        path: str = ".",
        recursive: bool = True,
        entity_types: list[str] | None = None,
        limit: int = 200,
        max_file_chars: int = 200000,
    ) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        limit = max(1, min(safe_int(limit, 200), 2000))
        max_file_chars = max(1000, min(safe_int(max_file_chars, 200000), 2000000))
        requested = {str(item).lower().strip() for item in (entity_types or []) if str(item).strip()}
        patterns: dict[str, re.Pattern[str]] = {
            "url": re.compile(r"https?://[^\s\"'<>]+", re.I),
            "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
            "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
            "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I),
            "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
            "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
            "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
            "aws_access_key": re.compile(r"\bA(?:KIA|SIA)[A-Z0-9]{16}\b"),
            "secret_assignment": re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)\b\s*[:=]\s*[\"']?([^\s\"']{8,})"),
        }
        selected_patterns = {name: pattern for name, pattern in patterns.items() if not requested or name in requested}
        if requested and not selected_patterns:
            return ToolResult(False, f"No supported entity types selected. Supported: {', '.join(sorted(patterns))}")
        candidates = [target] if target.is_file() else list(target.rglob("*") if recursive else target.iterdir())
        findings: list[dict[str, Any]] = []
        files_scanned = 0
        skipped_binary = 0

        def redact(value: str, entity_type: str) -> str:
            if entity_type in {"aws_access_key", "secret_assignment"}:
                cleaned = str(value)
                if len(cleaned) <= 8:
                    return "<redacted>"
                return f"{cleaned[:4]}…{cleaned[-4:]}"
            return value

        for candidate in candidates:
            if len(findings) >= limit:
                break
            if not candidate.is_file() or should_skip_checkpoint_path(candidate):
                continue
            if not looks_like_text_path(candidate):
                continue
            text = read_text_sample(candidate, max_file_chars)
            if not text:
                skipped_binary += 1
                continue
            files_scanned += 1
            line_starts = [0]
            for match in re.finditer(r"\n", text):
                line_starts.append(match.end())
            for entity_type, pattern in selected_patterns.items():
                for match in pattern.finditer(text):
                    value = match.group(1) if entity_type == "secret_assignment" and match.groups() else match.group(0)
                    line_no = 1 + sum(1 for start in line_starts if start <= match.start()) - 1
                    line = text.splitlines()[max(0, line_no - 1)] if text.splitlines() and line_no - 1 < len(text.splitlines()) else ""
                    findings.append(
                        {
                            "path": workspace_relative(candidate),
                            "line": line_no,
                            "entity_type": entity_type,
                            "value": redact(str(value), entity_type),
                            "preview": trim_text(line.replace(str(value), redact(str(value), entity_type)), 300),
                        }
                    )
                    if len(findings) >= limit:
                        break
                if len(findings) >= limit:
                    break

        counts = collections.Counter(str(item.get("entity_type")) for item in findings)
        payload = {
            "generated_at": utc_now(),
            "path": workspace_relative(target),
            "recursive": bool(recursive),
            "files_scanned": files_scanned,
            "skipped_binary_or_empty": skipped_binary,
            "entity_types": sorted(selected_patterns),
            "finding_count": len(findings),
            "counts_by_type": dict(sorted(counts.items())),
            "findings": findings,
            "recommendations": [
                "Secret-like values are redacted in output; inspect the referenced file directly before rotating anything.",
                "Use hash_workspace_file or lookup_malware_hash for hash enrichment after extracting suspicious hashes.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def generate_file_manifest(
        self,
        path: str = ".",
        recursive: bool = True,
        include_hashes: bool = True,
        max_files: int = 500,
        max_bytes_per_hash: int = 10485760,
    ) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        max_files = max(1, min(safe_int(max_files, 500), 5000))
        max_bytes_per_hash = max(0, min(safe_int(max_bytes_per_hash, 10485760), 100 * 1024 * 1024))
        candidates = [target] if target.is_file() else list(target.rglob("*") if recursive else target.iterdir())
        files: list[dict[str, Any]] = []
        extension_counts: collections.Counter[str] = collections.Counter()
        total_bytes = 0
        skipped = 0
        for candidate in sorted(candidates, key=lambda item: workspace_relative(item) if WORKSPACE_ROOT in item.resolve().parents or item.resolve() == WORKSPACE_ROOT else str(item)):
            if len(files) >= max_files:
                skipped += 1
                continue
            if not candidate.is_file() or should_skip_checkpoint_path(candidate):
                continue
            try:
                stat = candidate.stat()
            except OSError:
                continue
            suffix = candidate.suffix.lower() or "(none)"
            extension_counts[suffix] += 1
            total_bytes += stat.st_size
            row = {
                "path": workspace_relative(candidate),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "extension": suffix,
                "mime_guess": mimetypes.guess_type(str(candidate))[0] or "",
            }
            if include_hashes:
                if stat.st_size <= max_bytes_per_hash:
                    try:
                        row["sha256"] = _file_hashes(candidate)["sha256"]
                    except OSError as exc:
                        row["hash_error"] = str(exc)
                else:
                    row["sha256"] = "<skipped: file exceeds max_bytes_per_hash>"
            files.append(row)
        payload = {
            "generated_at": utc_now(),
            "path": workspace_relative(target),
            "recursive": bool(recursive),
            "file_count_returned": len(files),
            "skipped_after_limit": skipped,
            "total_bytes_returned": total_bytes,
            "extension_counts": dict(sorted(extension_counts.items())),
            "files": files,
            "recommendations": [
                "Use compare_workspace_files for content-level comparison between two manifest entries.",
                "Use include_hashes=false for very large trees when speed matters more than integrity fingerprints.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def compare_workspace_files(self, left_path: str, right_path: str, max_chars: int = 20000) -> ToolResult:
        left = resolve_workspace_path(left_path)
        right = resolve_workspace_path(right_path)
        if not left.is_file():
            return ToolResult(False, f"Left file not found: {left_path}")
        if not right.is_file():
            return ToolResult(False, f"Right file not found: {right_path}")
        max_chars = max(1000, min(safe_int(max_chars, 20000), 200000))
        try:
            left_stat = left.stat()
            right_stat = right.stat()
            left_hashes = _file_hashes(left)
            right_hashes = _file_hashes(right)
        except OSError as exc:
            return ToolResult(False, f"Could not inspect files: {exc}")
        left_text = read_text_sample(left, max_chars)
        right_text = read_text_sample(right, max_chars)
        diff_text = ""
        binary_or_empty = not left_text or not right_text
        if not binary_or_empty:
            diff_lines = difflib.unified_diff(
                left_text.splitlines(),
                right_text.splitlines(),
                fromfile=workspace_relative(left),
                tofile=workspace_relative(right),
                lineterm="",
            )
            diff_text = trim_text("\n".join(diff_lines), max_chars)
        payload = {
            "generated_at": utc_now(),
            "left": {"path": workspace_relative(left), "size": left_stat.st_size, "sha256": left_hashes["sha256"]},
            "right": {"path": workspace_relative(right), "size": right_stat.st_size, "sha256": right_hashes["sha256"]},
            "same_sha256": left_hashes["sha256"] == right_hashes["sha256"],
            "text_diff_available": not binary_or_empty,
            "diff_truncated_to_chars": max_chars,
            "unified_diff": diff_text,
            "recommendations": [
                "If same_sha256 is true, the files are byte-identical.",
                "For code changes, prefer git_diff when the comparison is against repository state.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_python_environment(
        self,
        include_packages: bool = True,
        include_env: bool = False,
        package_limit: int = 200,
    ) -> ToolResult:
        package_limit = max(0, min(safe_int(package_limit, 200), 2000))
        packages: list[dict[str, str]] = []
        if include_packages:
            try:
                import importlib.metadata as importlib_metadata
                for dist in sorted(importlib_metadata.distributions(), key=lambda item: (item.metadata.get("Name") or "").lower()):
                    name = dist.metadata.get("Name") or ""
                    if not name:
                        continue
                    packages.append({"name": name, "version": dist.version})
                    if len(packages) >= package_limit:
                        break
            except Exception as exc:
                packages.append({"name": "<package inspection failed>", "version": trim_text(str(exc), 200)})
        safe_env: dict[str, str] = {}
        if include_env:
            for key, value in sorted(os.environ.items()):
                lowered = key.lower()
                if any(secret_word in lowered for secret_word in ["key", "token", "secret", "password", "passwd", "credential"]):
                    safe_env[key] = "<redacted>"
                elif key.upper() in {"PATH", "PYTHONPATH", "VIRTUAL_ENV", "CONDA_PREFIX", "HOME", "USERPROFILE", "USERNAME", "USER"}:
                    safe_env[key] = trim_text(value, 1000)
        payload = {
            "generated_at": utc_now(),
            "python_executable": sys.executable,
            "python_version": sys.version,
            "platform": sys.platform,
            "cwd": str(WORKSPACE_ROOT),
            "prefix": sys.prefix,
            "base_prefix": getattr(sys, "base_prefix", ""),
            "in_virtualenv": sys.prefix != getattr(sys, "base_prefix", sys.prefix) or bool(os.environ.get("VIRTUAL_ENV")),
            "path_entries": sys.path[:20],
            "include_packages": bool(include_packages),
            "package_count_returned": len(packages),
            "packages": packages,
            "environment": safe_env,
            "recommendations": [
                "Use audit_dependency_health for project-level import/dependency concerns.",
                "Environment variables that look secret-bearing are redacted.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_process_table(self, filter: str = "", limit: int = 100, include_command: bool = False) -> ToolResult:
        limit = max(1, min(safe_int(limit, 100), 500))
        filter_text = str(filter or "").lower().strip()
        try:
            if sys.platform.startswith("win"):
                command = ["tasklist", "/FO", "CSV", "/V"]
                result = subprocess.run(command, capture_output=True, text=True, timeout=10, cwd=WORKSPACE_ROOT)
                if result.returncode != 0:
                    return ToolResult(False, trim_text(result.stderr or result.stdout or "tasklist failed", 2000))
                rows = list(csv.DictReader(result.stdout.splitlines()))
                processes = []
                for row in rows:
                    name = row.get("Image Name", "")
                    pid = row.get("PID", "")
                    window_title = row.get("Window Title", "")
                    searchable = f"{name} {pid} {window_title}".lower()
                    if filter_text and filter_text not in searchable:
                        continue
                    processes.append(
                        {
                            "pid": pid,
                            "name": name,
                            "session": row.get("Session Name", ""),
                            "memory": row.get("Mem Usage", ""),
                            "status": row.get("Status", ""),
                            "user": row.get("User Name", ""),
                            "command": trim_text(window_title, 500) if include_command else "<hidden>",
                        }
                    )
                    if len(processes) >= limit:
                        break
            else:
                command = ["ps", "-eo", "pid=,ppid=,user=,comm=,args="]
                result = subprocess.run(command, capture_output=True, text=True, timeout=10, cwd=WORKSPACE_ROOT)
                if result.returncode != 0:
                    return ToolResult(False, trim_text(result.stderr or result.stdout or "ps failed", 2000))
                processes = []
                for line in result.stdout.splitlines():
                    parts = line.strip().split(None, 4)
                    if len(parts) < 4:
                        continue
                    pid, ppid, user, comm = parts[:4]
                    args = parts[4] if len(parts) > 4 else ""
                    searchable = f"{pid} {ppid} {user} {comm} {args}".lower()
                    if filter_text and filter_text not in searchable:
                        continue
                    redacted_args = re.sub(r"(?i)(--?(?:api[_-]?key|token|secret|password)\s+)(\S+)", r"\1<redacted>", args)
                    redacted_args = re.sub(r"(?i)((?:api[_-]?key|token|secret|password)=)(\S+)", r"\1<redacted>", redacted_args)
                    processes.append(
                        {
                            "pid": pid,
                            "ppid": ppid,
                            "user": user,
                            "name": comm,
                            "command": trim_text(redacted_args, 1000) if include_command else "<hidden>",
                        }
                    )
                    if len(processes) >= limit:
                        break
        except FileNotFoundError as exc:
            return ToolResult(False, f"Process inspection command unavailable: {exc}")
        except subprocess.TimeoutExpired:
            return ToolResult(False, "Process inspection timed out after 10 seconds.")
        payload = {
            "generated_at": utc_now(),
            "platform": sys.platform,
            "filter": filter,
            "limit": limit,
            "include_command": bool(include_command),
            "process_count_returned": len(processes),
            "processes": processes,
            "recommendations": [
                "Command lines are hidden by default; set include_command=true only when needed.",
                "Secret-looking command-line arguments are redacted when command lines are shown.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def profile_csv_file(self, path: str, delimiter: str = "", sample_rows: int = 5, max_rows: int = 10000) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists() or not target.is_file():
            return ToolResult(False, f"CSV file not found: {path}")
        sample_rows = max(0, min(safe_int(sample_rows, 5), 25))
        max_rows = max(1, min(safe_int(max_rows, 10000), 250000))
        try:
            preview = target.read_text(encoding="utf-8-sig", errors="replace")[:8192]
            if delimiter:
                dialect = csv.excel()
                dialect.delimiter = str(delimiter)[:1]
            else:
                try:
                    dialect = csv.Sniffer().sniff(preview, delimiters=",\t;|")
                except csv.Error:
                    dialect = csv.excel()
            with target.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                reader = csv.DictReader(handle, dialect=dialect)
                columns = [str(column or "").strip() for column in (reader.fieldnames or [])]
                if not columns:
                    return ToolResult(False, "CSV appears to have no header row or columns.")
                missing_counts: dict[str, int] = {column: 0 for column in columns}
                nonempty_counts: dict[str, int] = {column: 0 for column in columns}
                unique_values: dict[str, set[str]] = {column: set() for column in columns}
                numeric_values: dict[str, list[float]] = {column: [] for column in columns}
                value_types: dict[str, dict[str, int]] = {column: {"number": 0, "string": 0, "empty": 0} for column in columns}
                samples: list[dict[str, Any]] = []
                row_count = 0
                for row in reader:
                    row_count += 1
                    if len(samples) < sample_rows:
                        samples.append({column: row.get(column, "") for column in columns})
                    for column in columns:
                        value = str(row.get(column, "") or "").strip()
                        if not value:
                            missing_counts[column] += 1
                            value_types[column]["empty"] += 1
                            continue
                        nonempty_counts[column] += 1
                        if len(unique_values[column]) < 100:
                            unique_values[column].add(value)
                        try:
                            numeric = float(value.replace(",", ""))
                            numeric_values[column].append(numeric)
                            value_types[column]["number"] += 1
                        except ValueError:
                            value_types[column]["string"] += 1
                    if row_count >= max_rows:
                        break
        except Exception as exc:
            return ToolResult(False, f"CSV profiling failed: {trim_text(str(exc), 600)}")

        numeric_profile: dict[str, dict[str, Any]] = {}
        for column, values in numeric_values.items():
            if not values:
                continue
            numeric_profile[column] = {
                "count": len(values),
                "min": min(values),
                "max": max(values),
                "mean": round(sum(values) / max(1, len(values)), 6),
            }
        column_profile = []
        for column in columns:
            column_profile.append(
                {
                    "name": column,
                    "missing": missing_counts[column],
                    "nonempty": nonempty_counts[column],
                    "unique_sample_count": len(unique_values[column]),
                    "value_types": value_types[column],
                    "sample_values": sorted(unique_values[column])[:10],
                    "numeric": numeric_profile.get(column),
                }
            )
        payload = {
            "generated_at": utc_now(),
            "path": workspace_relative(target),
            "size_bytes": target.stat().st_size,
            "delimiter": getattr(dialect, "delimiter", ","),
            "columns": columns,
            "column_count": len(columns),
            "rows_scanned": row_count,
            "row_limit_hit": row_count >= max_rows,
            "column_profile": column_profile,
            "sample_rows": samples,
            "recommendations": [
                "Use query_sqlite_database after importing larger CSVs into SQLite for deeper filtering.",
                "Check columns with high missing counts before using them in automation decisions.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_jsonl_file(self, path: str, limit: int = 5000, sample_rows: int = 5) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists() or not target.is_file():
            return ToolResult(False, f"JSONL file not found: {path}")
        limit = max(1, min(safe_int(limit, 5000), 250000))
        sample_rows = max(0, min(safe_int(sample_rows, 5), 25))
        key_counts: collections.Counter[str] = collections.Counter()
        type_counts: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
        samples: list[Any] = []
        errors: list[dict[str, Any]] = []
        parsed_count = 0
        total_lines = 0
        try:
            with target.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    total_lines += 1
                    if line_number > limit:
                        break
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        value = json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        if len(errors) < 20:
                            errors.append({"line": line_number, "error": f"column {exc.colno}: {exc.msg}", "preview": trim_text(stripped, 240)})
                        continue
                    parsed_count += 1
                    if len(samples) < sample_rows:
                        samples.append(value)
                    if isinstance(value, dict):
                        for key, item in value.items():
                            key_text = str(key)
                            key_counts[key_text] += 1
                            type_counts[key_text][type(item).__name__] += 1
                    else:
                        key_counts["<root>"] += 1
                        type_counts["<root>"][type(value).__name__] += 1
        except Exception as exc:
            return ToolResult(False, f"JSONL inspection failed: {trim_text(str(exc), 600)}")

        payload = {
            "generated_at": utc_now(),
            "path": workspace_relative(target),
            "size_bytes": target.stat().st_size,
            "lines_scanned": min(total_lines, limit),
            "line_limit_hit": total_lines > limit,
            "parsed_records": parsed_count,
            "parse_error_count": len(errors),
            "parse_errors": errors,
            "top_keys": [{"key": key, "count": count, "types": dict(type_counts[key])} for key, count in key_counts.most_common(80)],
            "sample_records": samples,
        }
        return ToolResult(len(errors) == 0 or parsed_count > 0, json.dumps(payload, indent=2), meta=payload)

    def query_sqlite_database(self, path: str, query: str = "", limit: int = 100, timeout: int = 5) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists() or not target.is_file():
            return ToolResult(False, f"SQLite database not found: {path}")
        limit = max(1, min(safe_int(limit, 100), 5000))
        timeout = max(1, min(safe_int(timeout, 5), 30))
        query_text = str(query or "").strip()
        if not query_text:
            query_text = "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table','view','index') ORDER BY type, name"
        lowered = re.sub(r"\s+", " ", query_text.lower()).strip()
        if ";" in query_text.rstrip(";"):
            return ToolResult(False, "Only one SQLite statement is allowed.")
        if not lowered.startswith(("select ", "with ", "pragma ")):
            return ToolResult(False, "Only read-only SELECT, WITH, or PRAGMA queries are allowed.")
        if re.search(r"\b(insert|update|delete|drop|alter|create|replace|attach|detach|vacuum|reindex|load_extension)\b", lowered):
            return ToolResult(False, "Blocked: query contains a write/admin SQLite keyword.")
        query_text = query_text.rstrip().rstrip(";")

        rows: list[dict[str, Any]] = []
        columns: list[str] = []
        start = time.monotonic()
        try:
            uri = f"file:{urllib.parse.quote(str(target))}?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=timeout)
            connection.row_factory = sqlite3.Row
            connection.set_progress_handler(lambda: 1 if time.monotonic() - start > timeout else 0, 10000)
            cursor = connection.execute(query_text)
            columns = [item[0] for item in (cursor.description or [])]
            fetched = cursor.fetchmany(limit + 1)
            rows = [{column: row[column] for column in columns} for row in fetched[:limit]]
            truncated = len(fetched) > limit
            connection.close()
        except sqlite3.Error as exc:
            return ToolResult(False, f"SQLite query failed: {trim_text(str(exc), 600)}")
        except Exception as exc:
            return ToolResult(False, f"SQLite inspection failed: {trim_text(str(exc), 600)}")

        payload = {
            "generated_at": utc_now(),
            "path": workspace_relative(target),
            "query": query_text,
            "columns": columns,
            "row_count": len(rows),
            "limit": limit,
            "truncated": truncated,
            "elapsed_seconds": round(time.monotonic() - start, 4),
            "rows": rows,
        }
        return ToolResult(True, json.dumps(payload, indent=2, default=str), meta=payload)

    def inspect_archive_file(self, path: str, limit: int = 200) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists() or not target.is_file():
            return ToolResult(False, f"Archive file not found: {path}")
        limit = max(1, min(safe_int(limit, 200), 2000))
        suffixes = [suffix.lower() for suffix in target.suffixes]
        entries: list[dict[str, Any]] = []
        archive_type = "unknown"
        total_uncompressed = 0
        dangerous_paths: list[str] = []
        try:
            if zipfile.is_zipfile(target):
                archive_type = "zip"
                with zipfile.ZipFile(target) as archive:
                    infos = archive.infolist()
                    for info in infos[:limit]:
                        name = info.filename
                        total_uncompressed += max(0, int(info.file_size))
                        if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                            dangerous_paths.append(name)
                        entries.append(
                            {
                                "name": name,
                                "size": info.file_size,
                                "compressed_size": info.compress_size,
                                "is_dir": name.endswith("/"),
                                "modified": datetime(*info.date_time).isoformat() if info.date_time else "",
                            }
                        )
                    entry_count = len(infos)
            elif tarfile.is_tarfile(target):
                archive_type = "tar"
                with tarfile.open(target) as archive:
                    members = archive.getmembers()
                    for member in members[:limit]:
                        name = member.name
                        total_uncompressed += max(0, int(member.size))
                        if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                            dangerous_paths.append(name)
                        entries.append(
                            {
                                "name": name,
                                "size": member.size,
                                "is_dir": member.isdir(),
                                "is_file": member.isfile(),
                                "type": member.type.decode("utf-8", errors="replace") if isinstance(member.type, bytes) else str(member.type),
                                "modified": datetime.fromtimestamp(member.mtime).isoformat() if member.mtime else "",
                            }
                        )
                    entry_count = len(members)
            else:
                return ToolResult(False, f"Unsupported or invalid archive: {path}")
        except Exception as exc:
            return ToolResult(False, f"Archive inspection failed: {trim_text(str(exc), 600)}")

        payload = {
            "generated_at": utc_now(),
            "path": workspace_relative(target),
            "archive_type": archive_type,
            "suffixes": suffixes,
            "size_bytes": target.stat().st_size,
            "entry_count": entry_count,
            "entries_returned": len(entries),
            "truncated": entry_count > limit,
            "estimated_uncompressed_bytes_in_returned_entries": total_uncompressed,
            "dangerous_paths": dangerous_paths[:50],
            "path_traversal_risk": bool(dangerous_paths),
            "entries": entries,
            "recommendations": [
                "This tool only inventories archives; it intentionally does not extract files.",
                "Do not extract archives with absolute paths or '..' components without sanitizing names first.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def extract_pdf_text(self, path: str, max_pages: int = 10, max_chars: int = 20000) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists() or not target.is_file():
            return ToolResult(False, f"PDF file not found: {path}")
        if target.suffix.lower() != ".pdf":
            return ToolResult(False, "extract_pdf_text only accepts .pdf files.")
        max_pages = max(1, min(safe_int(max_pages, 10), 100))
        max_chars = max(500, min(safe_int(max_chars, 20000), 200000))
        reader_factory = None
        backend = ""
        try:
            from pypdf import PdfReader  # type: ignore
            reader_factory = PdfReader
            backend = "pypdf"
        except Exception:
            try:
                from PyPDF2 import PdfReader  # type: ignore
                reader_factory = PdfReader
                backend = "PyPDF2"
            except Exception:
                return ToolResult(False, "PDF text extraction requires pypdf or PyPDF2. Install one of them to enable this tool.")
        try:
            reader = reader_factory(str(target))
            total_pages = len(reader.pages)
            page_texts: list[dict[str, Any]] = []
            collected = ""
            for index, page in enumerate(reader.pages[:max_pages], start=1):
                text = page.extract_text() or ""
                remaining = max_chars - len(collected)
                if remaining <= 0:
                    break
                clipped = text[:remaining]
                collected += clipped
                page_texts.append({"page": index, "chars": len(clipped), "text": clipped})
                if len(collected) >= max_chars:
                    break
        except Exception as exc:
            return ToolResult(False, f"PDF text extraction failed: {trim_text(str(exc), 600)}")
        payload = {
            "generated_at": utc_now(),
            "path": workspace_relative(target),
            "backend": backend,
            "size_bytes": target.stat().st_size,
            "total_pages": total_pages,
            "pages_returned": len(page_texts),
            "max_pages": max_pages,
            "chars_returned": len(collected),
            "truncated": total_pages > len(page_texts) or len(collected) >= max_chars,
            "pages": page_texts,
            "recommendations": ["This is text extraction only. Scanned PDFs require OCR outside this built-in tool."],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_image_metadata(self, path: str, include_exif: bool = False) -> ToolResult:
        target = resolve_workspace_path(path)
        if not target.exists() or not target.is_file():
            return ToolResult(False, f"Image file not found: {path}")
        mime, _ = mimetypes.guess_type(str(target))
        payload: dict[str, Any] = {
            "generated_at": utc_now(),
            "path": workspace_relative(target),
            "size_bytes": target.stat().st_size,
            "mime_guess": mime or "",
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "pillow_available": False,
        }
        try:
            from PIL import ExifTags, Image  # type: ignore
            payload["pillow_available"] = True
            with Image.open(target) as image:
                payload.update(
                    {
                        "format": image.format,
                        "mode": image.mode,
                        "width": image.width,
                        "height": image.height,
                        "frames": getattr(image, "n_frames", 1),
                        "animated": bool(getattr(image, "is_animated", False)),
                    }
                )
                if include_exif:
                    exif_payload: dict[str, Any] = {}
                    raw_exif = image.getexif()
                    for key, value in raw_exif.items():
                        name = ExifTags.TAGS.get(key, str(key))
                        if isinstance(value, bytes):
                            rendered = f"<bytes:{len(value)}>"
                        else:
                            rendered = trim_text(str(value), 500)
                        exif_payload[str(name)] = rendered
                    payload["exif"] = exif_payload
                    payload["exif_tag_count"] = len(exif_payload)
        except Exception as exc:
            payload["pillow_error"] = trim_text(str(exc), 600)
            header = target.read_bytes()[:32]
            payload["magic_hex"] = header.hex()
            payload["recommendations"] = ["Install Pillow for dimensions, frame count, format verification, and EXIF parsing."]
            return ToolResult(True, json.dumps(payload, indent=2), meta=payload)
        payload["recommendations"] = ["Use include_exif=true only when metadata is needed; EXIF can include sensitive location/device details."]
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def _load_external_tool_manifest(self, manifest_path: str = ".agent_external_tools.json") -> tuple[dict[str, Any], str]:
        target = resolve_workspace_path(manifest_path or ".agent_external_tools.json")
        if not target.exists():
            template = {
                "schema_version": 1,
                "tools": [
                    {
                        "name": "bandit_scan",
                        "description": "Run Bandit against a Python path when bandit is installed.",
                        "command": [sys.executable, "-m", "bandit", "-r", "{path}"],
                        "args_schema": {"path": "."},
                        "risk": "read_only",
                        "requires_authorization": False,
                        "max_timeout": 60,
                    },
                    {
                        "name": "semgrep_scan",
                        "description": "Run Semgrep with auto config when semgrep is installed.",
                        "command": ["semgrep", "--config", "auto", "{path}"],
                        "args_schema": {"path": "."},
                        "risk": "read_only",
                        "requires_authorization": False,
                        "max_timeout": 120,
                    },
                ],
            }
            return template, f"Manifest not found at {workspace_relative(target)}; returning a starter template. Save it to enable external tools."
        try:
            parsed = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return {}, f"Invalid external tool manifest JSON: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        except OSError as exc:
            return {}, f"Could not read manifest: {exc}"
        if not isinstance(parsed, dict) or not isinstance(parsed.get("tools"), list):
            return {}, "External tool manifest must be an object with a list field named 'tools'."
        return parsed, ""

    def list_external_tools(self, manifest_path: str = ".agent_external_tools.json") -> ToolResult:
        manifest, warning = self._load_external_tool_manifest(manifest_path)
        tools: list[dict[str, Any]] = []
        for raw in manifest.get("tools", []) if isinstance(manifest, dict) else []:
            if not isinstance(raw, dict):
                continue
            command = raw.get("command", [])
            exe = str(command[0]) if isinstance(command, list) and command else ""
            available = bool(exe) and (Path(exe).exists() or shutil.which(exe) is not None or exe == sys.executable)
            tools.append(
                {
                    "name": str(raw.get("name", "")),
                    "description": str(raw.get("description", "")),
                    "risk": str(raw.get("risk", "read_only")),
                    "requires_authorization": bool(raw.get("requires_authorization", False)),
                    "args_schema": raw.get("args_schema", {}),
                    "command_preview": [str(part) for part in command] if isinstance(command, list) else command,
                    "executable_available": available,
                    "max_timeout": safe_int(raw.get("max_timeout"), 30) or 30,
                }
            )
        payload = {
            "generated_at": utc_now(),
            "manifest_path": manifest_path or ".agent_external_tools.json",
            "warning": warning,
            "tool_count": len(tools),
            "tools": tools,
            "starter_template": manifest if warning and manifest else None,
            "recommendations": [
                "Keep external commands read-only by default and use placeholders like {path} for bounded arguments.",
                "Commands are executed without a shell, but destructive executables are still denied.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def run_external_tool(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        manifest_path: str = ".agent_external_tools.json",
        authorized: bool = False,
        timeout: int = 30,
    ) -> ToolResult:
        name = str(tool_name or "").strip()
        if not name:
            return ToolResult(False, "tool_name cannot be empty.")
        manifest, warning = self._load_external_tool_manifest(manifest_path)
        if warning or not manifest:
            return ToolResult(False, warning or "External tool manifest could not be loaded.")
        entries = [item for item in manifest.get("tools", []) if isinstance(item, dict) and str(item.get("name", "")).strip() == name]
        if not entries:
            return ToolResult(False, f"External tool not found in manifest: {name}")
        entry = entries[0]
        risk = str(entry.get("risk", "read_only")).lower()
        if (risk not in {"read_only", "low"} or bool(entry.get("requires_authorization", False))) and not authorized:
            payload = {
                "authorization_required": True,
                "tool_name": name,
                "risk": risk,
                "reason": "This manifest tool requires authorized=true before execution.",
            }
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)
        command_template = entry.get("command")
        if not isinstance(command_template, list) or not command_template:
            return ToolResult(False, "Manifest entry command must be a non-empty list.")
        provided_args = args if isinstance(args, dict) else {}
        defaults = entry.get("args_schema", {}) if isinstance(entry.get("args_schema"), dict) else {}
        merged_args = dict(defaults) | provided_args

        rendered_command: list[str] = []
        try:
            for part in command_template:
                part_text = str(part)
                for key, value in merged_args.items():
                    placeholder = "{" + str(key) + "}"
                    if placeholder not in part_text:
                        continue
                    rendered_value = str(value)
                    if "path" in str(key).lower() or str(key).lower() in {"file", "dir", "directory"}:
                        rendered_value = str(resolve_workspace_path(rendered_value))
                    part_text = part_text.replace(placeholder, rendered_value)
                rendered_command.append(part_text)
        except Exception as exc:
            return ToolResult(False, f"External tool argument rendering failed: {trim_text(str(exc), 600)}")

        executable = Path(rendered_command[0]).name.lower()
        denied_executables = {"rm", "del", "erase", "rmdir", "format", "shutdown", "reboot", "powershell", "pwsh"}
        if executable in denied_executables:
            return ToolResult(False, f"Blocked external tool executable: {executable}")
        denied_tokens = {"--delete", "--remove", "--force", "/f", "mkfs", "diskpart"}
        if any(str(part).lower() in denied_tokens for part in rendered_command[1:]):
            return ToolResult(False, "Blocked external tool arguments that look destructive.")
        if not (Path(rendered_command[0]).exists() or shutil.which(rendered_command[0]) is not None or rendered_command[0] == sys.executable):
            return ToolResult(False, f"Command not found: {rendered_command[0]}")

        max_timeout = max(1, min(safe_int(entry.get("max_timeout"), 30) or 30, 300))
        timeout = max(1, min(safe_int(timeout, max_timeout), max_timeout))
        started = time.monotonic()
        try:
            result = subprocess.run(
                rendered_command,
                cwd=WORKSPACE_ROOT,
                text=True,
                capture_output=True,
                timeout=timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(False, f"External tool timed out after {timeout} seconds.")
        except Exception as exc:
            return ToolResult(False, f"External tool execution failed: {trim_text(str(exc), 600)}")
        output = (result.stdout or "") + (("\n[stderr]\n" + result.stderr) if result.stderr else "")
        payload = {
            "generated_at": utc_now(),
            "tool_name": name,
            "description": str(entry.get("description", "")),
            "risk": risk,
            "command": rendered_command,
            "returncode": result.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 4),
            "output": trim_text(output, 20000),
        }
        return ToolResult(result.returncode == 0, json.dumps(payload, indent=2), meta=payload)

    def _extract_network_host(self, target: str) -> tuple[str, str, dict[str, Any]]:
        raw = str(target or "").strip()
        meta: dict[str, Any] = {"raw_target": raw, "kind": "unknown"}
        if not raw:
            return "", "Target cannot be empty.", meta
        candidate = raw
        if "://" in raw:
            try:
                parsed = urllib.parse.urlparse(raw)
            except Exception as exc:
                return "", f"Invalid URL: {exc}", meta
            if parsed.scheme not in {"http", "https"}:
                return "", "Only http/https URLs are accepted when a URL is supplied.", meta
            candidate = parsed.hostname or ""
            meta.update({"kind": "url", "scheme": parsed.scheme, "port": parsed.port, "path_present": bool(parsed.path and parsed.path != "/")})
        else:
            # Allow host:port without treating IPv6 colons as port separators.
            bracket_match = re.match(r"^\[([^\]]+)\](?::(\d+))?$", raw)
            if bracket_match:
                candidate = bracket_match.group(1)
                if bracket_match.group(2):
                    meta["port"] = safe_int(bracket_match.group(2), 0)
            elif raw.count(":") == 1 and not re.search(r"/[0-9]+$", raw):
                host_part, port_part = raw.rsplit(":", 1)
                if port_part.isdigit():
                    candidate = host_part
                    meta["port"] = safe_int(port_part, 0)
        candidate = candidate.strip().strip(".")
        if not candidate:
            return "", "Target did not contain a hostname or IP address.", meta
        if len(candidate) > 253:
            return "", "Hostname/IP target is too long.", meta
        return candidate, "ok", meta

    def _ip_classification(self, ip_text: str) -> dict[str, Any]:
        ip_obj = ipaddress.ip_address(ip_text)
        return {
            "ip": str(ip_obj),
            "version": ip_obj.version,
            "is_global": ip_obj.is_global,
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_link_local": ip_obj.is_link_local,
            "is_multicast": ip_obj.is_multicast,
            "is_reserved": ip_obj.is_reserved,
            "is_unspecified": ip_obj.is_unspecified,
            "is_publicly_routable": ip_obj.is_global and not any([ip_obj.is_loopback, ip_obj.is_private, ip_obj.is_link_local, ip_obj.is_multicast, ip_obj.is_reserved, ip_obj.is_unspecified]),
        }

    def _resolve_host_ips(self, host: str, *, timeout: int = 5) -> tuple[list[dict[str, Any]], list[str]]:
        # socket.getaddrinfo has no per-call timeout, but default resolver behavior is
        # acceptable for this local diagnostic helper. The timeout argument is preserved
        # in tool schemas for symmetry with network calls and future adapters.
        warnings: list[str] = []
        rows: list[dict[str, Any]] = []
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except Exception as exc:
            return [], [f"DNS resolution failed: {trim_text(str(exc), 400)}"]
        seen: set[str] = set()
        for family, _socktype, proto, canonname, sockaddr in infos:
            address = str(sockaddr[0])
            if address in seen:
                continue
            seen.add(address)
            try:
                classification = self._ip_classification(address)
            except ValueError:
                classification = {"ip": address, "is_publicly_routable": False}
            rows.append({
                "address": address,
                "family": "IPv6" if family == socket.AF_INET6 else "IPv4" if family == socket.AF_INET else str(family),
                "canonical_name": canonname,
                "protocol": proto,
                **classification,
            })
        return rows, warnings

    def _public_ip_from_target(self, target: str, *, allow_resolve: bool = True) -> tuple[str, dict[str, Any], str]:
        host, reason, meta = self._extract_network_host(target)
        if not host:
            return "", meta, reason
        try:
            network = ipaddress.ip_network(host, strict=False)
            if network.num_addresses != 1:
                meta.update({"kind": "cidr", "network": str(network), "prefixlen": network.prefixlen})
                return "", meta, "CIDR ranges are not accepted for this lookup; provide one IP address."
            ip_obj = network.network_address
            classification = self._ip_classification(str(ip_obj))
            meta.update({"kind": "ip", "host": str(ip_obj), "classification": classification})
            if not classification.get("is_publicly_routable"):
                return "", meta, "Target is not a public routable IP; external RDAP/GeoIP lookup is skipped."
            return str(ip_obj), meta, "ok"
        except ValueError:
            pass
        try:
            ip_obj = ipaddress.ip_address(host)
            classification = self._ip_classification(str(ip_obj))
            meta.update({"kind": "ip", "host": str(ip_obj), "classification": classification})
            if not classification.get("is_publicly_routable"):
                return "", meta, "Target is not a public routable IP; external RDAP/GeoIP lookup is skipped."
            return str(ip_obj), meta, "ok"
        except ValueError:
            meta.update({"kind": meta.get("kind") if meta.get("kind") != "unknown" else "hostname", "host": host})
        if not allow_resolve:
            return "", meta, "Target is a hostname; resolution disabled."
        records, warnings = self._resolve_host_ips(host)
        meta["resolved_addresses"] = records
        meta["resolution_warnings"] = warnings
        for record in records:
            if record.get("is_publicly_routable"):
                return str(record.get("address")), meta, "ok"
        return "", meta, "No public routable address found for target."

    def ingest_network_traffic_file(self, path: str, input_format: str = "auto", limit: int = 5000) -> ToolResult:
        """Ingest network traffic logs/captures into metadata-only normalized flow records."""
        try:
            flows, meta = _ids_read_traffic_records(path, input_format=input_format, limit=limit)
        except Exception as exc:
            return ToolResult(False, f"Failed to ingest network traffic source: {exc}", {"error": str(exc), "path": path})
        analysis = _ids_analyze_flows(flows, sensitivity="medium")
        sample = flows[:10]
        payload = {
            **meta,
            "flow_count": len(flows),
            "sample_flows": sample,
            "top_sources": analysis.get("top_sources", []),
            "top_destinations": analysis.get("top_destinations", []),
            "top_destination_ports": analysis.get("top_destination_ports", []),
            "protocols": analysis.get("protocols", []),
            "external_destination_count": analysis.get("external_destination_count", 0),
        }
        lines = [
            f"Ingested {len(flows)} metadata-only network flow/packet record(s) from {meta.get('path')}.",
            f"Detected format: {meta.get('format')}.",
        ]
        if meta.get("warnings"):
            lines.append("Warnings: " + "; ".join(str(item) for item in meta.get("warnings", [])[:4]))
        if analysis.get("top_destination_ports"):
            lines.append("Top destination ports: " + ", ".join(f"{port}/{count}" for port, count in analysis.get("top_destination_ports", [])[:10]))
        return ToolResult(True, "\n".join(lines), payload)

    def analyze_network_traffic_file(
        self,
        path: str,
        input_format: str = "auto",
        limit: int = 5000,
        baseline_path: str = "",
        sensitivity: str = "medium",
        record_alerts: bool = True,
    ) -> ToolResult:
        """Run IDS-style heuristics over a traffic source inside the workspace."""
        try:
            flows, meta = _ids_read_traffic_records(path, input_format=input_format, limit=limit)
        except Exception as exc:
            return ToolResult(False, f"Failed to analyze network traffic source: {exc}", {"error": str(exc), "path": path})
        baseline: dict[str, Any] = {}
        if baseline_path:
            try:
                baseline_target = resolve_workspace_path(baseline_path)
                if baseline_target.exists():
                    baseline = json.loads(baseline_target.read_text(encoding="utf-8"))
            except Exception as exc:
                meta.setdefault("warnings", []).append(f"Could not load baseline {baseline_path}: {exc}")
        analysis = _ids_analyze_flows(flows, baseline=baseline, sensitivity=sensitivity)
        alerts_recorded = _ids_append_alerts(analysis.get("alerts", []), source_path=meta.get("path", "")) if record_alerts else 0
        payload = {**meta, **analysis, "sensitivity": sensitivity, "baseline_used": bool(baseline), "alerts_recorded": alerts_recorded}
        lines = [
            f"Analyzed {len(flows)} network metadata record(s) from {meta.get('path')}.",
            f"IDS-style alerts generated: {analysis.get('alert_count', 0)}.",
        ]
        if analysis.get("severity_counts"):
            lines.append("Severity counts: " + ", ".join(f"{k}={v}" for k, v in analysis.get("severity_counts", {}).items()))
        for alert in analysis.get("alerts", [])[:8]:
            lines.append(f"- {str(alert.get('severity', 'info')).upper()}: {alert.get('title')} [{alert.get('category')}]")
        if alerts_recorded:
            lines.append(f"Recorded {alerts_recorded} alert(s) to {workspace_relative(IDS_ALERTS_FILE)}.")
        return ToolResult(True, "\n".join(lines), payload)

    def build_ids_baseline(
        self,
        path: str,
        input_format: str = "auto",
        label: str = "baseline",
        limit: int = 10000,
        baseline_path: str = ".agent_ids_baseline.json",
    ) -> ToolResult:
        """Create a simple known-good network baseline from traffic metadata."""
        try:
            flows, meta = _ids_read_traffic_records(path, input_format=input_format, limit=limit)
            baseline = _ids_baseline_from_flows(flows, label=label)
            target = resolve_workspace_path(baseline_path or workspace_relative(IDS_BASELINE_FILE))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
        except Exception as exc:
            return ToolResult(False, f"Failed to build IDS baseline: {exc}", {"error": str(exc), "path": path})
        payload = {**baseline, "source_path": meta.get("path"), "baseline_path": workspace_relative(target), "warnings": meta.get("warnings", [])}
        content = (
            f"Built IDS baseline `{label}` from {len(flows)} flow(s).\n"
            f"Saved to {workspace_relative(target)}.\n"
            f"Known destination ports: {', '.join(str(item) for item in baseline.get('dst_ports', [])[:30]) or 'none'}."
        )
        return ToolResult(True, content, payload)

    def compare_network_baseline(
        self,
        path: str,
        input_format: str = "auto",
        baseline_path: str = ".agent_ids_baseline.json",
        limit: int = 10000,
        sensitivity: str = "medium",
        record_alerts: bool = True,
    ) -> ToolResult:
        """Compare current traffic metadata against a saved baseline."""
        try:
            baseline_target = resolve_workspace_path(baseline_path or workspace_relative(IDS_BASELINE_FILE))
            if not baseline_target.exists():
                return ToolResult(False, f"Baseline file not found: {baseline_path}", {"baseline_path": baseline_path})
            baseline = json.loads(baseline_target.read_text(encoding="utf-8"))
            flows, meta = _ids_read_traffic_records(path, input_format=input_format, limit=limit)
            analysis = _ids_analyze_flows(flows, baseline=baseline, sensitivity=sensitivity)
        except Exception as exc:
            return ToolResult(False, f"Failed to compare traffic to baseline: {exc}", {"error": str(exc), "path": path, "baseline_path": baseline_path})
        alerts_recorded = _ids_append_alerts(analysis.get("alerts", []), source_path=meta.get("path", "")) if record_alerts else 0
        payload = {**meta, **analysis, "baseline_path": workspace_relative(baseline_target), "baseline_label": baseline.get("label"), "alerts_recorded": alerts_recorded}
        content = (
            f"Compared {len(flows)} flow(s) from {meta.get('path')} against baseline `{baseline.get('label', baseline_path)}`.\n"
            f"Alerts/deviations: {analysis.get('alert_count', 0)}."
        )
        return ToolResult(True, content, payload)

    def capture_network_metadata_sample(
        self,
        interface: str = "",
        duration_seconds: int = 15,
        max_packets: int = 200,
        output_path: str = ".agent_ids_captures/sample.jsonl",
        authorized: bool = False,
    ) -> ToolResult:
        """Capture a short metadata-only traffic sample using tshark, if installed and explicitly authorized."""
        if not authorized:
            return ToolResult(
                False,
                "Live capture requires authorized=true because packet capture may require admin rights and must only be used on networks you own or are allowed to monitor.",
                {"authorization_required": True, "authorized": False},
            )
        duration_seconds = max(1, min(int(duration_seconds), 60))
        max_packets = max(1, min(int(max_packets), 1000))
        tshark = shutil.which("tshark")
        if not tshark:
            return ToolResult(
                False,
                "tshark was not found. Install Wireshark/tshark or ingest an existing PCAP/Suricata/Zeek/CSV/JSONL traffic file instead.",
                {"missing_dependency": "tshark", "authorized": True},
            )
        target = resolve_workspace_path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "_ws.col.Protocol", "dns.qry.name", "tls.handshake.extensions_server_name", "http.host",
        ]
        command = [tshark, "-l", "-a", f"duration:{duration_seconds}", "-c", str(max_packets), "-T", "fields"]
        if interface:
            command.extend(["-i", interface])
        for field in fields:
            command.extend(["-e", field])
        command.extend(["-E", "separator=\t", "-E", "occurrence=f"])
        try:
            proc = subprocess.run(command, cwd=str(WORKSPACE_ROOT), text=True, capture_output=True, timeout=duration_seconds + 10)
        except Exception as exc:
            return ToolResult(False, f"Live metadata capture failed: {exc}", {"error": str(exc), "command": " ".join(shlex.quote(part) for part in command)})
        records: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            parts += [""] * (len(fields) - len(parts))
            row = dict(zip(fields, parts))
            src_ip = row.get("ip.src") or row.get("ipv6.src")
            dst_ip = row.get("ip.dst") or row.get("ipv6.dst")
            src_port = row.get("tcp.srcport") or row.get("udp.srcport")
            dst_port = row.get("tcp.dstport") or row.get("udp.dstport")
            records.append(_ids_normalize_flow({
                "ts": row.get("frame.time_epoch"),
                "src_ip": src_ip,
                "dest_ip": dst_ip,
                "src_port": src_port,
                "dest_port": dst_port,
                "proto": row.get("_ws.col.Protocol"),
                "dns_query": row.get("dns.qry.name"),
                "tls_sni": row.get("tls.handshake.extensions_server_name"),
                "http_host": row.get("http.host"),
                "event_type": "live_capture_metadata",
            }, source=workspace_relative(target)))
        with target.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        warnings: list[str] = []
        if proc.returncode not in {0, 1}:
            warnings.append(trim_text(proc.stderr, 600))
        payload = {
            "output_path": workspace_relative(target),
            "packet_count": len(records),
            "duration_seconds": duration_seconds,
            "max_packets": max_packets,
            "interface": interface,
            "command": " ".join(shlex.quote(part) for part in command),
            "warnings": warnings,
            "stderr_preview": trim_text(proc.stderr, 800),
        }
        return ToolResult(True, f"Captured {len(records)} metadata-only traffic row(s) to {workspace_relative(target)}.", payload)

    def build_ids_mode_plan(
        self,
        mode: str = "offline",
        source_path: str = "",
        duration_seconds: int = 30,
        interface: str = "",
        authorized: bool = False,
    ) -> ToolResult:
        """Build a defensive IDS-mode plan without silently starting live capture."""
        mode = str(mode or "offline").lower()
        duration_seconds = max(1, min(int(duration_seconds or 30), 60))
        sequence: list[dict[str, Any]] = []
        if source_path:
            sequence.append({"tool": "ingest_network_traffic_file", "purpose": "Normalize the supplied traffic source into metadata-only flow records.", "args": {"path": source_path, "input_format": "auto", "limit": 5000}})
            sequence.append({"tool": "analyze_network_traffic_file", "purpose": "Generate IDS-style alerts and traffic summary from the normalized source.", "args": {"path": source_path, "input_format": "auto", "sensitivity": "medium", "record_alerts": True}})
        elif mode == "live":
            sequence.append({"tool": "capture_network_metadata_sample", "purpose": "Collect a short metadata-only traffic sample after explicit authorization.", "args": {"interface": interface, "duration_seconds": duration_seconds, "max_packets": 200, "authorized": bool(authorized)}})
            sequence.append({"tool": "analyze_network_traffic_file", "purpose": "Analyze the saved live metadata sample for IDS-style alerts.", "args": {"path": ".agent_ids_captures/sample.jsonl", "input_format": "jsonl", "sensitivity": "medium", "record_alerts": True}})
        else:
            sequence.append({"tool": "ingest_network_traffic_file", "purpose": "Start with a PCAP, Suricata EVE JSONL, Zeek conn.log, CSV, or JSONL traffic file inside the workspace.", "args": {"path": "traffic.pcap", "input_format": "auto", "limit": 5000}})
            sequence.append({"tool": "build_ids_baseline", "purpose": "Optional: build a known-good baseline from clean traffic before monitoring deviations.", "args": {"path": "known_good.pcap", "input_format": "auto", "label": "known-good"}})
            sequence.append({"tool": "compare_network_baseline", "purpose": "Optional: compare current traffic against the saved baseline.", "args": {"path": "current.pcap", "baseline_path": ".agent_ids_baseline.json"}})
        payload = {
            "mode": mode,
            "source_path": source_path,
            "duration_seconds": duration_seconds,
            "interface": interface,
            "authorized": bool(authorized),
            "recommended_sequence": sequence,
            "safety_rules": [
                "Only monitor networks and devices you own or are explicitly authorized to defend.",
                "Prefer offline PCAP/Zeek/Suricata ingestion for repeatable analysis.",
                "Live capture is capped, metadata-only, and requires authorized=true.",
                "Do not retain packet payloads or secrets in agent state.",
                "Correlate alerts with endpoint/router/firewall logs before concluding compromise.",
            ],
            "supported_inputs": ["classic .pcap", "Suricata eve.json/eve.jsonl", "Zeek conn.log", "CSV flow exports", "generic IP-to-IP text logs"],
        }
        return ToolResult(True, "Built defensive IDS-mode plan.", payload)

    def show_ids_alerts(self, limit: int = 20, min_severity: str = "info") -> ToolResult:
        """Show recent IDS alerts recorded by the analysis tools."""
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = severity_rank.get(str(min_severity or "info").lower(), 0)
        limit = max(1, min(int(limit), 200))
        alerts: list[dict[str, Any]] = []
        if IDS_ALERTS_FILE.exists():
            for line in IDS_ALERTS_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict) and severity_rank.get(str(parsed.get("severity", "info")), 0) >= min_rank:
                    alerts.append(parsed)
        selected = alerts[-limit:]
        payload = {"alerts": selected, "total_alerts": len(alerts), "limit": limit, "min_severity": min_severity, "path": workspace_relative(IDS_ALERTS_FILE)}
        content = f"Showing {len(selected)} IDS alert(s) from {workspace_relative(IDS_ALERTS_FILE)}."
        return ToolResult(True, content, payload)

    def lookup_cve(self, cve_id: str, include_kev: bool = True, timeout: int = 15) -> ToolResult:
        """Look up a single CVE using NVD and optionally CISA KEV."""
        cve_id = _normalize_cve_id(cve_id)
        if not _is_cve_id(cve_id):
            return ToolResult(False, f"Invalid CVE id: {cve_id or '<empty>'}", {"cve_id": cve_id, "valid": False})
        kev_entry: dict[str, Any] | None = None
        warnings: list[str] = []
        if include_kev:
            catalog, kev_warnings = _load_cisa_kev_catalog(refresh=False, timeout=timeout)
            warnings.extend(kev_warnings)
            kev_entry = _kev_index(catalog).get(cve_id)
        try:
            payload = _nvd_get({"cveIds": cve_id}, timeout=timeout)
        except Exception as exc:
            return ToolResult(False, f"NVD lookup failed for {cve_id}: {trim_text(str(exc), 800)}", {"cve_id": cve_id, "error": str(exc), "warnings": warnings})
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
        if not vulnerabilities:
            return ToolResult(False, f"No NVD record returned for {cve_id}.", {"cve_id": cve_id, "nvd": payload, "warnings": warnings})
        normalized = _normalize_nvd_vulnerability(vulnerabilities[0], kev=kev_entry)
        result_payload = {
            "cve_id": cve_id,
            "cve": normalized,
            "nvd_total_results": payload.get("totalResults"),
            "include_kev": bool(include_kev),
            "warnings": warnings,
            "sources": {"nvd": NVD_CVE_API_URL, "cisa_kev": CISA_KEV_URLS[0]},
        }
        cvss = normalized.get("cvss") if isinstance(normalized.get("cvss"), dict) else {}
        content = f"{cve_id}: {cvss.get('base_severity', 'unknown')} {cvss.get('base_score', '')}; KEV={'yes' if normalized.get('is_known_exploited') else 'no'}"
        return ToolResult(True, content, result_payload)

    def search_cves(
        self,
        keyword: str = "",
        cpe_name: str = "",
        cvss_severity: str = "",
        published_days: int = 0,
        modified_days: int = 0,
        limit: int = 20,
        include_kev: bool = True,
        timeout: int = 15,
    ) -> ToolResult:
        """Search CVEs through NVD with bounded result count and optional KEV enrichment."""
        limit = max(1, min(int(limit or 20), 100))
        params: dict[str, Any] = {"resultsPerPage": limit, "startIndex": 0}
        if keyword:
            params["keywordSearch"] = str(keyword).strip()
        if cpe_name:
            params["cpeName"] = str(cpe_name).strip()
        severity = str(cvss_severity or "").strip().upper()
        if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            params["cvssV3Severity"] = severity
        now = datetime.now(timezone.utc)
        if int(published_days or 0) > 0:
            days = max(1, min(int(published_days), 120))
            start = now - __import__("datetime").timedelta(days=days)
            params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            params["pubEndDate"] = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if int(modified_days or 0) > 0:
            days = max(1, min(int(modified_days), 120))
            start = now - __import__("datetime").timedelta(days=days)
            params["lastModStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            params["lastModEndDate"] = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if not any(params.get(key) for key in ("keywordSearch", "cpeName", "cvssV3Severity", "pubStartDate", "lastModStartDate")):
            return ToolResult(False, "Provide keyword, cpe_name, cvss_severity, published_days, or modified_days for a bounded CVE search.", {"params": params})
        warnings: list[str] = []
        kev_by_cve: dict[str, dict[str, Any]] = {}
        if include_kev:
            catalog, kev_warnings = _load_cisa_kev_catalog(refresh=False, timeout=timeout)
            warnings.extend(kev_warnings)
            kev_by_cve = _kev_index(catalog)
        try:
            payload = _nvd_get(params, timeout=timeout)
        except Exception as exc:
            return ToolResult(False, f"NVD CVE search failed: {trim_text(str(exc), 800)}", {"error": str(exc), "params": params, "warnings": warnings})
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
        results = []
        for item in vulnerabilities[:limit]:
            cve_obj = item.get("cve") if isinstance(item, dict) and isinstance(item.get("cve"), dict) else {}
            cve_id = _normalize_cve_id(str(cve_obj.get("id") or ""))
            results.append(_normalize_nvd_vulnerability(item, kev=kev_by_cve.get(cve_id)))
        result_payload = {
            "query": {"keyword": keyword, "cpe_name": cpe_name, "cvss_severity": cvss_severity, "published_days": published_days, "modified_days": modified_days},
            "params": params,
            "total_results": payload.get("totalResults", len(results)),
            "results": results,
            "warnings": warnings,
            "sources": {"nvd": NVD_CVE_API_URL, "cisa_kev": CISA_KEV_URLS[0]},
        }
        return ToolResult(True, f"Found {len(results)} CVE result(s) shown from NVD search.", result_payload)

    def check_cisa_kev(
        self,
        cve_id: str = "",
        vendor: str = "",
        product: str = "",
        keyword: str = "",
        limit: int = 50,
        refresh: bool = False,
        timeout: int = 12,
    ) -> ToolResult:
        """Search CISA KEV by CVE/vendor/product/keyword."""
        limit = max(1, min(int(limit or 50), 500))
        catalog, warnings = _load_cisa_kev_catalog(refresh=refresh, timeout=timeout)
        rows = catalog.get("vulnerabilities") if isinstance(catalog.get("vulnerabilities"), list) else []
        norm_cve = _normalize_cve_id(cve_id) if cve_id else ""
        vendor_l = str(vendor or "").lower().strip()
        product_l = str(product or "").lower().strip()
        keyword_l = str(keyword or "").lower().strip()
        matches: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            searchable = " ".join(str(row.get(key, "")) for key in row)
            if norm_cve and _normalize_cve_id(str(row.get("cveID") or "")) != norm_cve:
                continue
            if vendor_l and vendor_l not in str(row.get("vendorProject", "")).lower():
                continue
            if product_l and product_l not in str(row.get("product", "")).lower():
                continue
            if keyword_l and keyword_l not in searchable.lower():
                continue
            matches.append(row)
        if not any([norm_cve, vendor_l, product_l, keyword_l]):
            matches = list(reversed(rows[-limit:]))
        selected = matches[:limit]
        result_payload = {
            "catalog_title": catalog.get("title"),
            "catalog_version": catalog.get("catalogVersion") or catalog.get("catalog_version"),
            "catalog_date_released": catalog.get("dateReleased"),
            "source_url": catalog.get("source_url", CISA_KEV_URLS[0]),
            "fetched_at": catalog.get("fetched_at", ""),
            "query": {"cve_id": norm_cve, "vendor": vendor, "product": product, "keyword": keyword},
            "catalog_count": len(rows),
            "match_count": len(matches),
            "matches": selected,
            "warnings": warnings,
        }
        return ToolResult(True, f"CISA KEV query returned {len(selected)} shown of {len(matches)} matching item(s).", result_payload)

    def lookup_malware_hash(self, file_hash: str, timeout: int = 15) -> ToolResult:
        """Query MalwareBazaar for a hash; never download samples."""
        candidate = str(file_hash or "").strip().lower()
        if not _is_hash_indicator(candidate):
            return ToolResult(False, "Provide a valid MD5, SHA1, or SHA256 hash.", {"hash": candidate, "valid": False})
        headers = {"User-Agent": "Cerebro-Agent/1.0"}
        auth_key = os.environ.get("MALWAREBAZAAR_API_KEY", "").strip()
        if auth_key:
            headers["Auth-Key"] = auth_key
        try:
            payload = http_post_form_json(MALWAREBAZAAR_API_URL, {"query": "get_info", "hash": candidate}, headers=headers, timeout=timeout)
        except Exception as exc:
            return ToolResult(False, f"MalwareBazaar lookup failed: {trim_text(str(exc), 800)}", {"hash": candidate, "error": str(exc)})
        if not isinstance(payload, dict):
            return ToolResult(False, "MalwareBazaar returned an unexpected payload shape.", {"hash": candidate, "raw": payload})
        data = payload.get("data") if isinstance(payload.get("data"), list) else []
        summarized_rows: list[dict[str, Any]] = []
        for row in data[:10]:
            if not isinstance(row, dict):
                continue
            summarized_rows.append({
                "sha256_hash": row.get("sha256_hash"),
                "sha1_hash": row.get("sha1_hash"),
                "md5_hash": row.get("md5_hash"),
                "file_name": row.get("file_name"),
                "file_type": row.get("file_type"),
                "file_size": row.get("file_size"),
                "signature": row.get("signature"),
                "tags": row.get("tags") if isinstance(row.get("tags"), list) else [],
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
                "reporter": row.get("reporter"),
            })
        result_payload = {
            "hash": candidate,
            "hash_algorithm": _hash_algorithm_for_value(candidate),
            "query_status": payload.get("query_status"),
            "data": summarized_rows,
            "result_count": len(summarized_rows),
            "source": MALWAREBAZAAR_API_URL,
            "sample_downloaded": False,
        }
        status = str(payload.get("query_status", "unknown"))
        return ToolResult(True, f"MalwareBazaar status for {candidate}: {status}.", result_payload)

    def hash_workspace_file(self, path: str, lookup_malware_bazaar: bool = False, timeout: int = 15) -> ToolResult:
        """Hash one workspace file and optionally enrich SHA256 with MalwareBazaar metadata."""
        target = resolve_workspace_path(path)
        if not target.exists() or not target.is_file():
            return ToolResult(False, f"File not found: {path}", {"path": path})
        try:
            hashes = _file_hashes(target)
        except OSError as exc:
            return ToolResult(False, f"Could not hash file: {exc}", {"path": workspace_relative(target), "error": str(exc)})
        lookup_payload = None
        if lookup_malware_bazaar:
            lookup = self.lookup_malware_hash(hashes["sha256"], timeout=timeout)
            lookup_payload = lookup.meta | {"ok": lookup.ok, "content": lookup.content}
        payload = {
            "path": workspace_relative(target),
            "size": target.stat().st_size,
            "hashes": hashes,
            "malware_lookup": lookup_payload,
        }
        return ToolResult(True, f"Calculated hashes for {workspace_relative(target)}.", payload)

    def list_crypto_algorithms(self) -> ToolResult:
        """List local cryptographic algorithm availability and supported envelope formats."""
        payload = _crypto_availability()
        lines = ["Cryptography tools available:"]
        for name, spec in payload["algorithms"].items():
            status = "available" if spec.get("available") else "unavailable"
            recommended = "recommended" if spec.get("recommended") else "fallback"
            lines.append(f"- {name}: {spec.get('display')} ({status}, {recommended})")
        if not payload.get("cryptography_available"):
            lines.append("Install `cryptography` to enable AES-GCM, ChaCha20-Poly1305, and Fernet.")
        return ToolResult(True, "\n".join(lines), payload)

    def encrypt_text(
        self,
        data: str,
        algorithm: str = "aesgcm",
        passphrase: str = "",
        key_b64: str = "",
        input_format: str = "text",
        associated_data: str = "",
        iterations: int = CRYPTO_DEFAULT_PBKDF2_ITERATIONS,
    ) -> ToolResult:
        """Encrypt text/base64/hex input into a portable authenticated envelope."""
        try:
            plaintext = _crypto_bytes_from_input(data, input_format=input_format)
            token, envelope = _crypto_encrypt_bytes(
                plaintext,
                algorithm=algorithm,
                passphrase=passphrase,
                key_b64=key_b64,
                associated_data=associated_data,
                iterations=iterations,
            )
        except Exception as exc:
            return ToolResult(False, f"Encryption failed: {exc}", {"error": str(exc), "algorithm": str(algorithm or "")})
        payload = {
            "algorithm": envelope.get("algorithm"),
            "kdf": envelope.get("kdf"),
            "plaintext_length": envelope.get("plaintext_length"),
            "associated_data_used": bool(associated_data),
            "encrypted_text": token,
            "warnings": [
                "Store the passphrase or raw key separately; it is not embedded in the envelope.",
                "For serious protection, prefer aesgcm or chacha20poly1305 when available.",
            ],
        }
        return ToolResult(True, token, payload)

    def decrypt_text(
        self,
        encrypted_text: str,
        passphrase: str = "",
        key_b64: str = "",
        output_format: str = "text",
        associated_data: str = "",
    ) -> ToolResult:
        """Decrypt a crypto envelope and return text, base64, or hex."""
        try:
            plaintext, meta = _crypto_decrypt_bytes(
                encrypted_text,
                passphrase=passphrase,
                key_b64=key_b64,
                associated_data=associated_data,
            )
            output, actual_format = _crypto_bytes_to_output(plaintext, output_format=output_format)
        except Exception as exc:
            return ToolResult(False, f"Decryption failed: {exc}", {"error": str(exc)})
        payload = meta | {
            "output_format": actual_format,
            "output_length": len(output),
            "note": "Tool-history preview redacts decrypt_text output, but the plaintext is returned to the current model turn.",
        }
        if actual_format != str(output_format or "text").lower().strip():
            payload["format_warning"] = "Plaintext was not valid UTF-8; returned base64 instead."
        return ToolResult(True, output, payload)

    def encrypt_file(
        self,
        input_path: str,
        output_path: str = "",
        algorithm: str = "aesgcm",
        passphrase: str = "",
        key_b64: str = "",
        associated_data: str = "",
        iterations: int = CRYPTO_DEFAULT_PBKDF2_ITERATIONS,
        overwrite: bool = False,
        max_bytes: int = CRYPTO_MAX_FILE_BYTES_DEFAULT,
    ) -> ToolResult:
        """Encrypt a workspace file into a text envelope file."""
        source = resolve_workspace_path(input_path)
        if not source.exists() or not source.is_file():
            return ToolResult(False, f"File not found: {input_path}", {"input_path": input_path})
        max_bytes = max(1, min(int(max_bytes or CRYPTO_MAX_FILE_BYTES_DEFAULT), 512 * 1024 * 1024))
        size = source.stat().st_size
        if size > max_bytes:
            return ToolResult(False, f"Refusing to encrypt {size} bytes because max_bytes={max_bytes}.", {"size": size, "max_bytes": max_bytes})
        target = resolve_workspace_path(output_path) if output_path else _default_encrypted_output_path(source)
        if target.exists() and not overwrite:
            return ToolResult(False, f"Output file already exists: {workspace_relative(target)}. Set overwrite=true to replace it.", {"output_path": workspace_relative(target)})
        try:
            plaintext = source.read_bytes()
            token, envelope = _crypto_encrypt_bytes(
                plaintext,
                algorithm=algorithm,
                passphrase=passphrase,
                key_b64=key_b64,
                associated_data=associated_data,
                iterations=iterations,
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(token + "\n", encoding="utf-8")
        except Exception as exc:
            return ToolResult(False, f"File encryption failed: {exc}", {"input_path": workspace_relative(source), "error": str(exc)})
        payload = {
            "input_path": workspace_relative(source),
            "output_path": workspace_relative(target),
            "input_bytes": size,
            "output_bytes": target.stat().st_size,
            "algorithm": envelope.get("algorithm"),
            "kdf": envelope.get("kdf"),
            "associated_data_used": bool(associated_data),
            "sha256_plaintext": hashlib.sha256(plaintext).hexdigest(),
            "warnings": ["Store the passphrase or raw key separately; it is not embedded in the envelope."],
        }
        return ToolResult(True, f"Encrypted {workspace_relative(source)} -> {workspace_relative(target)}", payload)

    def decrypt_file(
        self,
        input_path: str,
        output_path: str = "",
        passphrase: str = "",
        key_b64: str = "",
        associated_data: str = "",
        overwrite: bool = False,
        max_bytes: int = CRYPTO_MAX_FILE_BYTES_DEFAULT,
    ) -> ToolResult:
        """Decrypt a workspace crypto envelope file back to raw bytes."""
        source = resolve_workspace_path(input_path)
        if not source.exists() or not source.is_file():
            return ToolResult(False, f"File not found: {input_path}", {"input_path": input_path})
        max_bytes = max(1, min(int(max_bytes or CRYPTO_MAX_FILE_BYTES_DEFAULT), 512 * 1024 * 1024))
        size = source.stat().st_size
        if size > max_bytes * 2 + 4096:
            return ToolResult(False, f"Refusing to decrypt {size} bytes because max_bytes={max_bytes}.", {"size": size, "max_bytes": max_bytes})
        target = resolve_workspace_path(output_path) if output_path else _default_decrypted_output_path(source)
        if target.exists() and not overwrite:
            return ToolResult(False, f"Output file already exists: {workspace_relative(target)}. Set overwrite=true to replace it.", {"output_path": workspace_relative(target)})
        try:
            token = source.read_text(encoding="utf-8", errors="strict").strip()
            plaintext, meta = _crypto_decrypt_bytes(
                token,
                passphrase=passphrase,
                key_b64=key_b64,
                associated_data=associated_data,
            )
            if len(plaintext) > max_bytes:
                return ToolResult(False, f"Refusing to write decrypted payload of {len(plaintext)} bytes because max_bytes={max_bytes}.", {"plaintext_bytes": len(plaintext), "max_bytes": max_bytes})
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(plaintext)
        except Exception as exc:
            return ToolResult(False, f"File decryption failed: {exc}", {"input_path": workspace_relative(source), "error": str(exc)})
        payload = meta | {
            "input_path": workspace_relative(source),
            "output_path": workspace_relative(target),
            "input_bytes": size,
            "output_bytes": target.stat().st_size,
            "sha256_plaintext": hashlib.sha256(plaintext).hexdigest(),
        }
        return ToolResult(True, f"Decrypted {workspace_relative(source)} -> {workspace_relative(target)}", payload)

    def add_malware_signature(
        self,
        name: str,
        pattern: str,
        signature_type: str = "string",
        severity: str = "medium",
        tags: list[str] | str | None = None,
        description: str = "",
        source: str = "local",
        overwrite: bool = False,
        signature_path: str = "",
    ) -> ToolResult:
        """Add a local defensive malware signature."""
        cleaned_name = str(name or "").strip()
        cleaned_pattern = str(pattern or "")
        sig_type = str(signature_type or "string").lower().strip()
        if not cleaned_name:
            return ToolResult(False, "Signature name cannot be empty.", {})
        if not cleaned_pattern:
            return ToolResult(False, "Signature pattern cannot be empty.", {})
        if sig_type not in {"string", "regex", "hex", "hash", "md5", "sha1", "sha256", "yara"}:
            return ToolResult(False, "signature_type must be one of string, regex, hex, hash, md5, sha1, sha256, yara.", {"signature_type": sig_type})
        if sig_type == "regex":
            try:
                re.compile(cleaned_pattern)
            except re.error as exc:
                return ToolResult(False, f"Invalid regex signature: {exc}", {"error": str(exc)})
        if sig_type in {"hash", "md5", "sha1", "sha256"} and not _is_hash_indicator(cleaned_pattern):
            return ToolResult(False, "Hash signatures must use an MD5, SHA1, or SHA256 hex value.", {"pattern": cleaned_pattern})
        tag_list = [item.strip() for item in tags.split(",")] if isinstance(tags, str) else [str(item).strip() for item in (tags or [])]
        tag_list = [item for item in tag_list if item]
        catalog, warnings = _load_malware_signatures(signature_path)
        signatures = catalog.setdefault("signatures", [])
        existing_index = next((i for i, item in enumerate(signatures) if isinstance(item, dict) and str(item.get("name", "")).lower() == cleaned_name.lower()), None)
        if existing_index is not None and not overwrite:
            return ToolResult(False, f"Signature `{cleaned_name}` already exists. Re-run with overwrite=true to replace it.", {"name": cleaned_name, "warnings": warnings})
        record = {
            "name": cleaned_name,
            "signature_type": sig_type,
            "pattern": cleaned_pattern,
            "severity": str(severity or "medium").lower(),
            "tags": tag_list,
            "description": str(description or ""),
            "source": str(source or "local"),
            "created_at": utc_now(),
        }
        if existing_index is None:
            signatures.append(record)
        else:
            previous = signatures[existing_index] if isinstance(signatures[existing_index], dict) else {}
            record["created_at"] = previous.get("created_at", record["created_at"])
            record["updated_at"] = utc_now()
            signatures[existing_index] = record
        target = _save_malware_signatures(catalog, signature_path)
        payload = {"name": cleaned_name, "signature_path": workspace_relative(target), "signature_count": len(signatures), "warnings": warnings}
        return ToolResult(True, f"Saved signature `{cleaned_name}`.", payload)

    def scan_workspace_file_signatures(
        self,
        path: str,
        signature_path: str = "",
        recursive: bool = False,
        max_files: int = 50,
        max_bytes_per_file: int = 5_242_880,
        use_yara: bool = True,
    ) -> ToolResult:
        """Scan workspace files with local signatures without executing them."""
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}", {"path": path})
        max_files = max(1, min(int(max_files or 50), 500))
        max_bytes_per_file = max(1024, min(int(max_bytes_per_file or 5_242_880), 100 * 1024 * 1024))
        catalog, warnings = _load_malware_signatures(signature_path)
        signatures = [item for item in catalog.get("signatures", []) if isinstance(item, dict)]
        if not use_yara:
            signatures = [item for item in signatures if str(item.get("signature_type", item.get("type", ""))).lower() != "yara"]
        candidates = [target] if target.is_file() else list(target.rglob("*") if recursive else target.iterdir())
        files = [item for item in candidates if item.is_file() and not should_skip_checkpoint_path(item)][:max_files]
        matches: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        yara_warnings: list[str] = []
        for candidate in files:
            try:
                stat = candidate.stat()
            except OSError as exc:
                skipped.append({"path": workspace_relative(candidate), "reason": str(exc)})
                continue
            if stat.st_size > max_bytes_per_file:
                skipped.append({"path": workspace_relative(candidate), "reason": f"larger than max_bytes_per_file ({max_bytes_per_file})"})
                continue
            try:
                data = candidate.read_bytes()
            except OSError as exc:
                skipped.append({"path": workspace_relative(candidate), "reason": str(exc)})
                continue
            text = data.decode("latin-1", errors="ignore")
            hashes = _file_hashes(candidate)
            for signature in signatures:
                result = _scan_signature_against_bytes(signature, data, text, hashes)
                if not result:
                    continue
                if result.get("warning"):
                    yara_warnings.append(f"{signature.get('name')}: {result.get('warning')}")
                    continue
                if not result.get("matched"):
                    continue
                evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
                matches.append({
                    "path": workspace_relative(candidate),
                    "signature": result.get("name"),
                    "signature_type": evidence.get("signature_type") or signature.get("signature_type") or signature.get("type"),
                    "severity": result.get("severity"),
                    "tags": result.get("tags"),
                    "description": result.get("description"),
                    "source": result.get("source"),
                    "evidence": evidence,
                    "hashes": hashes,
                })
        warnings.extend(sorted(set(yara_warnings))[:20])
        severity_counts = dict(collections.Counter(str(match.get("severity", "info")).lower() for match in matches))
        payload = {
            "path": workspace_relative(target),
            "signature_path": signature_path or workspace_relative(MALWARE_SIGNATURES_FILE),
            "signature_count": len(signatures),
            "file_count": len(files),
            "match_count": len(matches),
            "severity_counts": severity_counts,
            "matches": matches[:200],
            "skipped": skipped[:50],
            "warnings": warnings,
        }
        return ToolResult(True, f"Scanned {len(files)} file(s) and found {len(matches)} signature match(es).", payload)

    def build_threat_intel_brief(self, indicator: str, include_cve: bool = True, include_malware: bool = True) -> ToolResult:
        """Build a defensive threat-intel brief and next-tool sequence for an indicator."""
        raw = str(indicator or "").strip()
        findings: list[dict[str, Any]] = []
        sequence: list[dict[str, Any]] = []
        if not raw:
            return ToolResult(False, "Indicator cannot be empty.", {})
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", raw, re.I)
        hash_match = re.search(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", raw)
        if cve_match and include_cve:
            cve_id = _normalize_cve_id(cve_match.group(0))
            findings.append({"type": "cve", "summary": f"Looks like a CVE identifier: {cve_id}."})
            sequence.append({"tool": "lookup_cve", "purpose": "Fetch NVD details and CISA KEV status.", "args": {"cve_id": cve_id, "include_kev": True}})
            sequence.append({"tool": "check_cisa_kev", "purpose": "Confirm known-exploited catalog details.", "args": {"cve_id": cve_id}})
        elif hash_match and include_malware:
            file_hash = hash_match.group(0).lower()
            findings.append({"type": "file_hash", "summary": f"Looks like a {_hash_algorithm_for_value(file_hash).upper()} file hash."})
            sequence.append({"tool": "lookup_malware_hash", "purpose": "Query MalwareBazaar metadata without downloading samples.", "args": {"file_hash": file_hash}})
        else:
            if include_cve:
                findings.append({"type": "cve_search", "summary": "No exact CVE id found; use keyword/CPE search for vulnerability discovery."})
                sequence.append({"tool": "search_cves", "purpose": "Search NVD by product, vendor, keyword, CPE, severity, or recent publication window.", "args": {"keyword": raw, "limit": 20, "include_kev": True}})
            if include_malware:
                findings.append({"type": "signature_workflow", "summary": "For malware signatures, add local string/regex/hex/hash/YARA signatures, then scan workspace files."})
                sequence.append({"tool": "add_malware_signature", "purpose": "Store a local defensive signature.", "args": {"name": "descriptive name", "pattern": "pattern", "signature_type": "string"}})
                sequence.append({"tool": "scan_workspace_file_signatures", "purpose": "Scan files with local signatures without executing them.", "args": {"path": "sample.bin", "recursive": False}})
        payload = {
            "indicator": raw,
            "findings": findings,
            "recommended_sequence": sequence,
            "safety_rules": [
                "Use these tools for defensive triage, patch prioritization, and local file assessment only.",
                "Do not download malware samples inside the agent.",
                "Do not execute suspect files; hash and scan them as inert bytes.",
                "Treat signature hits as indicators requiring corroboration, not standalone proof of compromise.",
            ],
            "supported_sources": ["NVD CVE API 2.0", "CISA KEV catalog", "MalwareBazaar hash metadata", "local JSON/YARA signatures"],
        }
        return ToolResult(True, "Built defensive threat-intelligence brief.", payload)

    def normalize_network_target(self, target: str, resolve: bool = False, allow_private: bool = False) -> ToolResult:
        host, reason, meta = self._extract_network_host(target)
        if not host:
            return ToolResult(False, reason, meta=meta)
        payload: dict[str, Any] = {
            "generated_at": utc_now(),
            "target": str(target or "").strip(),
            "host": host,
            "input": meta,
            "is_ip": False,
            "is_cidr": False,
            "addresses": [],
            "allowed_for_passive_lookup": True,
            "allowed_for_default_port_scan": True,
            "warnings": [],
        }
        try:
            network = ipaddress.ip_network(host, strict=False)
            payload["is_cidr"] = "/" in host
            payload["is_ip"] = network.num_addresses == 1
            payload["network"] = str(network)
            payload["prefixlen"] = network.prefixlen
            if network.num_addresses == 1:
                classification = self._ip_classification(str(network.network_address))
                payload["addresses"].append(classification)
                if not allow_private and not classification.get("is_publicly_routable"):
                    payload["allowed_for_passive_lookup"] = False
                    payload["warnings"].append("Private/local/special-use IP detected; external enrichment is skipped unless explicitly allowed by the caller.")
            else:
                payload["allowed_for_default_port_scan"] = False
                payload["warnings"].append("CIDR input is recognized but active scanning tools require a single host.")
        except ValueError:
            try:
                ip_obj = ipaddress.ip_address(host)
                classification = self._ip_classification(str(ip_obj))
                payload["is_ip"] = True
                payload["addresses"].append(classification)
            except ValueError:
                payload["kind"] = "hostname"
                if resolve:
                    records, warnings = self._resolve_host_ips(host)
                    payload["addresses"] = records
                    payload["warnings"].extend(warnings)
                    if not allow_private and any(not row.get("is_publicly_routable") for row in records):
                        payload["warnings"].append("Hostname resolves to at least one private/local/special-use address.")
        if payload["addresses"]:
            payload["public_addresses"] = [row for row in payload["addresses"] if row.get("is_publicly_routable")]
            payload["private_or_special_addresses"] = [row for row in payload["addresses"] if not row.get("is_publicly_routable")]
        payload["recommendations"] = [
            "Use resolve_dns_records before active checks when the target is a hostname.",
            "Use lookup_ip_rdap and lookup_ip_geolocation only for public routable IPs.",
            "Use scan_tcp_ports only for assets you own or are explicitly authorized to test; public scans require allow_public=true.",
        ]
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def resolve_dns_records(self, target: str, record_type: str = "A", allow_private: bool = False, timeout: int = 5) -> ToolResult:
        host, reason, meta = self._extract_network_host(target)
        if not host:
            return ToolResult(False, reason, meta=meta)
        record_type = str(record_type or "A").upper().strip()
        timeout = max(1, min(safe_int(timeout, 5), 20))
        records, warnings = self._resolve_host_ips(host, timeout=timeout)
        if record_type in {"A", "IPV4"}:
            records = [row for row in records if row.get("family") == "IPv4"]
        elif record_type in {"AAAA", "IPV6"}:
            records = [row for row in records if row.get("family") == "IPv6"]
        elif record_type in {"ANY", "ADDR", "ADDRESS"}:
            pass
        else:
            warnings.append("Only A/AAAA/ANY-style address lookups are supported without optional DNS libraries.")
        if not allow_private:
            private_hits = [row for row in records if not row.get("is_publicly_routable")]
            if private_hits:
                warnings.append("Some resolved addresses are private/local/special-use; they are included for diagnostics but should not be externally enriched.")
        payload = {
            "generated_at": utc_now(),
            "target": str(target or "").strip(),
            "host": host,
            "record_type": record_type,
            "records": records,
            "record_count": len(records),
            "warnings": warnings,
            "recommendations": ["Use reverse_dns_lookup for PTR context and lookup_ip_rdap for public ownership/ASN context."],
        }
        return ToolResult(bool(records) or bool(warnings), json.dumps(payload, indent=2), meta=payload)

    def reverse_dns_lookup(self, ip: str, allow_private: bool = False) -> ToolResult:
        ip_text = str(ip or "").strip()
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            return ToolResult(False, f"Invalid IP address: {exc}")
        classification = self._ip_classification(str(ip_obj))
        if not allow_private and not classification.get("is_publicly_routable"):
            payload = {
                "generated_at": utc_now(),
                "ip": str(ip_obj),
                "classification": classification,
                "ptr_records": [],
                "skipped": True,
                "reason": "Private/local/special-use IP reverse lookup skipped unless allow_private=true.",
            }
            return ToolResult(True, json.dumps(payload, indent=2), meta=payload)
        ptr_records: list[str] = []
        error = ""
        try:
            host, aliases, _addresses = socket.gethostbyaddr(str(ip_obj))
            ptr_records = [host] + list(aliases)
        except Exception as exc:
            error = trim_text(str(exc), 400)
        payload = {
            "generated_at": utc_now(),
            "ip": str(ip_obj),
            "classification": classification,
            "ptr_records": sorted(set(ptr_records)),
            "error": error,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def lookup_ip_rdap(self, target: str, timeout: int = 10) -> ToolResult:
        timeout = max(1, min(safe_int(timeout, 10), 30))
        public_ip, target_meta, reason = self._public_ip_from_target(target)
        if not public_ip:
            payload = {
                "generated_at": utc_now(),
                "target": str(target or "").strip(),
                "target_meta": target_meta,
                "skipped": True,
                "reason": reason,
            }
            return ToolResult(True, json.dumps(payload, indent=2), meta=payload)
        url = f"https://rdap.org/ip/{urllib.parse.quote(public_ip)}"
        try:
            payload_raw = http_get_json(url, {"accept": "application/rdap+json, application/json"}, timeout=timeout)
        except Exception as exc:
            return ToolResult(False, f"RDAP lookup failed for {public_ip}: {trim_text(str(exc), 600)}", meta={"ip": public_ip, "target_meta": target_meta})
        events = payload_raw.get("events", []) if isinstance(payload_raw, dict) else []
        entities = payload_raw.get("entities", []) if isinstance(payload_raw, dict) else []
        notices = payload_raw.get("notices", []) if isinstance(payload_raw, dict) else []
        payload = {
            "generated_at": utc_now(),
            "target": str(target or "").strip(),
            "ip": public_ip,
            "target_meta": target_meta,
            "rdap_url": url,
            "handle": payload_raw.get("handle") if isinstance(payload_raw, dict) else None,
            "name": payload_raw.get("name") if isinstance(payload_raw, dict) else None,
            "type": payload_raw.get("type") if isinstance(payload_raw, dict) else None,
            "country": payload_raw.get("country") if isinstance(payload_raw, dict) else None,
            "start_address": payload_raw.get("startAddress") if isinstance(payload_raw, dict) else None,
            "end_address": payload_raw.get("endAddress") if isinstance(payload_raw, dict) else None,
            "ip_version": payload_raw.get("ipVersion") if isinstance(payload_raw, dict) else None,
            "events": events[:8] if isinstance(events, list) else [],
            "entity_handles": [entity.get("handle") for entity in entities[:8] if isinstance(entity, dict)],
            "notices": [notice.get("title") for notice in notices[:6] if isinstance(notice, dict)],
            "raw_keys": sorted(payload_raw.keys()) if isinstance(payload_raw, dict) else [],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def lookup_ip_geolocation(self, target: str, timeout: int = 10) -> ToolResult:
        timeout = max(1, min(safe_int(timeout, 10), 30))
        public_ip, target_meta, reason = self._public_ip_from_target(target)
        if not public_ip:
            payload = {
                "generated_at": utc_now(),
                "target": str(target or "").strip(),
                "target_meta": target_meta,
                "skipped": True,
                "reason": reason,
            }
            return ToolResult(True, json.dumps(payload, indent=2), meta=payload)
        sources = [
            ("ipinfo", f"https://ipinfo.io/{urllib.parse.quote(public_ip)}/json"),
            ("ipapi", f"https://ipapi.co/{urllib.parse.quote(public_ip)}/json/"),
        ]
        errors: list[str] = []
        for source, url in sources:
            try:
                raw = http_get_json(url, {"accept": "application/json", "user-agent": "Cerebro-Agent/1.0 (+ip-enrichment)"}, timeout=timeout)
            except Exception as exc:
                errors.append(f"{source}: {trim_text(str(exc), 240)}")
                continue
            if not isinstance(raw, dict):
                errors.append(f"{source}: unexpected payload")
                continue
            payload = {
                "generated_at": utc_now(),
                "target": str(target or "").strip(),
                "ip": public_ip,
                "source": source,
                "target_meta": target_meta,
                "city": raw.get("city"),
                "region": raw.get("region") or raw.get("region_code"),
                "country": raw.get("country") or raw.get("country_name"),
                "loc": raw.get("loc") or raw.get("latitude"),
                "timezone": raw.get("timezone") or raw.get("utc_offset"),
                "org": raw.get("org") or raw.get("asn") or raw.get("network"),
                "asn": raw.get("asn"),
                "isp": raw.get("org") or raw.get("isp"),
                "postal": raw.get("postal"),
                "raw_keys": sorted(raw.keys()),
                "confidence_note": "GeoIP/ISP data is approximate and can be stale, proxied, or VPN/NAT affected.",
            }
            return ToolResult(True, json.dumps(payload, indent=2), meta=payload)
        payload = {"generated_at": utc_now(), "target": str(target or "").strip(), "ip": public_ip, "target_meta": target_meta, "errors": errors}
        return ToolResult(False, json.dumps(payload, indent=2), meta=payload)

    def get_public_ip_info(self, enrich: bool = True, timeout: int = 10) -> ToolResult:
        timeout = max(1, min(safe_int(timeout, 10), 30))
        sources = [
            ("ipify", "https://api.ipify.org?format=json", "ip"),
            ("ifconfig.me", "https://ifconfig.me/ip", "text"),
        ]
        errors: list[str] = []
        public_ip = ""
        source_used = ""
        for source, url, mode in sources:
            try:
                if mode == "json":
                    raw = http_get_json(url, {"accept": "application/json", "user-agent": "Cerebro-Agent/1.0 (+public-ip)"}, timeout=timeout)
                    candidate = str(raw.get("ip", "")).strip() if isinstance(raw, dict) else ""
                else:
                    request = urllib.request.Request(url, headers={"user-agent": "Cerebro-Agent/1.0 (+public-ip)", "accept": "text/plain"}, method="GET")
                    with urllib.request.urlopen(request, timeout=timeout) as response:
                        candidate = response.read(80).decode("utf-8", errors="replace").strip()
                ipaddress.ip_address(candidate)
                public_ip = candidate
                source_used = source
                break
            except Exception as exc:
                errors.append(f"{source}: {trim_text(str(exc), 240)}")
        if not public_ip:
            payload = {"generated_at": utc_now(), "public_ip": "", "errors": errors}
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)
        payload: dict[str, Any] = {
            "generated_at": utc_now(),
            "public_ip": public_ip,
            "source": source_used,
            "classification": self._ip_classification(public_ip),
            "errors": errors,
        }
        if enrich:
            enrichment = self.lookup_ip_geolocation(public_ip, timeout=timeout)
            payload["geolocation"] = enrichment.meta if enrichment.ok else {"ok": False, "error": enrichment.content}
            rdap = self.lookup_ip_rdap(public_ip, timeout=timeout)
            payload["rdap"] = rdap.meta if rdap.ok else {"ok": False, "error": rdap.content}
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def _parse_port_spec(self, ports: Any, *, max_ports: int = 32) -> tuple[list[int], list[str]]:
        warnings: list[str] = []
        if ports is None or ports == "":
            values: list[Any] = [22, 53, 80, 443, 445, 3389, 8000, 8080, 8443]
        elif isinstance(ports, int):
            values = [ports]
        elif isinstance(ports, list):
            values = ports
        else:
            values = []
            text = str(ports)
            for part in re.split(r"[\s,]+", text):
                if not part:
                    continue
                if "-" in part:
                    start_text, end_text = part.split("-", 1)
                    if start_text.strip().isdigit() and end_text.strip().isdigit():
                        start, end = int(start_text), int(end_text)
                        if start > end:
                            start, end = end, start
                        if end - start > 256:
                            warnings.append(f"Range {part} capped to first 256 ports before max_ports truncation.")
                            end = start + 256
                        values.extend(range(start, end + 1))
                    else:
                        warnings.append(f"Ignored invalid port range: {part}")
                elif part.isdigit():
                    values.append(int(part))
                else:
                    warnings.append(f"Ignored invalid port value: {part}")
        cleaned: list[int] = []
        for value in values:
            port = safe_int(value, -1)
            if 1 <= port <= 65535 and port not in cleaned:
                cleaned.append(port)
        max_ports = max(1, min(safe_int(max_ports, 32), 64))
        if len(cleaned) > max_ports:
            warnings.append(f"Port list truncated from {len(cleaned)} to {max_ports}.")
            cleaned = cleaned[:max_ports]
        return cleaned, warnings

    def scan_tcp_ports(self, target: str, ports: Any = "22,80,443", timeout: float = 0.5, allow_public: bool = False, max_ports: int = 32) -> ToolResult:
        host, reason, meta = self._extract_network_host(target)
        if not host:
            return ToolResult(False, reason, meta=meta)
        try:
            network = ipaddress.ip_network(host, strict=False)
            if network.num_addresses != 1:
                return ToolResult(False, "CIDR/range port scanning is not supported; provide one authorized host.")
        except ValueError:
            pass
        timeout_value = max(0.1, min(float(timeout), 3.0))
        port_list, warnings = self._parse_port_spec(ports, max_ports=max_ports)
        if not port_list:
            return ToolResult(False, "No valid ports to scan.")
        resolved, resolve_warnings = self._resolve_host_ips(host)
        warnings.extend(resolve_warnings)
        public_addresses = [row for row in resolved if row.get("is_publicly_routable")]
        if public_addresses and not allow_public:
            payload = {
                "generated_at": utc_now(),
                "target": str(target or "").strip(),
                "host": host,
                "resolved_addresses": resolved,
                "requested_ports": port_list,
                "blocked": True,
                "reason": "Public target scanning is blocked unless allow_public=true and you are authorized to test the asset.",
                "warnings": warnings,
            }
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)
        results: list[dict[str, Any]] = []
        started = time.time()
        for port in port_list:
            item: dict[str, Any] = {"port": port, "state": "unknown", "latency_ms": None, "error": ""}
            before = time.time()
            sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_value)
            try:
                code = sock.connect_ex((host, port))
                item["latency_ms"] = round((time.time() - before) * 1000, 2)
                item["state"] = "open" if code == 0 else "closed_or_filtered"
                if code != 0:
                    item["error_code"] = code
            except Exception as exc:
                item["latency_ms"] = round((time.time() - before) * 1000, 2)
                item["state"] = "error"
                item["error"] = trim_text(str(exc), 200)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            results.append(item)
        payload = {
            "generated_at": utc_now(),
            "target": str(target or "").strip(),
            "host": host,
            "resolved_addresses": resolved,
            "ports_scanned": len(port_list),
            "open_ports": [row for row in results if row.get("state") == "open"],
            "results": results,
            "elapsed_ms": round((time.time() - started) * 1000, 2),
            "warnings": warnings,
            "safety_note": "TCP connect scan only. Use only on systems you own or are explicitly authorized to assess.",
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def _parse_listening_socket_output(self, output: str, *, include_udp: bool = True, limit: int = 100) -> tuple[list[dict[str, Any]], list[str]]:
        entries: list[dict[str, Any]] = []
        warnings: list[str] = []
        limit = max(1, min(safe_int(limit, 100), 500))

        def split_host_port(value: str) -> tuple[str, int | None]:
            token = value.strip().strip('[]')
            if not token:
                return "", None
            if token.startswith("[") and "]:" in token:
                host_part, port_part = token.rsplit(":", 1)
                return host_part.strip("[]"), safe_int(port_part, -1) if port_part.isdigit() else None
            if token.count(":") > 1 and not token.rsplit(":", 1)[-1].isdigit():
                return token, None
            if ":" in token:
                host_part, port_part = token.rsplit(":", 1)
                if port_part.isdigit() or port_part == "*":
                    return host_part or "*", safe_int(port_part, -1) if port_part.isdigit() else None
            if "." in token:
                host_part, port_part = token.rsplit(".", 1)
                if port_part.isdigit():
                    return host_part or "*", safe_int(port_part, -1)
            return token, None

        def exposure_for(address: str) -> str:
            lowered = str(address or "").lower()
            if lowered in {"127.0.0.1", "::1", "localhost"} or lowered.startswith("127."):
                return "loopback_only"
            if lowered in {"0.0.0.0", "::", "*", "[::]"}:
                return "all_interfaces"
            return "specific_interface"

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line.lower().startswith(("proto", "active", "netid", "state")):
                continue
            parts = line.split()
            if not parts:
                continue
            proto = parts[0].upper()
            if not proto.startswith(("TCP", "UDP")):
                continue
            if proto.startswith("UDP") and not include_udp:
                continue

            state = ""
            local_token = ""
            pid = ""
            process = ""
            lowered_parts = [part.lower() for part in parts]

            if sys.platform.startswith("win"):
                # Windows netstat: Proto Local Address Foreign Address State PID
                if proto.startswith("TCP"):
                    if len(parts) < 4 or parts[3].upper() != "LISTENING":
                        continue
                    local_token = parts[1]
                    state = parts[3]
                    pid = parts[4] if len(parts) > 4 and parts[4].isdigit() else ""
                else:
                    if len(parts) < 2:
                        continue
                    local_token = parts[1]
                    state = "LISTENING"
                    pid = parts[3] if len(parts) > 3 and parts[3].isdigit() else ""
            elif parts[0].lower().startswith(("tcp", "udp")) and len(parts) >= 4:
                # ss -H -tuln[p]: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port [Process]
                if proto.startswith("TCP") and "listen" not in lowered_parts[:3]:
                    continue
                state = next((part for part in parts[1:4] if part.lower().startswith("listen")), "UNCONN" if proto.startswith("UDP") else "LISTEN")
                local_token = parts[4] if len(parts) >= 5 else parts[3]
                process_blob = " ".join(parts[5:])
                pid_match = re.search(r"pid=(\d+)", process_blob)
                if pid_match:
                    pid = pid_match.group(1)
                proc_match = re.search(r'users:\(\("([^"\\]+)"', process_blob)
                if proc_match:
                    process = proc_match.group(1)
            else:
                continue

            address, port = split_host_port(local_token)
            if port is None or port < 1:
                continue
            entries.append({
                "protocol": proto,
                "local_address": address or "*",
                "port": port,
                "state": state or "LISTENING",
                "pid": pid,
                "process": process,
                "exposure": exposure_for(address),
                "raw_line": trim_text(raw_line, 300),
            })
            if len(entries) >= limit:
                warnings.append(f"Listening socket list truncated to {limit} entries.")
                break

        entries.sort(key=lambda row: (str(row.get("protocol", "")), int(row.get("port") or 0), str(row.get("local_address", ""))))
        return entries, warnings

    def inspect_local_listening_ports(self, include_udp: bool = True, include_process_names: bool = True, limit: int = 100) -> ToolResult:
        """Inspect ports listening on the local machine without scanning the LAN."""
        limit = max(1, min(safe_int(limit, 100), 500))
        include_udp = bool(include_udp)
        include_process_names = bool(include_process_names)
        command: list[str]
        fallback_commands: list[list[str]] = []
        if sys.platform.startswith("win"):
            command = ["netstat", "-ano"]
        else:
            command = ["ss", "-H", "-tulnp" if include_process_names else "-tuln"]
            fallback_commands = [["netstat", "-tuln"]]

        raw_output = ""
        errors: list[str] = []
        used_command: list[str] = command
        for candidate in [command, *fallback_commands]:
            try:
                completed = subprocess.run(candidate, capture_output=True, text=True, timeout=5, check=False)
                raw_output = (completed.stdout or "") + (completed.stderr or "")
                used_command = candidate
                if raw_output.strip():
                    break
                errors.append(f"{' '.join(candidate)} returned no output")
            except FileNotFoundError:
                errors.append(f"command not found: {candidate[0]}")
            except Exception as exc:
                errors.append(f"{' '.join(candidate)} failed: {trim_text(str(exc), 300)}")

        entries, warnings = self._parse_listening_socket_output(raw_output, include_udp=include_udp, limit=limit)
        warnings.extend(errors[:4])
        payload = {
            "generated_at": utc_now(),
            "scope": "local_machine",
            "command": used_command,
            "include_udp": include_udp,
            "include_process_names": include_process_names,
            "entry_count": len(entries),
            "entries": entries,
            "warnings": warnings,
            "raw_output_preview": trim_text(raw_output, 3000),
            "safety_note": "This inspects local listening sockets only. It does not scan every host on the LAN.",
            "recommendations": [
                "Use scan_tcp_ports for one specific authorized host when you want an active TCP check.",
                "Do not infer whole-network exposure from local listening sockets; router/firewall/NAT rules can change what is reachable.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def inspect_tls_certificate(self, target: str, port: int = 443, server_name: str = "", timeout: int = 5, allow_private: bool = False) -> ToolResult:
        host, reason, meta = self._extract_network_host(target)
        if not host:
            return ToolResult(False, reason, meta=meta)
        port = max(1, min(safe_int(port, 443), 65535))
        timeout = max(1, min(safe_int(timeout, 5), 20))
        resolved, warnings = self._resolve_host_ips(host)
        if not allow_private and any(not row.get("is_publicly_routable") for row in resolved):
            payload = {
                "generated_at": utc_now(),
                "target": str(target or "").strip(),
                "host": host,
                "port": port,
                "resolved_addresses": resolved,
                "blocked": True,
                "reason": "Private/local/special-use TLS targets are blocked unless allow_private=true.",
                "warnings": warnings,
            }
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)
        sni = str(server_name or host).strip()
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=sni) as tls_socket:
                    cert = tls_socket.getpeercert() or {}
                    der = tls_socket.getpeercert(binary_form=True) or b""
                    payload = {
                        "generated_at": utc_now(),
                        "target": str(target or "").strip(),
                        "host": host,
                        "port": port,
                        "server_name": sni,
                        "resolved_addresses": resolved,
                        "tls_version": tls_socket.version(),
                        "cipher": tls_socket.cipher(),
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subject_alt_names": cert.get("subjectAltName", [])[:40],
                        "serial_number": cert.get("serialNumber"),
                        "sha256_fingerprint": hashlib.sha256(der).hexdigest() if der else "",
                        "warnings": warnings,
                    }
                    return ToolResult(True, json.dumps(payload, indent=2), meta=payload)
        except Exception as exc:
            payload = {"generated_at": utc_now(), "target": str(target or "").strip(), "host": host, "port": port, "error": trim_text(str(exc), 600), "warnings": warnings}
            return ToolResult(False, json.dumps(payload, indent=2), meta=payload)

    def inspect_local_network(self, include_command_output: bool = False) -> ToolResult:
        hostname = socket.gethostname()
        fqdn = socket.getfqdn()
        addresses: list[dict[str, Any]] = []
        try:
            infos = socket.getaddrinfo(hostname, None)
            seen: set[str] = set()
            for family, _socktype, proto, canonname, sockaddr in infos:
                address = str(sockaddr[0])
                if address in seen:
                    continue
                seen.add(address)
                try:
                    classification = self._ip_classification(address)
                except ValueError:
                    classification = {"ip": address, "is_publicly_routable": False}
                addresses.append({"address": address, "family": "IPv6" if family == socket.AF_INET6 else "IPv4" if family == socket.AF_INET else str(family), "canonical_name": canonname, "protocol": proto, **classification})
        except Exception as exc:
            addresses.append({"error": trim_text(str(exc), 400)})
        resolver_hints = {
            "default_timeout": getattr(socket, "getdefaulttimeout", lambda: None)(),
            "has_ipv6": socket.has_ipv6,
        }
        command_output = ""
        command = []
        if include_command_output:
            if sys.platform.startswith("win"):
                command = ["ipconfig", "/all"]
            else:
                command = ["sh", "-lc", "(ip addr 2>/dev/null || ifconfig 2>/dev/null); echo '--- routes ---'; (ip route 2>/dev/null || netstat -rn 2>/dev/null)"]
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False)
                command_output = trim_text((completed.stdout or "") + (completed.stderr or ""), 12000)
            except Exception as exc:
                command_output = f"command failed: {trim_text(str(exc), 400)}"
        payload = {
            "generated_at": utc_now(),
            "hostname": hostname,
            "fqdn": fqdn,
            "addresses": addresses,
            "resolver_hints": resolver_hints,
            "command": command,
            "command_output": command_output,
            "recommendations": [
                "Use get_public_ip_info for NAT/public egress context.",
                "Use resolve_dns_records and scan_tcp_ports for specific authorized services rather than broad network sweeps.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)


    def start_control_server(self, host: str = "", port: int = 0, authorized: bool = False) -> ToolResult:
        status = listen_for_connections(host=host, port=port, authorized=authorized)
        redacted = dict(status)
        redacted.pop("token", None)
        return ToolResult(bool(status.get("ok")), json.dumps(redacted, indent=2, sort_keys=True), meta=redacted)

    def show_control_server(self) -> ToolResult:
        status = control_server_status()
        return ToolResult(True, json.dumps(status, indent=2, sort_keys=True), meta=status)

    def route_control_command(
        self,
        command_type: str,
        payload: dict[str, Any] | None = None,
        target_ids: list[str] | None = None,
    ) -> ToolResult:
        result = route_command_to_clients(command_type, payload or {}, target_ids or [])
        return ToolResult(bool(result.get("ok")), json.dumps(result, indent=2, sort_keys=True), meta=result)

    def stop_control_server(self) -> ToolResult:
        status = stop_control_server()
        return ToolResult(True, json.dumps(status, indent=2, sort_keys=True), meta=status)


    def build_network_intel_brief(self, target: str, include_scan_plan: bool = True, allow_public_scan: bool = False) -> ToolResult:
        target_text = str(target or "").strip()
        if not target_text:
            return ToolResult(False, "Target cannot be empty.")
        normalized = self.normalize_network_target(target_text, resolve=True, allow_private=True)
        dns = self.resolve_dns_records(target_text, record_type="ANY", allow_private=True) if normalized.ok and not normalized.meta.get("is_ip") else ToolResult(True, "{}", meta={"records": []})
        public_candidates: list[str] = []
        for row in normalized.meta.get("addresses", []):
            if row.get("is_publicly_routable"):
                public_candidates.append(str(row.get("address") or row.get("ip")))
        public_ip = public_candidates[0] if public_candidates else ""
        rdap_hint: dict[str, Any] = {}
        geo_hint: dict[str, Any] = {}
        if public_ip:
            # Avoid slow external calls in the brief unless the caller later asks for the dedicated enrichment tools.
            rdap_hint = {"recommended_tool": "lookup_ip_rdap", "target": public_ip}
            geo_hint = {"recommended_tool": "lookup_ip_geolocation", "target": public_ip}
        scan_plan = []
        if include_scan_plan:
            scan_plan = [
                {"tool": "scan_tcp_ports", "args": {"target": target_text, "ports": "22,80,443,445,3389,8000,8080,8443", "allow_public": bool(allow_public_scan), "max_ports": 16}, "gate": "Only run if the asset is owned or explicitly authorized; public targets require allow_public=true."},
                {"tool": "inspect_tls_certificate", "args": {"target": target_text, "port": 443}, "gate": "Use when HTTPS/TLS posture is relevant."},
            ]
        payload = {
            "generated_at": utc_now(),
            "target": target_text,
            "normalized": normalized.meta,
            "dns_summary": dns.meta if dns.ok else {"ok": False, "error": dns.content},
            "public_ip_candidates": public_candidates,
            "recommended_sequence": [
                {"step": 1, "tool": "normalize_network_target", "purpose": "Classify the input and safety posture."},
                {"step": 2, "tool": "resolve_dns_records", "purpose": "Resolve hostnames to A/AAAA addresses."},
                {"step": 3, "tool": "reverse_dns_lookup", "purpose": "Add PTR context for resolved public IPs."},
                {"step": 4, "tool": "lookup_ip_rdap", "purpose": "Get registration, range, and ASN-like ownership context for public IPs."},
                {"step": 5, "tool": "lookup_ip_geolocation", "purpose": "Get approximate geolocation/ISP/org context for public IPs."},
                {"step": 6, "tool": "scan_tcp_ports", "purpose": "Bounded active check only after authorization is clear."},
            ],
            "rdap_hint": rdap_hint,
            "geo_hint": geo_hint,
            "scan_plan": scan_plan,
            "safety_rules": [
                "Do not scan CIDR ranges; tools only support a single host.",
                "Default port scans are blocked for public targets unless allow_public=true.",
                "GeoIP and RDAP are passive enrichment and can be stale or approximate.",
                "Use these tools for owned assets, troubleshooting, defensive inventory, and authorized OSINT.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def build_toolbox_brief(self, objective: str, path: str = ".") -> ToolResult:
        objective_text = str(objective or "").strip()
        if not objective_text:
            return ToolResult(False, "Objective cannot be empty.")
        scope = workspace_relative(resolve_workspace_path(path))
        profile = infer_task_profile(objective_text)
        registry = self.map_tool_capability_graph(objective=objective_text, include_edges=False)
        repo = self.map_repository_structure(path=scope, max_depth=2, include_hidden=False)
        entrypoints = self.inspect_project_entrypoints(path=scope, recursive=Path(scope).suffix == "", limit=40)
        config_surface = self.inspect_config_surface(path=scope, include_preview=False)
        chain = self.recommend_tool_chain(objective=objective_text, path=scope)
        tool_groups = {
            "repository_intelligence": ["map_repository_structure", "inspect_project_entrypoints", "extract_api_surface", "inspect_config_surface"],
            "debugging_intelligence": ["inspect_error_log", "trace_data_flow", "propose_test_plan_for_symbol", "run_python_smoke_test"],
            "planning_and_risk": ["build_execution_dossier", "build_toolbox_brief", "build_risk_register", "score_execution_readiness"],
            "model_and_context": ["route_multi_model_task", "build_context_budget_plan", "recommend_model_selection", "list_available_models"],
            "external_docs": ["inspect_http_endpoint", "fetch_url_text"],
            "network_intelligence": ["normalize_network_target", "resolve_dns_records", "lookup_ip_rdap", "lookup_ip_geolocation", "scan_tcp_ports", "inspect_local_listening_ports"],
            "ids_traffic_analysis": ["build_ids_mode_plan", "ingest_network_traffic_file", "analyze_network_traffic_file", "build_ids_baseline", "compare_network_baseline", "capture_network_metadata_sample", "show_ids_alerts"],
            "threat_intelligence": ["build_threat_intel_brief", "lookup_cve", "search_cves", "check_cisa_kev", "lookup_malware_hash", "hash_workspace_file", "add_malware_signature", "scan_workspace_file_signatures"],
            "cryptography": ["list_crypto_algorithms", "encrypt_text", "decrypt_text", "encrypt_file", "decrypt_file"],
            "validation": ["build_validation_matrix", "run_self_improvement_validation", "quality_gate"],
        }
        ordered_probe_plan: list[dict[str, Any]] = []
        if profile.get("tool_intent"):
            ordered_probe_plan.append({"step": 1, "tool": "build_toolbox_brief", "purpose": "Select the best evidence probes and tool groups."})
            ordered_probe_plan.append({"step": 2, "tool": "map_repository_structure", "purpose": "Confirm repository shape and likely boundaries."})
            ordered_probe_plan.append({"step": 3, "tool": "inspect_project_entrypoints", "purpose": "Find runnable paths before changing behavior."})
            ordered_probe_plan.append({"step": 4, "tool": "extract_api_surface", "purpose": "Identify public functions/classes likely affected."})
        if "network_intelligence" in profile.get("intents", []) and any(term in objective_text.lower() for term in ["ids", "traffic", "pcap", "suricata", "zeek", "intrusion", "packet", "flows"]):
            ordered_probe_plan.append({"step": len(ordered_probe_plan) + 1, "tool": "build_ids_mode_plan", "purpose": "Choose offline ingestion or explicitly authorized live metadata capture."})
            ordered_probe_plan.append({"step": len(ordered_probe_plan) + 1, "tool": "ingest_network_traffic_file", "purpose": "Normalize PCAP/Zeek/Suricata/CSV/JSONL traffic into metadata-only flows."})
            ordered_probe_plan.append({"step": len(ordered_probe_plan) + 1, "tool": "analyze_network_traffic_file", "purpose": "Generate IDS-style alerts and analyst recommendations."})
        if profile.get("write_intent"):
            ordered_probe_plan.extend([
                {"step": len(ordered_probe_plan) + 1, "tool": "plan_patch_strategy", "purpose": "Choose the smallest reversible edit path."},
                {"step": len(ordered_probe_plan) + 2, "tool": "build_validation_matrix", "purpose": "Define pass/fail checks before editing."},
                {"step": len(ordered_probe_plan) + 3, "tool": "score_execution_readiness", "purpose": "Gate write action until evidence is sufficient."},
            ])
        if not ordered_probe_plan:
            ordered_probe_plan.append({"step": 1, "tool": "decompose_goal", "purpose": "Decide whether direct answer is enough."})
        payload = {
            "generated_at": utc_now(),
            "objective": objective_text,
            "scope": scope,
            "task_profile": profile,
            "tool_groups": tool_groups,
            "ordered_probe_plan": ordered_probe_plan,
            "capability_graph_summary": {"ok": registry.ok, "node_count": registry.meta.get("node_count") if registry.ok else None},
            "repository_summary": {"ok": repo.ok, "extension_counts": repo.meta.get("extension_counts", {}) if repo.ok else {}},
            "entrypoint_summary": {"ok": entrypoints.ok, "entrypoint_count": len(entrypoints.meta.get("entrypoints", [])) if entrypoints.ok else 0},
            "config_summary": {"ok": config_surface.ok, "config_file_count": config_surface.meta.get("config_file_count") if config_surface.ok else 0},
            "recommended_tool_chain": chain.meta if chain.ok else {"error": chain.content},
            "subagent_guidance": [
                "Researcher: run repository/config/entrypoint probes and return exact paths.",
                "Architect: use API/data-flow surfaces to choose boundaries before refactoring.",
                "Coder: do not patch until patch_strategy and validation_matrix are clear.",
                "Tester: turn trace_data_flow and inspect_error_log into targeted checks.",
                "Safety: require checkpoint and readiness gate for write/control tools.",
            ],
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def decompose_goal(self, goal: str, context: str = "") -> ToolResult:
        objective = str(goal).strip()
        if not objective:
            return ToolResult(False, "Goal cannot be empty.")

        profile = infer_task_profile(f"{objective}\n{context}")
        team = self.recommend_team(task=objective, context=context)
        roles = team.meta.get("roles", profile.get("suggested_roles", [])) if team.ok else profile.get("suggested_roles", [])

        first_steps: list[str] = []
        if profile["tool_intent"]:
            first_steps.append("Build a grounded context pack before changing files.")
        if profile["write_intent"]:
            first_steps.append("Create or inspect a rollback point before edits, then keep the patch narrow.")
        if "debug" in profile["intents"]:
            first_steps.append("Reproduce or localize the failure before proposing a fix.")
        if "implementation" in profile["intents"]:
            first_steps.append("Identify the smallest feature slice that creates visible value.")
        if "refactoring" in profile["intents"]:
            first_steps.append("Analyze call impact before moving or rewriting shared helpers.")
        if "validation" in profile["intents"]:
            first_steps.append("Run deterministic validation and state what it proves.")
        if not first_steps:
            first_steps.append("Answer directly unless a tool provides necessary evidence.")

        acceptance_criteria = [
            "The answer directly satisfies the user's stated objective.",
            "Any file changes are explicit, narrow, and validation-backed.",
            "Residual risks or unknowns are stated plainly.",
        ]
        if profile["write_intent"]:
            acceptance_criteria.append("The changed file compiles or an explicit validation limitation is reported.")
        if profile["risk_level"] != "low":
            acceptance_criteria.append("Risk controls, rollback readiness, or policy constraints are checked before finalizing.")

        payload = {
            "generated_at": utc_now(),
            "goal": objective,
            "context_preview": trim_text(context, 600),
            "task_profile": profile,
            "recommended_team": {
                "roles": roles,
                "template": team.meta.get("template") if team.ok else "custom",
                "evidence": team.meta.get("reasons") if team.ok else {},
            },
            "suggested_first_steps": first_steps,
            "suggested_tools": profile.get("suggested_tools", []),
            "acceptance_criteria": acceptance_criteria,
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def build_context_pack(self, objective: str, path: str = ".", limit: int = 8) -> ToolResult:
        objective = str(objective).strip()
        if not objective:
            return ToolResult(False, "Objective cannot be empty.")
        target = resolve_workspace_path(path)
        if not target.exists():
            return ToolResult(False, f"Path does not exist: {path}")
        limit = max(1, min(int(limit), 25))
        scope = workspace_relative(target)

        profile = infer_task_profile(objective)
        workspace_stats = self.show_workspace_stats(path=scope, recursive=target.is_dir())
        recent_files = self.list_recent_files(path=scope, limit=limit)
        todos = self.search_todos(path=scope, recursive=target.is_dir())
        git_status = self.git_status()
        semantic_search = self.semantic_search_workspace(query=objective, path=scope, limit=limit)
        code_context = self.find_relevant_code_context(objective=objective, path=scope, limit=limit)

        memory_items = [
            {"key": key, "value": value, "content": f"{key}\n{value}"}
            for key, value in self.state.memory.items()
        ]
        relevant_memory = rank_relevant_text_items(objective, memory_items, text_fields=("content",), limit=limit)

        profile_data = load_user_profile()
        profile_candidates: list[dict[str, Any]] = []
        for section, value in profile_data.items():
            if section in {"updated_at", "schema_version"}:
                continue
            if isinstance(value, dict):
                for key, nested in value.items():
                    if nested:
                        profile_candidates.append({"section": section, "key": key, "value": nested, "content": f"{section}.{key}: {nested}"})
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    profile_candidates.append({"section": section, "key": str(index), "value": item, "content": json.dumps(item, ensure_ascii=False)})
        relevant_profile = rank_relevant_text_items(objective, profile_candidates, text_fields=("content",), limit=limit)

        board = load_blackboard()
        board_candidates: list[dict[str, Any]] = []
        for section, value in board.items():
            if isinstance(value, list):
                for index, item in enumerate(value):
                    board_candidates.append({"section": section, "key": str(index), "value": item, "content": json.dumps(item, ensure_ascii=False)})
            elif value:
                board_candidates.append({"section": section, "key": section, "value": value, "content": str(value)})
        relevant_blackboard = rank_relevant_text_items(objective, board_candidates, text_fields=("content",), limit=limit)

        tasks = load_tasks().get("tasks", [])
        task_candidates = [
            {**task, "content": json.dumps(task, ensure_ascii=False)}
            for task in tasks
            if isinstance(task, dict)
        ]
        relevant_tasks = rank_relevant_text_items(objective, task_candidates, text_fields=("content", "title", "objective"), limit=limit)

        hotspot_preview: dict[str, Any] = {"available": False, "hotspots": []}
        if CODE_HOTSPOTS_FILE.exists():
            try:
                hotspots_data = json.loads(CODE_HOTSPOTS_FILE.read_text(encoding="utf-8"))
                hotspots = hotspots_data.get("hotspots", []) if isinstance(hotspots_data, dict) else []
                hotspot_preview = {"available": True, "hotspots": hotspots[:limit], "source": workspace_relative(CODE_HOTSPOTS_FILE)}
            except (OSError, json.JSONDecodeError):
                hotspot_preview = {"available": False, "error": "Could not read hotspot file."}

        todo_matches = todos.meta.get("matches", []) if todos.ok else []
        ranked_todos = rank_relevant_text_items(
            objective,
            [{**item, "content": f"{item.get('path')}:{item.get('line')} {item.get('tag')} {item.get('text')}"} for item in todo_matches],
            text_fields=("content",),
            limit=limit,
        )
        if not ranked_todos:
            ranked_todos = todo_matches[:limit]

        recommendations = [
            "Use this pack to avoid starting from a blank prompt.",
            "Run recommend_tool_chain or build_execution_dossier when the next tool sequence is unclear.",
            "Prefer the suggested first tools and roles unless direct evidence points elsewhere.",
        ]
        if profile.get("write_intent"):
            recommendations.append("Before editing, inspect the exact target file and validate the changed file afterward.")
        if profile.get("risk_level") != "low":
            recommendations.append("Because risk is not low, keep changes reversible and check policy/rollback readiness.")
        if relevant_memory or relevant_profile or relevant_blackboard:
            recommendations.append("Relevant persisted context exists; reconcile it with current user instructions before acting.")

        payload = {
            "generated_at": utc_now(),
            "objective": objective,
            "scope": scope,
            "task_profile": profile,
            "workspace": {
                "stats": workspace_stats.meta if workspace_stats.ok else {"error": workspace_stats.content},
                "recent_files": recent_files.meta.get("files", []) if recent_files.ok else [],
                "todo_count": todos.meta.get("count", 0) if todos.ok else None,
                "relevant_todos": ranked_todos,
                "git_status": trim_text(git_status.content, 2000),
                "semantic_matches": semantic_search.meta.get("matches", []) if semantic_search.ok else [],
                "relevant_code_symbols": code_context.meta.get("symbols", []) if code_context.ok else [],
                "semantic_search": {
                    "ok": semantic_search.ok,
                    "searched_files": semantic_search.meta.get("searched_files", 0),
                    "skipped_files": semantic_search.meta.get("skipped_files", 0),
                    "match_count": semantic_search.meta.get("match_count", 0),
                },
                "code_context": {
                    "ok": code_context.ok,
                    "searched_files": code_context.meta.get("searched_files", 0),
                    "match_count": code_context.meta.get("match_count", 0),
                },
                "code_hotspots": hotspot_preview,
            },
            "memory": {
                "matches": relevant_memory,
                "total_keys": len(self.state.memory),
            },
            "user_profile_matches": relevant_profile,
            "blackboard_matches": relevant_blackboard,
            "task_matches": relevant_tasks,
            "recommended_team": self.recommend_team(task=objective, context=json.dumps({"task_profile": profile})).meta,
            "recommendations": recommendations,
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
        if target.name == Path(active_agent_file()).name and "--quick-self-test" in source:
            try:
                result = run_subprocess([sys.executable, str(target), "--quick-self-test"], timeout=15)
                payload["quick_self_test"] = parse_json_value(render_completed_process(result))
            except subprocess.TimeoutExpired:
                payload["quick_self_test"] = {"ok": False, "message": "--quick-self-test timed out; compile check still completed."}
        elif "argparse" in source:
            try:
                result = run_subprocess([sys.executable, str(target), "--help"], timeout=10)
                payload["help"] = parse_json_value(render_completed_process(result))
            except subprocess.TimeoutExpired:
                payload["help"] = {"ok": False, "message": "--help timed out; compile check still completed."}
        else:
            payload["help"] = {"skipped": True, "reason": "file does not appear to define an argparse --help CLI"}
        return ToolResult(compile_result.ok, json.dumps(payload, indent=2), meta=payload)

    def run_self_improvement_validation(self, path: str = ".") -> ToolResult:
        target = resolve_workspace_path(path)
        target_relative = workspace_relative(target)
        compile_check = self.validate_workspace_python(path=target_relative, recursive=target.is_dir())
        smoke_target = target_relative if target.is_file() and target.suffix.lower() == ".py" else active_agent_file()
        smoke_check = self.run_python_smoke_test(smoke_target)

        def skipped_optional_tool(name: str, reason: str) -> ToolResult:
            return ToolResult(False, f"{name} skipped: {reason}", meta={"skipped": True, "reason": reason})

        has_pytest_target = any((WORKSPACE_ROOT / item).exists() for item in ("pytest.ini", "tox.ini", "tests"))
        has_ruff_config = any((WORKSPACE_ROOT / item).exists() for item in ("ruff.toml", ".ruff.toml", "pyproject.toml"))
        pytest_check = self.run_pytest(path=target_relative) if target.is_dir() and has_pytest_target else skipped_optional_tool("pytest", "no pytest config or tests directory found")
        ruff_check = self.run_ruff(path=target_relative) if has_ruff_config else skipped_optional_tool("ruff", "no ruff config found")
        git_check = self.git_status()

        def optional_status(result: ToolResult, missing_phrase: str) -> str:
            if result.meta.get("skipped") is True:
                return "skipped"
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
        preflight_validation = self.run_self_improvement_validation(path=active_file)
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
            "model_router": config.get("model_router", {}),
            "autonomy_policy": config.get("autonomy_policy", {}),
            "llm_providers": redacted_llm_providers(config.get("llm_providers", {})),
            "role_providers": config.get("role_providers", {}),
            "role_models": config.get("role_models", {}),
            "config_file": workspace_relative(CONFIG_FILE),
            "model_catalog_file": workspace_relative(MODEL_CATALOG_FILE),
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
                "auto_discover_model": settings.get("auto_discover_model", False),
                "known_model_hints": len(settings.get("known_models", [])) if isinstance(settings.get("known_models"), list) else 0,
            }
            for name, settings in providers.items()
            if isinstance(settings, dict)
        }
        payload = {
            "default_provider": config.get("provider"),
            "fallback_provider": config.get("fallback_provider"),
            "providers": provider_summary,
            "routes": routes,
            "model_router": config.get("model_router", {}),
            "config_file": workspace_relative(CONFIG_FILE),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def show_model_router(self) -> ToolResult:
        config = load_config()
        router = dict(config.get("model_router", default_model_router_config()))
        providers = config.get("llm_providers", {})
        route_summaries: list[dict[str, Any]] = []
        for route in router.get("routes", []):
            if not isinstance(route, dict):
                continue
            provider = str(route.get("provider", "") or "<preserve selected>")
            model = str(route.get("model", "") or "<preserve selected>")
            route_summaries.append(
                {
                    "name": route.get("name"),
                    "max_input_tokens": route.get("max_input_tokens"),
                    "input_token_budget": route.get("input_token_budget"),
                    "provider": provider,
                    "provider_known": provider == "<preserve selected>" or provider in providers,
                    "model": model,
                    "temperature": route.get("temperature"),
                    "reason": route.get("reason", ""),
                }
            )
        payload = {
            "enabled": router.get("enabled", True),
            "estimate_chars_per_token": router.get("estimate_chars_per_token", APPROX_CHARS_PER_TOKEN),
            "respect_explicit_model": router.get("respect_explicit_model", False),
            "log_decisions": router.get("log_decisions", True),
            "enable_prompt_compaction": router.get("enable_prompt_compaction", True),
            "reserve_output_tokens": router.get("reserve_output_tokens", 1024),
            "min_compaction_tokens": router.get("min_compaction_tokens", 256),
            "compaction_margin_tokens": router.get("compaction_margin_tokens", 128),
            "routes": route_summaries,
            "how_to_configure": {
                "lmstudio_example": "Set a route provider to lmstudio and model to the exact model id loaded in LM Studio, or leave model blank to preserve the selected provider model.",
                "long_context_example": "Give the final route max_input_tokens=null and point it at your largest-context model.",
                "budget_example": "Set input_token_budget on a route, or context_window on a provider, to let Cerebro compact oversized prompts before calling the model.",
            },
            "config_file": workspace_relative(CONFIG_FILE),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)


    def validate_model_router_config(self) -> ToolResult:
        config = load_config()
        router = config.get("model_router", default_model_router_config())
        providers = config.get("llm_providers", {})
        routes = router.get("routes", []) if isinstance(router.get("routes"), list) else []
        issues: list[str] = []
        warnings: list[str] = []
        checks: list[dict[str, Any]] = []

        def record(name: str, ok: bool, detail: str = "") -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})
            if not ok:
                issues.append(f"{name}: {detail}".strip())

        record("router_is_dict", isinstance(router, dict), type(router).__name__)
        record("routes_present", bool(routes), f"count={len(routes)}")
        names = [str(route.get("name", "")) for route in routes if isinstance(route, dict)]
        record("route_names_unique", len(names) == len(set(names)), ", ".join(names))
        record("final_route_accepts_overflow", bool(routes) and routes[-1].get("max_input_tokens") is None, json.dumps(routes[-1] if routes else {}, indent=2))

        finite_thresholds: list[int] = []
        for index, route in enumerate(routes):
            if not isinstance(route, dict):
                record(f"route_{index + 1}_is_dict", False, repr(route))
                continue
            name = str(route.get("name") or f"route_{index + 1}")
            provider = str(route.get("provider", "") or "")
            budget = route.get("input_token_budget")
            max_input = route.get("max_input_tokens")
            if provider:
                record(f"{name}_provider_known", provider in providers, provider)
            if max_input is not None:
                max_value = safe_int(max_input, 0)
                record(f"{name}_max_input_positive", max_value > 0, str(max_input))
                finite_thresholds.append(max_value)
            if budget is not None:
                budget_value = safe_int(budget, 0)
                record(f"{name}_input_budget_positive", budget_value > 0, str(budget))
                if max_input is not None and budget_value > safe_int(max_input, 0):
                    warnings.append(f"{name}: input_token_budget exceeds max_input_tokens; compaction may not trigger until after route selection.")
            temperature = route.get("temperature")
            if temperature is not None:
                try:
                    temperature_value = float(temperature)
                    record(f"{name}_temperature_range", 0 <= temperature_value <= 2, str(temperature))
                except (TypeError, ValueError):
                    record(f"{name}_temperature_range", False, str(temperature))

        record("finite_thresholds_sorted", finite_thresholds == sorted(finite_thresholds), str(finite_thresholds))
        chars_per_token = float(router.get("estimate_chars_per_token", APPROX_CHARS_PER_TOKEN))
        record("chars_per_token_reasonable", 1.0 <= chars_per_token <= 8.0, str(chars_per_token))
        if not bool(router.get("enable_prompt_compaction", True)):
            warnings.append("Prompt compaction is disabled; oversized prompts may still overflow smaller local models.")
        if safe_int(router.get("reserve_output_tokens"), 0) < 256:
            warnings.append("reserve_output_tokens is low; model replies may be clipped on small context windows.")

        payload = {
            "ok": not issues,
            "issue_count": len(issues),
            "warning_count": len(warnings),
            "issues": issues,
            "warnings": warnings,
            "checks": checks,
            "routes": routes,
            "config_file": workspace_relative(CONFIG_FILE),
        }
        return ToolResult(not issues, json.dumps(payload, indent=2), meta=payload)

    def recommend_model_route(
        self,
        prompt: str = "",
        path: str = "",
        role: str = "",
        provider: str = "",
        model: str = "",
    ) -> ToolResult:
        config = load_config()
        source = "prompt"
        content = prompt or ""
        if path:
            target = resolve_workspace_path(path)
            if not target.exists() or not target.is_file():
                return ToolResult(False, f"Path does not exist or is not a file: {path}")
            content = read_text_sample(target, max_chars=MAX_FILE_CHARS * 4)
            source = workspace_relative(target)
        if not content:
            content = " "

        if role and role in ROLE_CATALOG:
            base_provider = get_role_provider(role, config)
            _, base_provider_config = get_provider_config(base_provider)
            base_model = get_role_model(role)
        else:
            base_provider, base_provider_config = get_provider_config(provider or None)
            base_model = model or str(base_provider_config.get("model", config.get("default_model", MODEL)))
        base_temperature = float(config.get("temperature", 0.25))
        messages = [{"role": "user", "content": content}]
        routed_provider, routed_config, routed_model, routed_temperature, decision = resolve_model_route(
            messages,
            provider_name=base_provider,
            provider_config=base_provider_config,
            selected_model=base_model,
            selected_temperature=base_temperature,
            config=config,
            explicit_model=bool(model),
            log_decision=False,
        )
        prompt_budget = model_input_token_budget(decision, routed_config, config)
        compaction_preview = None
        if prompt_budget:
            _preview_messages, compaction_preview = compact_messages_for_input_budget(
                messages,
                max_input_tokens=prompt_budget,
                chars_per_token=float(config.get("model_router", {}).get("estimate_chars_per_token", APPROX_CHARS_PER_TOKEN)),
                min_message_tokens=safe_int(config.get("model_router", {}).get("min_compaction_tokens"), 256),
            )
        payload = {
            "source": source,
            "role": role if role in ROLE_CATALOG else "",
            "input_characters": len(content),
            "estimated_input_tokens": decision.get("estimated_input_tokens"),
            "input_token_budget": prompt_budget,
            "would_compact_prompt": bool(compaction_preview and compaction_preview.get("compacted")),
            "compaction_preview": compaction_preview,
            "route_name": decision.get("route_name"),
            "route_reason": decision.get("route_reason"),
            "original": {
                "provider": decision.get("original_provider"),
                "model": decision.get("original_model"),
                "temperature": decision.get("original_temperature"),
            },
            "recommended": {
                "provider": routed_provider,
                "model": routed_model,
                "temperature": routed_temperature,
            },
            "changed": decision.get("changed", False),
            "router_enabled": decision.get("enabled", False),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def list_available_models(
        self,
        provider: str = "",
        refresh: bool = False,
        include_static: bool = True,
        limit: int = 200,
    ) -> ToolResult:
        config = load_config()
        provider = str(provider or "").strip()
        providers = config.get("llm_providers", {})
        if provider and provider not in providers:
            return ToolResult(False, f"Unknown provider: {provider}")

        discovery_meta: dict[str, Any] | None = None
        if refresh:
            discovery = self.discover_available_models(provider=provider, save=True)
            discovery_meta = discovery.meta

        models = combined_model_catalog(
            config,
            provider_filter=provider,
            include_cache=True,
            include_static=include_static,
        )
        limit = max(1, min(int(limit), 1000))
        provider_counts: dict[str, int] = {}
        capability_counts: dict[str, int] = {}
        for model_record in models:
            provider_name = str(model_record.get("provider", ""))
            provider_counts[provider_name] = provider_counts.get(provider_name, 0) + 1
            for capability in model_record.get("capabilities", []):
                capability = str(capability)
                capability_counts[capability] = capability_counts.get(capability, 0) + 1

        payload = {
            "provider_filter": provider,
            "model_count": len(models),
            "shown_count": min(len(models), limit),
            "provider_counts": dict(sorted(provider_counts.items())),
            "capability_counts": dict(sorted(capability_counts.items())),
            "models": models[:limit],
            "cache_file": workspace_relative(MODEL_CATALOG_FILE),
            "config_file": workspace_relative(CONFIG_FILE),
            "refreshed": bool(refresh),
            "discovery": discovery_meta,
            "usage": {
                "list_without_network": "refresh=false uses configured defaults plus cached live discoveries.",
                "live_refresh": "Set refresh=true, or call discover_available_models, after configuring API keys.",
                "set_route": "Use set_model_selection after choosing an exact provider/model id.",
            },
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def discover_available_models(
        self,
        provider: str = "",
        save: bool = True,
        timeout: int = 12,
    ) -> ToolResult:
        config = load_config()
        providers = config.get("llm_providers", {})
        provider = str(provider or "").strip()
        if provider and provider not in providers:
            return ToolResult(False, f"Unknown provider: {provider}")

        selected_provider_names = [provider] if provider else sorted(providers)
        all_records: list[dict[str, Any]] = []
        warnings: list[str] = []
        provider_results: dict[str, Any] = {}

        for provider_name in selected_provider_names:
            settings = providers.get(provider_name, {})
            if not isinstance(settings, dict):
                continue
            records, provider_warnings = discover_provider_models_live(provider_name, settings, timeout=timeout)
            all_records.extend(records)
            warnings.extend(provider_warnings)
            provider_results[provider_name] = {
                "ok": bool(records),
                "model_count": len(records),
                "warnings": provider_warnings,
                "base_url": settings.get("base_url", ""),
                "provider_type": settings.get("type", "openai_compatible"),
                "api_key_source": settings.get("api_key_env", "inline" if settings.get("api_key") else ""),
            }

        all_records = dedupe_model_records(all_records)
        if save:
            existing = load_model_catalog_cache()
            existing_models = [
                item for item in existing.get("models", [])
                if not provider or str(item.get("provider", "")) != provider
            ]
            merged = dedupe_model_records(existing_models + all_records)
            provider_cache = existing.get("providers", {}) if isinstance(existing.get("providers"), dict) else {}
            for provider_name, result in provider_results.items():
                provider_cache[provider_name] = {
                    "last_checked_at": utc_now(),
                    "model_count": result.get("model_count", 0),
                    "warnings": result.get("warnings", []),
                    "base_url": result.get("base_url", ""),
                    "provider_type": result.get("provider_type", ""),
                }
            save_model_catalog_cache(
                {
                    "schema_version": 1,
                    "providers": provider_cache,
                    "models": merged,
                    "notes": "Cached live model discovery. Safe to delete; Cerebro will regenerate it.",
                }
            )

        payload = {
            "provider_filter": provider,
            "providers_checked": selected_provider_names,
            "model_count": len(all_records),
            "models": all_records,
            "warnings": warnings,
            "provider_results": provider_results,
            "saved": bool(save),
            "cache_file": workspace_relative(MODEL_CATALOG_FILE),
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def recommend_model_selection(
        self,
        objective: str = "",
        role: str = "",
        provider: str = "",
        required_context_tokens: int = 0,
        prefer: str = "",
        limit: int = 8,
        refresh: bool = False,
    ) -> ToolResult:
        config = load_config()
        provider = str(provider or "").strip()
        providers = config.get("llm_providers", {})
        if provider and provider not in providers:
            return ToolResult(False, f"Unknown provider: {provider}")
        if role and role not in ROLE_CATALOG:
            return ToolResult(False, f"Unknown role: {role}")

        if refresh:
            self.discover_available_models(provider=provider, save=True)

        models = combined_model_catalog(config, provider_filter=provider, include_cache=True, include_static=True)
        if not models:
            return ToolResult(False, "No model records are available. Configure providers or call discover_available_models after setting API keys.")

        scored: list[dict[str, Any]] = []
        for record in models:
            score, reasons = score_model_record(
                record,
                objective=objective,
                role=role,
                required_context_tokens=max(0, int(required_context_tokens)),
                prefer=prefer,
            )
            enriched = dict(record)
            enriched["score"] = score
            enriched["score_reasons"] = reasons
            scored.append(enriched)
        scored.sort(key=lambda item: (-float(item.get("score", 0)), str(item.get("provider", "")), str(item.get("id", ""))))
        limit = max(1, min(int(limit), 50))
        best = scored[0]
        payload = {
            "objective": objective,
            "role": role,
            "provider_filter": provider,
            "required_context_tokens": max(0, int(required_context_tokens)),
            "prefer": prefer,
            "recommendation": {
                "provider": best.get("provider"),
                "model": best.get("id"),
                "score": best.get("score"),
                "reasons": best.get("score_reasons", []),
                "capabilities": best.get("capabilities", []),
            },
            "candidates": scored[:limit],
            "candidate_count": len(scored),
            "next_action": "Use set_model_selection with the recommended provider/model if you want to persist this route.",
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def build_model_portfolio(self, objective: str = "", refresh: bool = False) -> ToolResult:
        categories = [
            {"name": "default_general", "role": "planner", "prefer": "balanced general model"},
            {"name": "coding_refactor", "role": "coder", "prefer": "coding refactor debug software engineering"},
            {"name": "deep_reasoning", "role": "critic", "prefer": "reasoning hard problems architecture"},
            {"name": "fast_cheap", "role": "researcher", "prefer": "fast cheap quick small"},
            {"name": "long_context", "role": "planner", "prefer": "long context large files transcripts", "required_context_tokens": 30000},
            {"name": "local_private", "role": "coder", "prefer": "local private offline LM Studio Ollama"},
            {"name": "open_weight_meta", "role": "coder", "prefer": "open weights Meta Llama open source"},
        ]
        portfolio: dict[str, Any] = {}
        for category in categories:
            result = self.recommend_model_selection(
                objective=objective,
                role=category.get("role", ""),
                required_context_tokens=int(category.get("required_context_tokens", 0)),
                prefer=str(category.get("prefer", "")),
                limit=5,
                refresh=refresh,
            )
            portfolio[category["name"]] = result.meta.get("recommendation", {}) if result.ok else {"error": result.content}

        payload = {
            "objective": objective,
            "portfolio": portfolio,
            "role_mapping_suggestion": {
                "planner": portfolio.get("deep_reasoning", portfolio.get("default_general", {})),
                "architect": portfolio.get("deep_reasoning", portfolio.get("coding_refactor", {})),
                "coder": portfolio.get("coding_refactor", {}),
                "refactorer": portfolio.get("coding_refactor", {}),
                "reviewer": portfolio.get("deep_reasoning", {}),
                "tester": portfolio.get("coding_refactor", {}),
                "researcher": portfolio.get("fast_cheap", {}),
                "writer": portfolio.get("default_general", portfolio.get("fast_cheap", {})),
                "safety": portfolio.get("deep_reasoning", {}),
                "critic": portfolio.get("deep_reasoning", {}),
                "maintainer": portfolio.get("fast_cheap", portfolio.get("default_general", {})),
                "meta": portfolio.get("deep_reasoning", portfolio.get("default_general", {})),
            },
            "next_action": "Persist specific assignments with set_model_selection(scope='role', role='coder', provider='...', model='...').",
        }
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def set_model_selection(
        self,
        provider: str,
        model: str,
        scope: str = "default",
        role: str = "",
        route_name: str = "",
        allow_unknown: bool = False,
    ) -> ToolResult:
        provider = str(provider or "").strip()
        model = str(model or "").strip()
        scope = str(scope or "default").strip().lower()
        role = str(role or "").strip()
        route_name = str(route_name or "").strip()
        if not provider or not model:
            return ToolResult(False, "provider and model are required.")

        config = load_config()
        providers = config.get("llm_providers", {})
        if provider not in providers:
            return ToolResult(False, f"Unknown provider: {provider}. Use configure_llm_provider first.")

        known_models = combined_model_catalog(config, provider_filter=provider, include_cache=True, include_static=True)
        known_ids = {str(item.get("id", "")) for item in known_models}
        if not allow_unknown and model not in known_ids:
            return ToolResult(
                False,
                f"Model {model!r} is not in the known catalog for {provider}. "
                "Call discover_available_models or set allow_unknown=true if you know the exact provider model id."
            )

        before = {
            "provider": config.get("provider"),
            "default_model": config.get("default_model"),
            "role_provider": config.get("role_providers", {}).get(role) if role else None,
            "role_model": config.get("role_models", {}).get(role) if role else None,
            "route": None,
        }

        if scope == "default":
            config["provider"] = provider
            config["default_model"] = model
            providers[provider]["model"] = model
            config["base_url"] = providers[provider].get("base_url", config.get("base_url", ""))
            config["api_key"] = providers[provider].get("api_key", config.get("api_key", ""))
        elif scope == "role":
            if role not in ROLE_CATALOG:
                return ToolResult(False, f"Unknown role for role-scoped route: {role}")
            config.setdefault("role_providers", {})[role] = provider
            config.setdefault("role_models", {})[role] = model
            providers[provider]["model"] = model
        elif scope == "router":
            routes = config.get("model_router", {}).get("routes", [])
            if not route_name:
                return ToolResult(False, "route_name is required when scope='router'.")
            updated_route = None
            for route in routes if isinstance(routes, list) else []:
                if isinstance(route, dict) and str(route.get("name", "")) == route_name:
                    before["route"] = dict(route)
                    route["provider"] = provider
                    route["model"] = model
                    updated_route = route
                    break
            if updated_route is None:
                return ToolResult(False, f"No model-router route named {route_name!r}.")
        else:
            return ToolResult(False, "scope must be one of: default, role, router.")

        config["llm_providers"] = providers
        save_config(config)
        after = {
            "provider": config.get("provider"),
            "default_model": config.get("default_model"),
            "role_provider": config.get("role_providers", {}).get(role) if role else None,
            "role_model": config.get("role_models", {}).get(role) if role else None,
            "route": next(
                (dict(route) for route in config.get("model_router", {}).get("routes", []) if isinstance(route, dict) and str(route.get("name", "")) == route_name),
                None,
            ) if route_name else None,
        }
        payload = {
            "updated": True,
            "scope": scope,
            "provider": provider,
            "model": model,
            "role": role,
            "route_name": route_name,
            "allow_unknown": bool(allow_unknown),
            "before": before,
            "after": after,
            "config_file": workspace_relative(CONFIG_FILE),
        }
        log_run_event("model_selection_updated", payload)
        return ToolResult(True, json.dumps(payload, indent=2), meta=payload)

    def configure_llm_provider(
        self,
        name: str,
        provider_type: str = "openai_compatible",
        base_url: str = "",
        api_key_env: str = "",
        model: str = "",
        model_list_endpoint: str = "",
        overwrite: bool = False,
    ) -> ToolResult:
        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name or "").strip().lower())
        if not name:
            return ToolResult(False, "Provider name is required.")
        provider_type = str(provider_type or "openai_compatible").strip().lower()
        if provider_type not in {"openai", "openai_compatible", "anthropic"}:
            return ToolResult(False, "provider_type must be openai, openai_compatible, or anthropic.")

        config = load_config()
        providers = config.setdefault("llm_providers", {})
        if name in providers and not overwrite:
            return ToolResult(False, f"Provider {name!r} already exists. Set overwrite=true to update it.")

        if not base_url and provider_type == "anthropic":
            base_url = "https://api.anthropic.com"
        if not base_url and provider_type in {"openai", "openai_compatible"}:
            return ToolResult(False, "base_url is required for OpenAI-compatible providers.")

        settings = dict(providers.get(name, {})) if isinstance(providers.get(name), dict) else {}
        settings.update(
            {
                "type": provider_type,
                "base_url": base_url.rstrip("/") if base_url else settings.get("base_url", ""),
                "model": model or settings.get("model", MODEL),
                "auto_discover_model": True,
                "family": settings.get("family", name),
                "notes": settings.get("notes", "User-configured LLM provider."),
            }
        )
        if api_key_env:
            settings["api_key_env"] = api_key_env
            settings.pop("api_key", None)
        if model_list_endpoint:
            settings["model_list_endpoint"] = model_list_endpoint
        settings.setdefault("known_models", [{"id": settings.get("model", MODEL), "capabilities": ["configured"]}])
        providers[name] = settings
        config["llm_providers"] = providers
        save_config(config)

        payload = {
            "configured": True,
            "provider": name,
            "settings": redacted_llm_providers({name: settings}).get(name, {}),
            "config_file": workspace_relative(CONFIG_FILE),
            "next_actions": [
                f"Set {settings.get('api_key_env')} in your environment." if settings.get("api_key_env") else "Provider uses inline/local API key settings.",
                f"Run discover_available_models(provider='{name}') to populate exact model ids.",
                f"Run recommend_model_selection(provider='{name}', objective='...') to choose a model.",
            ],
        }
        log_run_event("llm_provider_configured", payload)
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

    def generate_health_report(self, goal: str = "improve this codebase", scope: str = ".") -> ToolResult:
        target = resolve_workspace_path(scope)
        scope_relative = workspace_relative(target)
        recursive = target.is_dir()
        validation = self.run_self_improvement_validation(path=scope_relative)
        code_index = self.index_codebase(path=scope_relative, recursive=recursive)
        code_graph = self.build_code_graph(path=scope_relative, recursive=recursive)
        hotspot_result = self.rank_code_hotspots(path=scope_relative, recursive=recursive)
        orphan_symbols = self.find_orphan_symbols(path=scope_relative, recursive=recursive)
        if scope_relative == ".":
            backlog = self.scan_improvement_opportunities(goal=goal)
            selected = self.select_next_improvement()
        else:
            backlog_payload = {"scope": scope_relative, "opportunities": [], "note": "Scope-limited health report skipped workspace-wide backlog scan."}
            backlog = ToolResult(True, json.dumps(backlog_payload, indent=2), meta=backlog_payload)
            selected = ToolResult(False, "Scope-limited health report skipped backlog selection.")
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
            "scope": scope_relative,
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

    def generate_planning_brief(self, goal: str = "improve this codebase", scope: str = ".") -> ToolResult:
        health = self.generate_health_report(goal=goal, scope=scope)
        selected = health.meta.get("improvement_backlog", {}).get("selected") if health.ok else None
        selected = selected or {}
        evaluation = selected.get("manager_evaluation", {}) if isinstance(selected, dict) else {}
        decision = evaluation.get("decision", "unknown")
        recommendation = self.recommend_team(
            task=goal,
            context=json.dumps({"selected_opportunity": selected, "governor_decision": decision}),
        )
        tool_chain = self.recommend_tool_chain(
            objective=goal,
            context=json.dumps({"selected_opportunity": selected, "governor_decision": decision}),
            path=scope,
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
            "scope": scope,
            "selected_opportunity": selected,
            "governor_decision": decision,
            "recommended_roles": roles,
            "team_recommendation": recommendation.meta,
            "recommended_tool_chain": tool_chain.meta if tool_chain.ok else {"error": tool_chain.content},
            "autonomy_policy": health.meta.get("autonomy_policy", {}),
            "health_recommendations": health.meta.get("recommendations", []),
            "execution_constraints": [
                "Prefer the smallest reversible change that can satisfy the selected opportunity.",
                "Use checkpoint, impact analysis, validation, policy evaluation, and rollback if needed.",
                "Use build_code_graph and analyze_symbol_impact before refactoring shared helpers.",
                "Use rank_code_hotspots to identify high-blast-radius symbols before broad edits.",
                "Review the recent cycle ledger before widening scope or starting a new refactor path.",
                "Use the recommended_tool_chain phases as the default order unless fresh evidence contradicts them.",
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

    def scan_workspace_secrets(
        self,
        path: str = ".",
        recursive: bool = True,
        max_files: int = 200,
        max_bytes_per_file: int = 1048576,
        include_low_confidence: bool = False,
    ) -> ToolResult:
        """Scan workspace text files for likely exposed secrets without revealing raw values."""
        target = resolve_workspace_path(path)
        max_files = max(1, min(int(max_files), 1000))
        max_bytes_per_file = max(1024, min(int(max_bytes_per_file), 20 * 1024 * 1024))
        if target.is_file():
            candidates = [target]
        elif recursive:
            candidates = iter_workspace_files(target)
        else:
            candidates = [item for item in target.iterdir() if item.is_file() and not should_skip_checkpoint_path(item)]
        candidates = sorted(candidates, key=lambda item: workspace_relative(item))[:max_files]

        secret_patterns: list[dict[str, Any]] = [
            {
                "name": "private_key_block",
                "severity": "critical",
                "regex": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", re.I),
                "description": "Private key material appears to be present.",
            },
            {
                "name": "openai_api_key",
                "severity": "high",
                "regex": re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
                "description": "OpenAI-style API key pattern.",
            },
            {
                "name": "anthropic_api_key",
                "severity": "high",
                "regex": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
                "description": "Anthropic-style API key pattern.",
            },
            {
                "name": "github_token",
                "severity": "high",
                "regex": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
                "description": "GitHub token pattern.",
            },
            {
                "name": "aws_access_key_id",
                "severity": "high",
                "regex": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
                "description": "AWS access key id pattern.",
            },
            {
                "name": "slack_token",
                "severity": "high",
                "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{20,}\b"),
                "description": "Slack token pattern.",
            },
            {
                "name": "jwt_token",
                "severity": "medium",
                "regex": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
                "description": "JWT-like token.",
            },
            {
                "name": "credential_assignment",
                "severity": "medium",
                "regex": re.compile(
                    r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|access[_-]?token)\b\s*[:=]\s*[\"']?([^\"'\s#]{12,})"
                ),
                "description": "Credential-looking assignment.",
            },
        ]

        def shannon_entropy(value: str) -> float:
            if not value:
                return 0.0
            counts = collections.Counter(value)
            length = float(len(value))
            return -sum((count / length) * math.log2(count / length) for count in counts.values())

        def redact_value(value: str) -> str:
            value = str(value)
            if len(value) <= 8:
                return "<redacted>"
            return f"{value[:4]}…{value[-4:]}"

        def redacted_context(line: str, raw_value: str) -> str:
            safe_line = line.replace(raw_value, redact_value(raw_value)) if raw_value else line
            return trim_text(safe_line.strip(), 220)

        findings: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        scanned_files = 0
        scanned_bytes = 0
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        for file_path in candidates:
            try:
                size = file_path.stat().st_size
            except OSError as exc:
                skipped.append({"path": workspace_relative(file_path), "reason": f"stat_failed: {exc}"})
                continue
            if size > max_bytes_per_file:
                skipped.append({"path": workspace_relative(file_path), "reason": f"larger_than_max_bytes_per_file:{size}"})
                continue
            try:
                raw = file_path.read_bytes()
            except OSError as exc:
                skipped.append({"path": workspace_relative(file_path), "reason": f"read_failed: {exc}"})
                continue
            if b"\x00" in raw[:4096]:
                skipped.append({"path": workspace_relative(file_path), "reason": "binary_or_null_bytes"})
                continue
            text = raw.decode("utf-8", errors="replace")
            scanned_files += 1
            scanned_bytes += len(raw)
            rel = workspace_relative(file_path)
            lines = text.splitlines()
            for line_no, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                for pattern in secret_patterns:
                    for match in pattern["regex"].finditer(line):
                        raw_value = match.group(1) if match.groups() else match.group(0)
                        if not raw_value:
                            continue
                        if pattern["name"] == "credential_assignment":
                            assignment_value = raw_value.strip()
                            if (
                                "(" in assignment_value
                                or ")" in assignment_value
                                or assignment_value.startswith(("read_", "os.", "str(", "dict(", "json.", "config.", "value."))
                            ):
                                continue
                        entropy = round(shannon_entropy(raw_value), 3)
                        finding = {
                            "path": rel,
                            "line": line_no,
                            "type": pattern["name"],
                            "severity": pattern["severity"],
                            "description": pattern["description"],
                            "redacted_value": redact_value(raw_value),
                            "entropy": entropy,
                            "context": redacted_context(line, raw_value),
                        }
                        findings.append(finding)

                # Generic high-entropy fallback catches provider keys Cerebro does not know yet.
                for match in re.finditer(r"\b[A-Za-z0-9_./+=\-]{24,}\b", line):
                    candidate = match.group(0)
                    if candidate.startswith(("http://", "https://")):
                        continue
                    if candidate.lower().endswith((".json", ".py", ".txt", ".md", ".sqlite")):
                        continue
                    if not (re.search(r"[A-Za-z]", candidate) and re.search(r"\d", candidate)):
                        continue
                    entropy = shannon_entropy(candidate)
                    if entropy < 4.1:
                        continue
                    near = line[max(0, match.start() - 48) : min(len(line), match.end() + 48)]
                    lower_near = near.lower()
                    confidence = "medium" if any(token in lower_near for token in ["key", "secret", "token", "password", "auth", "bearer"]) else "low"
                    if confidence == "low" and not include_low_confidence:
                        continue
                    findings.append(
                        {
                            "path": rel,
                            "line": line_no,
                            "type": "high_entropy_candidate",
                            "severity": "medium" if confidence == "medium" else "low",
                            "description": "High-entropy string that may be a token or generated secret.",
                            "redacted_value": redact_value(candidate),
                            "entropy": round(entropy, 3),
                            "confidence": confidence,
                            "context": redacted_context(line, candidate),
                        }
                    )

        unique: dict[tuple[str, int, str, str], dict[str, Any]] = {}
        for finding in findings:
            key = (
                str(finding.get("path")),
                int(finding.get("line", 0)),
                str(finding.get("type")),
                str(finding.get("redacted_value")),
            )
            existing = unique.get(key)
            if existing is None or severity_rank.get(str(finding.get("severity")), 0) > severity_rank.get(str(existing.get("severity")), 0):
                unique[key] = finding
        findings = sorted(
            unique.values(),
            key=lambda item: (-severity_rank.get(str(item.get("severity")), 0), str(item.get("path")), int(item.get("line", 0))),
        )
        counts_by_severity: dict[str, int] = {}
        counts_by_type: dict[str, int] = {}
        for finding in findings:
            counts_by_severity[str(finding.get("severity", "unknown"))] = counts_by_severity.get(str(finding.get("severity", "unknown")), 0) + 1
            counts_by_type[str(finding.get("type", "unknown"))] = counts_by_type.get(str(finding.get("type", "unknown")), 0) + 1

        recommendations = [
            "Rotate any confirmed exposed credentials before committing or sharing this workspace.",
            "Move secrets into environment variables or a dedicated local secret store.",
            "Review low-confidence high-entropy candidates manually before treating them as incidents.",
        ]
        payload = {
            "generated_at": utc_now(),
            "scope": workspace_relative(target),
            "recursive": bool(recursive),
            "scanned_files": scanned_files,
            "scanned_bytes": scanned_bytes,
            "skipped_count": len(skipped),
            "finding_count": len(findings),
            "counts_by_severity": counts_by_severity,
            "counts_by_type": counts_by_type,
            "findings": findings[:200],
            "truncated": len(findings) > 200,
            "skipped": skipped[:50],
            "recommendations": recommendations,
            "note": "Values are redacted by design; this tool does not print raw secrets.",
        }
        summary = [
            "Workspace secret scan complete.",
            f"Scanned files: {scanned_files}",
            f"Findings: {len(findings)}",
            f"Severity counts: {json.dumps(counts_by_severity, sort_keys=True)}",
        ]
        if findings:
            summary.append("Top findings:")
            for finding in findings[:10]:
                summary.append(
                    f"- {finding['severity']} {finding['type']} at {finding['path']}:{finding['line']} "
                    f"value={finding['redacted_value']}"
                )
        return ToolResult(True, "\n".join(summary), meta=payload)

    def build_workspace_snapshot(
        self,
        path: str = ".",
        recursive: bool = True,
        max_files: int = 250,
        include_hashes: bool = False,
    ) -> ToolResult:
        """Build a compact, read-only operational snapshot of the current workspace."""
        target = resolve_workspace_path(path)
        max_files = max(1, min(int(max_files), 2000))
        if target.is_file():
            files = [target]
        elif recursive:
            files = iter_workspace_files(target)
        else:
            files = [item for item in target.iterdir() if item.is_file() and not should_skip_checkpoint_path(item)]
        files = sorted(files, key=lambda item: workspace_relative(item))[:max_files]

        extension_counts: dict[str, int] = {}
        total_bytes = 0
        largest: list[dict[str, Any]] = []
        newest: list[dict[str, Any]] = []
        python_files: list[Path] = []
        file_records: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        for file_path in files:
            try:
                stat = file_path.stat()
            except OSError as exc:
                errors.append({"path": workspace_relative(file_path), "error": str(exc)})
                continue
            rel = workspace_relative(file_path)
            suffix = file_path.suffix.lower() or "<none>"
            extension_counts[suffix] = extension_counts.get(suffix, 0) + 1
            total_bytes += stat.st_size
            if file_path.suffix.lower() == ".py":
                python_files.append(file_path)
            record = {
                "path": rel,
                "bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "extension": suffix,
            }
            if include_hashes and stat.st_size <= 5 * 1024 * 1024:
                try:
                    record["sha256"] = hashlib.sha256(file_path.read_bytes()).hexdigest()
                except OSError as exc:
                    record["hash_error"] = str(exc)
            file_records.append(record)
            largest.append(record)
            newest.append(record)

        largest = sorted(largest, key=lambda item: int(item.get("bytes", 0)), reverse=True)[:12]
        newest = sorted(newest, key=lambda item: str(item.get("modified_at", "")), reverse=True)[:12]

        symbol_counts = {"functions": 0, "classes": 0, "methods": 0, "syntax_errors": 0}
        python_surface: list[dict[str, Any]] = []
        for py_file in python_files[:100]:
            rel = workspace_relative(py_file)
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source)
            except SyntaxError as exc:
                symbol_counts["syntax_errors"] += 1
                python_surface.append({"path": rel, "syntax_error": str(exc)})
                continue
            except OSError as exc:
                errors.append({"path": rel, "error": str(exc)})
                continue
            functions = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
            classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
            method_count = sum(1 for cls in classes for node in cls.body if isinstance(node, ast.FunctionDef))
            symbol_counts["functions"] += len(functions)
            symbol_counts["classes"] += len(classes)
            symbol_counts["methods"] += method_count
            python_surface.append(
                {
                    "path": rel,
                    "top_level_functions": len(functions),
                    "classes": [cls.name for cls in classes[:20]],
                    "method_count": method_count,
                    "lines": source.count("\n") + 1,
                }
            )

        risk_counts: dict[str, int] = {}
        for spec in self.tool_specs.values():
            risk_counts[spec.risk] = risk_counts.get(spec.risk, 0) + 1

        config = load_config()
        provider_count = len(config.get("llm_providers", {})) if isinstance(config.get("llm_providers"), dict) else 0
        route_count = len(config.get("model_router", {}).get("routes", [])) if isinstance(config.get("model_router"), dict) else 0
        state_files = {
            "config": CONFIG_FILE.exists(),
            "memory": MEMORY_FILE.exists(),
            "tasks": TASKS_FILE.exists(),
            "blackboard": BLACKBOARD_FILE.exists(),
            "code_index": CODE_INDEX_FILE.exists(),
            "code_graph": CODE_GRAPH_FILE.exists(),
            "hotspots": CODE_HOTSPOTS_FILE.exists(),
            "cycle_ledger": CYCLE_LEDGER_FILE.exists(),
        }
        payload = {
            "generated_at": utc_now(),
            "scope": workspace_relative(target),
            "recursive": bool(recursive),
            "file_count_sampled": len(file_records),
            "total_bytes_sampled": total_bytes,
            "extension_counts": dict(sorted(extension_counts.items(), key=lambda item: (-item[1], item[0]))),
            "largest_files": largest,
            "newest_files": newest,
            "python": {
                "file_count_sampled": len(python_files),
                "symbol_counts": symbol_counts,
                "surface": python_surface[:50],
            },
            "tool_registry": {
                "tool_count": len(self.tool_specs),
                "risk_counts": risk_counts,
                "recent_tool_history_count": len(self.state.tool_history),
            },
            "config_posture": {
                "provider": config.get("provider"),
                "fallback_provider": config.get("fallback_provider"),
                "provider_count": provider_count,
                "model_router_enabled": bool(config.get("model_router", {}).get("enabled", False)) if isinstance(config.get("model_router"), dict) else False,
                "model_route_count": route_count,
                "monitor": config.get("monitor"),
                "show_thinking_indicator": config.get("show_thinking_indicator"),
            },
            "state_files": state_files,
            "errors": errors[:50],
            "file_records": file_records[:100],
            "truncated": len(files) >= max_files,
        }
        summary = [
            "Workspace snapshot complete.",
            f"Scope: {payload['scope']}",
            f"Files sampled: {len(file_records)}",
            f"Python files sampled: {len(python_files)}",
            f"Registered tools: {len(self.tool_specs)}",
            f"Extensions: {json.dumps(payload['extension_counts'], sort_keys=True)[:600]}",
        ]
        return ToolResult(True, "\n".join(summary), meta=payload)

    def analyze_unified_diff_impact(
        self,
        diff: str = "",
        path: str = ".",
        max_diff_chars: int = 40000,
    ) -> ToolResult:
        """Analyze a patch diff for impact and validation hints without applying it."""
        max_diff_chars = max(1000, min(int(max_diff_chars), 200000))
        if not diff.strip():
            git_result = self.git_diff(path=path)
            if not git_result.ok:
                return ToolResult(False, f"Unable to obtain git diff: {git_result.content}", meta={"source": "git_diff", "ok": False})
            diff = git_result.content
        original_chars = len(diff)
        diff = diff[:max_diff_chars]
        changed_files: dict[str, dict[str, Any]] = {}
        current_file = ""
        hunk_header_re = re.compile(r"^@@ .* @@\s*(.*)$")
        current_hunk_context = ""
        for line in diff.splitlines():
            if line.startswith("diff --git "):
                parts = line.split()
                b_path = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else ""
                current_file = b_path
                if current_file:
                    changed_files.setdefault(
                        current_file,
                        {"path": current_file, "added": 0, "removed": 0, "hunks": 0, "symbols": [], "status": "modified", "risk_signals": []},
                    )
                continue
            if line.startswith("+++ b/"):
                current_file = line[6:]
                changed_files.setdefault(
                    current_file,
                    {"path": current_file, "added": 0, "removed": 0, "hunks": 0, "symbols": [], "status": "modified", "risk_signals": []},
                )
                continue
            if line.startswith("new file mode") and current_file:
                changed_files[current_file]["status"] = "added"
                continue
            if line.startswith("deleted file mode") and current_file:
                changed_files[current_file]["status"] = "deleted"
                continue
            hunk_match = hunk_header_re.match(line)
            if hunk_match and current_file:
                changed_files[current_file]["hunks"] += 1
                current_hunk_context = hunk_match.group(1).strip()
                if current_hunk_context:
                    changed_files[current_file]["symbols"].append(current_hunk_context)
                continue
            if not current_file or current_file not in changed_files:
                continue
            if line.startswith("+") and not line.startswith("+++"):
                changed_files[current_file]["added"] += 1
                symbol_match = re.match(r"\+\s*(?:async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
                if symbol_match:
                    changed_files[current_file]["symbols"].append(symbol_match.group(1))
            elif line.startswith("-") and not line.startswith("---"):
                changed_files[current_file]["removed"] += 1
                symbol_match = re.match(r"-\s*(?:async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
                if symbol_match:
                    changed_files[current_file]["symbols"].append(symbol_match.group(1))

        risk_patterns = [
            (re.compile(r"(^|/)(agent|main|app|server|router)\.py$", re.I), "entrypoint_or_core_python_file"),
            (re.compile(r"(^|/)\.agent_config\.json$", re.I), "agent_configuration_changed"),
            (re.compile(r"(^|/)(requirements|pyproject|setup|poetry\.lock|package-lock|package)\.(txt|toml|cfg|json|lock)$", re.I), "dependency_surface_changed"),
            (re.compile(r"(^|/)(auth|security|crypto|network|ids|threat|malware|tool|agent)", re.I), "security_or_agentic_surface_changed"),
            (re.compile(r"(^|/)\.github/", re.I), "ci_cd_surface_changed"),
        ]
        for record in changed_files.values():
            record["symbols"] = sorted(set(str(item) for item in record.get("symbols", []) if str(item).strip()))[:20]
            for regex, signal in risk_patterns:
                if regex.search(str(record.get("path", ""))):
                    record["risk_signals"].append(signal)
            if int(record.get("added", 0)) + int(record.get("removed", 0)) > 400:
                record["risk_signals"].append("large_patch")
            if int(record.get("hunks", 0)) > 20:
                record["risk_signals"].append("many_hunks")
            record["risk_signals"] = sorted(set(record.get("risk_signals", [])))

        total_added = sum(int(item.get("added", 0)) for item in changed_files.values())
        total_removed = sum(int(item.get("removed", 0)) for item in changed_files.values())
        total_hunks = sum(int(item.get("hunks", 0)) for item in changed_files.values())
        all_signals = sorted({signal for item in changed_files.values() for signal in item.get("risk_signals", [])})
        risk_score = 0
        risk_score += min(25, len(changed_files) * 3)
        risk_score += min(25, (total_added + total_removed) // 80)
        risk_score += min(20, total_hunks)
        risk_score += len(all_signals) * 8
        if any(item.get("status") == "deleted" for item in changed_files.values()):
            risk_score += 12
        if risk_score >= 55:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        validation_steps = [
            "python -m py_compile <changed .py files>",
            "python agent.py --self-test or use run_internal_self_tests when runtime dependencies are available",
        ]
        if any("dependency_surface_changed" in item.get("risk_signals", []) for item in changed_files.values()):
            validation_steps.append("Recreate or verify the environment and run dependency-health checks.")
        if any("security_or_agentic_surface_changed" in item.get("risk_signals", []) for item in changed_files.values()):
            validation_steps.append("Run tool schema health, policy evaluation, and focused safety regression checks.")
        if any(str(item.get("path", "")).endswith(".py") for item in changed_files.values()):
            validation_steps.append("Run targeted smoke tests against changed Python entrypoints.")

        payload = {
            "generated_at": utc_now(),
            "source": "argument" if diff.strip() else "git_diff",
            "original_diff_chars": original_chars,
            "analyzed_diff_chars": len(diff),
            "truncated": original_chars > len(diff),
            "file_count": len(changed_files),
            "total_added": total_added,
            "total_removed": total_removed,
            "total_hunks": total_hunks,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_signals": all_signals,
            "files": sorted(changed_files.values(), key=lambda item: str(item.get("path", ""))),
            "recommended_validation": validation_steps,
        }
        summary = [
            "Diff impact analysis complete.",
            f"Changed files: {len(changed_files)}",
            f"Lines added: {total_added}",
            f"Lines removed: {total_removed}",
            f"Risk level: {risk_level} ({risk_score})",
        ]
        if all_signals:
            summary.append(f"Risk signals: {', '.join(all_signals)}")
        return ToolResult(True, "\n".join(summary), meta=payload)

    def create_diagnostic_bundle(
        self,
        path: str = ".",
        output_path: str = ".agent_diagnostics/latest_diagnostic_bundle.json",
        max_files: int = 200,
    ) -> ToolResult:
        """Write a redacted operational diagnostic bundle inside the workspace."""
        output = resolve_workspace_path(output_path)
        if output.exists() and output.is_dir():
            return ToolResult(False, "output_path points to a directory; provide a JSON file path.")
        target = resolve_workspace_path(path)
        if output != WORKSPACE_ROOT and WORKSPACE_ROOT not in output.parents:
            return ToolResult(False, "output_path escapes the workspace.")
        output.parent.mkdir(parents=True, exist_ok=True)

        snapshot = self.build_workspace_snapshot(path=workspace_relative(target), recursive=target.is_dir(), max_files=max_files)
        schema_health = self.inspect_tool_schema_health()
        secret_scan = self.scan_workspace_secrets(path=workspace_relative(target), recursive=target.is_dir(), max_files=max_files, include_low_confidence=False)
        route_config = load_config()
        config_posture = dict(route_config)
        config_posture["llm_providers"] = redacted_llm_providers(config_posture.get("llm_providers", {}))
        if config_posture.get("api_key"):
            config_posture["api_key"] = "<redacted>"

        validation_hints = [
            "Run run_internal_self_tests for deterministic parser, registry, terminal-rendering, and policy checks.",
            "Run run_self_improvement_validation before and after any autonomous improvement cycle.",
            "Review scan_workspace_secrets findings before publishing diagnostics or committing files.",
        ]
        payload = {
            "generated_at": utc_now(),
            "workspace_root": str(WORKSPACE_ROOT),
            "scope": workspace_relative(target),
            "active_agent_file": active_agent_file(),
            "snapshot": snapshot.meta if snapshot.ok else {"error": snapshot.content},
            "tool_schema_health": {
                "ok": schema_health.ok,
                "schema_health_ok": schema_health.meta.get("schema_health_ok") if schema_health.ok else False,
                "issue_count": schema_health.meta.get("issue_count") if schema_health.ok else None,
                "severe_issue_count": schema_health.meta.get("severe_issue_count") if schema_health.ok else None,
                "issues": schema_health.meta.get("issues", [])[:100] if schema_health.ok else [],
            },
            "secret_scan": {
                "ok": secret_scan.ok,
                "finding_count": secret_scan.meta.get("finding_count") if secret_scan.ok else None,
                "counts_by_severity": secret_scan.meta.get("counts_by_severity", {}) if secret_scan.ok else {},
                "findings": secret_scan.meta.get("findings", [])[:50] if secret_scan.ok else [],
                "note": "secret values are redacted",
            },
            "config_posture": config_posture,
            "run_history": load_run_events(limit=50),
            "tool_history_tail": self.state.tool_history[-25:],
            "tasks": load_tasks(),
            "cycle_ledger_tail": load_cycle_ledger().get("cycles", [])[-10:],
            "validation_hints": validation_hints,
        }
        output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        content = (
            f"Diagnostic bundle written to {workspace_relative(output)}\n"
            f"Snapshot files sampled: {payload.get('snapshot', {}).get('file_count_sampled')}\n"
            f"Tool schema severe issues: {payload.get('tool_schema_health', {}).get('severe_issue_count')}\n"
            f"Redacted secret findings included: {payload.get('secret_scan', {}).get('finding_count')}"
        )
        return ToolResult(True, content, meta={"path": workspace_relative(output), "bundle": payload})

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
        active_file = active_agent_file()
        check("active_agent_file_resolves", bool(active_file) and active_file.endswith(".py"), active_file)
        check("config_has_autonomy_policy", isinstance(config.get("autonomy_policy"), dict))
        check("thinking_indicator_enabled", config.get("show_thinking_indicator") is True)
        check("config_has_known_fallback_provider", config.get("fallback_provider") in config.get("llm_providers", {}))
        check("config_has_llm_providers", isinstance(config.get("llm_providers"), dict) and bool(config.get("llm_providers")))
        check("lmstudio_auto_discovers_model", config.get("llm_providers", {}).get("lmstudio", {}).get("auto_discover_model") is True)
        check("config_has_model_router", isinstance(config.get("model_router"), dict) and isinstance(config.get("model_router", {}).get("routes"), list))
        check("token_estimation_is_monotonic", estimate_token_count("hello world") < estimate_token_count("hello world " * 200))
        route_probe = model_route_decision_payload(
            messages=[{"role": "user", "content": "hello"}],
            provider_name=str(config.get("provider", "lmstudio")),
            selected_model=str(config.get("default_model", MODEL)),
            selected_temperature=float(config.get("temperature", 0.25)),
            config=config,
        )
        check("model_router_returns_route_decision", "estimated_input_tokens" in route_probe and "route_name" in route_probe, json.dumps(route_probe, indent=2))
        prompt_budget = model_input_token_budget(route_probe, get_provider_config(str(config.get("provider", "lmstudio")))[1], config)
        check("model_router_resolves_prompt_budget", prompt_budget is not None and prompt_budget > 0, str(prompt_budget))
        compacted_probe, compaction_probe = compact_messages_for_input_budget(
            [{"role": "user", "content": "alpha beta gamma " * 4000}],
            max_input_tokens=512,
            chars_per_token=float(config.get("model_router", {}).get("estimate_chars_per_token", APPROX_CHARS_PER_TOKEN)),
        )
        check(
            "prompt_compaction_reduces_oversized_message",
            compaction_probe.get("compacted") is True
            and compaction_probe.get("new_estimated_tokens", 10**9) < compaction_probe.get("original_estimated_tokens", 0)
            and "Cerebro compacted" in compacted_probe[0].get("content", ""),
            json.dumps(compaction_probe, indent=2),
        )
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

        check("run_logging_is_nonfatal", log_run_event("self_test_probe", {"ok": True}) is None)

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

        oversized_batch = parse_model_reply(
            json.dumps(
                {
                    "type": "batch",
                    "why": "test oversized batch repair",
                    "actions": [
                        {"tool": "list_files", "args": {}},
                        {"tool": "read_control_state", "args": {}},
                        {"tool": "show_workspace_stats", "args": {}},
                        {"tool": "inspect_path", "args": {"path": "."}},
                    ],
                }
            ),
            tool_names=set(self.tools),
        )
        check(
            "parse_oversized_batch_repairs_instead_of_printing_json",
            oversized_batch.get("type") == "batch" and len(oversized_batch.get("actions", [])) == configured_max_batch_actions(),
            json.dumps(oversized_batch),
        )

        invalid_tool_json = json.dumps({"type": "tool", "tool": "missing_tool", "args": {}})
        invalid_tool_action = parse_model_reply(invalid_tool_json, tool_names=set(self.tools))
        check(
            "invalid_action_json_suppressed_instead_of_printed",
            invalid_tool_action.get("type") == "final"
            and "missing_tool" in invalid_tool_action.get("content", "")
            and "{\"" not in invalid_tool_action.get("content", ""),
            invalid_tool_action.get("content", ""),
        )

        rendered_batch_json = render_terminal_markdown(
            json.dumps(
                {
                    "type": "batch",
                    "actions": [
                        {"tool": "inspect_path", "args": {"path": "."}},
                        {"tool": "show_workspace_stats", "args": {"path": "."}},
                    ],
                }
            )
        )
        check(
            "renderer_suppresses_raw_batch_action_json",
            "internal batch request suppressed" in rendered_batch_json
            and "\"type\"" not in rendered_batch_json
            and "\"actions\"" not in rendered_batch_json,
            rendered_batch_json,
        )

        check(
            "system_prompt_uses_live_tool_registry_note",
            "Registered tool specs are injected at runtime" in SYSTEM_PROMPT
            and "Available tools and JSON arg schemas:" not in SYSTEM_PROMPT,
        )

        conversation_state = AgentState()
        conversation_state.record_conversation_turn("What is Cerebro in X-Men?", "Cerebro is a telepathic amplifier used by Professor Xavier.")
        check(
            "conversation_history_records_recent_turn",
            len(conversation_state.recent_conversation_messages()) == 2,
            json.dumps(conversation_state.recent_conversation_messages()),
        )
        check(
            "short_followup_detected",
            user_input_looks_like_conversational_followup("Anything else?"),
        )
        check(
            "conversational_followup_blocks_workspace_tool",
            should_block_tool_for_conversational_followup("inspect_path", "Anything else?", conversation_state),
        )
        check(
            "turn_guidance_for_followup_forces_direct_answer",
            "return a final answer" in build_turn_guidance("Anything else?", conversation_state),
            build_turn_guidance("Anything else?", conversation_state),
        )
        check(
            "turn_guidance_for_plain_question_prefers_direct_answer",
            "ordinary conversation or an informational question" in build_turn_guidance("What is Cerebro?", AgentState()),
            build_turn_guidance("What is Cerebro?", AgentState()),
        )
        inventory_request_text = "give me a table of the tools and what they do"
        rendered_inventory = build_direct_tool_inventory_response(inventory_request_text, self)
        check(
            "direct_tool_inventory_detects_table_request",
            _looks_like_tool_inventory_request(inventory_request_text),
            inventory_request_text,
        )
        check(
            "direct_tool_inventory_renders_live_registry",
            rendered_inventory is not None
            and "CEREBRO TOOL INVENTORY" in rendered_inventory
            and "lookup_cve" in rendered_inventory
            and "scan_workspace_file_signatures" in rendered_inventory
            and "| # | Tool | Risk | What it does |" in rendered_inventory
            and "### Threat Intelligence" in rendered_inventory,
            trim_text(rendered_inventory or "", 1000),
        )
        try:
            parse_cli_roles("planner,definitely_missing")
            unknown_role_rejected = False
        except ValueError:
            unknown_role_rejected = True
        check("cli_role_parser_rejects_unknown_roles", unknown_role_rejected)

        required_tools = {
            "self_improve_codebase",
            "generate_health_report",
            "generate_planning_brief",
            "scan_workspace_secrets",
            "build_workspace_snapshot",
            "analyze_unified_diff_impact",
            "create_diagnostic_bundle",
            "recommend_team",
            "audit_tool_coverage",
            "recommend_tool_chain",
            "build_execution_dossier",
            "inspect_tool_schema_health",
            "map_tool_capability_graph",
            "mine_tool_usage_patterns",
            "trace_goal_to_symbols",
            "build_validation_matrix",
            "plan_patch_strategy",
            "score_execution_readiness",
            "read_json_file",
            "validate_json_file",
            "show_last_self_improvement_changes",
            "search_todos",
            "list_recent_files",
            "find_large_files",
            "semantic_search_workspace",
            "find_relevant_code_context",
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
            "route_multi_model_task",
            "inspect_runtime_environment",
            "audit_dependency_health",
            "inspect_prompt_surface",
            "build_context_budget_plan",
            "propose_test_plan_for_symbol",
            "simulate_tool_execution_plan",
            "build_risk_register",
            "map_repository_structure",
            "inspect_project_entrypoints",
            "extract_api_surface",
            "trace_data_flow",
            "inspect_error_log",
            "inspect_config_surface",
            "fetch_url_text",
            "inspect_http_endpoint",
            "fetch_json_api",
            "extract_html_metadata",
            "check_http_security_headers",
            "crawl_url_map",
            "infer_json_schema",
            "extract_text_entities",
            "generate_file_manifest",
            "compare_workspace_files",
            "inspect_python_environment",
            "inspect_process_table",
            "normalize_network_target",
            "resolve_dns_records",
            "reverse_dns_lookup",
            "lookup_ip_rdap",
            "lookup_ip_geolocation",
            "get_public_ip_info",
            "scan_tcp_ports",
            "inspect_local_listening_ports",
            "inspect_tls_certificate",
            "inspect_local_network",
            "build_network_intel_brief",
            "ingest_network_traffic_file",
            "analyze_network_traffic_file",
            "build_ids_baseline",
            "compare_network_baseline",
            "capture_network_metadata_sample",
            "build_ids_mode_plan",
            "show_ids_alerts",
            "lookup_cve",
            "search_cves",
            "check_cisa_kev",
            "lookup_malware_hash",
            "hash_workspace_file",
            "add_malware_signature",
            "scan_workspace_file_signatures",
            "build_threat_intel_brief",
            "build_toolbox_brief",
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

        graph = self.build_code_graph(active_file, recursive=False)
        callers = self.find_callers("load_config")
        symbol_impact = self.analyze_symbol_impact("load_config")
        orphans = self.find_orphan_symbols(active_file, recursive=False)
        hotspots = self.rank_code_hotspots(active_file, recursive=False)
        cycle_ledger = self.show_cycle_ledger(limit=3)
        config_view = self.show_config()
        model_router_view = self.show_model_router()
        model_router_validation = self.validate_model_router_config()
        model_route_recommendation = self.recommend_model_route(prompt="hello world", role="planner")
        available_models = self.list_available_models(limit=20)
        model_selection = self.recommend_model_selection(objective="debug and refactor python code", role="coder", prefer="coding", limit=5)
        model_portfolio = self.build_model_portfolio(objective="autonomous coding and reasoning")
        tool_coverage = self.audit_tool_coverage("implement a safe feature", include_specs=False)
        tool_chain = self.recommend_tool_chain("implement a safe feature", path=active_file)
        execution_dossier = self.build_execution_dossier("implement a safe feature", path=active_file, limit=2)
        tool_schema_health = self.inspect_tool_schema_health()
        capability_graph = self.map_tool_capability_graph("implement a safe feature", include_edges=True)
        usage_patterns = self.mine_tool_usage_patterns(limit=20)
        goal_trace = self.trace_goal_to_symbols("render markdown tables", active_file, limit=2)
        validation_matrix = self.build_validation_matrix("implement a safe feature", changed_files=[active_file], path=active_file)
        patch_strategy = self.plan_patch_strategy("render markdown tables", target_path=active_file, max_files=2)
        readiness_score = self.score_execution_readiness("implement a safe feature", context="checkpoint validation compile", changed_files=[active_file])
        multi_model_route = self.route_multi_model_task("implement a safe feature", path=active_file, prefer="coding", refresh=False)
        runtime_environment = self.inspect_runtime_environment(include_packages=True, include_env=True)
        dependency_health = self.audit_dependency_health(active_file, recursive=False, limit=5)
        prompt_surface = self.inspect_prompt_surface(include_snippets=False)
        context_budget = self.build_context_budget_plan("implement a safe feature", path=active_file, role="coder")
        symbol_test_plan = self.propose_test_plan_for_symbol("load_config", path=active_file, objective="configuration routing", limit=3)
        simulated_plan = self.simulate_tool_execution_plan("implement a safe feature", path=active_file)
        risk_register = self.build_risk_register("implement a safe feature", path=active_file, context="checkpoint validation compile", changed_files=[active_file])
        repository_structure = self.map_repository_structure(path=active_file, max_depth=2, include_hidden=False)
        project_entrypoints = self.inspect_project_entrypoints(path=active_file, recursive=False, limit=10)
        api_surface = self.extract_api_surface(path=active_file, recursive=False, include_private=False, limit=10)
        data_flow = self.trace_data_flow("configuration routing", symbol="load_config", path=active_file, limit=3)
        error_log = self.inspect_error_log(text="Traceback (most recent call last):\n  File \"agent.py\", line 1, in <module>\nModuleNotFoundError: No module named 'openai'", limit=5)
        config_surface = self.inspect_config_surface(path=active_file, include_preview=False)
        toolbox_brief = self.build_toolbox_brief("implement a safe feature", path=active_file)
        network_target = self.normalize_network_target("127.0.0.1", resolve=False, allow_private=True)
        dns_records = self.resolve_dns_records("localhost", record_type="ANY", allow_private=True, timeout=2)
        reverse_dns = self.reverse_dns_lookup("127.0.0.1", allow_private=True)
        rdap_private = self.lookup_ip_rdap("127.0.0.1", timeout=2)
        geo_private = self.lookup_ip_geolocation("127.0.0.1", timeout=2)
        port_scan_private = self.scan_tcp_ports("127.0.0.1", ports="9", timeout=0.1, allow_public=False, max_ports=1)
        local_ports = self.inspect_local_listening_ports(include_udp=True, include_process_names=False, limit=10)
        direct_port_action = build_direct_network_tool_action("What ports are open on this network?")
        direct_ids_action = build_direct_network_tool_action("Can you act as an IDS and ingest network traffic?")
        direct_cve_action = build_direct_threat_intel_tool_action("Look up CVE-2024-3094")
        direct_hash_action = build_direct_threat_intel_tool_action("Check hash d41d8cd98f00b204e9800998ecf8427e")
        threat_brief = self.build_threat_intel_brief("CVE-2024-3094")
        local_network = self.inspect_local_network(include_command_output=False)
        network_brief = self.build_network_intel_brief("localhost", include_scan_plan=True, allow_public_scan=False)
        ids_sample_path = ".agent_ids_selftest.jsonl"
        try:
            resolve_workspace_path(ids_sample_path).write_text(
                "\n".join([
                    json.dumps({"timestamp": 1, "event_type": "flow", "src_ip": "192.168.1.10", "dest_ip": "8.8.8.8", "src_port": 51500, "dest_port": 53, "proto": "UDP", "dns": {"rrname": "example.com"}}),
                    json.dumps({"timestamp": 2, "event_type": "flow", "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "src_port": 51501, "dest_port": 4444, "proto": "TCP"}),
                    json.dumps({"timestamp": 3, "event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "192.168.1.20", "src_port": 4444, "dest_port": 3389, "proto": "TCP", "alert": {"signature": "self-test suspicious RDP", "category": "self-test", "severity": 2}}),
                ]) + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass
        ids_ingest = self.ingest_network_traffic_file(ids_sample_path, input_format="jsonl", limit=10)
        ids_analysis = self.analyze_network_traffic_file(ids_sample_path, input_format="jsonl", limit=10, sensitivity="medium", record_alerts=False)
        ids_baseline = self.build_ids_baseline(ids_sample_path, input_format="jsonl", label="self-test", limit=10, baseline_path=".agent_ids_selftest_baseline.json")
        ids_compare = self.compare_network_baseline(ids_sample_path, input_format="jsonl", baseline_path=".agent_ids_selftest_baseline.json", limit=10, record_alerts=False)
        ids_plan = self.build_ids_mode_plan(mode="offline", source_path=ids_sample_path, authorized=False)
        ids_alerts = self.show_ids_alerts(limit=5)
        signature_sample_path = ".agent_signature_selftest.txt"
        try:
            resolve_workspace_path(signature_sample_path).write_text("hello X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* world", encoding="utf-8")
        except OSError:
            pass
        hash_selftest = self.hash_workspace_file(signature_sample_path, lookup_malware_bazaar=False)
        signature_scan = self.scan_workspace_file_signatures(signature_sample_path, recursive=False, max_files=1, use_yara=False)
        signature_add = self.add_malware_signature("self-test literal", "self-test-needle", signature_type="string", severity="low", tags=["self-test"], overwrite=True, signature_path=".agent_signature_selftest_signatures.json")
        ids_capture_guard = self.capture_network_metadata_sample(duration_seconds=1, max_packets=1, authorized=False)
        user_profile = self.show_user_profile()
        blackboard_summary = self.summarize_blackboard(limit=2)
        workspace_stats = self.show_workspace_stats(path=active_file, recursive=False)
        run_history = self.show_run_history(limit=5)
        json_read = self.read_json_file(".agent_config.json")
        json_validation = self.validate_json_file(".agent_config.json")
        last_self_improvement_changes = self.show_last_self_improvement_changes()
        todos = self.search_todos(active_file, recursive=False)
        recent_files = self.list_recent_files(".", limit=3)
        large_files = self.find_large_files(".", limit=3)
        inspected_active_file = self.inspect_path(active_file)
        semantic_search = self.semantic_search_workspace("render markdown tables", active_file, limit=3)
        relevant_code_context = self.find_relevant_code_context("render markdown tables", active_file, limit=3)
        context_pack = self.build_context_pack("render markdown tables", active_file, limit=3)
        complexity = self.analyze_python_complexity(active_file, recursive=False)
        import_graph = self.build_import_graph(active_file, recursive=False)
        duplicates = self.find_duplicate_blocks(active_file, min_lines=6)
        refactor_targets = self.suggest_refactor_targets(active_file, recursive=False)
        check("code_graph_builds", graph.ok and bool(graph.meta.get("nodes")), trim_text(graph.content, 500))
        check("find_callers_returns_payload", callers.ok and isinstance(callers.meta.get("callers"), list), trim_text(callers.content, 500))
        check("analyze_symbol_impact_scores_symbol", symbol_impact.ok and symbol_impact.meta.get("risk_level") in {"low", "medium", "high"}, trim_text(symbol_impact.content, 500))
        check("find_orphan_symbols_returns_list", orphans.ok and isinstance(orphans.meta.get("orphans"), list), trim_text(orphans.content, 500))
        check("rank_code_hotspots_returns_list", hotspots.ok and isinstance(hotspots.meta.get("hotspots"), list), trim_text(hotspots.content, 500))
        check("rank_code_hotspots_persists_file", CODE_HOTSPOTS_FILE.exists(), workspace_relative(CODE_HOTSPOTS_FILE))
        check("show_cycle_ledger_returns_list", cycle_ledger.ok and isinstance(cycle_ledger.meta.get("cycles"), list), trim_text(cycle_ledger.content, 500))
        check("show_config_returns_payload", config_view.ok and "role_models" in config_view.meta, trim_text(config_view.content, 500))
        check("show_model_router_returns_routes", model_router_view.ok and isinstance(model_router_view.meta.get("routes"), list), trim_text(model_router_view.content, 500))
        check("validate_model_router_config_passes", model_router_validation.ok and model_router_validation.meta.get("ok") is True, trim_text(model_router_validation.content, 500))
        check("recommend_model_route_estimates_prompt", model_route_recommendation.ok and "estimated_input_tokens" in model_route_recommendation.meta, trim_text(model_route_recommendation.content, 500))
        check("recommend_model_route_reports_budget", model_route_recommendation.ok and "input_token_budget" in model_route_recommendation.meta, trim_text(model_route_recommendation.content, 500))
        check("list_available_models_returns_catalog", available_models.ok and available_models.meta.get("model_count", 0) > 0 and isinstance(available_models.meta.get("models"), list), trim_text(available_models.content, 500))
        check("recommend_model_selection_returns_provider_model", model_selection.ok and model_selection.meta.get("recommendation", {}).get("provider") and model_selection.meta.get("recommendation", {}).get("model"), trim_text(model_selection.content, 500))
        check("build_model_portfolio_returns_categories", model_portfolio.ok and "coding_refactor" in model_portfolio.meta.get("portfolio", {}), trim_text(model_portfolio.content, 500))
        check("audit_tool_coverage_returns_capabilities", tool_coverage.ok and "capabilities" in tool_coverage.meta and tool_coverage.meta.get("tool_count", 0) >= len(required_tools), trim_text(tool_coverage.content, 500))
        check("recommend_tool_chain_returns_phases", tool_chain.ok and bool(tool_chain.meta.get("phases")) and bool(tool_chain.meta.get("tool_sequence")), trim_text(tool_chain.content, 500))
        check("execution_dossier_contains_chain_and_route", execution_dossier.ok and "tool_chain" in execution_dossier.meta and "model_route" in execution_dossier.meta, trim_text(execution_dossier.content, 500))
        check("tool_schema_health_returns_rows", tool_schema_health.ok and isinstance(tool_schema_health.meta.get("tools"), list), trim_text(tool_schema_health.content, 500))
        check("capability_graph_returns_nodes_and_edges", capability_graph.ok and capability_graph.meta.get("node_count", 0) >= len(required_tools) and isinstance(capability_graph.meta.get("edges"), list), trim_text(capability_graph.content, 500))
        check("usage_patterns_returns_stats", usage_patterns.ok and isinstance(usage_patterns.meta.get("tool_stats"), list), trim_text(usage_patterns.content, 500))
        check("goal_trace_returns_targets", goal_trace.ok and (goal_trace.meta.get("candidate_files") or goal_trace.meta.get("candidate_symbols")), trim_text(goal_trace.content, 500))
        check("validation_matrix_returns_minimum_pass_set", validation_matrix.ok and isinstance(validation_matrix.meta.get("minimum_pass_set"), list), trim_text(validation_matrix.content, 500))
        check("patch_strategy_returns_patch_steps", patch_strategy.ok and bool(patch_strategy.meta.get("patch_steps")), trim_text(patch_strategy.content, 500))
        check("readiness_score_returns_decision", readiness_score.ok and readiness_score.meta.get("decision") in {"ready", "proceed_with_caution", "not_ready"}, trim_text(readiness_score.content, 500))
        check("route_multi_model_task_returns_phase_routes", multi_model_route.ok and isinstance(multi_model_route.meta.get("role_routes"), dict) and isinstance(multi_model_route.meta.get("phase_routes"), list), trim_text(multi_model_route.content, 500))
        check("inspect_runtime_environment_returns_python_payload", runtime_environment.ok and "python" in runtime_environment.meta and "providers" in runtime_environment.meta, trim_text(runtime_environment.content, 500))
        check("audit_dependency_health_returns_imports", dependency_health.ok and "imports" in dependency_health.meta and "health" in dependency_health.meta, trim_text(dependency_health.content, 500))
        check("inspect_prompt_surface_returns_prompt_rows", prompt_surface.ok and isinstance(prompt_surface.meta.get("prompts"), list), trim_text(prompt_surface.content, 500))
        check("build_context_budget_plan_returns_budget", context_budget.ok and "budget" in context_budget.meta and "sections" in context_budget.meta, trim_text(context_budget.content, 500))
        check("propose_test_plan_for_symbol_returns_cases", symbol_test_plan.ok and isinstance(symbol_test_plan.meta.get("test_cases"), list), trim_text(symbol_test_plan.content, 500))
        check("simulate_tool_execution_plan_returns_steps", simulated_plan.ok and isinstance(simulated_plan.meta.get("simulated_steps"), list), trim_text(simulated_plan.content, 500))
        check("build_risk_register_returns_risks", risk_register.ok and isinstance(risk_register.meta.get("risks"), list), trim_text(risk_register.content, 500))
        check("map_repository_structure_returns_tree", repository_structure.ok and isinstance(repository_structure.meta.get("tree"), list), trim_text(repository_structure.content, 500))
        check("inspect_project_entrypoints_returns_entrypoints", project_entrypoints.ok and isinstance(project_entrypoints.meta.get("entrypoints"), list), trim_text(project_entrypoints.content, 500))
        check("extract_api_surface_returns_modules", api_surface.ok and isinstance(api_surface.meta.get("modules"), list), trim_text(api_surface.content, 500))
        check("trace_data_flow_returns_flows", data_flow.ok and isinstance(data_flow.meta.get("flows"), list), trim_text(data_flow.content, 500))
        check("inspect_error_log_detects_missing_module", error_log.ok and "openai" in error_log.meta.get("missing_modules", []), trim_text(error_log.content, 500))
        check("inspect_config_surface_returns_files", config_surface.ok and isinstance(config_surface.meta.get("files"), list), trim_text(config_surface.content, 500))
        check("build_toolbox_brief_returns_groups", toolbox_brief.ok and "tool_groups" in toolbox_brief.meta and "repository_intelligence" in toolbox_brief.meta.get("tool_groups", {}), trim_text(toolbox_brief.content, 500))
        check("network_target_normalizes_loopback", network_target.ok and network_target.meta.get("addresses") and network_target.meta["addresses"][0].get("is_loopback") is True, trim_text(network_target.content, 500))
        check("resolve_dns_records_returns_payload", dns_records.ok and isinstance(dns_records.meta.get("records"), list), trim_text(dns_records.content, 500))
        check("reverse_dns_lookup_returns_ptr_payload", reverse_dns.ok and "ptr_records" in reverse_dns.meta, trim_text(reverse_dns.content, 500))
        check("lookup_ip_rdap_skips_private", rdap_private.ok and rdap_private.meta.get("skipped") is True, trim_text(rdap_private.content, 500))
        check("lookup_ip_geolocation_skips_private", geo_private.ok and geo_private.meta.get("skipped") is True, trim_text(geo_private.content, 500))
        check("scan_tcp_ports_returns_results", port_scan_private.ok and isinstance(port_scan_private.meta.get("results"), list) and port_scan_private.meta.get("ports_scanned") == 1, trim_text(port_scan_private.content, 500))
        check("inspect_local_listening_ports_returns_entries_list", local_ports.ok and isinstance(local_ports.meta.get("entries"), list), trim_text(local_ports.content, 500))
        check("direct_network_routes_open_ports_to_local_listener_tool", isinstance(direct_port_action, dict) and direct_port_action.get("tool") == "inspect_local_listening_ports", str(direct_port_action))
        check("direct_ids_request_routes_to_ids_plan", isinstance(direct_ids_action, dict) and direct_ids_action.get("tool") == "build_ids_mode_plan", str(direct_ids_action))
        check("direct_cve_request_routes_to_lookup_cve", isinstance(direct_cve_action, dict) and direct_cve_action.get("tool") == "lookup_cve", str(direct_cve_action))
        check("direct_hash_request_routes_to_malware_lookup", isinstance(direct_hash_action, dict) and direct_hash_action.get("tool") == "lookup_malware_hash", str(direct_hash_action))
        check("threat_brief_returns_sequence", threat_brief.ok and isinstance(threat_brief.meta.get("recommended_sequence"), list) and threat_brief.meta.get("recommended_sequence"), trim_text(threat_brief.content, 500))
        check("inspect_local_network_returns_hostname", local_network.ok and "hostname" in local_network.meta and isinstance(local_network.meta.get("addresses"), list), trim_text(local_network.content, 500))
        check("build_network_intel_brief_returns_sequence", network_brief.ok and isinstance(network_brief.meta.get("recommended_sequence"), list) and "safety_rules" in network_brief.meta, trim_text(network_brief.content, 500))
        check("ids_ingest_returns_flow_count", ids_ingest.ok and ids_ingest.meta.get("flow_count", 0) >= 3 and isinstance(ids_ingest.meta.get("sample_flows"), list), trim_text(ids_ingest.content, 500))
        check("ids_analysis_generates_alerts", ids_analysis.ok and ids_analysis.meta.get("alert_count", 0) >= 1 and isinstance(ids_analysis.meta.get("alerts"), list), trim_text(ids_analysis.content, 500))
        check("ids_baseline_saves_known_good", ids_baseline.ok and ids_baseline.meta.get("baseline_path") == ".agent_ids_selftest_baseline.json" and "dst_ports" in ids_baseline.meta, trim_text(ids_baseline.content, 500))
        check("ids_compare_returns_deviation_payload", ids_compare.ok and "baseline_label" in ids_compare.meta and isinstance(ids_compare.meta.get("alerts"), list), trim_text(ids_compare.content, 500))
        check("ids_plan_returns_supported_inputs", ids_plan.ok and isinstance(ids_plan.meta.get("recommended_sequence"), list) and "supported_inputs" in ids_plan.meta, trim_text(ids_plan.content, 500))
        check("ids_capture_requires_authorization", not ids_capture_guard.ok and ids_capture_guard.meta.get("authorization_required") is True, trim_text(ids_capture_guard.content, 500))
        check("show_ids_alerts_returns_alert_list", ids_alerts.ok and isinstance(ids_alerts.meta.get("alerts"), list), trim_text(ids_alerts.content, 500))
        check("hash_workspace_file_returns_hashes", hash_selftest.ok and "sha256" in hash_selftest.meta.get("hashes", {}), trim_text(hash_selftest.content, 500))
        check("scan_workspace_file_signatures_detects_eicar", signature_scan.ok and signature_scan.meta.get("match_count", 0) >= 1, trim_text(signature_scan.content, 500))
        check("add_malware_signature_saves_catalog", signature_add.ok and signature_add.meta.get("signature_count", 0) >= 1, trim_text(signature_add.content, 500))
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
        check("inspect_path_returns_metadata", inspected_active_file.ok and inspected_active_file.meta.get("path") == active_file, trim_text(inspected_active_file.content, 500))
        check("semantic_search_workspace_returns_ranked_matches", semantic_search.ok and bool(semantic_search.meta.get("matches")), trim_text(semantic_search.content, 500))
        check("find_relevant_code_context_returns_symbols", relevant_code_context.ok and bool(relevant_code_context.meta.get("symbols")), trim_text(relevant_code_context.content, 500))
        check(
            "context_pack_includes_semantic_matches",
            context_pack.ok and bool(context_pack.meta.get("workspace", {}).get("semantic_matches")),
            trim_text(context_pack.content, 500),
        )
        check(
            "context_pack_includes_relevant_code_symbols",
            context_pack.ok and bool(context_pack.meta.get("workspace", {}).get("relevant_code_symbols")),
            trim_text(context_pack.content, 500),
        )
        check("analyze_python_complexity_returns_callables", complexity.ok and isinstance(complexity.meta.get("callables"), list), trim_text(complexity.content, 500))
        check("build_import_graph_returns_files", import_graph.ok and isinstance(import_graph.meta.get("files"), dict), trim_text(import_graph.content, 500))
        check("find_duplicate_blocks_returns_list", duplicates.ok and isinstance(duplicates.meta.get("duplicates"), list), trim_text(duplicates.content, 500))
        check("suggest_refactor_targets_returns_targets", refactor_targets.ok and isinstance(refactor_targets.meta.get("targets"), list), trim_text(refactor_targets.content, 500))

        profile_update = self.update_user_profile("custom.__self_test__", "ok")
        profile_forget = self.forget_user_profile_field("custom.__self_test__")
        check("update_user_profile_writes_field", profile_update.ok, trim_text(profile_update.content, 500))
        check("forget_user_profile_field_removes_field", profile_forget.ok, trim_text(profile_forget.content, 500))

        workspace_snapshot_probe = self.build_workspace_snapshot(path=active_file, recursive=False, max_files=1)
        secret_scan_probe = self.scan_workspace_secrets(path=active_file, recursive=False, max_files=1, include_low_confidence=False)
        diff_impact_probe = self.analyze_unified_diff_impact(
            diff="diff --git a/sample.py b/sample.py\n--- a/sample.py\n+++ b/sample.py\n@@ -1 +1 @@ def demo():\n-old = 1\n+new = 2\n"
        )
        check("workspace_snapshot_probe_returns_sample", workspace_snapshot_probe.ok and workspace_snapshot_probe.meta.get("file_count_sampled", 0) >= 1, trim_text(workspace_snapshot_probe.content, 500))
        check("secret_scan_probe_returns_findings_list", secret_scan_probe.ok and isinstance(secret_scan_probe.meta.get("findings"), list), trim_text(secret_scan_probe.content, 500))
        check("diff_impact_probe_scores_patch", diff_impact_probe.ok and diff_impact_probe.meta.get("file_count") == 1, trim_text(diff_impact_probe.content, 500))

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
            markdown_table = render_terminal_markdown("| Company | Location |\n| --- | --- |\n| Apple | Cupertino |")
            loose_table = render_terminal_markdown("| Company | Location |\n| Apple | Cupertino |\n| Microsoft | Redmond |")
            heading = render_terminal_markdown("# Main Title\n## Sub Title")
            fenced_table = render_terminal_markdown("```\n| A | B |\n| --- | --- |\n| 1 | 2 |\n```")
            check(
                "terminal_markdown_table_box_rendering",
                "┌" in markdown_table and "│ Company" in markdown_table and "Apple" in markdown_table,
                markdown_table,
            )
            check(
                "terminal_loose_pipe_table_box_rendering",
                "┌" in loose_table and "Microsoft" in loose_table and "Redmond" in loose_table,
                loose_table,
            )
            plain_heading = strip_ansi(heading)
            check(
                "terminal_heading_strips_marker_and_adds_visual_rules",
                "#" not in plain_heading
                and "MAIN TITLE" in plain_heading
                and "Sub Title" in plain_heading
                and "═" in plain_heading
                and "─" in plain_heading,
                heading,
            )
            check("terminal_code_fence_table_not_rendered", "┌" not in fenced_table and "| A | B |" in fenced_table, fenced_table)
            rendered_list = render_terminal_markdown("- item\n- [x] done\n- [ ] todo")
            rendered_quote = render_terminal_markdown("> quoted text")
            rendered_inline = render_terminal_markdown("Use `agent.py` and **bold** text")
            fenced_inline = render_terminal_markdown("```\nUse `raw` and **raw**\n```")
            check("terminal_unordered_lists_use_bullets", "• item" in rendered_list and "☑ done" in rendered_list and "☐ todo" in rendered_list, rendered_list)
            check("terminal_blockquote_uses_visual_bar", "│ quoted text" in rendered_quote, rendered_quote)
            check("terminal_inline_markdown_removes_source_markers", "`" not in strip_ansi(rendered_inline) and "**" not in strip_ansi(rendered_inline), rendered_inline)
            check("terminal_code_fence_inline_markdown_not_rendered", "`raw`" in fenced_inline and "**raw**" in fenced_inline, fenced_inline)
        finally:
            sys.stdout.isatty = terminal_was_tty

        check("ordinary_informational_request_blocks_write_tools", should_block_write_action("write_file", "Give me a table of tech companies"))
        check("explicit_file_change_request_allows_write_tools", not should_block_write_action("write_file", "Save this table to a csv file"))
        blocked_result = execute_action(
            {"type": "tool", "tool": "write_file", "args": {"path": "blocked_selftest.txt", "content": "x"}},
            self,
            user_input="Give me a table of tech companies",
        )
        check("execute_action_blocks_unrequested_write", blocked_result[0][1].ok is False and blocked_result[0][1].meta.get("blocked") is True)

        brief = self.generate_planning_brief("internal self-test planning brief", scope=active_file)
        check("planning_brief_generates", brief.ok and bool(brief.meta.get("acceptance_criteria")), trim_text(brief.content, 500))
        check("planning_brief_includes_tool_chain", brief.ok and "recommended_tool_chain" in brief.meta, trim_text(brief.content, 500))

        validation = self.run_self_improvement_validation(path=active_file)
        check("self_improvement_validation_runs_on_active_file", validation.ok, trim_text(validation.content, 500))

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
        limit = max(1, min(int(limit), 20))
        items = [
            {"key": key, "value": value, "content": f"{key}\n{value}"}
            for key, value in self.state.memory.items()
        ]
        selected = rank_relevant_text_items(query, items, text_fields=("content",), limit=limit)
        if not selected:
            return ToolResult(False, f"No memory matches for query: {query}", meta={"query_terms": search_terms(query)})
        lines = [
            f"{item['key']} (score={item['relevance_score']}): {trim_text(str(item['value']), 300)}"
            for item in selected
        ]
        payload = {"query": query, "query_terms": search_terms(query), "matches": selected}
        return ToolResult(True, "\n\n".join(lines), meta=payload)

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


def execute_action(action: dict[str, Any], tools: AgentTools, *, user_input: str = "") -> list[tuple[str, ToolResult]]:
    def activity_for_tool(tool_name: str, args: dict[str, Any]) -> tuple[str, str]:
        if tool_name in WRITE_TOOL_NAMES:
            target = str(args.get("path", "")) if isinstance(args, dict) else ""
            return "editing", f"Editing a file: {target or tool_name}"
        return "tool", f"Ran {tool_name}"

    action_type = action.get("type")
    if action_type == "tool":
        tool_name = str(action.get("tool", ""))
        args = action.get("args", {})
        if not isinstance(args, dict):
            args = {}
        if should_block_tool_for_conversational_followup(tool_name, user_input, tools.state):
            result = blocked_conversational_tool_result(tool_name, user_input)
            emit_activity("warning", result.content, animate=False)
            return [(tool_name, result)]
        if should_block_write_action(tool_name, user_input):
            result = blocked_write_tool_result(tool_name, user_input)
            emit_activity("warning", result.content, animate=False)
            return [(tool_name, result)]
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
        for item in normalize_batch_actions(action.get("actions", []), tool_names=set(tools.tools)):
            if should_block_tool_for_conversational_followup(item["tool"], user_input, tools.state):
                result = blocked_conversational_tool_result(item["tool"], user_input)
                emit_activity("warning", result.content, animate=False)
                executed.append((item["tool"], result))
                continue
            if should_block_write_action(item["tool"], user_input):
                result = blocked_write_tool_result(item["tool"], user_input)
                emit_activity("warning", result.content, animate=False)
                executed.append((item["tool"], result))
                continue
            kind, message = activity_for_tool(item["tool"], item["args"])
            indicator = start_activity_indicator(kind, message)
            try:
                result = tools.call(item["tool"], item["args"])
            finally:
                stop_activity_indicator(indicator)
            executed.append((item["tool"], result))
        if not executed:
            return [("batch", ToolResult(False, "No valid batch actions were provided."))]
        edit_count = sum(1 for name, _ in executed if name in WRITE_TOOL_NAMES)
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
            state.record_conversation_turn(user_input, answer)
            log_run_event("agent_exception", {"error": str(exc)})
        transcript.append({"role": "agent", "content": answer})
        print("\n" + terminal_color("Cerebro: ", "94"), end="", flush=True)
        typewriter_print(render_terminal_markdown(answer))


def cli_flag_value(flag: str, default: str = "") -> str:
    if flag not in sys.argv:
        return default
    index = sys.argv.index(flag)
    if len(sys.argv) <= index + 1:
        return default
    value = sys.argv[index + 1]
    if value.startswith("--"):
        return default
    return value


def cli_int_value(flag: str, default: int) -> int:
    value = cli_flag_value(flag, "")
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_cli_roles(value: str) -> list[str]:
    if not value.strip():
        return ["planner", "coder", "reviewer"]
    requested = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [role for role in requested if role not in ROLE_CATALOG]
    if unknown:
        raise ValueError(f"Unknown role(s): {', '.join(unknown)}")
    return requested or ["planner", "coder", "reviewer"]



def main() -> None:
    if "--self-test" in sys.argv:
        global RUNTIME_OUTPUT_SUPPRESSED
        RUNTIME_OUTPUT_SUPPRESSED = True
        state = AgentState()
        tools = AgentTools(state)
        result = tools.run_internal_self_tests()
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--quick-self-test" in sys.argv:
        RUNTIME_OUTPUT_SUPPRESSED = True
        checks = {
            "active_file": active_agent_file(),
            "renders_headers_without_hashes": "#" not in strip_ansi(render_terminal_markdown("# Title")),
            "renders_tables_as_boxes": "┌" in render_terminal_markdown("| A | B |\n|---|---|\n| 1 | 2 |"),
            "blocks_unrequested_writes": should_block_write_action("write_file", "Give me a table of tech companies"),
            "allows_requested_writes": not should_block_write_action("write_file", "Save this as a csv file"),
            "detects_conversation_followup": user_input_looks_like_conversational_followup("Anything else?"),
            "repairs_oversized_batch": len(parse_model_reply(json.dumps({"type": "batch", "actions": [{"tool": "list_files", "args": {}}, {"tool": "read_control_state", "args": {}}, {"tool": "show_workspace_stats", "args": {}}, {"tool": "inspect_path", "args": {"path": "."}}]}), tool_names=set(AgentTools(AgentState()).tools)).get("actions", [])) == configured_max_batch_actions(),
            "suppresses_raw_action_json": "internal tool request suppressed" in render_terminal_markdown(json.dumps({"type": "tool", "tool": "missing_tool", "args": {}})),
            "uses_dynamic_tool_registry_prompt": "Registered tool specs are injected at runtime" in SYSTEM_PROMPT and "Available tools and JSON arg schemas:" not in SYSTEM_PROMPT,
            "direct_tool_inventory_detects_table_request": _looks_like_tool_inventory_request("give me a table of the tools and what they do"),
            "direct_tool_inventory_renders_live_registry": "lookup_cve" in (build_direct_tool_inventory_response("give me a list of the tools CEREBRO has access to", AgentTools(AgentState())) or ""),
            "direct_guidance_for_plain_question": "direct final answer" in build_turn_guidance("What is Cerebro?", AgentState()),
            "cli_roles_validate": parse_cli_roles("planner,coder") == ["planner", "coder"],
            "task_profile_detects_implementation": "implementation" in infer_task_profile("Improve the agent with more intelligence")["intents"],
            "task_profile_estimates_tokens": infer_task_profile("Improve the agent with more intelligence").get("estimated_input_tokens", 0) > 0,
            "context_tools_registered": {"build_context_pack", "decompose_goal", "semantic_search_workspace", "find_relevant_code_context"}.issubset(set(AgentTools(AgentState()).tools)),
            "control_server_tools_registered": {"start_control_server", "show_control_server", "route_control_command", "stop_control_server"}.issubset(set(AgentTools(AgentState()).tools)),
            "control_server_safe_command_allows_ping": _control_server_command_is_allowed("ping"),
            "control_server_blocks_exec_command": not _control_server_command_is_allowed("exec"),
            "diagnostic_tools_registered": {"scan_workspace_secrets", "build_workspace_snapshot", "analyze_unified_diff_impact", "create_diagnostic_bundle"}.issubset(set(AgentTools(AgentState()).tools)),
            "workspace_snapshot_smoke": AgentTools(AgentState()).build_workspace_snapshot(path=active_agent_file(), recursive=False, max_files=1).ok,
            "secret_scan_smoke": AgentTools(AgentState()).scan_workspace_secrets(path=active_agent_file(), recursive=False, max_files=1).ok,
            "diff_impact_smoke": AgentTools(AgentState()).analyze_unified_diff_impact(diff="diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a=1\n+b=2\n").ok,
            "model_router_tools_registered": {"show_model_router", "validate_model_router_config", "recommend_model_route"}.issubset(set(AgentTools(AgentState()).tools)),
            "model_router_smoke": AgentTools(AgentState()).recommend_model_route(prompt="hello", role="planner").ok,
            "prompt_compaction_smoke": compact_messages_for_input_budget([{"role": "user", "content": "x " * 8000}], max_input_tokens=512)[1].get("compacted") is True,
            "route_recommendation_reports_budget": "input_token_budget" in AgentTools(AgentState()).recommend_model_route(prompt="hello", role="planner").meta,
            "model_router_config_validates": AgentTools(AgentState()).validate_model_router_config().ok,
            "inspect_path_smoke": AgentTools(AgentState()).inspect_path(active_agent_file()).ok,
            "semantic_search_smoke": AgentTools(AgentState()).semantic_search_workspace("render markdown", active_agent_file(), limit=2).ok,
            "code_context_smoke": AgentTools(AgentState()).find_relevant_code_context("render markdown", active_agent_file(), limit=2).ok,
            "relevance_scoring_matches_terms": score_text_relevance("advanced agent intelligence", "agent intelligence context pack")[0] > 0,
        }
        ok = all(bool(value) for key, value in checks.items() if key != "active_file")
        print(json.dumps({"ok": ok, "checks": checks}, indent=2))
        raise SystemExit(0 if ok else 1)

    if "--tools" in sys.argv:
        state = AgentState()
        tools = AgentTools(state)
        print(render_registered_tool_inventory(tools, include_schemas="--tool-schemas" in sys.argv))
        raise SystemExit(0)

    if "--model-router" in sys.argv:
        state = AgentState()
        tools = AgentTools(state)
        result = tools.show_model_router()
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--validate-router" in sys.argv:
        state = AgentState()
        tools = AgentTools(state)
        result = tools.validate_model_router_config()
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--route-prompt" in sys.argv:
        prompt = cli_flag_value("--route-prompt", "")
        role = cli_flag_value("--role", "")
        provider = cli_flag_value("--provider", "")
        model = cli_flag_value("--model", "")
        state = AgentState()
        tools = AgentTools(state)
        result = tools.recommend_model_route(prompt=prompt, role=role, provider=provider, model=model)
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--route-file" in sys.argv:
        target = cli_flag_value("--route-file", active_agent_file())
        role = cli_flag_value("--role", "")
        provider = cli_flag_value("--provider", "")
        model = cli_flag_value("--model", "")
        state = AgentState()
        tools = AgentTools(state)
        result = tools.recommend_model_route(path=target, role=role, provider=provider, model=model)
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--validate" in sys.argv:
        target = cli_flag_value("--validate", active_agent_file())
        state = AgentState()
        tools = AgentTools(state)
        result = tools.validate_python_file(target)
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--health-report" in sys.argv:
        goal = cli_flag_value("--health-report", "improve this codebase")
        scope = cli_flag_value("--scope", active_agent_file())
        state = AgentState()
        tools = AgentTools(state)
        result = tools.generate_health_report(goal=goal, scope=scope)
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--planning-brief" in sys.argv:
        goal = cli_flag_value("--planning-brief", "improve this codebase")
        scope = cli_flag_value("--scope", active_agent_file())
        state = AgentState()
        tools = AgentTools(state)
        result = tools.generate_planning_brief(goal=goal, scope=scope)
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--secret-scan" in sys.argv:
        target = cli_flag_value("--secret-scan", active_agent_file())
        max_files = cli_int_value("--max-files", 200)
        state = AgentState()
        tools = AgentTools(state)
        result = tools.scan_workspace_secrets(
            path=target,
            recursive="--no-recursive" not in sys.argv,
            max_files=max_files,
            include_low_confidence="--include-low-confidence" in sys.argv,
        )
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--workspace-snapshot" in sys.argv:
        target = cli_flag_value("--workspace-snapshot", active_agent_file())
        max_files = cli_int_value("--max-files", 250)
        state = AgentState()
        tools = AgentTools(state)
        result = tools.build_workspace_snapshot(
            path=target,
            recursive="--no-recursive" not in sys.argv,
            max_files=max_files,
            include_hashes="--hashes" in sys.argv,
        )
        print(json.dumps(result.meta, indent=2, sort_keys=True) if "--json" in sys.argv else result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--diff-impact" in sys.argv:
        target = cli_flag_value("--diff-impact", ".")
        diff_text = sys.stdin.read() if not sys.stdin.isatty() else ""
        state = AgentState()
        tools = AgentTools(state)
        result = tools.analyze_unified_diff_impact(diff=diff_text, path=target)
        print(json.dumps(result.meta, indent=2, sort_keys=True) if "--json" in sys.argv else result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--diagnostic-bundle" in sys.argv:
        target = cli_flag_value("--diagnostic-bundle", active_agent_file())
        output_path = cli_flag_value("--output", ".agent_diagnostics/latest_diagnostic_bundle.json")
        max_files = cli_int_value("--max-files", 200)
        state = AgentState()
        tools = AgentTools(state)
        result = tools.create_diagnostic_bundle(path=target, output_path=output_path, max_files=max_files)
        print(result.content)
        raise SystemExit(0 if result.ok else 1)

    if "--self-improve" in sys.argv:
        goal = cli_flag_value("--self-improve", "improve this codebase")
        cycles = max(1, cli_int_value("--cycles", DEFAULT_SELF_IMPROVE_CYCLES))
        try:
            roles = parse_cli_roles(cli_flag_value("--roles", "planner,coder,reviewer"))
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            raise SystemExit(2)
        state = AgentState()
        tools = AgentTools(state)
        result = tools.self_improve_codebase(goal=goal, max_cycles=cycles, roles=roles)
        print(result.content)
        raise SystemExit(0 if result.ok else 1)


    if "--control-server-status" in sys.argv:
        status = control_server_status()
        print(json.dumps(status, indent=2, sort_keys=True))
        raise SystemExit(0 if status.get("ok") else 1)

    if "--control-server" in sys.argv:
        host = cli_flag_value("--host", CONTROL_SERVER_DEFAULT_HOST)
        port = cli_int_value("--port", CONTROL_SERVER_DEFAULT_PORT)
        status = listen_for_connections(
            host=host,
            port=port,
            authorized="--authorized-network-bind" in sys.argv,
        )
        print(json.dumps(status, indent=2, sort_keys=True))
        if not status.get("ok"):
            raise SystemExit(1)
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(json.dumps(stop_control_server(), indent=2, sort_keys=True))
            raise SystemExit(0)

    if "--route-control-command" in sys.argv:
        command_type = cli_flag_value("--route-control-command", "ping")
        payload_raw = cli_flag_value("--payload", "{}")
        try:
            payload = json.loads(payload_raw)
        except json.JSONDecodeError as exc:
            print(f"Invalid --payload JSON: {exc}", file=sys.stderr)
            raise SystemExit(2)
        target_ids_raw = cli_flag_value("--target-ids", "")
        target_ids = [item.strip() for item in target_ids_raw.split(",") if item.strip()]
        result = route_command_to_clients(command_type, payload, target_ids)
        print(json.dumps(result, indent=2, sort_keys=True))
        raise SystemExit(0 if result.get("ok") else 1)


    if "--run-prompt" in sys.argv:
        index = sys.argv.index("--run-prompt")
        if len(sys.argv) <= index + 1:
            print("Missing prompt after --run-prompt", file=sys.stderr)
            raise SystemExit(2)
        prompt = " ".join(sys.argv[index + 1 :])
        answer = run_agent(prompt, state=AgentState())
        print(render_terminal_markdown(answer))
        raise SystemExit(0)

    if "--render-sample" in sys.argv:
        sample = "# Cerebro Renderer Sample\n\n## Tables\n\n| Feature | Status |\n| --- | --- |\n| Headers | Improved |\n| Tables | Boxed |\n\n## Lists\n\n- item\n- [x] done\n- [ ] todo\n\n> blockquote example\n\nUse `inline code` and **bold** text."
        print(render_terminal_markdown(sample))
        raise SystemExit(0)

    if "--render-markdown" in sys.argv:
        index = sys.argv.index("--render-markdown")
        if len(sys.argv) > index + 1:
            payload = sys.argv[index + 1]
            payload = payload.encode("utf-8").decode("unicode_escape")
        else:
            payload = sys.stdin.read()
        print(render_terminal_markdown(payload))
        raise SystemExit(0)

    repl()


if __name__ == "__main__":
    main()
