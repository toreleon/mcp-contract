"""Rule-based tool classification: `ToolIR` -> capability signals.

Conservative by design (spec §4.3-§4.4): a rule emits `inferred` only when
the scope is concretely known (URL/hostname/path literal); anything whose
*class* is implied but whose scope is not becomes `needs_review`, and
`proc.exec` is never auto-inferred at all — a human must approve exec.
Every emitted capability carries `Evidence` naming the exact signal.
"""
from __future__ import annotations

import re

from mcp_contract.models import (
    Capability,
    CapabilityId,
    CapabilityStatus,
    Evidence,
    ToolIR,
)

# --- net.http signals -------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s'\"<>()\[\],;]+", re.IGNORECASE)

_HOSTNAME_RE = re.compile(
    r"(?<![\w.\-/@])((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,})(?![\w\-])",
    re.IGNORECASE,
)

# Final labels that make a dotted literal look like a filename, not a host.
# This is only a fast path to DROP obvious filenames; it is inherently
# incomplete and therefore never sufficient to justify a grant (see
# _KNOWN_TLDS below).
_FILE_EXTENSIONS = frozenset(
    {
        "avro", "bak", "bash", "bin", "c", "cc", "cfg", "conf", "cpp", "cs",
        "css", "csv", "dat", "db", "dll", "doc", "docx", "env", "exe",
        "feather", "gif", "go", "gz", "h", "htm", "html", "ini", "ipynb",
        "java", "jpeg", "jpg", "js", "json", "jsonl", "jsx", "lock", "log",
        "md", "npy", "npz", "onnx", "parquet", "pdf", "pkl", "png", "pth",
        "py", "rb", "rs", "rst", "safetensors", "sh", "so", "sql", "sqlite",
        "svg", "tar", "tmp", "toml", "ts", "tsx", "tsv", "txt", "wasm",
        "whl", "xls", "xlsx", "xml", "yaml", "yml", "zip",
    }
)

# Conservative allowlist of final labels that make a dotted literal an
# UNAMBIGUOUS hostname. A denylist of file extensions can never be complete
# (data.parquet, model.pt, weights.bin, os.path, ...), so a bare dotted
# literal is only inferred (granted) when its TLD is on this list;
# everything else is clamped to needs_review — fail closed. Deliberately
# excludes real TLDs that collide with file/artifact suffixes
# (.pt, .ai, .app, .sh, .md, .rs, .zip, ...).
_KNOWN_TLDS = frozenset(
    {
        "at", "au", "be", "biz", "br", "ca", "cc", "ch", "cloud", "cn",
        "co", "com", "de", "dev", "dk", "edu", "es", "eu", "fi", "fr",
        "gov", "ie", "in", "info", "int", "io", "it", "jp", "kr", "me",
        "mil", "net", "nl", "no", "nz", "org", "pl", "se", "tech", "tv",
        "uk", "us",
    }
)

_NET_PARAM_RE = re.compile(r"url|uri|link|endpoint|host|domain|address", re.IGNORECASE)

_NET_VERB_RE = re.compile(
    r"\b(?:fetch|download|https?|api|request|webhook|scrape|crawl)"
    r"(?:s|es|ed|ing)?\b"
    r"|\bpost(?:s|ed|ing)?\s+to\b",
    re.IGNORECASE,
)

_NET_NAME_TOKENS = frozenset(
    {"fetch", "download", "http", "https", "api", "request", "requests",
     "webhook", "scrape", "crawl"}
)

# --- fs.read / fs.write signals ---------------------------------------------

_FS_PARAM_RE = re.compile(
    r"path|file|filename|filepath|dir|directory|folder|dest|destination",
    re.IGNORECASE,
)

_FS_NAME_TOKENS = frozenset(
    {"file", "files", "filename", "filepath", "dir", "directory",
     "directories", "folder", "folders", "path", "paths"}
)

_READ_VERBS = frozenset(
    {"read", "get", "list", "view", "cat", "open", "stat", "search", "glob",
     "load"}
)
_WRITE_VERBS = frozenset(
    {"write", "create", "save", "delete", "remove", "move", "copy", "append",
     "edit", "mkdir", "rename"}
)
# move/copy read the source before writing the destination.
_MOVEISH_VERBS = frozenset({"move", "copy"})

_READ_VERB_RE = re.compile(
    r"\b(?:read|get|list|view|cat|open|stat|search|glob|load)(?:s|ed|ing)?\b",
    re.IGNORECASE,
)
_WRITE_VERB_RE = re.compile(
    r"\b(?:write|create|save|delete|remove|move|copy|append|edit|mkdir|rename)"
    r"(?:s|d|ed|ing)?\b",
    re.IGNORECASE,
)
_MOVEISH_RE = re.compile(r"\b(?:move|copy)(?:s|d|ed|ing)?\b", re.IGNORECASE)

_PATH_RE = re.compile(r"(?<![\w.:])((?:/|\./)[A-Za-z0-9._~\-]+(?:/[A-Za-z0-9._~\-]+)*)")

# --- proc.exec signals ------------------------------------------------------

_PROC_RE = re.compile(
    r"\b(?:exec(?:ut(?:e[sd]?|ing))?|shell|bash|command|cmd|terminal"
    r"|subprocess|spawn(?:s|ed|ing)?|script)s?\b",
    re.IGNORECASE,
)

_PROC_NAME_TOKENS = frozenset(
    {"exec", "execute", "shell", "bash", "command", "commands", "cmd",
     "terminal", "subprocess", "spawn", "script", "scripts"}
)

# --- env signals ------------------------------------------------------------

_ENV_PHRASE_RE = re.compile(
    r"\b(?:api[ _-]?keys?|tokens?|credentials?|secrets?"
    r"|environment variables?|env vars?)\b",
    re.IGNORECASE,
)

# ALL_CAPS identifiers that look like env vars: _TOKEN/_KEY/_SECRET suffix
# or API_ prefix (word chars include "_", so \b sits at the real edges).
_ENV_VAR_RE = re.compile(
    r"\b(?:[A-Z][A-Z0-9_]*(?:_TOKEN|_KEY|_SECRET)|API_[A-Z0-9_]+)\b"
)


def classify_tool(tool: ToolIR) -> list[Capability]:
    """Classify one tool into capability signals, evidence attached.

    Returns at most one `Capability` per class this tool implies; a tool
    with no signals (pure computation) returns ``[]``. Statuses are only
    ever `inferred` (concrete scope known) or `needs_review`.
    """
    caps: list[Capability] = []
    caps.extend(_classify_net(tool))
    caps.extend(_classify_fs(tool))
    caps.extend(_classify_proc(tool))
    caps.extend(_classify_env(tool))
    return caps


# --- helpers ----------------------------------------------------------------


def _name_tokens(name: str) -> set[str]:
    """Word-ish tokens of a tool name: snake/kebab/camelCase split, lowered."""
    tokens: list[str] = []
    for part in re.split(r"[^0-9A-Za-z]+", name):
        tokens.extend(re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", part))
    return {t.lower() for t in tokens}


def _params(tool: ToolIR) -> list[tuple[str, dict]]:
    props = tool.input_schema.get("properties")
    if not isinstance(props, dict):
        return []
    return [
        (str(name), schema if isinstance(schema, dict) else {})
        for name, schema in props.items()
    ]


def _host_from_url(url: str) -> str:
    """Extract the host from a matched URL literal (strip scheme/port/path)."""
    rest = url.split("://", 1)[1] if "://" in url else url
    netloc = rest.split("/", 1)[0]
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    host = netloc.rsplit(":", 1)[0] if _has_port(netloc) else netloc
    return host.strip(".").lower()


def _has_port(netloc: str) -> bool:
    if ":" not in netloc:
        return False
    return netloc.rsplit(":", 1)[1].isdigit()


def _dedupe_add(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _net_context(tool: ToolIR, stripped: str) -> bool:
    """True when the tool carries any network signal.

    Used by the fs rules: an API-shaped tool's "path" param and "/..."
    literals are URL routes, so fs scope must never be auto-granted in a
    network context (fail closed to needs_review).
    """
    if _URL_RE.search(tool.description) or _NET_VERB_RE.search(stripped):
        return True
    for m in _HOSTNAME_RE.finditer(stripped):
        if m.group(1).lower().rsplit(".", 1)[-1] not in _FILE_EXTENSIONS:
            return True
    if any(_NET_PARAM_RE.search(pname) for pname, _ in _params(tool)):
        return True
    if _name_tokens(tool.name) & _NET_NAME_TOKENS:
        return True
    return False


# --- per-class rules --------------------------------------------------------


def _classify_net(tool: ToolIR) -> list[Capability]:
    hosts: list[str] = []          # unambiguous literals -> inferred-capable
    review_hosts: list[str] = []   # ambiguous bare literals -> review only
    host_evidence: list[Evidence] = []
    review_evidence: list[Evidence] = []

    for m in _URL_RE.finditer(tool.description):
        host = _host_from_url(m.group(0))
        if host:
            _dedupe_add(hosts, host)
            host_evidence.append(
                Evidence(tool.name, "description", f"URL literal {m.group(0)}")
            )

    # Scan for bare hostnames with URLs removed so URL hosts are not
    # double-counted and URL paths cannot masquerade as literals.
    stripped = _URL_RE.sub(" ", tool.description)
    for m in _HOSTNAME_RE.finditer(stripped):
        candidate = m.group(1).lower()
        label = candidate.rsplit(".", 1)[-1]
        if label in _FILE_EXTENSIONS:
            continue  # filename lookalike (config.yaml, main.py, ...)
        if label in _KNOWN_TLDS:
            _dedupe_add(hosts, candidate)
            host_evidence.append(
                Evidence(tool.name, "description", f"hostname literal {candidate}")
            )
        elif candidate not in hosts:
            # Ambiguous dotted literal (model.pt, data.parquet, os.path):
            # never granted from rules alone — a human must confirm.
            _dedupe_add(review_hosts, candidate)
            review_evidence.append(
                Evidence(
                    tool.name,
                    "description",
                    f"ambiguous hostname-like literal {candidate} "
                    "(unrecognized TLD, needs review)",
                )
            )

    # Scope-unknown signals: the endpoint is a caller-supplied runtime
    # value, so the class is implied but the scope is NOT known — even when
    # a host literal (e.g. an example URL) also appears (SPEC §4.4).
    param_evidence: list[Evidence] = []
    for pname, pschema in _params(tool):
        if _NET_PARAM_RE.search(pname):
            param_evidence.append(
                Evidence(
                    tool.name,
                    "param",
                    f"parameter '{pname}' suggests a network endpoint",
                )
            )
        elif str(pschema.get("format", "")).lower().startswith("uri"):
            param_evidence.append(
                Evidence(
                    tool.name,
                    "param",
                    f"parameter '{pname}' has JSON-Schema format "
                    f"'{pschema.get('format')}'",
                )
            )

    # Confirmation-only signals: imply the class, say nothing about scope.
    confirm_evidence: list[Evidence] = []
    verb = _NET_VERB_RE.search(stripped)
    if verb:
        confirm_evidence.append(
            Evidence(tool.name, "description", f"network verb '{verb.group(0)}'")
        )
    name_hits = _name_tokens(tool.name) & _NET_NAME_TOKENS
    if name_hits:
        confirm_evidence.append(
            Evidence(
                tool.name,
                "name",
                f"network verb '{sorted(name_hits)[0]}' in tool name",
            )
        )

    evidence = host_evidence + review_evidence + param_evidence + confirm_evidence
    if hosts and not param_evidence and not review_hosts:
        # Concrete, unambiguous host literals and no scope-unknown signal:
        # the verb/name signals just confirm the class.
        return [
            Capability(
                CapabilityId.NET_HTTP,
                CapabilityStatus.INFERRED,
                values=hosts,
                evidence=evidence,
            )
        ]
    if hosts or review_hosts or param_evidence or confirm_evidence:
        # Any scope-unknown or ambiguous signal clamps the whole cap to
        # needs_review; harvested literals are kept for the reviewer, and
        # "*" marks the runtime-value (param) scope.
        values = hosts + review_hosts
        if param_evidence or not values:
            values = values + ["*"]
        return [
            Capability(
                CapabilityId.NET_HTTP,
                CapabilityStatus.NEEDS_REVIEW,
                values=values,
                evidence=evidence,
            )
        ]
    return []


def _classify_fs(tool: ToolIR) -> list[Capability]:
    class_evidence: list[Evidence] = []
    for pname, _ in _params(tool):
        if _FS_PARAM_RE.search(pname):
            class_evidence.append(
                Evidence(
                    tool.name,
                    "param",
                    f"parameter '{pname}' suggests a filesystem path",
                )
            )
    tokens = _name_tokens(tool.name)
    name_hits = tokens & _FS_NAME_TOKENS
    if name_hits:
        class_evidence.append(
            Evidence(
                tool.name,
                "name",
                f"filesystem term '{sorted(name_hits)[0]}' in tool name",
            )
        )
    if not class_evidence:
        return []

    stripped = _URL_RE.sub(" ", tool.description)

    reads = False
    writes = False
    direction_evidence: dict[CapabilityId, list[Evidence]] = {
        CapabilityId.FS_READ: [],
        CapabilityId.FS_WRITE: [],
    }
    read_hits = tokens & _READ_VERBS
    if read_hits:
        reads = True
        direction_evidence[CapabilityId.FS_READ].append(
            Evidence(
                tool.name,
                "name",
                f"read verb '{sorted(read_hits)[0]}' in tool name",
            )
        )
    else:
        m = _READ_VERB_RE.search(stripped)
        if m:
            reads = True
            direction_evidence[CapabilityId.FS_READ].append(
                Evidence(tool.name, "description", f"read verb '{m.group(0)}'")
            )
    write_hits = tokens & _WRITE_VERBS
    if write_hits:
        writes = True
        direction_evidence[CapabilityId.FS_WRITE].append(
            Evidence(
                tool.name,
                "name",
                f"write verb '{sorted(write_hits)[0]}' in tool name",
            )
        )
    else:
        m = _WRITE_VERB_RE.search(stripped)
        if m:
            writes = True
            direction_evidence[CapabilityId.FS_WRITE].append(
                Evidence(tool.name, "description", f"write verb '{m.group(0)}'")
            )
    # move/copy write the destination but must read the source too.
    if (tokens & _MOVEISH_VERBS or _MOVEISH_RE.search(stripped)) and not reads:
        reads = True
        direction_evidence[CapabilityId.FS_READ].append(
            Evidence(tool.name, "description", "move/copy implies reading the source")
        )

    paths: list[str] = []
    path_evidence: list[Evidence] = []
    for m in _PATH_RE.finditer(stripped):
        candidate = m.group(1).rstrip(".")
        if not candidate or candidate in ("/", "./"):
            continue
        rest = stripped[m.end():]
        if rest.startswith("{") or rest.startswith("/{"):
            # Route template ("/repos/{owner}/...") — an API path, never a
            # mount prefix.
            continue
        _dedupe_add(paths, candidate)
        path_evidence.append(
            Evidence(tool.name, "description", f"path literal {candidate}")
        )

    direction_known = reads or writes
    ids: list[CapabilityId] = []
    if reads:
        ids.append(CapabilityId.FS_READ)
    if writes:
        ids.append(CapabilityId.FS_WRITE)
    if not ids:
        # Class implied but direction unknown: flag both, never grant.
        ids = [CapabilityId.FS_READ, CapabilityId.FS_WRITE]

    # inferred only with a concrete path AND a clear direction AND no
    # network context; a REST-wrapper tool's "path" param and "/..."
    # literals are URL routes, not filesystem paths, so any net signal
    # clamps fs to needs_review (values kept for the reviewer to confirm).
    status = (
        CapabilityStatus.INFERRED
        if paths and direction_known and not _net_context(tool, stripped)
        else CapabilityStatus.NEEDS_REVIEW
    )
    return [
        Capability(
            cap_id,
            status,
            values=list(paths),
            evidence=class_evidence + direction_evidence[cap_id] + path_evidence,
        )
        for cap_id in ids
    ]


def _classify_proc(tool: ToolIR) -> list[Capability]:
    evidence: list[Evidence] = []
    name_hits = _name_tokens(tool.name) & _PROC_NAME_TOKENS
    if name_hits:
        evidence.append(
            Evidence(
                tool.name,
                "name",
                f"exec term '{sorted(name_hits)[0]}' in tool name",
            )
        )
    m = _PROC_RE.search(tool.description)
    if m:
        evidence.append(
            Evidence(tool.name, "description", f"exec term '{m.group(0)}'")
        )
    if not evidence:
        return []
    # Red flag per spec §4.3: exec is never auto-inferred, a human approves.
    return [
        Capability(
            CapabilityId.PROC_EXEC,
            CapabilityStatus.NEEDS_REVIEW,
            values=[],
            evidence=evidence,
        )
    ]


def _classify_env(tool: ToolIR) -> list[Capability]:
    evidence: list[Evidence] = []
    values: list[str] = []
    m = _ENV_PHRASE_RE.search(tool.description)
    if m:
        evidence.append(
            Evidence(tool.name, "description", f"secret/credential term '{m.group(0)}'")
        )
    for var in _ENV_VAR_RE.findall(tool.description):
        _dedupe_add(values, var)
        evidence.append(
            Evidence(tool.name, "description", f"env-var-like identifier {var}")
        )
    if not evidence:
        return []
    return [
        Capability(
            CapabilityId.ENV,
            CapabilityStatus.NEEDS_REVIEW,
            values=values,
            evidence=evidence,
        )
    ]
