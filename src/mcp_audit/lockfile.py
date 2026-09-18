"""The approval lockfile: what this machine was last known to consent to.

Every other check in this tool is a point-in-time opinion about a config.
This one is different: it records what you approved, so a later scan can tell
you what *changed*. A server that passed review on Monday and quietly ships a
new tool description on Friday is the failure mode that point-in-time
scanning cannot see, because the Friday config is just as clean-looking as
the Monday one.

That is the whole reason this file exists, and it is why the lock stores the
fingerprint of everything the model reads -- name, description, and input
schema -- rather than a package version.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import (PromptSpec, ResourceSpec, ServerSpec, SkillSpec, ToolSpec,
                    instructions_fingerprint)

LOCK_VERSION = 1
DEFAULT_LOCK_NAME = ".mcp-audit.lock"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class Lock:
    version: int = LOCK_VERSION
    generated: str = field(default_factory=_now)
    servers: dict[str, Any] = field(default_factory=dict)
    skills: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None

    @property
    def is_empty(self) -> bool:
        return not self.servers and not self.skills

    # -- persistence -------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "Lock":
        if not path.is_file():
            return cls(path=path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"{path}: cannot read lockfile ({exc})") from None
        if not isinstance(data, dict):
            raise ValueError(f"{path}: lockfile is not an object")
        version = int(data.get("version", 0))
        if version > LOCK_VERSION:
            raise ValueError(
                f"{path}: lockfile version {version} is newer than this tool understands "
                f"(supports {LOCK_VERSION}); upgrade mcp-audit"
            )
        return cls(
            version=version or LOCK_VERSION,
            generated=str(data.get("generated") or _now()),
            servers=dict(data.get("servers") or {}),
            skills=dict(data.get("skills") or {}),
            path=path,
        )

    def save(self, path: Path | None = None) -> Path:
        target = path or self.path
        if target is None:
            raise ValueError("no lockfile path given")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": LOCK_VERSION,
            "generated": self.generated,
            "servers": self.servers,
            "skills": self.skills,
        }
        # Write-then-rename so an interrupted run cannot truncate the record
        # of what was previously approved.
        tmp = target.with_suffix(target.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(target)
        self.path = target
        return target

    # -- building ----------------------------------------------------------

    def record(self, servers: list[ServerSpec], tools: list[ToolSpec],
               skills: list[SkillSpec],
               prompts: list[PromptSpec] | None = None,
               resources: list[ResourceSpec] | None = None,
               instructions: dict[str, str] | None = None) -> None:
        """Replace the lock contents with the current observed state.

        Covers every surface a server controls that reaches the model, not
        just tools: `instructions` (which the spec allows a client to add to
        the system prompt), prompt templates, and resource descriptions. A
        lockfile that pinned only tools would let a server rewrite the agent's
        standing orders without tripping anything.
        """
        by_server: dict[str, list[ToolSpec]] = {}
        for t in tools:
            by_server.setdefault(t.server, []).append(t)
        prompts_by_server: dict[str, list[PromptSpec]] = {}
        for pr in prompts or []:
            prompts_by_server.setdefault(pr.server, []).append(pr)
        resources_by_server: dict[str, list[ResourceSpec]] = {}
        for rs in resources or []:
            resources_by_server.setdefault(rs.server, []).append(rs)
        instructions = instructions or {}

        # Argument policy is written by a person, not observed from a server,
        # so re-approving must not throw it away. Everything else in an entry
        # is a fact about what was seen and is rebuilt from scratch.
        kept_policies = {
            key: value["policy"]
            for key, value in self.servers.items()
            if isinstance(value, dict) and isinstance(value.get("policy"), dict)
        }

        self.servers = {}
        for s in servers:
            entry: dict[str, Any] = {
                "name": s.name,
                "client": s.client,
                "source": s.source,
                "transport": s.transport,
                "command_line": s.command_line,
                "url": s.url,
                "approved_at": _now(),
            }
            if s.name in instructions:
                text = instructions[s.name]
                entry["instructions"] = {
                    "fingerprint": instructions_fingerprint(text),
                    "preview": text[:160],
                    "length": len(text),
                }
            observed_prompts = prompts_by_server.get(s.name)
            if observed_prompts is not None:
                entry["prompts"] = {
                    pr.name: {"fingerprint": pr.fingerprint(),
                              "description_preview": (pr.description or "")[:160]}
                    for pr in sorted(observed_prompts, key=lambda x: x.name)
                }
            observed_resources = resources_by_server.get(s.name)
            if observed_resources is not None:
                entry["resources"] = {
                    rs.uri: {"fingerprint": rs.fingerprint(),
                             "description_preview": (rs.description or "")[:160]}
                    for rs in sorted(observed_resources, key=lambda x: x.uri)
                }
            carried = kept_policies.get(s.identity())
            if carried:
                entry["policy"] = carried
            observed = by_server.get(s.name)
            if observed is not None:
                entry["tools"] = {
                    t.name: {
                        "fingerprint": t.fingerprint(),
                        "description_preview": (t.description or "")[:160],
                    }
                    for t in sorted(observed, key=lambda t: t.name)
                }
            self.servers[s.identity()] = entry

        self.skills = {
            sk.path: {"name": sk.name, "fingerprint": sk.fingerprint(), "approved_at": _now()}
            for sk in skills
        }
        self.generated = _now()

    def merge_unprobed(self, previous: "Lock") -> None:
        """Carry forward tool fingerprints for servers we could not probe.

        Without this, running `--update` without `--probe` would silently
        discard the tool baseline and permanently blind the drift check.
        """
        for ident, entry in self.servers.items():
            old = previous.servers.get(ident)
            if not isinstance(old, dict):
                continue
            carried = False
            for key in ("tools", "prompts", "resources", "instructions"):
                if key not in entry and key in old:
                    entry[key] = old[key]
                    carried = True
            if carried:
                entry["approved_at"] = old.get("approved_at", entry["approved_at"])
                entry["carried_forward"] = True
