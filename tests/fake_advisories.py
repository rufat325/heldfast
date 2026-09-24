"""OSV and the npm registry, as `heldfast.advisories` sees them, without a network.

Every version asked about exists, was published long ago, runs no install
script and has no advisory, unless a test says otherwise.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator
from unittest import mock

from heldfast import advisories

LONG_AGO = "2020-01-01T00:00:00.000Z"


class FakeEcosystem:
    def __init__(self) -> None:
        self.advisories: dict[tuple[str, str], list[str]] = {}
        self.published: dict[tuple[str, str], str] = {}
        self.hooks: dict[tuple[str, str], dict[str, str]] = {}
        self.pulled: set[tuple[str, str]] = set()
        self.seen: dict[str, set[str]] = {}
        self.down = False
        self.queries: list[Any] = []

    def post(self, url: str, body: Any) -> Any:
        if self.down:
            raise advisories.AdvisoryError("api.osv.dev: unreachable")
        self.queries.append(body)
        results = []
        for q in body["queries"]:
            name, version = q["package"]["name"], q["version"]
            self.seen.setdefault(name, set()).add(version)
            ids = self.advisories.get((name, version), [])
            results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
        return {"results": results}

    def get(self, url: str) -> Any:
        if self.down:
            raise advisories.AdvisoryError("registry.npmjs.org: unreachable")
        name = url[len(advisories.NPM_URL):].replace("%2F", "/")
        versions = self.seen.get(name, set()) | {v for (n, v) in self.published if n == name}
        doc: dict[str, Any] = {"name": name, "time": {}, "versions": {}}
        for v in versions:
            doc["time"][v] = self.published.get((name, v), LONG_AGO)
            if (name, v) not in self.pulled:
                doc["versions"][v] = {"name": name, "version": v,
                                      "scripts": dict(self.hooks.get((name, v), {}))}
        return doc

    @contextmanager
    def active(self) -> Iterator["FakeEcosystem"]:
        with mock.patch.object(advisories, "post_json", self.post), \
                mock.patch.object(advisories, "get_json", self.get):
            yield self
