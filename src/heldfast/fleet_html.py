"""`fleet --html`: the organisation report as one page anyone can open.

One file, nothing fetched: no script, font, stylesheet or image from
anywhere. It is opened by the people a security team reports to, often from
an email attachment, and every name on it came from a config file on some
machine -- so it is built as if each of those names were hostile. Every
string goes through `html.escape`, and the page's Content-Security-Policy
allows no script at all, so a name that got past the escaping still could
not run. The tables are the data; the bars beside them only make the
largest numbers easy to find.
"""

from __future__ import annotations

from html import escape
from typing import Any

_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"

_STYLE = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;
--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);--accent:#2a78d6;
--track:#cde2fb;--good:#006300;--good-mark:#0ca30c;--warn:#fab219;--serious:#ec835a;
--critical:#d03b3b;--alarm-bg:#fbe9e9}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;
--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--grid:#2c2c2a;--axis:#383835;
--ring:rgba(255,255,255,.10);--accent:#3987e5;--track:#184f95;--good:#0ca30c;
--alarm-bg:#3a1717}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;
--ink2:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--accent:#3987e5;
--track:#184f95;--good:#0ca30c;--alarm-bg:#3a1717}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 48px}
header h1{font-size:24px;margin:0 0 4px;font-weight:650}
header p{margin:0;color:var(--ink2)}
h2{font-size:17px;margin:36px 0 10px;font-weight:650}
.sub{color:var(--ink2);font-size:13px;margin:-4px 0 12px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:22px}
.tile{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:14px 16px}
.tile .label{color:var(--ink2);font-size:13px}
.tile .value{font-size:30px;font-weight:600;margin-top:2px}
.tile .note{color:var(--muted);font-size:12px}
.meters{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
.meter{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:12px 16px}
.meter .row{display:flex;justify-content:space-between;gap:8px;font-size:14px}
.meter .row span:last-child{color:var(--ink2);font-variant-numeric:tabular-nums}
.track{height:8px;border-radius:4px;background:var(--track);margin-top:8px;overflow:hidden}
.fill{height:100%;background:var(--accent);border-radius:4px}
.meter .why{color:var(--muted);font-size:12px;margin-top:6px}
.alarm{background:var(--alarm-bg);border:1px solid var(--critical);border-radius:10px;
padding:14px 16px;margin-top:22px}
.alarm strong{color:var(--critical)}
.wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--ring);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;font-weight:600;color:var(--ink2);font-size:12px;padding:9px 12px;
border-bottom:1px solid var(--axis);white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid var(--grid);vertical-align:top}
tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.key{word-break:break-all;min-width:220px}
.bar{display:inline-block;height:8px;border-radius:0 4px 4px 0;background:var(--accent);
vertical-align:middle;margin-left:8px}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:600;
white-space:nowrap}
.badge i{font-style:normal;display:inline-grid;place-items:center;width:16px;height:16px;
border-radius:50%;color:#fff;font-size:11px}
.b-good i{background:var(--good-mark)}.b-warn i{background:var(--warn);color:#0b0b0b}
.b-serious i{background:var(--serious);color:#0b0b0b}.b-critical i{background:var(--critical)}
.b-none{color:var(--muted);font-weight:400}
.muted{color:var(--muted)}
ul.notes{color:var(--ink2);font-size:13px;padding-left:18px}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--grid);
padding-top:14px}
"""


def _e(value: Any) -> str:
    return escape(str(value), quote=True)


def _badge(level: str, text: str) -> str:
    icon = {"good": "&#10003;", "warn": "!", "serious": "!", "critical": "&#10005;"}.get(level)
    if icon is None:
        return f'<span class="badge b-none">{_e(text)}</span>'
    return f'<span class="badge b-{level}"><i aria-hidden="true">{icon}</i>{_e(text)}</span>'


def _tile(label: str, value: Any, note: str = "") -> str:
    return (f'<div class="tile"><div class="label">{_e(label)}</div>'
            f'<div class="value">{_e(value)}</div>'
            + (f'<div class="note">{_e(note)}</div>' if note else "") + "</div>")


def _meter(label: str, part: int, whole: int, why: str) -> str:
    width = 0 if not whole else round(100 * part / whole)
    return (f'<div class="meter"><div class="row"><span>{_e(label)}</span>'
            f'<span>{part} of {whole}</span></div>'
            f'<div class="track" role="img" aria-label="{_e(label)}: {part} of {whole}">'
            f'<div class="fill" style="width:{width}%"></div></div>'
            f'<div class="why">{_e(why)}</div></div>')


def _policy_badge(word: str) -> str:
    return {"denied": _badge("critical", "denied"), "unlisted": _badge("warn", "unlisted"),
            "allowed": _badge("good", "allowed")}.get(word, _badge("", "no policy"))


def _versions(entry: dict[str, Any]) -> str:
    items = sorted(entry["versions"].items(), key=lambda kv: (-kv[1], kv[0]))
    if not items:
        return '<span class="muted">-</span>'
    parts = [f"{_e(v)}" + (f' <span class="muted">&times;{n}</span>' if n > 1 else "")
             for v, n in items[:5]]
    more = f' <span class="muted">+{len(items) - 5} more</span>' if len(items) > 5 else ""
    return ", ".join(parts) + more


def _servers_table(report: dict[str, Any]) -> str:
    servers = report["servers"]
    widest = max((len(s["machines"]) for s in servers), default=1) or 1
    rows = []
    for s in servers:
        n = len(s["machines"])
        bar = f'<span class="bar" style="width:{max(2, round(90 * n / widest))}px"></span>'
        unapproved = s["installs"] - s["approved"]
        advisories = ""
        if s["malware"]:
            advisories = _badge("critical", "malware: " + ", ".join(s["malware"]))
        elif s["advisories"]:
            advisories = _badge("serious", f"{len(s['advisories'])} advisory")
        machines = ", ".join(s["machines"][:6]) + (" ..." if n > 6 else "")
        rows.append(
            f'<tr><td class="key" title="{_e(machines)}">{_e(s["key"])}</td>'
            f'<td>{_e(s["kind"])}</td><td class="num">{n}{bar}</td>'
            f'<td>{_versions(s)}</td>'
            f'<td class="num">{unapproved or ""}</td>'
            f'<td class="num">{s["installs"] - s["enforced"] or ""}</td>'
            f'<td>{_policy_badge(s["policy"])}</td><td>{advisories}</td></tr>')
    return ('<div class="wrap"><table><thead><tr><th>Server</th><th>Kind</th>'
            '<th>Machines</th><th>Versions in use</th><th>Unapproved</th>'
            '<th>Unchecked at call</th><th>Policy</th><th>Advisories</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def _machines_table(report: dict[str, Any]) -> str:
    rows = []
    for h in report["machines"]:
        if h["deny"]:
            verdict = _badge("critical", f"{h['deny']} violation(s)")
        elif h["warn"]:
            verdict = _badge("warn", f"{h['warn']} warning(s)")
        elif report.get("policy"):
            verdict = _badge("good", "meets policy")
        else:
            verdict = _badge("", "-")
        seen = _e(h["generated"]) + (" " + _badge("warn", "stale") if h["stale"] else "")
        rows.append(
            f'<tr><td class="key">{_e(h["label"])}</td><td>{seen}</td>'
            f'<td class="num">{h["servers"]}</td><td class="num">{h["unapproved"] or ""}</td>'
            f'<td class="num">{h["unenforced"] or ""}</td>'
            f'<td>{"yes" if h["plugin"] else ""}</td><td>{verdict}</td>'
            f'<td class="num">{h["unreadable"] or ""}</td></tr>')
    return ('<div class="wrap"><table><thead><tr><th>Machine or repository</th>'
            '<th>Inventory written</th><th>Servers</th><th>Unapproved</th>'
            '<th>Unchecked at call</th><th>Plugin</th><th>Policy</th>'
            '<th>Unreadable configs</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def _violations_table(report: dict[str, Any]) -> str:
    rows = []
    for v in sorted(report["violations"],
                    key=lambda v: (v["level"] != "deny", v["machine"], v["server"])):
        level = _badge("critical", "deny") if v["level"] == "deny" else _badge("warn", "warn")
        rows.append(f'<tr><td>{level}</td><td>{_e(v["machine"])}</td>'
                    f'<td class="key">{_e(v["server"])}</td><td>{_e(v["code"])}</td>'
                    f'<td>{_e(v["message"])}</td></tr>')
    return ('<div class="wrap"><table><thead><tr><th>Level</th><th>Machine</th>'
            '<th>Server</th><th>Rule</th><th>Why</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def _alarms(report: dict[str, Any]) -> str:
    out = []
    for a in report["alarms"]:
        out.append(f'<div class="alarm" role="alert"><strong>&#10005; Malware in use: '
                   f'{_e(a["release"])}</strong> ({_e(", ".join(a["ids"]))}) runs on '
                   f'{len(a["machines"])} machine(s): {_e(", ".join(a["machines"]))}. '
                   f'Remove it there, and rotate every credential those machines '
                   f'could reach.</div>')
    return "".join(out)


def _summary(report: dict[str, Any]) -> str:
    t = report["totals"]
    policy = report.get("policy")
    violations = (_tile("Policy violations", t["deny"],
                        f"on {t['machines_failing']} machine(s); {t['warn']} warning(s)")
                  if policy else _tile("Policy", "none", "pass --policy to check one"))
    malware = {
        "asked": _tile("Running malware", t["malware"], "machine(s), per OSV"),
        "failed": _tile("Advisories", "unknown", "OSV could not be asked; see the notes"),
    }.get(report["advisories"], _tile("Advisories", "not asked", "--advisories asks OSV"))
    return ('<section class="tiles">'
            + _tile("Machines and repositories", t["machines"],
                    f"{t['stale']} stale" if t["stale"] else "all reporting")
            + _tile("Distinct MCP servers", t["servers"], f"{t['installs']} installs")
            + violations + malware
            + _tile("Unreadable configs", t["unreadable"], "blind spots, not passes")
            + "</section>")


def _posture(report: dict[str, Any]) -> str:
    t = report["totals"]
    return ('<h2>Posture</h2><p class="sub">Counts of installs, not a score: the gaps '
            'are not equal, and each row below names its own.</p><section class="meters">'
            + _meter("Approved in a lockfile", t["approved"], t["installs"],
                     "someone reviewed it and committed what they saw")
            + _meter("Tool definitions pinned", t["pinned"], t["installs"],
                     "approved with what it says recorded, so a change can be refused")
            + _meter("Checked at call time", t["enforced"], t["installs"],
                     "behind wrap, the gateway, or the Claude Code plugin")
            + _meter("Exact package versions", t["exact"], t["packages"],
                     "the rest run whatever was published last")
            + "</section>")


def render_html(report: dict[str, Any]) -> str:
    policy = report.get("policy") or {}
    title = policy.get("name") or "MCP fleet"
    subtitle = f"{report['totals']['machines']} machine(s) and repositories, " \
               f"report written {report['generated']}"
    if policy.get("sha256"):
        subtitle += f" against policy sha256:{policy['sha256'][:12]}"
    violations = (f'<h2>Policy violations</h2>{_violations_table(report)}'
                  if report["violations"] else "")
    notes = ("<h2>Notes</h2><ul class=\"notes\">"
             + "".join(f"<li>{_e(n)}</li>" for n in report["notes"]) + "</ul>"
             if report["notes"] else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<meta name="referrer" content="no-referrer">
<title>{_e(title)} - heldfast fleet</title><style>{_STYLE}</style></head>
<body><main>
<header><h1>{_e(title)}</h1><p>{_e(subtitle)}</p></header>
{_alarms(report)}{_summary(report)}{_posture(report)}
<h2>Servers, by how many machines run them</h2>
<p class="sub">One row per package, hosted address or local command, joined across every inventory.</p>
{_servers_table(report)}
{violations}
<h2>Machines and repositories</h2>{_machines_table(report)}
{notes}
<footer>Written by heldfast fleet from {report['totals']['machines']} inventory file(s).
Each inventory is what a machine said about itself; no tool definitions were read on
any of them, so a tool rewritten under an approved name does not show here &mdash;
that is what <code>wrap</code>, <code>gateway</code> and <code>verify</code> are for.</footer>
</main></body></html>
"""
