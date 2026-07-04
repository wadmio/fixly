"""Build the labeled name corpus.

Positives: malicious npm package names from OSV's `MAL-*` advisories.
Negatives: popular real npm package names.

Uses the public OSV export and npm registry APIs. If the network is
unavailable, falls back to a small bundled seed so the pipeline still runs
end-to-end (clearly labeled — never silently pretends to have real data).
"""

from __future__ import annotations

import io
import json
import urllib.request
import zipfile
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
OSV_NPM_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search?text={q}&size=250&from={offset}"

# The npm search API rejects an empty text query, so we page real popular
# packages through a spread of common keywords (ranked by popularity). This
# yields a broad, genuinely-popular benign set without a hardcoded list.
_BENIGN_QUERIES = [
    "react", "vue", "server", "test", "cli", "build", "type", "css",
    "http", "util", "data", "file", "async", "parser", "config", "log",
    "date", "auth", "api", "stream", "database", "queue", "format", "ui",
    "component", "hook", "plugin", "loader", "router", "state", "form",
    "validation", "crypto", "hash", "json", "yaml", "markdown", "template",
    "image", "video", "pdf", "excel", "email", "sms", "webhook", "graphql",
    "websocket", "cache", "session", "cookie", "jwt", "oauth", "storage",
    "aws", "google", "azure", "docker", "kubernetes", "cli-tool", "eslint",
]

# Bundled fallback seeds — tiny, only used when offline. Real runs pull
# thousands of names from the sources above.
_SEED_MALICIOUS = [
    "lodahs", "loadsh", "crossenv", "cross-env.js", "d3.js", "fabric-js",
    "ffmepg", "gruntcli", "http-proxy.js", "jquery.js", "mariadb", "mongose",
    "mssql.js", "mssql-node", "mysqljs", "nodefabric", "node-fabric",
    "nodemailer-js", "nodemssql", "noderequest", "nodesqlite", "opencv.js",
    "openssl.js", "proxy.js", "shadowsocks", "smb", "sqlite.js", "sqliter",
    "sqlserver", "tensorflow", "node-tensorflow", "webscoket", "discordi.js",
]
_SEED_BENIGN = [
    "lodash", "react", "express", "axios", "chalk", "commander", "debug",
    "cross-env", "d3", "fabric", "jquery", "mongoose", "mysql", "sqlite3",
    "nodemailer", "opencv4nodejs", "webpack", "vite", "typescript", "eslint",
    "prettier", "vitest", "jest", "zod", "dayjs", "uuid", "dotenv", "cors",
    "next", "vue", "svelte", "tailwindcss", "postcss", "rimraf", "glob",
]


_UA = {"User-Agent": "fixly-ml/0.1 (+https://github.com/wadmio/fixly)"}


def _get(url: str, timeout: int) -> bytes:
    # A User-Agent is required — the GCS/registry endpoints 400 without one.
    return urllib.request.urlopen(
        urllib.request.Request(url, headers=_UA), timeout=timeout
    ).read()


def _download_osv_malicious(limit: int | None) -> list[str]:
    blob = _get(OSV_NPM_ZIP, timeout=120)
    names: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for entry in zf.namelist():
            if not entry.startswith("MAL-"):
                continue
            try:
                rec = json.loads(zf.read(entry))
            except json.JSONDecodeError:
                continue
            for affected in rec.get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("ecosystem", "").lower().startswith("npm") and pkg.get("name"):
                    names.add(pkg["name"])
            if limit and len(names) >= limit:
                break
    return sorted(names)


def _download_popular(target: int) -> list[str]:
    names: set[str] = set()
    per_query = max(250, target // len(_BENIGN_QUERIES) + 250)
    for q in _BENIGN_QUERIES:
        if len(names) >= target:
            break
        offset = 0
        while offset < per_query:
            url = NPM_SEARCH.format(q=q, offset=offset)
            data = json.loads(_get(url, timeout=30))
            objs = data.get("objects", [])
            if not objs:
                break
            for obj in objs:
                name = obj.get("package", {}).get("name")
                if name:
                    names.add(name)
            offset += len(objs)
    return sorted(names)


def build(limit_malicious: int | None = None, target_benign: int = 2000) -> dict:
    """Return {'malicious': [...], 'benign': [...], 'source': 'network'|'seed'}."""
    DATA_DIR.mkdir(exist_ok=True)
    try:
        malicious = _download_osv_malicious(limit_malicious)
        benign = _download_popular(target_benign)
        if malicious and benign:
            source = "network"
        else:
            raise RuntimeError("empty download")
    except Exception as err:  # noqa: BLE001 — offline fallback is intentional
        print(f"[dataset] network unavailable ({err}); using bundled seed corpus.")
        malicious, benign, source = _SEED_MALICIOUS, _SEED_BENIGN, "seed"

    # A name can't be both; benign wins ties (popular + real beats a stale MAL).
    benign_set = set(benign)
    malicious = [m for m in malicious if m not in benign_set]

    corpus = {"malicious": malicious, "benign": benign, "source": source}
    out = DATA_DIR / "name-corpus.json"
    out.write_text(json.dumps(corpus, indent=2))
    print(
        f"[dataset] {len(malicious)} malicious + {len(benign)} benign names "
        f"({source}) -> {out}"
    )
    return corpus


if __name__ == "__main__":
    build()
