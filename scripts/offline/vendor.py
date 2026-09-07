#!/usr/bin/env python3
"""Offline ("air-gapped") crate vendoring tool.

This project's dependencies are declared normally against crates.io.  In
environments where ``static.crates.io`` / ``index.crates.io`` are unreachable but
GitHub is reachable, this tool reconstructs an equivalent vendor directory:

* registry *metadata* is read from the official crates.io index, which is itself
  a git repository hosted on GitHub (``rust-lang/crates.io-index``).  Only the
  index entries that are actually needed are materialised, using a treeless
  partial clone plus a sparse checkout.
* registry *sources* are reconstructed from the upstream source repository of
  each crate, fetched from GitHub at the release tag that corresponds to the
  published version.  The manifest is normalised the same way ``cargo package``
  normalises it (workspace inheritance is inlined, ``path`` overrides are
  dropped, workspace/patch tables are removed) so the result is byte-equivalent
  in meaning to the published crate.

The output layout is the one understood by cargo's ``directory`` source
replacement: ``vendor/<crate>-<version>/{,.cargo-checksum.json}``.

Usage:
    vendor.py info <crate>                  # show known versions
    vendor.py fetch <crate> <version>       # vendor one crate
    vendor.py sync [--manifest-path P]      # resolve + vendor until `cargo metadata` succeeds
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDOR_DIR = Path(os.environ.get("VENDOR_DIR", REPO_ROOT / "vendor"))
CACHE_DIR = Path(os.environ.get("VENDOR_CACHE", Path.home() / ".cache" / "rdt-vendor"))
INDEX_DIR = Path(os.environ.get("VENDOR_INDEX", Path.home() / ".cache" / "crates-io-index"))
REPO_MAP_FILE = Path(__file__).resolve().with_name("repo-map.json")
SRC_URL = "https://codeload.github.com"
INDEX_REMOTE = "https://github.com/rust-lang/crates.io-index"

MAX_ITERATIONS = int(os.environ.get("VENDOR_MAX_ITERATIONS", "600"))


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def run(cmd, cwd=None, check=True, capture=True, timeout=600):
    """Run a command, returning CompletedProcess. Raises on non-zero exit."""
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            "command failed (%d): %s\n%s" % (proc.returncode, " ".join(map(str, cmd)), (proc.stderr or "")[-4000:])
        )
    return proc


def log(msg):
    print("[vendor] %s" % msg, flush=True)


def http_get(url, timeout=120, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "rdt-offline-vendor"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def gh_api(path, timeout=60):
    """Call the GitHub REST API (uses $GH_TOKEN when present)."""
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "rdt-offline-vendor"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer %s" % token
    return json.loads(http_get("https://api.github.com%s" % path, timeout=timeout, headers=headers))


# --------------------------------------------------------------------------- #
# semver
# --------------------------------------------------------------------------- #
_VER_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+](.*))?$")


class Version:
    __slots__ = ("major", "minor", "patch", "pre", "raw")

    def __init__(self, raw):
        self.raw = raw
        m = _VER_RE.match(raw.strip())
        if not m:
            raise ValueError("bad version %r" % raw)
        self.major = int(m.group(1))
        self.minor = int(m.group(2) or 0)
        self.patch = int(m.group(3) or 0)
        pre = (m.group(4) or "").split("+")[0]
        self.pre = tuple(_pre_key(p) for p in pre.split(".")) if pre else ()

    @property
    def is_prerelease(self):
        return bool(self.pre)

    def key(self):
        return (self.major, self.minor, self.patch, 0 if self.pre else 1, self.pre)

    def __lt__(self, other):
        return self.key() < other.key()

    def __le__(self, other):
        return self.key() <= other.key()

    def __eq__(self, other):
        return self.key() == other.key()

    def __hash__(self):
        return hash(self.key())

    def __repr__(self):
        return "Version(%s)" % self.raw


def _pre_key(part):
    return (1, int(part)) if part.isdigit() else (0, part)


def _comparator_matches(op, base, ver):
    """base is a Version (possibly partial, i.e. minor/patch defaulted)."""
    if op in ("", "^"):
        if base.major != 0:
            lo, hi = base, Version("%d.0.0" % (base.major + 1))
        elif base.raw.count(".") == 0:  # ^0  -> <1.0.0
            lo, hi = Version("0.0.0"), Version("1.0.0")
        elif base.minor != 0:
            lo, hi = base, Version("0.%d.0" % (base.minor + 1))
        elif base.raw.count(".") < 2:  # ^0.0 -> <0.1.0
            lo, hi = Version("0.0.0"), Version("0.1.0")
        else:
            lo, hi = base, Version("0.0.%d" % (base.patch + 1))
        return lo <= ver < hi
    if op == "~":
        if base.raw.count(".") >= 2:
            return base <= ver < Version("%d.%d.0" % (base.major, base.minor + 1))
        if base.raw.count(".") == 1:
            return base <= ver < Version("%d.%d.0" % (base.major, base.minor + 1))
        return base <= ver < Version("%d.0.0" % (base.major + 1))
    if op == "=":
        return ver == base
    if op == ">":
        return ver > base
    if op == ">=":
        return ver >= base
    if op == "<":
        return ver < base
    if op == "<=":
        return ver <= base
    raise ValueError("unknown op %r" % op)


def req_matches(req, version):
    """Cargo requirement matching. ``req`` e.g. '^1.2', '~0.4.1', '>=1, <2', '*', '1.*'."""
    ver = version if isinstance(version, Version) else Version(version)
    req = (req or "").strip()
    if req in ("", "*", "x"):
        return True
    for comp in req.split(","):
        comp = comp.strip()
        if not comp:
            continue
        if "*" in comp or comp.endswith(".x") or comp.endswith(".X"):
            m = re.match(r"^(\d+)(?:\.(\d+))?", comp.replace(".x", "").replace(".X", "").replace(".*", ""))
            if not m:
                return True
            if m.group(2) is None:
                if ver.major != int(m.group(1)):
                    return False
            elif ver.major != int(m.group(1)) or ver.minor != int(m.group(2)):
                return False
            continue
        m = re.match(r"^(>=|<=|==|=|\^|~|>|<)?\s*(.+)$", comp)
        op, base = m.group(1) or "", m.group(2).strip()
        if op == "==":
            op = "="
        if not _comparator_matches(op, Version(base), ver):
            return False
    if ver.is_prerelease:
        # cargo only selects pre-releases when a comparator explicitly mentions one
        return any(Version(c.strip()).is_prerelease for c in req.split(",") if re.match(r"^\d", c.strip()))
    return True


def req_allows_prerelease(req):
    return any(
        re.match(r"^\d", c.strip()) and Version(re.sub(r"^(>=|<=|=|\^|~|>|<)", "", c.strip())).is_prerelease
        for c in (req or "").split(",")
        if c.strip()
    )


# --------------------------------------------------------------------------- #
# crates.io index (read from the GitHub mirror, materialised sparsely)
# --------------------------------------------------------------------------- #
def index_path(crate):
    """Layout used by the crates.io index: 1/x, 2/xy, 3/x/xyz, xx/yz/xyzw..."""
    n = len(crate)
    if n == 1:
        return "1/%s" % crate
    if n == 2:
        return "2/%s" % crate
    if n == 3:
        return "3/%s/%s" % (crate[0], crate)
    return "%s/%s/%s" % (crate[0:2], crate[2:4], crate)


def ensure_index_repo():
    if not (INDEX_DIR / ".git").exists():
        INDEX_DIR.parent.mkdir(parents=True, exist_ok=True)
        if INDEX_DIR.exists():
            shutil.rmtree(INDEX_DIR)
        log("cloning crates.io index metadata (treeless partial clone) ...")
        run(
            ["git", "clone", "--filter=tree:0", "--no-checkout", "--single-branch", "--branch", "master", INDEX_REMOTE,
             str(INDEX_DIR)],
            timeout=900,
        )
        sparse = INDEX_DIR / ".git" / "info" / "sparse-checkout"
        sparse.parent.mkdir(parents=True, exist_ok=True)
        sparse.write_text("/*\n!/*/\n")
        run(["git", "config", "core.sparseCheckout", "true"], cwd=INDEX_DIR)
        run(["git", "config", "core.sparseCheckoutCone", "false"], cwd=INDEX_DIR)
        run(["git", "checkout", "-f", "master"], cwd=INDEX_DIR)


def _index_add_path(rel):
    """Add ``rel`` to the sparse-checkout patterns and materialise it."""
    sparse = INDEX_DIR / ".git" / "info" / "sparse-checkout"
    patterns = sparse.read_text().splitlines() if sparse.exists() else ["/*", "!/*/"]
    entry = "/%s" % rel
    if entry not in patterns:
        patterns.append(entry)
        sparse.write_text("\n".join(patterns) + "\n")
    run(["git", "read-tree", "-mu", "HEAD"], cwd=INDEX_DIR, check=False)
    if not (INDEX_DIR / rel).exists():
        run(["git", "checkout", "-f", "master"], cwd=INDEX_DIR, check=False)


def index_entry(crate, allow_fetch=True):
    """Return the list of index records (one per published version) for a crate."""
    cache = CACHE_DIR / "index" / ("%s.json" % crate)
    if cache.exists():
        try:
            return json.loads(cache.read_text())
        except json.JSONDecodeError:
            cache.unlink()
    if not allow_fetch:
        return None
    ensure_index_repo()
    rel = index_path(crate)
    local = INDEX_DIR / rel
    if not local.exists():
        _index_add_path(rel)
    if not local.exists():
        return None
    records = [json.loads(line) for line in local.read_text().splitlines() if line.strip()]
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(records))
    return records


def available_versions(crate):
    records = index_entry(crate) or []
    return sorted(
        (Version(r["vers"]) for r in records if not r.get("yanked")),
        key=lambda v: v.key(),
    )


def pick_version(crate, reqs):
    """Highest version satisfying every requirement in ``reqs`` (list of req strings)."""
    reqs = [r for r in reqs if r]
    want_pre = any(req_allows_prerelease(r) for r in reqs)
    best = None
    for v in available_versions(crate):
        if v.is_prerelease and not want_pre:
            continue
        if all(req_matches(r, v) for r in reqs):
            best = v
    return best


# --------------------------------------------------------------------------- #
# upstream source discovery
# --------------------------------------------------------------------------- #
def repo_map():
    if REPO_MAP_FILE.exists():
        return json.loads(REPO_MAP_FILE.read_text())
    return {}


def save_repo_map(mapping):
    REPO_MAP_FILE.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n")


def discover_repo(crate, version=None):
    """Guess the upstream GitHub repository for a crate (cached and verified)."""
    mapping = repo_map()
    if crate in mapping:
        return mapping[crate]
    guesses = ["%s/%s" % (crate, crate), "%s-rs/%s" % (crate, crate), "rust-lang/%s" % crate]
    for query in ("%s+in:name", "%s+rust+in:name,description"):
        try:
            results = gh_api(
                "/search/repositories?q=%s&sort=stars&per_page=8" % (query % urllib.parse.quote(crate))
            )
            for item in results.get("items", []):
                guesses.append(item["full_name"])
        except Exception as exc:  # pragma: no cover - network dependent
            log("repo search failed for %s: %s" % (crate, exc))
    for guess in guesses:
        try:
            run(["git", "ls-remote", "--tags", "https://github.com/%s" % guess], timeout=120)
        except Exception:
            continue
        if version is not None and pick_tag(guess, crate, version) is None:
            log("repo %s has no tag for %s %s; trying the next candidate" % (guess, crate, version))
            continue
        mapping = repo_map()
        mapping[crate] = guess
        save_repo_map(mapping)
        log("discovered repo for %s: %s" % (crate, guess))
        return guess
    raise RuntimeError("could not locate an upstream repository for crate %r" % crate)


def tags_for(repo):
    cache = CACHE_DIR / "tags" / (repo.replace("/", "__") + ".json")
    if cache.exists():
        return json.loads(cache.read_text())
    out = run(["git", "ls-remote", "--tags", "https://github.com/%s" % repo], timeout=300).stdout
    tags = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[1].startswith("refs/tags/"):
            tag = parts[1][len("refs/tags/"):]
            if not tag.endswith("^{}"):
                tags.append(tag)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(tags))
    return tags


def _tag_version(tag, crate):
    """Extract a semver from a release tag name, if there is one."""
    text = tag
    for prefix in ("%s-" % crate, "%s/" % crate, "%s_" % crate, "release-", "release/", "v"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    m = re.match(r"^v?(\d+\.\d+\.\d+(?:[-+].*)?)$", text)
    if not m:
        return None
    try:
        return Version(m.group(1))
    except ValueError:
        return None


def default_branch_ref(repo):
    """``heads/<default branch>`` for repositories that publish no release tags."""
    cache = CACHE_DIR / "tags" / (repo.replace("/", "__") + ".branch")
    if cache.exists():
        return cache.read_text().strip() or None
    try:
        info = gh_api("/repos/%s" % repo)
        branch = info.get("default_branch")
    except Exception:
        branch = None
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("heads/%s" % branch if branch else "")
    return "heads/%s" % branch if branch else None


def pick_tag(repo, crate, version):
    tags = tags_for(repo)
    by_name = {t: True for t in tags}
    exact = [
        "v%s" % version,
        version,
        "%s-v%s" % (crate, version),
        "%s-%s" % (crate, version),
        "%s/v%s" % (crate, version),
        "%s-v.%s" % (crate, version),
        "release-%s" % version,
        "release/%s" % version,
        "v%s-release" % version,
        "%s_v%s" % (crate, version),
    ]
    for cand in exact:
        if cand in by_name:
            return cand
    norm = lambda s: s.lstrip("v").replace("%s-" % crate, "").replace("%s/" % crate, "")
    for tag in tags:
        if norm(tag) == version:
            return tag
    # Monorepos sometimes tag only the base release of a series (for example
    # `0.61.0` covering the published `windows-sys 0.61.2`).  Fall back to the
    # highest tag in the same major.minor series that is not newer than the
    # requested version, and record the substitution in the vendor metadata.
    try:
        target = Version(version)
    except ValueError:
        return None
    best = None
    for tag in tags:
        candidate = _tag_version(tag, crate)
        if candidate is None or candidate > target:
            continue
        if (candidate.major, candidate.minor) != (target.major, target.minor):
            continue
        if best is None or candidate > best[0]:
            best = (candidate, tag)
    if best is not None:
        log("no tag for %s %s in %s; using nearest release tag %s" % (crate, version, repo, best[1]))
        return best[1]
    if not tags:
        branch = default_branch_ref(repo)
        if branch:
            log("no release tags in %s; vendoring %s from %s" % (repo, crate, branch))
            return branch
    return None


def find_in_cache(crate, version):
    """Search previously downloaded source trees for a crate (monorepo aware).

    Monorepo tarballs contain many crates, so a source tree fetched for one
    crate usually satisfies several others.  This is what makes an offline
    rebuild possible when the registry mirrors are unreachable.
    """
    src_root = CACHE_DIR / "src"
    if not src_root.exists():
        return None
    best = None
    for tree in sorted(src_root.iterdir()):
        if not tree.is_dir():
            continue
        candidate = _match_crate_dir(tree, crate, version)
        if candidate is None:
            continue
        score, path = candidate
        if best is None or score < best[0]:
            best = (score, path)
    return best[1] if best else None


def _match_crate_dir(root, crate, version):
    for toml_path in root.rglob("Cargo.toml"):
        if any(part in (".git", "target", "vendor", "tests", "benches", "examples") for part in toml_path.parts):
            continue
        try:
            data = tomllib.loads(toml_path.read_text())
        except Exception:
            continue
        pkg = data.get("package") or {}
        if pkg.get("name") != crate:
            continue
        ver = pkg.get("version")
        depth = len(toml_path.relative_to(root).parts)
        if ver is None:
            ws = workspace_root_for(toml_path)
            if ws is not None:
                try:
                    ver = ((tomllib.loads(ws.read_text()).get("workspace") or {}).get("package") or {}).get("version")
                except Exception:
                    ver = None
        return (0 if ver == version else 1, depth), toml_path.parent
    return None


def fetch_source(repo, tag):
    """Download and extract a release tarball; returns the extracted root dir."""
    stamp = "%s__%s" % (repo.replace("/", "__"), tag.replace("/", "_"))
    dest = CACHE_DIR / "src" / stamp
    if dest.exists() and any(dest.iterdir()):
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    ref = tag if tag.startswith(("tags/", "heads/")) else "tags/%s" % tag
    url = "%s/%s/tar.gz/refs/%s" % (SRC_URL, repo, urllib.parse.quote(ref, safe="/"))
    tarball = CACHE_DIR / "src" / (stamp + ".tar.gz")
    tarball.parent.mkdir(parents=True, exist_ok=True)
    if not tarball.exists():
        log("downloading %s" % url)
        data = http_get(url, timeout=600)
        tarball.write_bytes(data)
    tmp = Path(str(dest) + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    with tarfile.open(tarball, "r:gz") as tf:
        try:
            tf.extractall(tmp, filter="data")  # py3.12+: reject unsafe members
        except TypeError:  # pragma: no cover - py3.11 and older
            tf.extractall(tmp)
    entries = [p for p in tmp.iterdir() if p.is_dir()]
    root = entries[0] if len(entries) == 1 and not list(tmp.glob("*.*")) else tmp
    if dest.exists():
        shutil.rmtree(dest)
    shutil.move(str(root), str(dest))
    shutil.rmtree(tmp, ignore_errors=True)
    return dest


def find_crate_dir(root, crate, version):
    """Locate the directory of ``crate`` inside an extracted source tree."""
    candidates = []
    for toml_path in root.rglob("Cargo.toml"):
        if any(part in (".git", "target", "vendor", "tests", "benches", "examples") for part in toml_path.parts):
            continue
        try:
            data = tomllib.loads(toml_path.read_text())
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            continue
        pkg = data.get("package") or {}
        if pkg.get("name") != crate:
            continue
        ver = pkg.get("version")
        depth = len(toml_path.relative_to(root).parts)
        if ver is None:  # workspace-inherited: resolve against the workspace root
            ws = workspace_root_for(toml_path)
            if ws is not None:
                try:
                    wsdata = tomllib.loads(ws.read_text())
                    ver = (wsdata.get("workspace") or {}).get("package", {}).get("version")
                except Exception:
                    ver = None
        score = (0 if ver == version else 1, depth)
        candidates.append((score, toml_path.parent))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0])
    return candidates[0][1]


def workspace_root_for(crate_toml):
    """Nearest ancestor Cargo.toml declaring a [workspace] table."""
    for parent in crate_toml.parent.parents:
        cand = parent / "Cargo.toml"
        if cand.exists():
            try:
                data = tomllib.loads(cand.read_text())
            except Exception:
                continue
            if "workspace" in data:
                return cand
            if "package" in data:
                # keep walking up: workspaces may be virtual and higher up
                continue
    return None


# --------------------------------------------------------------------------- #
# manifest normalisation (mirrors what `cargo package` does)
# --------------------------------------------------------------------------- #
def flatten_manifest(crate_dir, crate, version):
    """Inline workspace inheritance and drop path/workspace/patch tables."""
    toml_path = crate_dir / "Cargo.toml"
    data = tomllib.loads(toml_path.read_text())
    ws_toml = workspace_root_for(toml_path)
    ws_pkg, ws_deps = {}, {}
    if ws_toml is not None and ws_toml != toml_path:
        try:
            wsdata = tomllib.loads(ws_toml.read_text())
            ws_pkg = (wsdata.get("workspace") or {}).get("package", {}) or {}
            ws_deps = (wsdata.get("workspace") or {}).get("dependencies", {}) or {}
        except Exception:
            pass

    pkg = data.setdefault("package", {})
    for key, value in list(pkg.items()):
        if isinstance(value, dict) and value.get("workspace") is True:
            if key in ws_pkg:
                pkg[key] = ws_pkg[key]
            else:
                del pkg[key]
    pkg.setdefault("name", crate)
    if "version" not in pkg:
        pkg["version"] = version

    data.pop("workspace", None)
    data.pop("patch", None)

    def strip(section):
        if not isinstance(section, dict):
            return
        for name, spec in list(section.items()):
            if isinstance(spec, dict) and spec.get("workspace") is True:
                base = ws_deps.get(name)
                if base is None:
                    del section[name]
                    continue
                # `workspace = true` may be combined with the local overrides
                # cargo permits next to it; merge them into the inherited entry.
                spec = {"version": base} if not isinstance(base, dict) else dict(base)
                for key in ("optional", "features", "default-features"):
                    if key in section[name]:
                        spec[key] = section[name][key]
            if isinstance(spec, dict):
                spec = dict(spec)
                spec.pop("path", None)
                if "version" not in spec:
                    # path-only dependency: never published, safe to drop
                    del section[name]
                    continue
            section[name] = spec

    for key in ("dependencies", "build-dependencies", "dev-dependencies"):
        strip(data.get(key))
    for cfg_tables in (data.get("target") or {}).values():
        if not isinstance(cfg_tables, dict):
            continue
        for key in ("dependencies", "build-dependencies", "dev-dependencies"):
            strip(cfg_tables.get(key))
    return data


# --------------------------------------------------------------------------- #
# minimal TOML writer (sufficient for Cargo manifests)
# --------------------------------------------------------------------------- #
_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _qkey(key):
    return key if _BARE_KEY.match(key) else "'%s'" % key.replace("'", "\\'")


def _val(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        if all(isinstance(v, (str, int, float, bool)) for v in value):
            return "[%s]" % ", ".join(_val(v) for v in value)
        return "[%s]" % ", ".join(_val(v) for v in value)
    if isinstance(value, dict):
        return "{ %s }" % ", ".join("%s = %s" % (_qkey(k), _val(v)) for k, v in value.items())
    raise TypeError("unsupported TOML value %r" % (value,))


def dump_toml(data, prefix=""):
    """Serialise a parsed Cargo manifest back to TOML.

    Handles the subset of TOML used by cargo manifests: scalars, arrays, inline
    tables, ``[a.b.c]`` tables and ``[[a]]`` arrays of tables.
    """
    out = []
    tables = []
    arrays = []
    for key, value in data.items():
        full = "%s%s" % (prefix, _qkey(key))
        if isinstance(value, dict):
            tables.append((full, key, value))
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            arrays.append((full, value))
        else:
            out.append("%s = %s" % (_qkey(key), _val(value)))
    for full, key, value in tables:
        out.append("\n[%s]" % full)
        out.append(dump_toml(value, full + "."))
    for full, items in arrays:
        for item in items:
            out.append("\n[[%s]]" % full)
            out.append(dump_toml(item, full + "."))
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# vendoring
# --------------------------------------------------------------------------- #
SKIP_DIRS = {".git", ".github", "target", "tests", "benches", ".circleci"}
SKIP_FILES = {".gitignore", ".gitattributes"}
METADATA_ONLY_LIST = Path(__file__).resolve().with_name("metadata-only.txt")
#: When true, never touch the network: only the local source cache is used.
OFFLINE_ONLY = os.environ.get("VENDOR_OFFLINE", "") not in ("", "0", "false")


PATCH_FILE = Path(__file__).resolve().with_name("patches.json")


def apply_patches(crate, version, dest):
    """Apply the documented offline substitutions recorded in patches.json."""
    if not PATCH_FILE.exists():
        return
    table = json.loads(PATCH_FILE.read_text())
    for patch in table.get("%s %s" % (crate, version), []):
        target = dest / patch["file"]
        text = target.read_text()
        if patch["old"] not in text:
            log("patch for %s %s did not apply (pattern missing)" % (crate, version))
            continue
        target.write_text(text.replace(patch["old"], patch["new"], 1))
        log("applied offline patch to %s %s: %s" % (crate, version, patch.get("reason", "")))


def is_metadata_only(crate):
    if not METADATA_ONLY_LIST.exists():
        return False
    entries = {
        line.split("#")[0].strip()
        for line in METADATA_ONLY_LIST.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    return crate in entries


def vendor_crate(crate, version, metadata_only=None):
    dest = VENDOR_DIR / ("%s-%s" % (crate, version))
    if dest.exists() and (dest / "Cargo.toml").exists():
        return dest
    if metadata_only is None:
        metadata_only = is_metadata_only(crate)

    # Fast path: the crate may already be inside a previously downloaded source
    # tree (monorepos publish many crates from one repository).
    cached = find_in_cache(crate, version)
    if cached is not None:
        log("vendoring %s %s from the local source cache (%s)" % (crate, version, cached))
        crate_dir = cached
        origin = "cache:%s" % cached
    else:
        if OFFLINE_ONLY:
            raise RuntimeError(
                "%s %s is not present in the local source cache and the network is unavailable"
                % (crate, version)
            )
        repo = discover_repo(crate, version)
        tag = pick_tag(repo, crate, version)
        if tag is None:
            raise RuntimeError(
                "repository %s has no release tag for %s %s; add the correct "
                "repository to scripts/offline/repo-map.json" % (repo, crate, version)
            )
        log("vendoring %s %s from %s@%s%s" % (crate, version, repo, tag, " (metadata only)" if metadata_only else ""))
        root = fetch_source(repo, tag)
        crate_dir = find_crate_dir(root, crate, version)
        if crate_dir is None:
            raise RuntimeError("crate %s not found in %s@%s" % (crate, repo, tag))
        origin = "%s@%s path=%s" % (repo, tag, crate_dir.relative_to(root))

    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    if metadata_only:
        # The crate is present for dependency *resolution* only: it is never
        # activated by any feature we enable, therefore it is never compiled.
        # Its dependency tables are emptied so that an inactive branch of the
        # graph cannot pull further crates into the vendor directory.
        data = flatten_manifest(crate_dir, crate, version)
        pkg = data.get("package", {})
        data = {"package": {k: v for k, v in pkg.items() if k not in ("build", "autobins", "autotests")}}
        data["package"].setdefault("name", crate)
        data["package"]["version"] = version
        data["package"].setdefault("edition", "2021")
        (dest / "Cargo.toml").write_text(dump_toml(data))
        (dest / "src").mkdir(exist_ok=True)
        (dest / "src" / "lib.rs").write_text("// metadata-only vendor entry: never compiled\n")
        (dest / ".cargo-checksum.json").write_text(json.dumps({"files": {}, "package": None}))
        (dest / ".vendor-metadata-only").write_text("%s\n" % origin)
        return dest

    for item in crate_dir.iterdir():
        if item.name in SKIP_FILES:
            continue
        if item.is_dir():
            if item.name in SKIP_DIRS:
                continue
            shutil.copytree(item, dest / item.name, symlinks=True)
        else:
            shutil.copy2(item, dest / item.name)

    data = flatten_manifest(crate_dir, crate, version)
    data.setdefault("package", {})["name"] = crate
    data["package"]["version"] = version
    (dest / "Cargo.toml").write_text(dump_toml(data))
    (dest / ".cargo-checksum.json").write_text(json.dumps({"files": {}, "package": None}))
    (dest / ".vendor-source").write_text("%s\n" % origin)
    apply_patches(crate, version, dest)
    return dest


# --------------------------------------------------------------------------- #
# requirement harvesting + sync loop
# --------------------------------------------------------------------------- #
def harvest_requirements(crate, extra_manifests):
    """Collect every version requirement for ``crate`` from vendored + workspace manifests."""
    reqs = []
    manifests = (
        [VENDOR_DIR / d.name / "Cargo.toml" for d in VENDOR_DIR.iterdir() if (VENDOR_DIR / d.name / "Cargo.toml").exists()]
        if VENDOR_DIR.exists()
        else []
    )
    manifests += [Path(p) for p in extra_manifests]
    workspace_deps = {}
    for path in manifests:
        try:
            data = tomllib.loads(path.read_text())
        except Exception:
            continue
        ws = data.get("workspace") or {}
        if ws.get("dependencies"):
            workspace_deps.update(ws["dependencies"])
    for path in manifests:
        try:
            data = tomllib.loads(path.read_text())
        except Exception:
            continue
        tables = [data.get("dependencies"), data.get("build-dependencies"), data.get("dev-dependencies")]
        for section in (data.get("target") or {}).values():
            if isinstance(section, dict):
                tables += [section.get("dependencies"), section.get("build-dependencies")]
        for table in tables:
            if not isinstance(table, dict):
                continue
            spec = table.get(crate)
            if isinstance(spec, str):
                reqs.append(spec)
            elif isinstance(spec, dict):
                if spec.get("workspace") is True:
                    inherited = workspace_deps.get(crate)
                    if isinstance(inherited, str):
                        reqs.append(inherited)
                    elif isinstance(inherited, dict) and "version" in inherited:
                        reqs.append(inherited["version"])
                elif "version" in spec:
                    reqs.append(spec["version"])
    return reqs


def parse_cargo_error(stderr):
    """Extract (crate, requirement-or-None) from a cargo resolution error."""
    m = re.search(r"searched package name: `([^`]+)`", stderr)
    if m:
        return m.group(1), None
    m = re.search(r"no matching package named `([^`]+)` found", stderr)
    if m:
        return m.group(1), None
    m = re.search(r"failed to select a version for (?:the requirement )?`([^`=]+?)\s*=\s*\"([^\"]*)\"`", stderr)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"failed to select a version for `([^`]+)`", stderr)
    if m:
        return m.group(1), None
    m = re.search(r"unable to get packages from source[\s\S]*?failed to parse manifest at `([^`]+)`", stderr)
    if m:
        return ("__manifest__", m.group(1)), None
    return None, None


def workspace_manifests(manifest_path):
    path = Path(manifest_path)
    try:
        data = tomllib.loads(path.read_text())
    except Exception:
        return [str(path)]
    members = []
    ws = data.get("workspace") or {}
    for member in ws.get("members", []):
        members.extend(sorted(str(p) for p in (path.parent / member).glob("Cargo.toml")))
    if path.parent.joinpath("Cargo.toml").exists():
        members.append(str(path.parent / "Cargo.toml"))
    for member in list(members):
        try:
            sub = tomllib.loads(Path(member).read_text())
            if (sub.get("package") or {}).get("name"):
                pass
        except Exception:
            continue
    return members or [str(path)]


def sync(manifest_path):
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    manifests = workspace_manifests(manifest_path)
    cargo = os.environ.get("CARGO", "cargo")
    env = dict(os.environ, CARGO_NET_OFFLINE="true")
    for i in range(MAX_ITERATIONS):
        proc = subprocess.run(
            [cargo, "metadata", "--offline", "--format-version", "1", "--manifest-path", str(manifest_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=str(Path(manifest_path).parent),
        )
        if proc.returncode == 0:
            log("resolution complete after %d vendoring step(s)" % i)
            return 0
        err = proc.stderr or ""
        crate, req = parse_cargo_error(err)
        if crate is None:
            sys.stderr.write(err)
            log("unrecognised cargo error; stopping")
            return 1
        if isinstance(crate, tuple):
            sys.stderr.write(err)
            return 1
        reqs = [req] if req else harvest_requirements(crate, manifests)
        reqs = [r for r in reqs if r]
        vendored = [
            d.name[len(crate) + 1:]
            for d in VENDOR_DIR.iterdir()
            if d.name.startswith(crate + "-") and (d / "Cargo.toml").exists()
        ] if VENDOR_DIR.exists() else []
        vendored_versions = []
        for raw in vendored:
            try:
                vendored_versions.append(Version(raw))
            except ValueError:
                continue
        unsatisfied = [r for r in reqs if not any(req_matches(r, v) for v in vendored_versions)]
        version = None
        for requirement in (unsatisfied or reqs or ["*"]):
            candidates = [
                v
                for v in available_versions(crate)
                if req_matches(requirement, v) and v.raw not in vendored
            ]
            if candidates:
                version = candidates[-1]
                break
        if version is None:
            candidates = [v for v in available_versions(crate) if v.raw not in vendored]
            version = candidates[-1] if candidates else None
        if version is None:
            sys.stderr.write(err)
            log("cannot pick a version for %s (reqs=%r)" % (crate, reqs))
            return 1
        log("missing %s (reqs=%r) -> %s" % (crate, reqs or ["latest"], version.raw))
        try:
            vendor_crate(crate, version.raw)
        except Exception as exc:
            log("FAILED to vendor %s %s: %s" % (crate, version.raw, exc))
            return 2
    log("gave up after %d iterations" % MAX_ITERATIONS)
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_info = sub.add_parser("info", help="list published versions of a crate")
    p_info.add_argument("crate")
    p_fetch = sub.add_parser("fetch", help="vendor a single crate")
    p_fetch.add_argument("crate")
    p_fetch.add_argument("version")
    p_fetch.add_argument("--metadata-only", action="store_true", help="vendor manifest only (never compiled)")
    p_fetch.add_argument("--offline", action="store_true", help="only use the local source cache")
    p_sync = sub.add_parser("sync", help="resolve dependencies and vendor everything required")
    p_sync.add_argument("--manifest-path", default=str(REPO_ROOT / "Cargo.toml"))
    args = parser.parse_args()

    if args.cmd == "info":
        records = index_entry(args.crate) or []
        live = [r for r in records if not r.get("yanked")]
        print("%s: %d published versions, latest %s" % (args.crate, len(live), live[-1]["vers"] if live else "-"))
        for record in live[-8:]:
            print("  %s  deps=%d" % (record["vers"], len(record.get("deps", []))))
        return 0
    if args.cmd == "fetch":
        if args.offline:
            global OFFLINE_ONLY
            OFFLINE_ONLY = True
        vendor_crate(args.crate, args.version, metadata_only=args.metadata_only or None)
        return 0
    if args.cmd == "sync":
        return sync(args.manifest_path)
    return 1


if __name__ == "__main__":
    sys.exit(main())
