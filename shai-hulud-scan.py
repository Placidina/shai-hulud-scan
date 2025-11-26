#!/usr/bin/env python3

import os
import sys
import re
import requests
import json
from packaging.version import parse as vparse

CSV_URL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"

if len(sys.argv) < 2:
    print("Usage: shai-hulud-scan /path/to/project [--fail]")
    sys.exit(1)

SEARCH_DIR = sys.argv[1]
FAIL_ON_FIND = "--fail" in sys.argv

print("🔍 Loading suspicious package list...")
resp = requests.get(CSV_URL)
lines = resp.text.strip().split("\n")[1:]  # skip header


SUSPICIOUS = {}
for line in lines:
    if not line.strip():
        continue
    parts = line.split(",")
    pkg = parts[0].strip()
    versions_raw = parts[1].strip() if len(parts) > 1 else ""
    versions = re.findall(r"(\d+\.\d+\.\d+)", versions_raw)
    SUSPICIOUS[pkg] = set(versions)

print(f"🔍 Loaded {len(SUSPICIOUS)} suspicious packages")


VALID_FILES = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
ARTIFACT_FILES = {"bun_environment.js", "trufflehog", "trufflehog.exe"}
FOUND_ARTIFACT_FILES = []
FOUND_ARTIFACT_DIRS = []
FILES = []


for root, dirs, files in os.walk(SEARCH_DIR):
    for d in dirs:
        if d == ".truffler-cache":
            FOUND_ARTIFACT_DIRS.append(os.path.join(root, d))
        if d == "extract" and ".truffler-cache" in root:
            FOUND_ARTIFACT_DIRS.append(os.path.join(root, d))

    for f in files:
        full = os.path.join(root, f)
        if f in VALID_FILES:
            FILES.append(full)
        if f in ARTIFACT_FILES:
            if f.startswith("trufflehog") and ".truffler-cache" not in full:
                continue
            FOUND_ARTIFACT_FILES.append(full)

print(f"📂 Total metadata files found: {len(FILES)}")
print(f"📄 Suspicious artifact files found: {len(FOUND_ARTIFACT_FILES)}")
print(f"📁 Suspicious artifact directories found: {len(FOUND_ARTIFACT_DIRS)}")
print(f"📦 Total suspicious packages: {len(SUSPICIOUS)}")
print("----------------------------------")


def extract_version(raw):
    """Return first semver-like x.y.z found in raw string or None."""
    m = re.search(r"(\d+\.\d+\.\d+)", raw)
    return m.group(1) if m else None

def split_or_clauses(range_raw):
    """Split a range string by '||' into list of trimmed parts."""
    return [p.strip() for p in re.split(r"\|\|", range_raw) if p.strip()]

def caret_range_to_bounds(ver_str):
    m = re.match(r"^\^(\d+)\.(\d+)\.(\d+)$", ver_str)
    if not m:
        return None
    major = int(m.group(1))
    lower = f"{major}.{m.group(2)}.{m.group(3)}"
    upper = f"{major+1}.0.0"
    return (vparse(lower), vparse(upper))

def tilde_range_to_bounds(ver_str):
    m = re.match(r"^~(\d+)\.(\d+)\.(\d+)$", ver_str)
    if not m:
        return None
    major = int(m.group(1)); minor = int(m.group(2))
    lower = f"{major}.{minor}.{m.group(3)}"
    upper = f"{major}.{minor+1}.0"
    return (vparse(lower), vparse(upper))

def wildcard_to_bounds(ver_str):
    m = re.match(r"^(\d+)\.(x|\*)$", ver_str)
    if not m:
        m2 = re.match(r"^(\d+)\.(x|\*)\.(x|\*)$", ver_str)
        if m2:
            major = int(m2.group(1))
            return (vparse(f"{major}.0.0"), vparse(f"{major+1}.0.0"))
        return None
    major = int(m.group(1))
    return (vparse(f"{major}.0.0"), vparse(f"{major+1}.0.0"))

def inequality_to_bounds(op, ver):
    v = vparse(ver)
    if op == ">=":
        return (v, None)
    if op == ">":
        return (v, None)
    if op == "<=":
        return (None, v)
    if op == "<":
        return (None, v)
    if op == "=" or op == "":
        return (v, v)
    return None

def range_allows_version(range_raw, mal_version):
    """
    Returns True if the declared range (which may contain ||) allows mal_version.
    Supports common npm range syntaxes: ^ ~ >= <= > < = exact, wildcard x, and combinations with ||.
    """
    if not range_raw or not mal_version:
        return False

    mal_v = vparse(mal_version)

    parts = split_or_clauses(range_raw)
    for p in parts:
        p = p.strip()
        m_eq = re.match(r"^=?\s*(\d+\.\d+\.\d+)$", p)
        if m_eq:
            if vparse(m_eq.group(1)) == mal_v:
                return True
            else:
                continue

        if p.startswith("^"):
            bounds = caret_range_to_bounds(p)
            if bounds:
                lower, upper = bounds
                if mal_v >= lower and mal_v < upper:
                    return True
                continue

        if p.startswith("~"):
            bounds = tilde_range_to_bounds(p)
            if bounds:
                lower, upper = bounds
                if mal_v >= lower and mal_v < upper:
                    return True
                continue

        if re.match(r"^\d+\.(x|\*)", p) or re.match(r"^\d+\.\d+\.(x|\*)", p):
            bounds = wildcard_to_bounds(p)
            if bounds:
                lower, upper = bounds
                if mal_v >= lower and mal_v < upper:
                    return True
                continue

        m_op = re.match(r"^(>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)$", p)
        if m_op:
            op = m_op.group(1) or ""
            ver = m_op.group(2)
            bounds = inequality_to_bounds(op, ver)
            if bounds is None:
                continue
            low, high = bounds
            ok = True
            if low is not None:
                if op == ">" and not (mal_v > low):
                    ok = False
                elif op in (">=", "") and not (mal_v >= low):
                    ok = False
            if high is not None:
                if op == "<" and not (mal_v < high):
                    ok = False
                elif op in ("<=",) and not (mal_v <= high):
                    ok = False
            if ok:
                return True
            continue

        m_hy = re.match(r"^(\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+)$", p)
        if m_hy:
            lo = vparse(m_hy.group(1)); hi = vparse(m_hy.group(2))
            if mal_v >= lo and mal_v <= hi:
                return True
            continue

        m_plain = re.search(r"(\d+\.\d+\.\d+)", p)
        if m_plain:
            if vparse(m_plain.group(1)) == mal_v:
                return True

    return False


suspicious_hits = []
range_vulnerable_hits = []


def parse_package_json_declared(path):
    declared = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return declared
    for sec in ("dependencies", "devDependencies", "peerDependencies"):
        if sec in data and isinstance(data[sec], dict):
            for k, v in data[sec].items():
                declared[k] = v
    return declared

def parse_package_lock_installed(path):
    installed = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return installed
    # handle npm's package-lock v2 structure
    if "packages" in data:
        for pkg_path, info in data["packages"].items():
            if pkg_path.startswith("node_modules/"):
                name = pkg_path.split("/", 1)[1]
                ver = info.get("version")
                if ver:
                    installed[name] = ver
    if "dependencies" in data:
        for name, info in data["dependencies"].items():
            ver = info.get("version")
            if ver:
                installed[name] = ver
    return installed

def parse_yarn_lock_installed(path):
    installed = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
    except Exception:
        return installed
    entries = raw.split("\n\n")
    for entry in entries:
        header = entry.splitlines()[0] if entry.strip() else ""
        m_name = re.match(r'^("?@?[^:"]+).*?:', header)
        if not m_name:
            continue
        pkg = m_name.group(1).split("@")[0].strip('"')
        m_version = re.search(r'^\s*version\s+"?([^"\n]+)"?', entry, flags=re.M)
        if m_version:
            installed[pkg] = m_version.group(1)
    return installed

def parse_pnpm_lock_installed(path):
    installed = {}
    try:
        import yaml
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
    except Exception:
        return installed
    pkgs = data.get("packages") or {}
    for key, info in pkgs.items():
        m = re.match(r"^/?([^@/]+)@([\d\.]+)", key)
        if m:
            name = m.group(1)
            ver = info.get("version") or m.group(2)
            if ver:
                installed[name] = ver
    return installed

for fpath in FILES:
    fname = os.path.basename(fpath)
    declared_map = {}
    installed_map = {}

    if fname == "package.json":
        declared_map = parse_package_json_declared(fpath)
    elif fname == "package-lock.json":
        installed_map = parse_package_lock_installed(fpath)
    elif fname == "yarn.lock":
        installed_map = parse_yarn_lock_installed(fpath)
    elif fname == "pnpm-lock.yaml":
        installed_map = parse_pnpm_lock_installed(fpath)

    # Check installed versions that exactly match malicious set
    for pkg, inst_ver in installed_map.items():
        if pkg in SUSPICIOUS and inst_ver in SUSPICIOUS[pkg]:
            suspicious_hits.append((pkg, inst_ver, fpath))
            print(f"🚨 Suspicious package detected (installed): {pkg}@{inst_ver}")
            print(f"📄 File: {fpath}")
            print("----------------------------------")

    for pkg, declared_raw in declared_map.items():
        if pkg not in SUSPICIOUS:
            continue
        mal_versions = SUSPICIOUS[pkg]
        for mal_v in mal_versions:
            try:
                if range_allows_version(declared_raw, mal_v):
                    range_vulnerable_hits.append((pkg, declared_raw, mal_v, fpath))
                    print(f"⚠️ Declared range allows malicious version: {pkg}")
                    print(f"🔢 Declared: {declared_raw}  → allows {mal_v}")
                    print(f"📄 File: {fpath}")
                    print("----------------------------------")
                    break
            except Exception:
                continue


if FOUND_ARTIFACT_FILES:
    print("⚠️ Suspicious artifact files detected:")
    for p in FOUND_ARTIFACT_FILES:
        print(f"📄 File: {p}")
    print("----------------------------------")

if FOUND_ARTIFACT_DIRS:
    print("⚠️ Suspicious directories detected:")
    for p in FOUND_ARTIFACT_DIRS:
        print(f"📁 Directory: {p}")
    print("----------------------------------")


found_something = bool(FOUND_ARTIFACT_FILES or FOUND_ARTIFACT_DIRS or suspicious_hits or range_vulnerable_hits)
if FAIL_ON_FIND and found_something:
    print("❌ Suspicious activity detected. Exiting with error due to --fail.")
    sys.exit(1)

print("✅ Finished")
