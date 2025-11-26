#!/usr/bin/env python3
import os
import sys
import requests

CSV_URL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"

if len(sys.argv) < 2:
    print("Usage: shai-hulud-scan /path/to/project")
    sys.exit(1)

SEARCH_DIR = sys.argv[1]

print("🔍 Loading suspicious package list...")
response = requests.get(CSV_URL)
lines = response.text.strip().split("\n")[1:]  # skip header
PACKAGES = [line.split(",")[0].strip() for line in lines if line.strip()]

print("🔍 Searching for package.json, lockfiles, and suspicious artifacts...")

VALID_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}

ARTIFACT_FILES = {
    "bun_environment.js",
    "trufflehog",
    "trufflehog.exe",
}

ARTIFACT_DIRS = {
    ".truffler-cache",
    "extract",
}

FILES = []
FOUND_ARTIFACT_FILES = []
FOUND_ARTIFACT_DIRS = []

for root, dirs, files in os.walk(SEARCH_DIR):
    for d in dirs:
        full_path = os.path.join(root, d)

        if d == ".truffler-cache":
            FOUND_ARTIFACT_DIRS.append(full_path)

        if d == "extract" and ".truffler-cache" in root:
            FOUND_ARTIFACT_DIRS.append(full_path)

    for f in files:
        full_path = os.path.join(root, f)

        if f in VALID_FILES:
            FILES.append(full_path)

        if f in ARTIFACT_FILES:
            if f.startswith("trufflehog") and ".truffler-cache" not in full_path:
                continue
            FOUND_ARTIFACT_FILES.append(full_path)

print(f"📂 Total metadata files found: {len(FILES)}")
print(f"📄 Suspicious artifact files found: {len(FOUND_ARTIFACT_FILES)}")
print(f"📁 Suspicious artifact directories found: {len(FOUND_ARTIFACT_DIRS)}")
print(f"📦 Total suspicious packages: {len(PACKAGES)}")
print("----------------------------------")

for file_path in FILES:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        continue

    for package in PACKAGES:
        if f"\"{package}\"" in content:
            print(f"🚨 Suspicious package detected: {package}")
            print(f"📄 File: {file_path}")
            print("----------------------------------")

if FOUND_ARTIFACT_FILES:
    print("⚠️ Suspicious artifact files detected:")
    for path in FOUND_ARTIFACT_FILES:
        print(f"📄 File: {path}")
    print("----------------------------------")
else:
    print("✔ No suspicious artifact files found.")
    print("----------------------------------")

if FOUND_ARTIFACT_DIRS:
    print("⚠️ Suspicious directories detected:")
    for path in FOUND_ARTIFACT_DIRS:
        print(f"📁 Directory: {path}")
    print("----------------------------------")
else:
    print("✔ No suspicious directories found.")
    print("----------------------------------")

print("✅ Finished")
