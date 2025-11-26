# Shai Hulud Scan

A lightweight security scanner designed to detect suspicious Node.js packages and known malicious artifacts related to the Shai Hulud supply-chain attack.
It checks for compromised packages listed by WIZ Threat Research and searches the filesystem for malicious files and directories dropped during exploitation.

## Installation

Install dependencies:

```sh
pip install -r requirements.txt
```

## Usage

Run the scan against a project directory:

```sh
python3 shai-hulud-scan.py /path/to/project
```

> For the CI/CD using `--fail` to exit code 1.

Fail exit code on detect:

```sh
python3 shai-hulud-scan.py /path/to/project --fail
```

The scanner will:

- Download the latest list of suspicious packages from WIZ Research
- Search for:
  - `package.json`
  - `package-lock.json`
  - `yarn.lock`
  - `pnpm-lock.yaml`
- Detect indicators of compromise (IOCs), including:
  - `bun_environment.js`
  - `.truffler-cache/`
  - `.truffler-cache/extract/`
  - `.truffler-cache/trufflehog`
  - `.truffler-cache/trufflehog.exe`

## Using Inside Docker (recommended)

```sh
docker run --rm -it placidina/shai-hulud-scan:latest bash
```

Once inside the container:

```sh
shai-hulud-scan /workspace/path/to/cloned-or-mounted-volume/project
```

## Notes

- No code is executed from the target project.
- The scan is fully offline after downloading the IOC list.
- Designed for CI pipelines, local audits, and bulk repository scanning.
