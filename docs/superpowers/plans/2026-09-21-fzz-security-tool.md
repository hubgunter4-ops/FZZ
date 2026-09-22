# FZZ Security Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the repository prototypes into a usable, authorized-security Python tool with configurable HTTP fuzzing, JavaScript SAST, CLI commands, and an optional Tkinter interface.

**Architecture:** A small `fzztool` package separates YAML payload loading, HTTP request execution, indicative response detection, and JavaScript SAST findings. `argparse` exposes `fuzz` and `sast`; the GUI calls the same service functions and never duplicates scanning logic. Existing extensionless prototype files remain as historical compatibility wrappers/documented legacy artifacts.

**Tech Stack:** Python 3.11+, `requests`, `PyYAML`, `argparse`, `pytest`, optional `tkinter`.

**Spec:** `README.md`

## Global Constraints

- The tool is for authorized security testing only and must display that scope in its documentation and CLI help.
- Payloads load with `yaml.safe_load` from a document containing the `vulnerabilities` key.
- Fuzzing supports GET, POST form, and POST JSON.
- Timeout and pause are configurable and bounded to reduce accidental saturation.
- SAST scans `.js` files and reports rule, file, line, detail, and matching code.
- CLI exit codes: 0 clean, 1 findings, 2 configuration/usage error, 3 runtime error.
- File size, file count, request count, timeout, and pause are bounded.

---

### Task 1: Core payload and fuzzing services

**Files:**
- Create: `fzztool/payloads.py`, `fzztool/detectors.py`, `fzztool/fuzzer.py`
- Test: `tests/test_payloads.py`, `tests/test_fuzzer.py`

- [ ] Implement validated payload normalization with useful `ValueError` messages.
- [ ] Implement bounded GET/form/JSON requests and structured `FuzzResult` records.
- [ ] Implement indicative SSTI, file-read/OS-command, and time-based signals without claiming proof of exploitation.
- [ ] Test request shape, timeout/pause configuration, malformed YAML, and findings.
- [ ] Commit as `feat: add validated payload loading and HTTP fuzzing services`.

### Task 2: JavaScript SAST service

**Files:**
- Create: `fzztool/sast.py`
- Test: `tests/test_sast.py`

- [ ] Implement regex rules for SQL concatenation, reflected/template XSS, and dangerous command/eval APIs.
- [ ] Restrict scanning to `.js`, enforce file and size limits, and return structured findings.
- [ ] Test recursive scanning and exact rule/file/line/detail/code fields.
- [ ] Commit as `feat: add structured JavaScript SAST scanning`.

### Task 3: CLI, GUI, packaging, and documentation

**Files:**
- Create: `fzztool/cli.py`, `fzztool/gui.py`, `fzztool/__main__.py`, `fzz`, `pyproject.toml`, `requirements.txt`, `.gitignore`, `tests/test_cli.py`
- Modify: `README.md`

- [ ] Expose `python -m fzztool` and `./fzz` with `fuzz`, `sast`, and `gui` commands.
- [ ] Add JSON output and documented exit codes.
- [ ] Build a Tkinter form for URL, parameter, method, body type, payload file, timeout, and pause using the same services.
- [ ] Add installation, authorized-use, examples, and YAML schema documentation.
- [ ] Commit as `feat: expose CLI and optional desktop interface`.

### Task 4: Target reconnaissance and pre-flight validation

**Files:**
- Create: `fzztool/recon.py`, `tests/test_recon.py`
- Modify: `fzztool/fuzzer.py`, `fzztool/cli.py`, `README.md`, `tests/test_fuzzer.py`

- [ ] Validate HTTP(S) scheme, hostname, port, timeout, response size, and reject embedded credentials.
- [ ] Perform exactly one bounded GET request and report status, final URL, title, content type, and informative headers.
- [ ] Run reconnaissance before fuzzing and stop before payloads when validation or connectivity fails.
- [ ] Expose standalone `recon` and JSON output, then test with a controlled fake session.
- [ ] Commit as `feat: add validated target reconnaissance before fuzzing`.

### Task 5: Verification

- [ ] Install dependencies in the environment if needed.
- [ ] Run `pytest -q`, CLI help, a local HTTP fixture smoke test, and a local SAST fixture test.
- [ ] Review staged diff for secrets and unintended files.
- [ ] Commit any isolated fixes, then report changes and intentional non-changes.
