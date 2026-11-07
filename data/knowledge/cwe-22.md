# CWE-22: Path Traversal

## What it is

Path traversal (CWE-22) happens when a program uses untrusted input to build a file path and does not check that the final path stays inside the intended directory. Input such as `../../etc/passwd`, an absolute path like `/etc/shadow` or `C:\Windows\win.ini`, or a symlink can point outside the base folder. In Python, `os.path.join(BASE, name)` is not a protection: `..` segments are kept, and if `name` is absolute, `join` throws `BASE` away completely. Path traversal appears in download and upload handlers, static file servers, report and template loaders, log viewers, and archive extraction with `tarfile.extractall` (often called "zip slip").

## How attackers exploit it

An attacker exploits path traversal by sending a file name that climbs out of the allowed folder. For a download route like `/files?name=report.pdf`, they send `name=../../../etc/passwd`, `name=../app/config.py` or `name=/home/app/.ssh/id_rsa` to read source code, configuration, keys and database files. URL-encoded forms such as `..%2f` are decoded by the web framework before the code sees them. On upload and write paths, path traversal lets the attacker overwrite files, for example a template or a `.py` module, which can lead to code execution. Malicious tar archives contain members named `../../home/app/.bashrc` or symlinks pointing outside the target folder, so extracting them writes files wherever the process has permission.

## How to fix it in Python

To fix path traversal, resolve the final path and confirm it is inside the base directory before using it:

- `pathlib`: `base = Path(BASE_DIR).resolve()`, `target = (base / name).resolve()`, then `if not target.is_relative_to(base): raise PermissionError(...)`.
- `os.path`: `base = os.path.realpath(BASE_DIR)`, `target = os.path.realpath(os.path.join(base, name))`, then require `os.path.commonpath([base, target]) == base`.
- Resolving removes `..` and follows symlinks; check the resolved path and open that same path.
- Flask downloads: `send_from_directory(BASE_DIR, name)` rejects paths outside the folder with a 404.
- Uploads: clean the client's filename with `werkzeug.utils.secure_filename` (Werkzeug ships with Flask), or `os.path.basename` when only a bare name is expected.
- Archives: on Python 3.11.4+ use `tar.extractall(dest, filter="data")`, or check every member's resolved path first.
- Report a bad path the same way the code already reports errors (exception, 403 or 404).

## Unsafe example

This path traversal example joins a user-supplied name onto the base folder and opens it without any check:

```python
import os

REPORTS_DIR = "/srv/school/reports"

def read_report(name: str) -> str:
    path = os.path.join(REPORTS_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()

# read_report("../../../etc/passwd") reads a system file
# read_report("/etc/passwd") does too, because join drops REPORTS_DIR
```

Both `..` segments and absolute paths escape `REPORTS_DIR`, so a caller can read any file the process is allowed to open.

## Safe example

The path traversal fix resolves the path and checks it against the resolved base directory:

```python
from pathlib import Path

REPORTS_DIR = "/srv/school/reports"

def read_report(name: str) -> str:
    base = Path(REPORTS_DIR).resolve()
    path = (base / name).resolve()
    if not path.is_relative_to(base):
        raise PermissionError(f"path outside reports folder: {name}")
    with open(path, encoding="utf-8") as f:
        return f.read()
```

`resolve()` removes `..` and follows symlinks, so the check sees the real location. The `os.path` version is the same idea: `os.path.realpath` on both paths, then `os.path.commonpath([base, path]) == base`. Normal names such as `term1/alice.txt` keep working exactly as before.

## Common wrong fixes

These changes look like path traversal fixes but can be bypassed:

- Removing `../` with `name.replace("../", "")`. The input `....//` turns back into `../`, and absolute paths are untouched.
- Only rejecting names that contain `..`; absolute paths and symlinks still get through.
- Using a plain string `startswith(BASE_DIR)`, especially on unresolved paths. `/srv/data_private` also starts with `/srv/data`.
- Calling `os.path.normpath` or `os.path.abspath` without comparing the result to the base directory.
- Checking one path and then opening a different, unresolved one.
- Adding `# nosec`, wrapping the open in try/except, or removing the download or upload feature.

## Checklist for a correct fix

Before accepting a path traversal fix, confirm:

- Both the base directory and the target are resolved with `Path.resolve()` or `os.path.realpath`.
- The containment check is `target.is_relative_to(base)` or `os.path.commonpath([base, target]) == base`, not a string `startswith`.
- The file is opened, saved or deleted using the checked path.
- Absolute paths, `..` segments and symlinks pointing outside are all rejected.
- Flask code uses `send_from_directory` or `secure_filename` where that fits; archives use `filter="data"` or per-member checks.
- Bad paths fail the same way the code already reports errors.
- The function keeps its name, parameters and normal behaviour; valid file names still work.
- No new third-party imports and no `# nosec`.
