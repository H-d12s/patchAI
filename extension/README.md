# PatchAI – AI Security Fixes (VS Code extension)

The VS Code front end for PatchAI. It underlines security vulnerabilities in Python code, asks the
local PatchAI server to fix one, and shows the fix in a side panel so a human can **accept** or
**reject** it. Nothing in your project changes until you click Accept.

The extension does no AI work itself. Scanning, RAG, the model and the checks all run in the
Python server (`patchai/server.py`); the extension talks to it over HTTP on `127.0.0.1`.

## What it does

- **Scan:** `PatchAI: Scan Workspace for Vulnerabilities` sends the workspace folder to the server
  and shows every finding as a squiggly underline and in the Problems panel
  (high = error, medium = warning, low = information). The status bar shows `PatchAI: 5 issues`.
- **Fix:** on an underlined line, open the quick-fix menu (lightbulb or `Ctrl+.`) and choose
  **🛡️ Fix with PatchAI**. You can also run `PatchAI: Fix with AI` from the Command Palette or the
  editor's right-click menu to fix the finding at the cursor. A notification shows progress
  (a fix takes 30 seconds to 3 minutes).
- **Review panel:** opens beside the editor and shows
  - the vulnerability, file and line, model and time taken
  - a verdict badge: **Fixed ✔**, **Failed ✘**, **Cannot fix** or **False positive**
  - the model's explanation and confidence
  - the diff, with added and removed lines coloured
  - every check (format, safety guard, tests, security test, re-scan) with ✔ / ✘, and earlier
    failed attempts in collapsible sections, so you can see the retry loop
  - **What the AI read:** the security guides, project code and past fixes that RAG retrieved,
    with their scores
- **Accept** (only enabled when every check passed): replaces the file with the fix as one
  undoable edit, saves it, records the approval, and scans again so the underline disappears.
- **Reject:** asks for a reason (pick one or type your own) and records it.
- **Open in diff editor:** shows the current file next to the proposed file in VS Code's diff view.

## How to run it

1. **Install the Python side** (from the repo root): set up the virtual environment and
   `pip install -r requirements.txt`, and make sure Ollama is running with the models.
2. **Build the extension** (once):
   ```
   cd extension
   npm install
   npm run compile
   ```
3. **Launch it:** open the `extension` folder in VS Code and press **F5**. A second VS Code window
   (the *Extension Development Host*) opens with PatchAI loaded. The launch menu also has
   *Run PatchAI Extension on vuln_shop (demo)*, which opens `demo_projects/vuln_shop` directly.
4. **Start the server:** in the new window run `PatchAI: Start PatchAI Server`. It opens a terminal
   named *PatchAI Server* running
   ```
   python -m uvicorn patchai.server:app --port 8765
   ```
   in the repo root. Wait for `Application startup complete`. (You can also start this command
   yourself in any terminal.) If PatchAI ever cannot reach the server, the error message has a
   **Start Server** button.

## Walkthrough (demo)

1. Open `demo_projects/vuln_shop` in the Extension Development Host and start the server.
2. Click **PatchAI** in the status bar (or run the scan command). The vulnerable lines are underlined.
3. Hover the SQL-injection line in `shop/db.py`: the message reads `CWE-89 SQL injection: ...`.
4. Press `Ctrl+.` and pick **🛡️ Fix with PatchAI**. Wait for the notification to finish.
5. In the panel, walk through the verdict, the explanation, the diff, the checks (open an earlier
   attempt to show a retry), and *What the AI read*.
6. Click **Open in diff editor** to show the change side by side.
7. Click **Accept**: the file is patched and saved, and the underline disappears after the re-scan.
   `Ctrl+Z` undoes it.
8. To compare models, click the model name in the status bar (or run `PatchAI: Select Model`),
   choose `qwen2.5-coder:3b`, and fix the same finding again.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `patchai.serverUrl` | `http://127.0.0.1:8765` | Where the PatchAI server listens. |
| `patchai.model` | `""` | Model used for fixes. Empty means the server's default. Set it with `PatchAI: Select Model`. |
| `patchai.pythonPath` | `python` | Interpreter for `Start PatchAI Server`. A relative path such as `.venv/Scripts/python.exe` is resolved against the server folder. |
| `patchai.serverDir` | `""` | Folder the server starts in. Empty means the parent of the extension folder (the repo root). |
| `patchai.scanOnSave` | `false` | Scan again whenever a Python file is saved. |

## How the code is organised

| File | Job |
| --- | --- |
| `src/api.ts` | TypeScript types for the server's JSON (`Finding`, `FixResult`, ...), CWE names, and one `fetch` wrapper per endpoint (`/health`, `/scan`, `/fix`, `/decision`). |
| `src/panel.ts` | The review panel: builds its HTML (everything escaped, strict Content-Security-Policy with a nonce) and reports button clicks. |
| `src/extension.ts` | Activation, the four commands, diagnostics, the quick fix, the status bar, and the Accept / Reject / diff actions. |

The server API is fixed: `GET /health`, `POST /scan`, `POST /fix` (up to 5 minutes) and
`POST /decision`. Errors come back as `{"detail": "message"}` and are shown as VS Code error messages.

## Troubleshooting

- **"Cannot reach the PatchAI server"**: start it (button in the message), check the terminal for
  a Python error, and check that `patchai.serverUrl` matches the port.
- **The server terminal says `No module named uvicorn`**: set `patchai.pythonPath` to the
  virtual environment's Python, for example `.venv/Scripts/python.exe` on Windows.
- **Accept is greyed out**: the fix did not pass every check, so PatchAI will not apply it. The
  panel explains why; you can still reject it to record the decision.
