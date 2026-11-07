// extension.ts: the entry point. It registers the PatchAI commands, shows scan findings as
// diagnostics (squiggly underlines), offers the "Fix with PatchAI" quick fix, and carries out the
// Accept / Reject / diff actions from the fix panel. HTTP calls live in api.ts, the panel in panel.ts.

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import * as api from './api';
import { Finding, FixResult } from './api';
import { closeFixPanel, PanelAction, showFixPanel } from './panel';

const PROPOSED_SCHEME = 'patchai-proposed';
const SERVER_TERMINAL = 'PatchAI Server';
const REJECT_REASONS = ['Wrong fix', 'Breaks behaviour', 'Too large', 'Not a real vulnerability'];

let extensionPath = '';
let diagnostics: vscode.DiagnosticCollection;
let scanStatus: vscode.StatusBarItem;
let modelStatus: vscode.StatusBarItem;
let scanRunning = false;

// The code action provider receives diagnostics back from VS Code; this map finds their Finding.
const findingByDiagnostic = new Map<vscode.Diagnostic, Finding>();

// Text of proposed files for the diff editor, keyed by the virtual document's query string.
const proposedTexts = new Map<string, string>();
let diffCounter = 0;

export function activate(context: vscode.ExtensionContext): void {
  extensionPath = context.extensionPath;
  diagnostics = vscode.languages.createDiagnosticCollection('patchai');

  scanStatus = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  scanStatus.command = 'patchai.scan';
  setScanStatus('$(shield) PatchAI', 'Scan the workspace for vulnerabilities');
  scanStatus.show();

  modelStatus = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 99);
  modelStatus.command = 'patchai.selectModel';
  updateModelStatus();
  modelStatus.show();

  context.subscriptions.push(
    diagnostics,
    scanStatus,
    modelStatus,
    vscode.commands.registerCommand('patchai.scan', () => scanWorkspace(false)),
    vscode.commands.registerCommand('patchai.fix', (arg?: unknown) => fixFinding(arg)),
    vscode.commands.registerCommand('patchai.startServer', startServer),
    vscode.commands.registerCommand('patchai.selectModel', selectModel),
    vscode.languages.registerCodeActionsProvider(
      { language: 'python' },
      { provideCodeActions: (_document, _range, ctx) => fixActions(ctx.diagnostics) },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
    vscode.workspace.registerTextDocumentContentProvider(PROPOSED_SCHEME, {
      provideTextDocumentContent: uri => proposedTexts.get(uri.query) ?? '',
    }),
    vscode.workspace.onDidSaveTextDocument(document => {
      const scanOnSave = vscode.workspace.getConfiguration('patchai').get<boolean>('scanOnSave', false);
      if (scanOnSave && document.languageId === 'python' && vscode.workspace.workspaceFolders) {
        void scanWorkspace(true);
      }
    }),
    vscode.workspace.onDidChangeConfiguration(event => {
      if (event.affectsConfiguration('patchai.model')) {
        updateModelStatus();
      }
    }),
  );
}

export function deactivate(): void {
  // Nothing to clean up: everything is registered in context.subscriptions.
}

// ---------- Scan ----------

/** POST /scan for the first workspace folder and show the findings. Quiet scans skip the popups. */
async function scanWorkspace(quiet: boolean): Promise<void> {
  const folder = projectFolder();
  if (!folder || scanRunning) {
    return;
  }
  scanRunning = true;
  setScanStatus('$(sync~spin) PatchAI: scanning…', 'Scanning the workspace');
  try {
    const findings = quiet
      ? await api.scan(folder.uri.fsPath)
      : await vscode.window.withProgress(
          { location: vscode.ProgressLocation.Notification, title: 'PatchAI: scanning the workspace…' },
          () => api.scan(folder.uri.fsPath),
        );
    await showFindings(folder, findings);
    if (!quiet) {
      announceScan(findings.length);
    }
  } catch (error) {
    setScanStatus('$(shield) PatchAI: scan failed', 'Click to try again');
    void showError(error);
  } finally {
    scanRunning = false;
  }
}

/** Replaces all PatchAI diagnostics with one per finding. */
async function showFindings(folder: vscode.WorkspaceFolder, findings: Finding[]): Promise<void> {
  diagnostics.clear();
  findingByDiagnostic.clear();

  const files = new Map<string, { uri: vscode.Uri; lines: string[]; items: vscode.Diagnostic[] }>();
  for (const finding of findings) {
    const uri = findingUri(folder, finding);
    let file = files.get(uri.toString());
    if (!file) {
      file = { uri, lines: await readLines(uri), items: [] };
      files.set(uri.toString(), file);
    }
    const diagnostic = toDiagnostic(finding, file.lines);
    findingByDiagnostic.set(diagnostic, finding);
    file.items.push(diagnostic);
  }
  for (const file of files.values()) {
    diagnostics.set(file.uri, file.items);
  }

  const count = (severity: api.Severity) => findings.filter(f => f.severity === severity).length;
  const total = findings.length;
  setScanStatus(
    `$(shield) PatchAI: ${total === 0 ? 'no issues' : total === 1 ? '1 issue' : `${total} issues`}`,
    `${count('high')} high · ${count('medium')} medium · ${count('low')} low\nClick to scan again`,
  );
  scanStatus.backgroundColor = total > 0 ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
}

function toDiagnostic(finding: Finding, lines: string[]): vscode.Diagnostic {
  const severities: Record<api.Severity, vscode.DiagnosticSeverity> = {
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information,
  };
  const diagnostic = new vscode.Diagnostic(
    findingRange(finding, lines),
    `${api.findingLabel(finding)}: ${finding.message}`,
    severities[finding.severity] ?? vscode.DiagnosticSeverity.Warning,
  );
  diagnostic.source = 'PatchAI';
  // A CWE code becomes a link to its MITRE page in the hover and the Problems panel.
  const cweNumber = finding.cwe?.match(/^CWE-(\d+)$/)?.[1];
  diagnostic.code = finding.cwe && cweNumber
    ? { value: finding.cwe, target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${cweNumber}.html`) }
    : (finding.cwe ?? finding.rule_id);
  return diagnostic;
}

/** Underline from the first non-blank character of start_line to the end of end_line (1-based lines). */
function findingRange(finding: Finding, lines: string[]): vscode.Range {
  const start = Math.max(finding.start_line - 1, 0);
  const end = Math.max(finding.end_line - 1, start);
  const firstLine = lines[start] ?? '';
  const startColumn = firstLine.length - firstLine.trimStart().length;
  return new vscode.Range(start, startColumn, end, (lines[end] ?? '').length);
}

/** Reads a file from disk (the scanner looked at the saved version). Empty if it cannot be read. */
async function readLines(uri: vscode.Uri): Promise<string[]> {
  try {
    const bytes = await vscode.workspace.fs.readFile(uri);
    return Buffer.from(bytes).toString('utf8').split(/\r?\n/);
  } catch {
    return [];
  }
}

function announceScan(total: number): void {
  if (total === 0) {
    void vscode.window.showInformationMessage('PatchAI found no vulnerabilities.');
    return;
  }
  const text = `PatchAI found ${total} ${total === 1 ? 'vulnerability' : 'vulnerabilities'}. Use the 🛡️ quick fix on an underlined line to fix one.`;
  void vscode.window.showInformationMessage(text, 'Show Problems').then(choice => {
    if (choice) {
      void vscode.commands.executeCommand('workbench.actions.view.problems');
    }
  });
}

// ---------- Code actions ----------

/** One "Fix with PatchAI" quick fix per PatchAI diagnostic under the cursor. */
function fixActions(contextDiagnostics: readonly vscode.Diagnostic[]): vscode.CodeAction[] {
  const ours = contextDiagnostics.filter(diagnostic => findingByDiagnostic.has(diagnostic));
  return ours.map((diagnostic, index) => {
    const finding = findingByDiagnostic.get(diagnostic)!;
    // When two findings share a line, add the label so the user can tell them apart.
    const title = ours.length > 1 ? `🛡️ Fix with PatchAI: ${api.findingLabel(finding)}` : '🛡️ Fix with PatchAI';
    const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];
    action.isPreferred = index === 0;
    action.command = { command: 'patchai.fix', title, arguments: [finding] };
    return action;
  });
}

// ---------- Fix ----------

/** Runs from the quick fix (with a Finding) or from the palette / context menu (finding at the cursor). */
async function fixFinding(arg?: unknown): Promise<void> {
  const folder = projectFolder();
  if (!folder) {
    return;
  }
  const finding = isFinding(arg) ? arg : await pickFindingAtCursor();
  if (!finding) {
    return;
  }

  const request = api.fix(folder.uri.fsPath, finding, configuredModel());

  // "Cancel" only hides the notification: the server keeps working and the panel still opens.
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `PatchAI is fixing ${finding.cwe ?? finding.rule_id}…`,
      cancellable: true,
    },
    (progress, token) =>
      new Promise<void>(resolve => {
        const started = Date.now();
        const report = () => {
          const seconds = Math.round((Date.now() - started) / 1000);
          progress.report({ message: `reading guides, writing and testing a fix (${seconds} s)` });
        };
        report();
        const timer = setInterval(report, 1000);
        const finish = () => {
          clearInterval(timer);
          resolve();
        };
        token.onCancellationRequested(finish);
        request.then(finish, finish);
      }),
  );

  try {
    const result = await request;
    showFixPanel(result, action => handlePanelAction(action, folder, result));
  } catch (error) {
    void showError(error);
  }
}

function isFinding(value: unknown): value is Finding {
  return typeof value === 'object' && value !== null && 'rule_id' in value && 'file_path' in value;
}

/** The PatchAI finding on the cursor line; asks the user to choose when there are several. */
async function pickFindingAtCursor(): Promise<Finding | undefined> {
  const editor = vscode.window.activeTextEditor;
  const line = editor?.selection.active.line ?? -1;
  const here = (editor ? diagnostics.get(editor.document.uri) ?? [] : [])
    .filter(diagnostic => diagnostic.range.start.line <= line && line <= diagnostic.range.end.line)
    .map(diagnostic => findingByDiagnostic.get(diagnostic))
    .filter((finding): finding is Finding => finding !== undefined);

  if (here.length === 0) {
    void vscode.window.showInformationMessage(
      'No PatchAI finding at the cursor. Run "PatchAI: Scan Workspace for Vulnerabilities", then put the cursor on an underlined line.',
    );
    return undefined;
  }
  if (here.length === 1) {
    return here[0];
  }
  const picked = await vscode.window.showQuickPick(
    here.map(finding => ({ label: api.findingLabel(finding), description: finding.rule_id, detail: finding.message, finding })),
    { placeHolder: 'Which finding should PatchAI fix?' },
  );
  return picked?.finding;
}

// ---------- Panel actions ----------

async function handlePanelAction(action: PanelAction, folder: vscode.WorkspaceFolder, result: FixResult): Promise<void> {
  try {
    switch (action) {
      case 'accept':
        await acceptFix(folder, result);
        break;
      case 'reject':
        await rejectFix(folder, result);
        break;
      case 'openDiff':
        await openDiff(folder, result);
        break;
    }
  } catch (error) {
    void showError(error);
  }
}

/** Replaces the file with the verified fix (one undoable edit), saves it, records the approval. */
async function acceptFix(folder: vscode.WorkspaceFolder, result: FixResult): Promise<void> {
  const newText = result.patched_file_text;
  if (result.verdict !== 'fixed' || newText === null) {
    return; // the Accept button is disabled in this case
  }
  const uri = findingUri(folder, result.finding);
  const fileName = result.finding.file_path;
  const document = await vscode.workspace.openTextDocument(uri);

  if (document.isDirty) {
    const answer = await vscode.window.showWarningMessage(
      `${fileName} has unsaved changes. The fix was made from the saved file. Replace it anyway?`,
      { modal: true },
      'Replace',
    );
    if (answer !== 'Replace') {
      return;
    }
  }

  const edit = new vscode.WorkspaceEdit();
  const wholeFile = new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length));
  edit.replace(uri, wholeFile, newText);
  if (!(await vscode.workspace.applyEdit(edit))) {
    throw new Error(`PatchAI could not edit ${fileName}.`);
  }
  if (!(await document.save())) {
    throw new Error(`PatchAI changed ${fileName} but could not save it.`);
  }

  await api.sendDecision(folder.uri.fsPath, result.finding.id, 'approved', null, result.model);
  closeFixPanel();

  const line = Math.max(result.finding.start_line - 1, 0);
  await vscode.window.showTextDocument(document, {
    viewColumn: vscode.ViewColumn.One,
    selection: new vscode.Range(line, 0, line, 0),
  });
  void vscode.window.showInformationMessage(`PatchAI fix applied to ${fileName}. Use Undo to revert it.`);
  await scanWorkspace(true);
}

/** Asks why the fix is wrong, then records the rejection. */
async function rejectFix(folder: vscode.WorkspaceFolder, result: FixResult): Promise<void> {
  const reason = await askRejectReason();
  if (!reason) {
    return; // cancelled: keep the panel open
  }
  await api.sendDecision(folder.uri.fsPath, result.finding.id, 'rejected', reason, result.model);
  closeFixPanel();
  void vscode.window.showInformationMessage(`Fix rejected. Reason saved: "${reason}".`);
}

/** A quick pick that offers common reasons but also accepts whatever the user types. */
function askRejectReason(): Promise<string | undefined> {
  return new Promise(resolve => {
    const pick = vscode.window.createQuickPick();
    pick.title = 'Why are you rejecting this fix?';
    pick.placeholder = 'Pick a reason or type your own (required)';
    const suggestions = REJECT_REASONS.map(label => ({ label }));
    pick.items = suggestions;

    pick.onDidChangeValue(value => {
      // Put the typed text first so Enter submits it as a free-text reason.
      const typed = value.trim();
      pick.items = typed && !REJECT_REASONS.includes(typed)
        ? [{ label: typed, description: 'your reason' }, ...suggestions]
        : suggestions;
    });
    pick.onDidAccept(() => {
      const reason = (pick.selectedItems[0]?.label ?? pick.value).trim();
      if (reason) {
        resolve(reason);
        pick.hide();
      }
    });
    pick.onDidHide(() => {
      resolve(undefined); // no effect if a reason was already chosen
      pick.dispose();
    });
    pick.show();
  });
}

/** Shows the current file next to the proposed file in VS Code's diff editor. */
async function openDiff(folder: vscode.WorkspaceFolder, result: FixResult): Promise<void> {
  if (result.patched_file_text === null) {
    return;
  }
  const originalUri = findingUri(folder, result.finding);
  // A fresh query per click means VS Code never reuses a cached copy of an older proposal.
  // Keeping the original path (and its .py extension) gives the right side Python highlighting.
  const key = `${result.finding.id}-${++diffCounter}`;
  proposedTexts.set(key, result.patched_file_text);
  const proposedUri = originalUri.with({ scheme: PROPOSED_SCHEME, query: key });
  await vscode.commands.executeCommand(
    'vscode.diff',
    originalUri,
    proposedUri,
    `PatchAI fix: ${path.posix.basename(result.finding.file_path)}`,
    { viewColumn: vscode.ViewColumn.One },
  );
}

// ---------- Server and model ----------

/** Starts uvicorn in a terminal. The terminal runs Python directly, so paths with spaces need no quoting. */
function startServer(): void {
  const existing = vscode.window.terminals.find(terminal => terminal.name === SERVER_TERMINAL);
  if (existing && existing.exitStatus === undefined) {
    existing.show(); // already running: a second server would clash on the same port
    return;
  }
  existing?.dispose(); // the old server stopped; replace its terminal

  const config = vscode.workspace.getConfiguration('patchai');
  // By default the extension lives in <repo>/extension, so the repo root is its parent folder.
  const serverDir = config.get<string>('serverDir', '').trim() || path.dirname(extensionPath);
  let python = config.get<string>('pythonPath', '').trim();
  if (!python) {
    // Prefer the repository's virtual environment, where PatchAI's packages are installed.
    const venv = process.platform === 'win32'
      ? path.join(serverDir, '.venv', 'Scripts', 'python.exe')
      : path.join(serverDir, '.venv', 'bin', 'python');
    python = fs.existsSync(venv) ? venv : 'python';
  }
  if (!path.isAbsolute(python) && /[\\/]/.test(python)) {
    python = path.resolve(serverDir, python); // e.g. ".venv/Scripts/python.exe"
  }
  const port = serverPort();

  const terminal = vscode.window.createTerminal({
    name: SERVER_TERMINAL,
    cwd: serverDir,
    shellPath: python,
    shellArgs: ['-m', 'uvicorn', 'patchai.server:app', '--port', port],
    iconPath: new vscode.ThemeIcon('shield'),
  });
  terminal.show();
  void vscode.window.showInformationMessage(
    `Starting the PatchAI server on port ${port}. Scan once the terminal says "Application startup complete".`,
  );
}

/** The port from patchai.serverUrl, so the started server matches the URL the extension calls. */
function serverPort(): string {
  try {
    return new URL(api.serverUrl()).port || '8765';
  } catch {
    return '8765';
  }
}

async function selectModel(): Promise<void> {
  let health: api.Health;
  try {
    health = await api.getHealth();
  } catch (error) {
    void showError(error);
    return;
  }
  const current = configuredModel();
  const items: (vscode.QuickPickItem & { model: string })[] = [
    { label: 'Server default', description: health.default_model + (current === null ? ' · ✓ selected' : ''), model: '' },
    ...health.models.map(model => ({
      label: model,
      description: [model === health.default_model ? 'server default' : '', model === current ? '✓ selected' : '']
        .filter(Boolean)
        .join(' · '),
      model,
    })),
  ];
  const picked = await vscode.window.showQuickPick(items, {
    title: 'PatchAI model',
    placeHolder: `Choose the model that writes fixes (now: ${current ?? `server default, ${health.default_model}`})`,
  });
  if (!picked) {
    return;
  }
  const target = vscode.workspace.workspaceFolders ? vscode.ConfigurationTarget.Workspace : vscode.ConfigurationTarget.Global;
  await vscode.workspace.getConfiguration('patchai').update('model', picked.model, target);
  void vscode.window.showInformationMessage(
    picked.model ? `PatchAI will use ${picked.model}.` : `PatchAI will use the server default (${health.default_model}).`,
  );
}

// ---------- Helpers ----------

/** The model chosen in settings, or null to let the server use its default. */
function configuredModel(): string | null {
  return vscode.workspace.getConfiguration('patchai').get<string>('model', '').trim() || null;
}

function updateModelStatus(): void {
  const model = configuredModel();
  modelStatus.text = `$(hubot) ${model ?? 'default model'}`;
  modelStatus.tooltip = 'PatchAI model: click to change';
}

function setScanStatus(text: string, tooltip: string): void {
  scanStatus.text = text;
  scanStatus.tooltip = tooltip;
  scanStatus.backgroundColor = undefined;
}

function projectFolder(): vscode.WorkspaceFolder | undefined {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showWarningMessage('PatchAI: open your project folder first (File > Open Folder).');
  }
  return folder;
}

/** file_path is relative to the project folder and uses forward slashes, which joinPath accepts. */
function findingUri(folder: vscode.WorkspaceFolder, finding: Finding): vscode.Uri {
  return vscode.Uri.joinPath(folder.uri, finding.file_path);
}

/** Shows an error; when the server is down, offers to start it. */
async function showError(error: unknown): Promise<void> {
  const message = error instanceof Error ? error.message : String(error);
  if (error instanceof api.ServerUnreachableError) {
    const choice = await vscode.window.showErrorMessage(message, 'Start Server');
    if (choice === 'Start Server') {
      await vscode.commands.executeCommand('patchai.startServer');
    }
  } else {
    void vscode.window.showErrorMessage(message);
  }
}
