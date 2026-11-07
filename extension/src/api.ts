// api.ts: talks to the local PatchAI server (patchai/server.py).
// It holds the TypeScript types of the JSON the server sends, the CWE names, and one small
// fetch wrapper per endpoint. No other file makes HTTP requests.

import * as vscode from 'vscode';

// ---------- Data types (they mirror the server's JSON) ----------

export type Severity = 'low' | 'medium' | 'high';
export type Verdict = 'fixed' | 'failed' | 'cannot_fix' | 'false_positive';
export type Decision = 'approved' | 'rejected';

/** A vulnerability reported by a scanner. */
export interface Finding {
  id: string;
  scanner: string;
  rule_id: string;
  cwe: string | null;
  severity: Severity;
  file_path: string; // relative to the project folder, forward slashes
  start_line: number; // 1-based
  end_line: number;
  message: string;
}

/** One piece of information RAG found and gave to the model. */
export interface RetrievedChunk {
  source: 'guide' | 'code' | 'past_fix';
  title: string;
  text: string;
  file_path: string | null;
  score: number;
}

/** What the model answered in one attempt. */
export interface FixProposal {
  status: 'fixed' | 'cannot_fix' | 'false_positive';
  fixed_code: string;
  imports_to_add: string[];
  explanation: string;
  confidence: number; // 0 to 1
}

/** The result of one check (guard, tests, re-scan, ...). */
export interface CheckResult {
  name: 'format' | 'guard' | 'tests' | 'security_test' | 'rescan';
  passed: boolean;
  details: string;
}

/** One try of the fix loop. The proposal is null when the model's answer could not be parsed. */
export interface Attempt {
  number: number;
  seconds: number;
  diff: string;
  proposal: FixProposal | null;
  checks: CheckResult[];
}

/** Everything the server knows about fixing one finding. */
export interface FixResult {
  finding: Finding;
  model: string;
  verdict: Verdict;
  seconds: number;
  diff: string; // unified diff of the final attempt
  patched_file_text: string | null; // full new file, or null when there is no usable fix
  retrieved: RetrievedChunk[];
  attempts: Attempt[];
}

export interface Health {
  ok: boolean;
  models: string[];
  default_model: string;
}

// ---------- Vulnerability names ----------

export const CWE_NAMES: Record<string, string> = {
  'CWE-89': 'SQL injection',
  'CWE-78': 'Command injection',
  'CWE-22': 'Path traversal',
  'CWE-79': 'Cross-site scripting',
  'CWE-798': 'Hard-coded secret',
  'CWE-327': 'Weak cryptography',
  'CWE-502': 'Unsafe deserialization',
};

/** "SQL injection" for the seven known types, otherwise the CWE id or the scanner rule id. */
export function vulnerabilityName(finding: Finding): string {
  return (finding.cwe && CWE_NAMES[finding.cwe]) || finding.cwe || finding.rule_id;
}

/** Short label such as "CWE-89 SQL injection" (or just "CWE-123" / "B105" when the name is unknown). */
export function findingLabel(finding: Finding): string {
  const id = finding.cwe ?? finding.rule_id;
  const name = finding.cwe ? CWE_NAMES[finding.cwe] : undefined;
  return name ? `${id} ${name}` : id;
}

// ---------- Errors ----------

/** The server is not running (or not reachable at patchai.serverUrl). */
export class ServerUnreachableError extends Error {}

/** The server answered with an HTTP error; the message is its "detail" text. */
export class ServerError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

// ---------- Requests ----------

const DEFAULT_URL = 'http://127.0.0.1:8765';
const SECOND = 1000;
const MINUTE = 60 * SECOND;

export function serverUrl(): string {
  const url = vscode.workspace.getConfiguration('patchai').get<string>('serverUrl', DEFAULT_URL).trim();
  return (url || DEFAULT_URL).replace(/\/+$/, '');
}

/** Sends one request and returns the parsed JSON, turning every failure into a readable error. */
async function request<T>(method: 'GET' | 'POST', path: string, body: unknown, timeoutMs: number): Promise<T> {
  const base = serverUrl();
  let response: Response;
  let text: string;
  try {
    response = await fetch(base + path, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    text = await response.text();
  } catch (error) {
    if (isTimeout(error)) {
      throw new Error(`The PatchAI server did not answer within ${Math.round(timeoutMs / SECOND)} seconds.`);
    }
    throw new ServerUnreachableError(`Cannot reach the PatchAI server at ${base}. Is it running?`);
  }

  let data: unknown;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = undefined; // not JSON; handled below
  }

  if (!response.ok) {
    throw new ServerError(`PatchAI server error (${response.status}): ${errorDetail(data, text, response.statusText)}`, response.status);
  }
  if (data === undefined) {
    throw new Error(`The PatchAI server sent an invalid response to ${path}.`);
  }
  return data as T;
}

/** Our own timeout, or Node's built-in fetch timeouts (also five minutes). */
function isTimeout(error: unknown): boolean {
  const err = error as { name?: string; cause?: { code?: string } } | undefined;
  return err?.name === 'TimeoutError' || err?.cause?.code === 'UND_ERR_HEADERS_TIMEOUT' || err?.cause?.code === 'UND_ERR_BODY_TIMEOUT';
}

/** FastAPI sends {"detail": "text"}, or {"detail": [{"msg": ...}]} for invalid requests. */
function errorDetail(data: unknown, text: string, statusText: string): string {
  const detail = (data as { detail?: unknown } | undefined)?.detail;
  if (typeof detail === 'string') {
    return detail;
  }
  if (Array.isArray(detail)) {
    return detail.map(item => (item as { msg?: string }).msg ?? JSON.stringify(item)).join('; ');
  }
  return text.trim() || statusText || 'unknown error';
}

// ---------- Endpoints ----------

export function getHealth(): Promise<Health> {
  return request<Health>('GET', '/health', undefined, 10 * SECOND);
}

export async function scan(projectDir: string): Promise<Finding[]> {
  const data = await request<{ findings: Finding[] }>('POST', '/scan', { project_dir: projectDir }, 3 * MINUTE);
  return data.findings ?? [];
}

/** Asks the server to fix one finding. This runs RAG, the model and all checks, so it can take minutes. */
export async function fix(projectDir: string, finding: Finding, model: string | null): Promise<FixResult> {
  const result = await request<FixResult>('POST', '/fix', { project_dir: projectDir, finding, model }, 5 * MINUTE);
  // Fill in missing fields so the panel never has to guard against them.
  return {
    ...result,
    diff: result.diff ?? '',
    retrieved: result.retrieved ?? [],
    attempts: (result.attempts ?? []).map(attempt => ({
      ...attempt,
      diff: attempt.diff ?? '',
      proposal: attempt.proposal ?? null,
      checks: attempt.checks ?? [],
    })),
  };
}

/** Records the human's decision so the team can learn from approved and rejected fixes. */
export async function sendDecision(
  projectDir: string,
  findingId: string,
  decision: Decision,
  reason: string | null,
  model: string,
): Promise<void> {
  await request<{ ok: boolean }>(
    'POST',
    '/decision',
    { project_dir: projectDir, finding_id: findingId, decision, reason, model },
    30 * SECOND,
  );
}
