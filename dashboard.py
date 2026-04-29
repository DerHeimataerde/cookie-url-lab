#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen
from flask import Flask, jsonify, render_template_string, request

HOST = "127.0.0.1"
PORT = 8890
TRACKER_BASE = "http://127.0.0.1:8765"

ROOT = Path(__file__).resolve().parent
CAPTURE_DEFAULT = "capture.json"
FINDINGS_DEFAULT = "findings.json"

app = Flask(__name__)


class AppState:
    def __init__(self):
        self.lock = threading.RLock()
        self.pipeline_running = False
        self.pipeline_started_at: float | None = None
        self.pipeline_finished_at: float | None = None
        self.pipeline_error: str | None = None
        self.pipeline_logs: list[str] = []
        self.last_summary: dict[str, Any] = {}

        self.server_process: subprocess.Popen[str] | None = None
        self.server_logs: list[str] = []

    def append_pipeline_log(self, line: str):
        with self.lock:
            self.pipeline_logs.append(f"[{time.strftime('%H:%M:%S')}] {line}")
            self.pipeline_logs = self.pipeline_logs[-300:]

    def append_server_log(self, line: str):
        with self.lock:
            self.server_logs.append(f"[{time.strftime('%H:%M:%S')}] {line}")
            self.server_logs = self.server_logs[-200:]


state = AppState()


def _python_cmd() -> str:
    return sys.executable


def tracker_reachable(base_url: str = TRACKER_BASE, timeout: float = 1.0) -> bool:
    try:
        with urlopen(base_url, timeout=timeout):
            return True
    except (URLError, OSError, ValueError):
        return False


def wait_for_tracker(base_url: str = TRACKER_BASE, timeout: float = 8.0, poll: float = 0.25) -> bool:
  """Poll until the tracker endpoint is reachable or timeout (seconds) elapses."""
  start = time.time()
  while time.time() - start < timeout:
    if tracker_reachable(base_url, timeout=1.0):
      return True
    time.sleep(poll)
  return False


def _run_step(args: list[str], label: str):
    state.append_pipeline_log(f"Running {label}: {' '.join(args)}")
    proc = subprocess.run(
        args,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.stdout:
        for line in proc.stdout.splitlines():
            state.append_pipeline_log(f"[{label}] {line}")
    if proc.stderr:
        for line in proc.stderr.splitlines():
            state.append_pipeline_log(f"[{label}:stderr] {line}")
    if proc.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {proc.returncode}")


def _read_json_if_exists(path: Path):
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _server_reader_thread(proc: subprocess.Popen[str]):
    if proc.stdout is None:
        return
    for line in proc.stdout:
        state.append_server_log(line.rstrip())


def start_lab_server() -> tuple[bool, str]:
    if tracker_reachable():
        return False, "Tracker endpoint is already reachable (possibly external)."

    with state.lock:
        proc = state.server_process
        if proc is not None and proc.poll() is None:
            return False, "Server is already running."

    cmd = [_python_cmd(), "server.py"]
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    with state.lock:
        state.server_process = proc
    state.append_server_log("Started local lab server process.")

    t = threading.Thread(target=_server_reader_thread, args=(proc,), daemon=True)
    t.start()
    # Wait briefly for the server to become reachable
    if wait_for_tracker(timeout=6.0):
      state.append_server_log("Tracker endpoint is reachable after start.")
      return True, "Server started and reachable."
    else:
      state.append_server_log("Server process started but tracker endpoint not reachable yet.")
      return True, "Server started but tracker not reachable yet."


def stop_lab_server() -> tuple[bool, str]:
    with state.lock:
        proc = state.server_process

    if proc is None or proc.poll() is not None:
        if tracker_reachable():
            return False, "Tracker is running externally; stop it in its own terminal."
        return False, "Server is not running."

    proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)

    with state.lock:
        state.server_process = None
    state.append_server_log("Stopped local lab server process.")

    return True, "Server stopped."


def run_pipeline_async(config: dict[str, Any]):
    with state.lock:
        if state.pipeline_running:
            return False
        state.pipeline_running = True
        state.pipeline_started_at = time.time()
        state.pipeline_finished_at = None
        state.pipeline_error = None
        state.pipeline_logs = []

    def worker():
        try:
            base = str(config.get("base", TRACKER_BASE))
            auto_start = bool(config.get("auto_start_server", True))

            if auto_start and not tracker_reachable(base):
              ok, msg = start_lab_server()
              state.append_pipeline_log(msg)
              # wait for the tracker to accept connections
              if not wait_for_tracker(base, timeout=8.0):
                state.append_pipeline_log("Tracker not reachable after auto-start; aborting pipeline.")
                raise RuntimeError("Tracker not reachable after auto-start")
            elif tracker_reachable(base):
                state.append_pipeline_log("Tracker endpoint already reachable; using existing server.")

            runs = int(config.get("runs", 3))
            threshold = float(config.get("threshold", 0.95))
            capture = str(config.get("capture", CAPTURE_DEFAULT))
            findings = str(config.get("findings", FINDINGS_DEFAULT))
            cookie_name = str(config.get("cookie_name", "tid_b64"))
            param_name = str(config.get("param_name", "xid"))

            _run_step(
                [
                    _python_cmd(),
                    "crawler.py",
                    "--base",
                    base,
                    "--output",
                    capture,
                    "--runs",
                    str(runs),
                ],
                "crawler",
            )

            _run_step(
                [
                    _python_cmd(),
                    "detector.py",
                    capture,
                    "--threshold",
                    str(threshold),
                    "--output",
                    findings,
                ],
                "detector",
            )

            _run_step(
                [_python_cmd(), "reverse_engineer_toy.py", capture, cookie_name, param_name],
                "reverse_engineer_toy",
            )

            capture_data = _read_json_if_exists(ROOT / capture)
            findings_data = _read_json_if_exists(ROOT / findings)

            summary = {
                "capture_path": capture,
                "findings_path": findings,
                "capture_events": len(capture_data) if isinstance(capture_data, list) else None,
                "findings_count": len(findings_data) if isinstance(findings_data, list) else None,
                "top_findings": findings_data[:5] if isinstance(findings_data, list) else [],
            }

            with state.lock:
                state.last_summary = summary

            state.append_pipeline_log("Pipeline complete.")
        except Exception as exc:
            with state.lock:
                state.pipeline_error = str(exc)
            state.append_pipeline_log(f"Pipeline error: {exc}")
        finally:
            with state.lock:
                state.pipeline_running = False
                state.pipeline_finished_at = time.time()

    threading.Thread(target=worker, daemon=True).start()
    return True


PAGE = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Tracker Lab Dashboard</title>
  <style>
    :root {
      --bg: #f4f0e8;
      --ink: #1f2a2b;
      --accent: #0c6d67;
      --accent-2: #d4572f;
      --panel: rgba(255, 253, 247, 0.9);
      --shadow: rgba(31, 42, 43, 0.15);
      --muted: #5b6667;
      --ok: #2d7d46;
      --warn: #a33f22;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Avenir Next", "Century Gothic", "Trebuchet MS", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 15% 10%, rgba(12,109,103,0.24), transparent 36%),
        radial-gradient(circle at 88% 8%, rgba(212,87,47,0.21), transparent 32%),
        linear-gradient(160deg, #f4f0e8 0%, #eee6d7 46%, #e7ddc9 100%);
      min-height: 100vh;
      padding: 24px;
    }

    .layout {
      max-width: 1200px;
      margin: 0 auto;
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 18px;
    }

    .hero {
      grid-column: 1 / -1;
      background: var(--panel);
      border: 1px solid rgba(31, 42, 43, 0.08);
      border-radius: 18px;
      padding: 20px 24px;
      box-shadow: 0 10px 20px var(--shadow);
      animation: slideDown 0.55s ease;
    }

    h1 {
      margin: 0;
      letter-spacing: 0.02em;
      font-size: clamp(1.5rem, 2.8vw, 2.4rem);
      font-weight: 700;
    }

    .sub {
      margin: 8px 0 0;
      color: var(--muted);
      max-width: 86ch;
    }

    .card {
      background: var(--panel);
      border: 1px solid rgba(31, 42, 43, 0.08);
      border-radius: 16px;
      padding: 18px;
      box-shadow: 0 10px 20px var(--shadow);
      animation: rise 0.5s ease;
    }

    .card h2 {
      margin-top: 0;
      margin-bottom: 12px;
      font-size: 1.05rem;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }

    label {
      display: block;
      font-size: 0.82rem;
      color: var(--muted);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    input {
      width: 100%;
      border: 1px solid rgba(31, 42, 43, 0.2);
      border-radius: 10px;
      padding: 10px;
      font-size: 0.95rem;
      background: #fffefb;
      color: var(--ink);
    }

    .buttons {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }

    button {
      border: none;
      border-radius: 999px;
      padding: 10px 14px;
      font-weight: 600;
      font-size: 0.9rem;
      cursor: pointer;
      transition: transform 120ms ease, filter 120ms ease;
    }

    button:hover { transform: translateY(-1px); filter: brightness(1.03); }

    .primary { background: var(--accent); color: #fff; }
    .secondary { background: var(--accent-2); color: #fff; }
    .ghost { background: rgba(31, 42, 43, 0.08); color: var(--ink); }

    .status {
      margin-top: 10px;
      font-weight: 600;
    }

    .ok { color: var(--ok); }
    .warn { color: var(--warn); }

    pre {
      margin: 0;
      background: #202628;
      color: #f0f0ea;
      padding: 12px;
      border-radius: 12px;
      font-size: 0.82rem;
      line-height: 1.35;
      max-height: 280px;
      overflow: auto;
      white-space: pre-wrap;
    }

    .small { color: var(--muted); font-size: 0.86rem; }
    .hint {
      margin: 6px 2px 0;
      color: var(--muted);
      font-size: 0.78rem;
      line-height: 1.3;
    }

    @keyframes rise {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes slideDown {
      from { opacity: 0; transform: translateY(-8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @media (max-width: 930px) {
      .layout { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class=\"layout\">
    <section class=\"hero\">
      <h1>Local Tracker Lab Dashboard</h1>
      <p class=\"sub\">Run crawler, detector, and reverse-engineer helper from one place. Start the synthetic server, launch a full pipeline, and inspect top findings without switching shells.</p>
    </section>

    <section class=\"card\">
      <h2>Pipeline Controls</h2>
      <div class=\"grid\">
        <div>
          <label for=\"base\">Base URL</label>
          <input id=\"base\" value=\"http://127.0.0.1:8765\" />
          <p class=\"hint\">Target lab server URL used by the crawler for all scenario requests.</p>
        <div>
          <label for="paramSelect">URL Parameter</label>
          <select id="paramSelect" disabled><option>Run crawler to populate</option></select>
          <p class="hint">Choose which URL parameter to analyze (populated from capture).</p>
        </div>
        <div>
          <label for="cookieSelect">Cookie Name</label>
          <select id="cookieSelect" disabled><option>Run crawler to populate</option></select>
          <p class="hint">Choose which cookie to analyze (populated from capture).</p>
        </div>
        </div>
        <div>
          <label for=\"capture\">Capture File</label>
          <input id=\"capture\" value=\"capture.json\" />
          <p class=\"hint\">Output path for crawler event logs written during this pipeline run.</p>
        </div>
        <div>
          <label for=\"findings\">Findings File</label>
          <input id=\"findings\" value=\"findings.json\" />
          <p class=\"hint\">Output path for ranked detector mappings produced after analysis.</p>
        </div>
      </div>

      <div class=\"buttons\">
        <button class=\"primary\" onclick=\"runPipeline()\">Run Full Pipeline</button>
        <button class=\"secondary\" onclick=\"runCrawler()\">Run Crawler</button>
        <button class=\"secondary\" onclick=\"runDetector()\">Run Detector</button>
        <button class=\"secondary\" onclick=\"runReverse()\">Run Reverse Helper</button>
        <button class=\"ghost\" onclick=\"refreshState()\">Refresh State</button>
      </div>
      <p class=\"hint\">Run Full Pipeline executes crawler, detector, and reverse-engineer helper in sequence.</p>
      <p id=\"pipelineStatus\" class=\"status small\">Idle</p>
    </section>

    <section class=\"card\">
      <h2>Server Controls</h2>
      <div class=\"buttons\">
        <button class=\"secondary\" onclick=\"startServer()\">Start Server</button>
        <button class=\"ghost\" onclick=\"stopServer()\">Stop Server</button>
      </div>
      <p id=\"serverStatus\" class=\"status small\">Checking...</p>
      <p class=\"small\">Synthetic tracker endpoint expected at <strong>http://127.0.0.1:8765</strong>.</p>
    </section>
    <section class="card">
      <h2>Data Controls</h2>
      <div class="buttons">
        <button class="ghost" onclick="clearData()">Clear Captures & Findings</button>
      </div>
      <p class="hint">Remove capture.json and findings.json, and reset the UI state.</p>
    </section>
    <section class=\"card\">
      <h2>Pipeline Log</h2>
      <pre id=\"pipelineLog\">No pipeline run yet.</pre>
    </section>

    <section class=\"card\">
      <h2>Server Log</h2>
      <pre id=\"serverLog\">No server log yet.</pre>
    </section>

    <section class=\"card\" style=\"grid-column: 1 / -1;\">
      <h2>Findings</h2>
      <div id=\"findingsView\" style=\"overflow-x: auto;\">No findings yet.</div>
    </section>

    <section class=\"card\" style=\"grid-column: 1 / -1;\">
      <h2>Latest Summary</h2>
      <pre id=\"summary\">No summary yet.</pre>
    </section>
  </main>

<script>
async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload || {})
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.message || ('HTTP ' + res.status));
  }
  return data;
}

function readConfig() {
  // Safely read values from either legacy inputs or new selects with defaults.
  function elValue(id, def) {
    const el = document.getElementById(id);
    if (!el) return def;
    try { return el.value; } catch (e) { return def; }
  }
  const cookieEl = document.getElementById('cookieSelect') || document.getElementById('cookie');
  const paramEl = document.getElementById('paramSelect') || document.getElementById('param');
  return {
    auto_start_server: true,
    base: elValue('base', 'http://127.0.0.1:8765'),
    runs: Number(elValue('runs', '3')),
    threshold: Number(elValue('threshold', '0.95')),
    capture: elValue('capture', 'capture.json'),
    findings: elValue('findings', 'findings.json'),
    cookie_name: cookieEl ? (cookieEl.value || null) : null,
    param_name: paramEl ? (paramEl.value || null) : null,
  };
}

function setStatus(elId, text, ok) {
  const el = document.getElementById(elId);
  el.textContent = text;
  el.className = ok === null ? 'status small' : ('status ' + (ok ? 'ok' : 'warn'));
}

async function startServer() {
  try {
    const data = await postJson('/api/server/start', {});
    setStatus('serverStatus', data.message, data.ok);
  } catch (err) {
    setStatus('serverStatus', 'Failed to start server: ' + err.message, false);
  }
  await refreshState();
}

async function stopServer() {
  try {
    const data = await postJson('/api/server/stop', {});
    setStatus('serverStatus', data.message, data.ok);
  } catch (err) {
    setStatus('serverStatus', 'Failed to stop server: ' + err.message, false);
  }
  await refreshState();
}

async function clearData() {
  if (!confirm('Clear all captures and findings files? This cannot be undone.')) {
    return;
  }
  try {
    const data = await postJson('/api/clear', {});
    setStatus('pipelineStatus', data.message, data.ok);
    document.getElementById('findingsView').textContent = 'No findings yet.';
    document.getElementById('summary').textContent = 'No summary yet.';
    const psel = document.getElementById('paramSelect');
    const csel = document.getElementById('cookieSelect');
    if (psel) psel.innerHTML = '<option>Run crawler to populate</option>';
    if (csel) csel.innerHTML = '<option>Run crawler to populate</option>';
  } catch (err) {
    setStatus('pipelineStatus', 'Failed to clear data: ' + err.message, false);
  }
  await refreshState();
}

async function runPipeline() {
  const cfg = readConfig();
  try {
    const data = await postJson('/api/pipeline/run', cfg);
    setStatus('pipelineStatus', data.message, data.ok);
  } catch (err) {
    setStatus('pipelineStatus', 'Failed to start pipeline: ' + err.message, false);
  }
  await refreshState();
}

async function runCrawler() {
  const cfg = readConfig();
  try {
    const data = await postJson('/api/pipeline/crawl', cfg);
    setStatus('pipelineStatus', data.message, data.ok);
  } catch (err) {
    setStatus('pipelineStatus', 'Failed to start crawler: ' + err.message, false);
  }
  await refreshState();
}

async function runDetector() {
  const cfg = readConfig();
  try {
    const data = await postJson('/api/pipeline/detect', cfg);
    setStatus('pipelineStatus', data.message, data.ok);
  } catch (err) {
    setStatus('pipelineStatus', 'Failed to start detector: ' + err.message, false);
  }
  await refreshState();
}

async function runReverse() {
  const cfg = readConfig();
  try {
    const data = await postJson('/api/pipeline/reverse', cfg);
    setStatus('pipelineStatus', data.message, data.ok);
  } catch (err) {
    setStatus('pipelineStatus', 'Failed to start reverse helper: ' + err.message, false);
  }
  await refreshState();
}

let lastMetadata = { params: [], cookies: [] };

async function loadMetadata() {
  const capture = document.getElementById('capture').value;
  try {
    const res = await fetch('/api/metadata?capture=' + encodeURIComponent(capture));
    const data = await res.json();
    
    // Check if metadata has actually changed
    const paramsChanged = JSON.stringify(data.params || []) !== JSON.stringify(lastMetadata.params || []);
    const cookiesChanged = JSON.stringify(data.cookies || []) !== JSON.stringify(lastMetadata.cookies || []);
    
    if (!paramsChanged && !cookiesChanged) {
      return; // Metadata hasn't changed, don't update
    }
    
    lastMetadata = data;
    
    const psel = document.getElementById('paramSelect');
    const csel = document.getElementById('cookieSelect');
    
    // Preserve current selections
    const prevParamValue = psel.value;
    const prevCookieValue = csel.value;
    
    psel.innerHTML = '';
    csel.innerHTML = '';
    
    // If no metadata yet, keep selects disabled and show instruction
    if (!data.params || data.params.length === 0) {
      psel.appendChild(new Option('Run crawler to populate', ''));
      psel.disabled = true;
      psel.value = ''; // Reset to empty
    } else {
      // add 'All' option
      psel.appendChild(new Option('All', ''));
      data.params.forEach(p => psel.appendChild(new Option(p, p)));
      psel.disabled = false;
      // Restore previous selection if it still exists, otherwise default to 'All'
      if (prevParamValue && Array.from(psel.options).some(opt => opt.value === prevParamValue)) {
        psel.value = prevParamValue;
      } else {
        psel.value = '';
      }
    }
    if (!data.cookies || data.cookies.length === 0) {
      csel.appendChild(new Option('Run crawler to populate', ''));
      csel.disabled = true;
      csel.value = ''; // Reset to empty
    } else {
      csel.appendChild(new Option('All', ''));
      data.cookies.forEach(c => csel.appendChild(new Option(c, c)));
      csel.disabled = false;
      // Restore previous selection if it still exists, otherwise default to 'All'
      if (prevCookieValue && Array.from(csel.options).some(opt => opt.value === prevCookieValue)) {
        csel.value = prevCookieValue;
      } else {
        csel.value = '';
      }
    }
  } catch (err) {
    console.warn('Failed to load metadata', err);
  }
}

async function refreshState() {
  let data;
  try {
    const res = await fetch('/api/state');
    data = await res.json();
  } catch (err) {
    setStatus('serverStatus', 'Dashboard API unavailable', false);
    setStatus('pipelineStatus', 'Waiting for dashboard API...', null);
    return;
  }

  if (data.server_running) {
    setStatus('serverStatus', 'Server running (dashboard-managed)', true);
  } else if (data.tracker_reachable) {
    setStatus('serverStatus', 'Server running (external process)', true);
  } else {
    setStatus('serverStatus', 'Server not running', false);
  }

  if (data.pipeline_running) {
    setStatus('pipelineStatus', 'Pipeline running...', null);
  } else if (data.pipeline_error) {
    setStatus('pipelineStatus', 'Pipeline failed: ' + data.pipeline_error, false);
  } else if (data.pipeline_finished_at) {
    setStatus('pipelineStatus', 'Pipeline finished successfully', true);
  } else {
    setStatus('pipelineStatus', 'Idle', null);
  }

  document.getElementById('pipelineLog').textContent = (data.pipeline_logs || []).join('\\n') || 'No pipeline log yet.';
  document.getElementById('serverLog').textContent = (data.server_logs || []).join('\\n') || 'No server log yet.';
  document.getElementById('summary').textContent = JSON.stringify(data.last_summary || {}, null, 2) || 'No summary yet.';
  
  // Fetch all findings from api_findings instead of just top_findings
  try {
    const findingsRes = await fetch('/api/findings');
    const findingsData = await findingsRes.json();
    const findings = (findingsData.findings && Array.isArray(findingsData.findings)) ? findingsData.findings : [];
    renderFindingsList(findings);
  } catch (err) {
    console.warn('Failed to load findings', err);
    renderFindingsList([]);
  }
  
  // refresh metadata selects
  loadMetadata();
}

// initial refresh handled by wrapper below
// Findings chart support
function renderFindingsList(findings) {
  const view = document.getElementById('findingsView');
  if (!view) return;
  if (!findings || findings.length === 0) {
    view.innerHTML = '<div class="small">No findings yet.</div>';
    return;
  }
  // build HTML table of findings
  const rows = findings.map((f, i) => {
    const m = f.mapping || {};
    const example = (f.examples && f.examples[0]) || {};
    const url_param = m.param_or_index || example.param_or_index || '';
    const url_value = example.token || '';
    const cookie_key = m.cookie_name || example.cookie_name || '';
    const cookie_value = example.cookie_value || '';
    const method = m.transform || example.transform || '';
    const score = (f.avg_score || example.score || 0).toFixed ? (Number(f.avg_score || example.score || 0).toFixed(3)) : (f.avg_score || example.score || 0);
    const decoded = example.transformed || '';
    return `
      <tr>
        <td style="padding:10px;border-bottom:1px solid rgba(0,0,0,0.1);text-align:center;font-weight:600;">${i+1}</td>
        <td style="padding:10px;border-bottom:1px solid rgba(0,0,0,0.1);"><code>${escapeHtml(url_param)}</code></td>
        <td style="padding:10px;border-bottom:1px solid rgba(0,0,0,0.1);"><code>${escapeHtml(url_value)}</code></td>
        <td style="padding:10px;border-bottom:1px solid rgba(0,0,0,0.1);"><code>${escapeHtml(cookie_key)}</code></td>
        <td style="padding:10px;border-bottom:1px solid rgba(0,0,0,0.1);"><code>${escapeHtml(cookie_value)}</code></td>
        <td style="padding:10px;border-bottom:1px solid rgba(0,0,0,0.1);text-align:center;">${escapeHtml(method)}</td>
        <td style="padding:10px;border-bottom:1px solid rgba(0,0,0,0.1);text-align:center;font-weight:600;">${score}</td>
        <td style="padding:10px;border-bottom:1px solid rgba(0,0,0,0.1);"><code>${escapeHtml(decoded)}</code></td>
      </tr>`;
  });
  const table = `
    <table style="width:100%;border-collapse:collapse;font-size:0.9rem;">
      <thead>
        <tr style="background:rgba(12,109,103,0.1);">
          <th style="padding:10px;text-align:left;font-weight:700;">#</th>
          <th style="padding:10px;text-align:left;font-weight:700;">URL Param</th>
          <th style="padding:10px;text-align:left;font-weight:700;">URL Value</th>
          <th style="padding:10px;text-align:left;font-weight:700;">Cookie Key</th>
          <th style="padding:10px;text-align:left;font-weight:700;">Cookie Value</th>
          <th style="padding:10px;text-align:left;font-weight:700;">Transform</th>
          <th style="padding:10px;text-align:left;font-weight:700;">Score</th>
          <th style="padding:10px;text-align:left;font-weight:700;">Decoded</th>
        </tr>
      </thead>
      <tbody>
        ${rows.join('')}
      </tbody>
    </table>`;
  view.innerHTML = table;
}

function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

// Initial refresh
refreshState();
setInterval(refreshState, 2000);
</script>
</body>
</html>
"""


@app.get("/")
def index():
    return render_template_string(PAGE)


@app.get("/api/state")
def api_state():
    with state.lock:
        server_running = state.server_process is not None and state.server_process.poll() is None
        reachable = tracker_reachable()
        return jsonify(
            {
                "pipeline_running": state.pipeline_running,
                "pipeline_started_at": state.pipeline_started_at,
                "pipeline_finished_at": state.pipeline_finished_at,
                "pipeline_error": state.pipeline_error,
                "pipeline_logs": state.pipeline_logs,
                "last_summary": state.last_summary,
                "server_running": server_running,
                "tracker_reachable": reachable,
                "server_logs": state.server_logs,
            }
        )


@app.post("/api/server/start")
def api_server_start():
    ok, msg = start_lab_server()
    return jsonify({"ok": ok, "message": msg})


@app.post("/api/server/stop")
def api_server_stop():
    ok, msg = stop_lab_server()
    return jsonify({"ok": ok, "message": msg})


@app.post("/api/pipeline/run")
def api_pipeline_run():
    payload = request.get_json(silent=True) or {}
    ok = run_pipeline_async(payload)
    if not ok:
        return jsonify({"ok": False, "message": "Pipeline is already running."}), 409
    return jsonify({"ok": True, "message": "Pipeline started."})


def _start_step_thread(label: str, args: list[str]):
  def worker():
    try:
      _run_step(args, label)
    except Exception as exc:
      state.append_pipeline_log(f"{label} error: {exc}")

  threading.Thread(target=worker, daemon=True).start()


@app.post("/api/pipeline/crawl")
def api_pipeline_crawl():
  p = request.get_json(silent=True) or {}
  base = str(p.get("base", TRACKER_BASE))
  runs = int(p.get("runs", 3))
  auto_start = bool(p.get("auto_start_server", True))
  # auto-start local tracker if requested and not reachable
  if auto_start and not tracker_reachable(base):
    ok, msg = start_lab_server()
    state.append_pipeline_log(msg)
    # wait for the tracker to be reachable before launching crawler
    if not wait_for_tracker(base, timeout=8.0):
      state.append_pipeline_log("Tracker not reachable after auto-start; not starting crawler.")
      return jsonify({"ok": False, "message": "Tracker not reachable after auto-start."}), 503
  capture = str(p.get("capture", CAPTURE_DEFAULT))
  args = [_python_cmd(), "crawler.py", "--base", base, "--output", capture, "--runs", str(runs)]
  _start_step_thread("crawler", args)
  return jsonify({"ok": True, "message": "Crawler started."})


@app.post("/api/pipeline/detect")
def api_pipeline_detect():
  p = request.get_json(silent=True) or {}
  capture = str(p.get("capture", CAPTURE_DEFAULT))
  findings = str(p.get("findings", FINDINGS_DEFAULT))
  threshold = float(p.get("threshold", 0.95))
  param_name = p.get("param_name") or p.get("param") or ""
  cookie_name = p.get("cookie_name") or p.get("cookie") or ""

  def worker():
    try:
      args = [_python_cmd(), "detector.py", capture, "--threshold", str(threshold), "--output", findings]
      _run_step(args, "detector")
      # after detector finishes, load findings and apply optional filters
      full = ROOT / findings
      data = []
      if full.exists():
        try:
          with full.open("r", encoding="utf-8") as f:
            data = json.load(f) or []
        except Exception:
          data = []

      # apply filters if provided (non-empty strings)
      def keep(fobj):
        try:
          m = fobj.get("mapping", {})
          if param_name:
            if str(m.get("param_or_index") or "") != str(param_name):
              return False
          if cookie_name:
            if str(m.get("cookie_name") or "") != str(cookie_name):
              return False
          return True
        except Exception:
          return False

      filtered = [f for f in (data or []) if keep(f)] if (param_name or cookie_name) else (data or [])
      with state.lock:
        state.last_summary = state.last_summary or {}
        state.last_summary["findings_path"] = findings
        state.last_summary["top_findings"] = filtered[:50]
      state.append_pipeline_log(f"Loaded {len(filtered)} findings from {findings}")
    except Exception as exc:
      state.append_pipeline_log(f"detector error: {exc}")

  threading.Thread(target=worker, daemon=True).start()
  return jsonify({"ok": True, "message": "Detector started."})


@app.post("/api/pipeline/reverse")
def api_pipeline_reverse():
  p = request.get_json(silent=True) or {}
  capture = str(p.get("capture", CAPTURE_DEFAULT))
  cookie_name = str(p.get("cookie_name") or p.get("cookie") or "tid_b64")
  param_name = str(p.get("param_name") or p.get("param") or "xid")
  args = [_python_cmd(), "reverse_engineer_toy.py", capture, cookie_name, param_name]
  _start_step_thread("reverse_engineer_toy", args)
  return jsonify({"ok": True, "message": "Reverse helper started."})


@app.get("/api/metadata")
def api_metadata():
  capture = request.args.get("capture", CAPTURE_DEFAULT)
  path = ROOT / capture
  params = set()
  cookies = set()
  try:
    if path.exists():
      with path.open("r", encoding="utf-8") as f:
        events = json.load(f)
      from urllib.parse import urlparse, parse_qsl

      for ev in events:
        url = ev.get("request_url", "")
        try:
          q = urlparse(url).query
          for k, _ in parse_qsl(q, keep_blank_values=True):
            params.add(k)
        except Exception:
          pass
        for ck in ev.get("set_cookies", {}) or {}:
          cookies.add(ck)
        for ck in ev.get("cookies_sent", {}) or {}:
          cookies.add(ck)
  except Exception:
    pass
  return jsonify({"params": sorted(list(params)), "cookies": sorted(list(cookies))})


@app.get("/api/findings")
def api_findings():
    path = request.args.get("path", FINDINGS_DEFAULT)
    full = ROOT / path
    data = None
    try:
        if full.exists():
            with full.open("r", encoding="utf-8") as f:
                data = json.load(f)
    except Exception:
        data = None
    return jsonify({"path": path, "ok": bool(data is not None), "findings": data or []})


@app.post("/api/clear")
def api_clear():
    """Clear capture.json and findings.json files and reset UI state."""
    try:
        capture = ROOT / CAPTURE_DEFAULT
        findings = ROOT / FINDINGS_DEFAULT
        if capture.exists():
            capture.unlink()
        if findings.exists():
            findings.unlink()
        with state.lock:
            state.last_summary = {}
        state.append_pipeline_log("Cleared capture and findings files.")
        return jsonify({"ok": True, "message": "Capture and findings cleared."})
    except Exception as exc:
        return jsonify({"ok": False, "message": f"Failed to clear: {exc}"}), 500


def clear_previous_files():
    """Clear any previous capture.json and findings.json files on startup."""
    capture = ROOT / CAPTURE_DEFAULT
    findings = ROOT / FINDINGS_DEFAULT
    if capture.exists():
        capture.unlink()
        print(f"Cleared {capture}")
    if findings.exists():
        findings.unlink()
        print(f"Cleared {findings}")


def main():
    clear_previous_files()
    app.run(host=HOST, port=PORT, debug=False)


if __name__ == "__main__":
    main()
