package wizard

// indexHTML is the embedded wizard HTML page
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Insights Generator</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --accent-hover: #79c0ff;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #d29922;
    --radius: 6px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  .container { max-width: 960px; margin: 0 auto; padding: 24px; }
  header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 0 24px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 24px;
  }
  header h1 { font-size: 24px; font-weight: 600; }
  header span { color: var(--text-muted); font-size: 14px; }

  /* Scan bar */
  .scan-bar {
    display: flex;
    gap: 8px;
    margin-bottom: 24px;
  }
  .scan-bar input {
    flex: 1;
    padding: 8px 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-size: 14px;
  }
  .scan-bar input::placeholder { color: var(--text-muted); }
  .scan-bar input:focus { outline: none; border-color: var(--accent); }

  /* Buttons */
  button, .btn {
    padding: 8px 16px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface);
    color: var(--text);
    font-size: 14px;
    cursor: pointer;
    transition: border-color 0.15s;
    white-space: nowrap;
  }
  button:hover { border-color: var(--text-muted); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-primary {
    background: #238636;
    border-color: #2ea043;
    font-weight: 600;
  }
  .btn-primary:hover { background: #2ea043; border-color: #3fb950; }
  .btn-accent {
    background: #1f6feb;
    border-color: #388bfd;
  }
  .btn-accent:hover { background: #388bfd; }
  .btn-sm { padding: 4px 10px; font-size: 12px; }
  .btn-danger { color: var(--red); }
  .btn-danger:hover { border-color: var(--red); }

  /* Tabs */
  .tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 20px;
  }
  .tab {
    padding: 10px 16px;
    border: none;
    background: none;
    color: var(--text-muted);
    font-size: 14px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--text); border-bottom-color: var(--accent); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Form */
  .section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    margin-bottom: 16px;
  }
  .section-title {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 12px;
  }
  .field:last-child { margin-bottom: 0; }
  .field label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .field input, .field select, .field textarea {
    padding: 6px 10px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-size: 14px;
    font-family: inherit;
  }
  .field input:focus, .field select:focus, .field textarea:focus {
    outline: none;
    border-color: var(--accent);
  }
  .field textarea { resize: vertical; min-height: 60px; }
  .field-row { display: flex; gap: 12px; }
  .field-row .field { flex: 1; }

  .checkbox-field {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .checkbox-field input[type="checkbox"] {
    width: 16px;
    height: 16px;
    accent-color: var(--accent);
  }
  .checkbox-field label {
    font-size: 14px;
    color: var(--text);
    cursor: pointer;
  }

  /* List items */
  .list-item {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
    margin-bottom: 8px;
    position: relative;
  }
  .list-item .remove-btn {
    position: absolute;
    top: 8px;
    right: 8px;
  }

  /* Field-level validation errors */
  .field-error {
    font-size: 12px;
    color: var(--red);
    margin-top: 2px;
  }
  .field-warning {
    font-size: 12px;
    color: var(--yellow);
    margin-top: 2px;
  }
  .field.has-error input,
  .field.has-error select,
  .field.has-error textarea {
    border-color: var(--red);
  }
  .field.has-warning input,
  .field.has-warning select,
  .field.has-warning textarea {
    border-color: var(--yellow);
  }
  .section-error {
    font-size: 13px;
    color: var(--red);
    background: rgba(248, 81, 73, 0.1);
    border: 1px solid rgba(248, 81, 73, 0.3);
    border-radius: var(--radius);
    padding: 6px 10px;
    margin-bottom: 8px;
  }
  .section-warning {
    font-size: 13px;
    color: var(--yellow);
    background: rgba(210, 153, 34, 0.1);
    border: 1px solid rgba(210, 153, 34, 0.3);
    border-radius: var(--radius);
    padding: 6px 10px;
    margin-bottom: 8px;
  }

  /* YAML preview */
  .yaml-preview {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
    font-size: 13px;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 600px;
    overflow-y: auto;
    color: var(--text);
  }

  /* Status */
  .status-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 0;
    font-size: 13px;
    color: var(--text-muted);
    min-height: 32px;
  }
  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Action bar */
  .action-bar {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    margin-top: 16px;
  }

  /* Toast */
  .toast {
    position: fixed;
    bottom: 24px;
    right: 24px;
    padding: 12px 20px;
    border-radius: var(--radius);
    font-size: 14px;
    z-index: 1000;
    animation: slideIn 0.2s ease;
  }
  .toast-success { background: #238636; color: white; }
  .toast-error { background: #da3633; color: white; }
  @keyframes slideIn { from { transform: translateY(20px); opacity: 0; } }

  .inline-banner {
    border-radius: var(--radius);
    padding: 12px 16px;
    font-size: 13px;
    line-height: 1.6;
  }
  .inline-banner.pass {
    background: rgba(63, 185, 80, 0.1);
    border: 1px solid var(--green);
    color: var(--green);
  }
  .inline-banner.fail {
    background: rgba(248, 81, 73, 0.1);
    border: 1px solid var(--red);
    color: var(--red);
  }
  .inline-banner.warn {
    background: rgba(210, 153, 34, 0.1);
    border: 1px solid var(--yellow);
    color: var(--yellow);
  }
  .inline-banner .banner-title { font-weight: 600; margin-bottom: 4px; }
  .inline-banner .banner-item { padding: 1px 0; }
  .empty-state {
    padding: 48px;
    color: var(--text-muted);
  }
  .empty-state p { margin-top: 8px; font-size: 14px; }

  /* Sticky error summary banner */
  .sticky-errors {
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(248, 81, 73, 0.12);
    border: 1px solid rgba(248, 81, 73, 0.4);
    border-radius: var(--radius);
    padding: 10px 16px;
    margin-bottom: 16px;
    font-size: 13px;
    backdrop-filter: blur(8px);
  }
  .sticky-errors .sticky-title {
    font-weight: 600;
    color: var(--red);
    margin-bottom: 4px;
  }
  .sticky-errors .sticky-link {
    color: var(--red);
    cursor: pointer;
    text-decoration: underline;
    text-decoration-style: dotted;
    text-underline-offset: 2px;
  }
  .sticky-errors .sticky-link:hover {
    text-decoration-style: solid;
    color: #ff7b72;
  }
  .sticky-errors .sticky-list {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 12px;
    margin-top: 4px;
  }
  .sticky-warnings {
    position: sticky;
    top: 0;
    z-index: 99;
    background: rgba(210, 153, 34, 0.12);
    border: 1px solid rgba(210, 153, 34, 0.4);
    border-radius: var(--radius);
    padding: 10px 16px;
    margin-bottom: 16px;
    font-size: 13px;
    backdrop-filter: blur(8px);
  }
  .sticky-warnings .sticky-title {
    font-weight: 600;
    color: var(--yellow);
  }

  /* Confirm dialog overlay */
  .dialog-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.6);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .dialog-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    max-width: 440px;
    width: 90%;
  }
  .dialog-box h3 { margin-bottom: 12px; font-size: 16px; }
  .dialog-box p { color: var(--text-muted); font-size: 14px; margin-bottom: 16px; }
  .dialog-actions { display: flex; gap: 8px; justify-content: flex-end; }
</style>
</head>
<body>
<div class="container">
  <header>
    <svg width="32" height="32" viewBox="0 0 16 16" fill="currentColor" style="color:var(--accent)">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
    </svg>
    <h1>Security Insights Generator</h1>
    <span>OSSF Spec v2.0.0</span>
  </header>

  <!-- Scan bar -->
  <div class="scan-bar">
    <input type="text" id="repoUrl" placeholder="https://github.com/owner/repo" value="{{REPO_URL}}" />
    <button class="btn-accent" id="scanBtn" onclick="scanRepo()">Scan Repository</button>
  </div>
  <div class="status-bar" id="status"></div>

  <!-- Main content (hidden until scan) -->
  <div id="mainContent" style="display:none">
    <!-- Sticky error summary (visible across all tabs) -->
    <div id="stickyErrorBanner"></div>

    <div class="tabs">
      <button class="tab active" onclick="switchTab('editor', event)">Editor</button>
      <button class="tab" onclick="switchTab('preview', event)">Preview</button>
    </div>

    <!-- Editor Tab -->
    <div id="tab-editor" class="tab-content active">

      <!-- Header Section -->
      <div class="section">
        <div class="section-title">Header</div>
        <div class="field-row">
          <div class="field">
            <label>Schema Version</label>
            <input type="text" id="h-schema-version" value="2.0.0" readonly />
          </div>
          <div class="field">
            <label>Last Updated</label>
            <input type="date" id="h-last-updated" />
          </div>
          <div class="field">
            <label>Last Reviewed</label>
            <input type="date" id="h-last-reviewed" />
          </div>
        </div>
        <div class="field">
          <label>URL</label>
          <input type="text" id="h-url" placeholder="URL to this security-insights.yml" />
        </div>
        <div class="field">
          <label>Comment</label>
          <input type="text" id="h-comment" placeholder="Optional comment" />
        </div>
      </div>

      <!-- Project Section -->
      <div class="section">
        <div class="section-title">Project</div>
        <div class="field-row">
          <div class="field">
            <label>Name</label>
            <input type="text" id="p-name" />
          </div>
          <div class="field">
            <label>Homepage</label>
            <input type="text" id="p-homepage" placeholder="https://..." />
          </div>
        </div>
        <div class="field-row">
          <div class="field">
            <label>Funding</label>
            <input type="text" id="p-funding" placeholder="Funding URL" />
          </div>
          <div class="field">
            <label>Roadmap</label>
            <input type="text" id="p-roadmap" placeholder="Roadmap URL" />
          </div>
        </div>
      </div>

      <!-- Steward -->
      <div class="section">
        <div class="section-title">Steward</div>
        <div class="field-row">
          <div class="field">
            <label>URI</label>
            <input type="text" id="p-steward-uri" placeholder="Organization URL" />
          </div>
          <div class="field">
            <label>Comment</label>
            <input type="text" id="p-steward-comment" />
          </div>
        </div>
      </div>

      <!-- Administrators -->
      <div class="section">
        <div class="section-title">
          Administrators
          <button class="btn btn-sm" onclick="addPerson('admins')">+ Add</button>
        </div>
        <div id="admins-list"></div>
      </div>

      <!-- Project Documentation -->
      <div class="section">
        <div class="section-title">Project Documentation</div>
        <div class="field">
          <label>Detailed Guide</label>
          <input type="text" id="pd-detailed-guide" oninput="scheduleValidation()" />
        </div>
        <div class="field">
          <label>Code of Conduct</label>
          <input type="text" id="pd-code-of-conduct" oninput="scheduleValidation()" />
        </div>
        <div class="field">
          <label>Release Process</label>
          <input type="text" id="pd-release-process" oninput="scheduleValidation()" />
        </div>
        <div class="field">
          <label>Support Policy</label>
          <input type="text" id="pd-support-policy" oninput="scheduleValidation()" />
        </div>
      </div>

      <!-- Project Repositories -->
      <div class="section">
        <div class="section-title">
          Project Repositories
          <button class="btn btn-sm" onclick="addRepo()">+ Add</button>
        </div>
        <div id="repos-list"></div>
      </div>

      <!-- Vulnerability Reporting -->
      <div class="section">
        <div class="section-title">Vulnerability Reporting</div>
        <div class="checkbox-field">
          <input type="checkbox" id="vr-reports-accepted" />
          <label for="vr-reports-accepted">Reports Accepted</label>
        </div>
        <div class="checkbox-field">
          <input type="checkbox" id="vr-bug-bounty" />
          <label for="vr-bug-bounty">Bug Bounty Available</label>
        </div>
        <div class="field">
          <label>Bug Bounty Program URL</label>
          <input type="text" id="vr-bug-bounty-url" />
        </div>
        <div class="field">
          <label>Policy URL</label>
          <input type="text" id="vr-policy" />
        </div>
      </div>

      <!-- Repository Section -->
      <div class="section">
        <div class="section-title">Repository</div>
        <div class="field">
          <label>URL</label>
          <input type="text" id="r-url" />
        </div>
        <div class="field-row">
          <div class="field">
            <label>Status</label>
            <select id="r-status">
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="abandoned">Abandoned</option>
              <option value="concept">Concept</option>
              <option value="moved">Moved</option>
              <option value="suspended">Suspended</option>
              <option value="unsupported">Unsupported</option>
              <option value="WIP">WIP</option>
            </select>
          </div>
        </div>
        <div class="checkbox-field">
          <input type="checkbox" id="r-accepts-cr" />
          <label for="r-accepts-cr">Accepts Change Requests</label>
        </div>
        <div class="checkbox-field">
          <input type="checkbox" id="r-accepts-auto-cr" />
          <label for="r-accepts-auto-cr">Accepts Automated Change Requests</label>
        </div>
        <div class="checkbox-field">
          <input type="checkbox" id="r-no-third-party" />
          <label for="r-no-third-party">No Third-Party Packages</label>
        </div>
      </div>

      <!-- Core Team -->
      <div class="section">
        <div class="section-title">
          Core Team
          <button class="btn btn-sm" onclick="addPerson('core-team')">+ Add</button>
        </div>
        <div id="core-team-list"></div>
      </div>

      <!-- Repository Documentation -->
      <div class="section">
        <div class="section-title">Repository Documentation</div>
        <div class="field">
          <label>Contributing Guide</label>
          <input type="text" id="rd-contributing" oninput="scheduleValidation()" />
        </div>
        <div class="field">
          <label>Security Policy</label>
          <input type="text" id="rd-security-policy" oninput="scheduleValidation()" />
        </div>
        <div class="field">
          <label>Governance</label>
          <input type="text" id="rd-governance" oninput="scheduleValidation()" />
        </div>
        <div class="field">
          <label>Review Policy</label>
          <input type="text" id="rd-review-policy" oninput="scheduleValidation()" />
        </div>
        <div class="field">
          <label>Dependency Management Policy</label>
          <input type="text" id="rd-dep-policy" oninput="scheduleValidation()" />
        </div>
      </div>

      <!-- License -->
      <div class="section">
        <div class="section-title">License</div>
        <div class="field-row">
          <div class="field">
            <label>SPDX Expression</label>
            <input type="text" id="r-license-expr" placeholder="MIT, Apache-2.0, etc." />
          </div>
          <div class="field">
            <label>License URL</label>
            <input type="text" id="r-license-url" />
          </div>
        </div>
      </div>

      <!-- Release -->
      <div class="section">
        <div class="section-title">Release</div>
        <div class="checkbox-field">
          <input type="checkbox" id="rel-automated" />
          <label for="rel-automated">Automated Pipeline</label>
        </div>
        <div class="field">
          <label>Changelog URL</label>
          <input type="text" id="rel-changelog" />
        </div>
      </div>

      <!-- Distribution Points -->
      <div class="section">
        <div class="section-title">
          Distribution Points
          <button class="btn btn-sm" onclick="addDistPoint()">+ Add</button>
        </div>
        <div id="dist-points-list"></div>
      </div>

      <!-- Security Assessments -->
      <div class="section">
        <div class="section-title">Security Assessments</div>
        <div class="field">
          <label>Self-Assessment Evidence URL</label>
          <input type="text" id="sa-self-evidence" />
        </div>
        <div class="field-row">
          <div class="field">
            <label>Self-Assessment Date</label>
            <input type="date" id="sa-self-date" />
          </div>
          <div class="field">
            <label>Self-Assessment Comment</label>
            <input type="text" id="sa-self-comment" />
          </div>
        </div>
      </div>

      <!-- Security Champions -->
      <div class="section">
        <div class="section-title">
          Security Champions
          <button class="btn btn-sm" onclick="addPerson('champions')">+ Add</button>
        </div>
        <div id="champions-list"></div>
      </div>

      <!-- Security Tools -->
      <div class="section">
        <div class="section-title">
          Security Tools
          <button class="btn btn-sm" onclick="addTool()">+ Add</button>
        </div>
        <div id="tools-list"></div>
      </div>

      <!-- Inline validation banner -->
      <div id="inlineValidation" style="margin-top:16px"></div>
    </div>

    <!-- Preview Tab -->
    <div id="tab-preview" class="tab-content">
      <div class="section" style="margin-bottom:16px">
        <div class="field">
          <label>Output File Path</label>
          <input type="text" id="output-path" value="{{OUTPUT_PATH}}" placeholder="./security-insights.yml" />
        </div>
      </div>
      <div class="action-bar" style="border-top:none;margin-top:0;padding-top:0">
        <button class="btn-primary" onclick="generateFile()">Generate File</button>
      </div>
      <div class="yaml-preview" id="yamlOutput">Switch to this tab to see the YAML preview.</div>
    </div>
  </div>

  <!-- Empty state before scan -->
  <div id="emptyState" class="empty-state">
    <svg width="48" height="48" viewBox="0 0 16 16" fill="currentColor" style="color:var(--text-muted)">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
    </svg>
    <p>Enter a GitHub repository URL above and click <strong>Scan Repository</strong> to get started.</p>
  </div>
</div>

<script>
let currentInsights = null;

// Auto-scan if repo URL was provided via CLI flag
window.addEventListener('DOMContentLoaded', function() {
  const url = document.getElementById('repoUrl').value.trim();
  if (url) scanRepo();
});

function setStatus(msg, loading) {
  const el = document.getElementById('status');
  el.innerHTML = loading ? '<span class="spinner"></span> ' + msg : msg;
}

function showToast(msg, type) {
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

function switchTab(name, evt) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector('.tab-content#tab-' + name).classList.add('active');
  // Activate the correct tab button
  const btn = evt && evt.target ? evt.target : document.querySelector('.tabs .tab:' + (name === 'editor' ? 'first-child' : 'last-child'));
  if (btn) btn.classList.add('active');
  if (name === 'preview') previewYAML();
}

// ---- Scan ----
async function scanRepo() {
  const url = document.getElementById('repoUrl').value.trim();
  if (!url) { showToast('Enter a repository URL', 'error'); return; }

  document.getElementById('scanBtn').disabled = true;
  setStatus('Scanning repository...', true);

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({repoUrl: url})
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Scan failed');

    currentInsights = data;
    populateForm(data);
    document.getElementById('mainContent').style.display = 'block';
    document.getElementById('emptyState').style.display = 'none';
    setStatus('Scan complete — review and edit the fields below.', false);
    // Run validation on the scanned data
    inlineValidate();
  } catch (e) {
    setStatus('', false);
    showToast(e.message, 'error');
  } finally {
    document.getElementById('scanBtn').disabled = false;
  }
}

// ---- Populate Form ----
function populateForm(d) {
  // Header
  val('h-schema-version', g(d, 'header.schema-version'));
  val('h-last-updated', g(d, 'header.last-updated'));
  val('h-last-reviewed', g(d, 'header.last-reviewed'));
  val('h-url', g(d, 'header.url'));
  val('h-comment', g(d, 'header.comment'));

  // Project
  const p = d.project || {};
  val('p-name', p.name);
  val('p-homepage', p.homepage);
  val('p-funding', p.funding);
  val('p-roadmap', p.roadmap);
  val('p-steward-uri', g(p, 'steward.uri'));
  val('p-steward-comment', g(p, 'steward.comment'));

  // Project docs
  const pd = p.documentation || {};
  val('pd-detailed-guide', pd['detailed-guide']);
  val('pd-code-of-conduct', pd['code-of-conduct']);
  val('pd-release-process', pd['release-process']);
  val('pd-support-policy', pd['support-policy']);

  // Administrators
  clearList('admins');
  (p.administrators || []).forEach(a => addPerson('admins', a));

  // Repos
  clearList('repos');
  (p.repositories || []).forEach(r => addRepo(r));

  // Vulnerability reporting
  const vr = p['vulnerability-reporting'] || {};
  check('vr-reports-accepted', vr['reports-accepted']);
  check('vr-bug-bounty', vr['bug-bounty-available']);
  val('vr-bug-bounty-url', vr['bug-bounty-program']);
  val('vr-policy', vr.policy);

  // Repository
  const repo = d.repository || {};
  val('r-url', repo.url);
  val('r-status', repo.status);
  check('r-accepts-cr', repo['accepts-change-request']);
  check('r-accepts-auto-cr', repo['accepts-automated-change-request']);
  check('r-no-third-party', repo['no-third-party-packages']);

  // Core team
  clearList('core-team');
  (repo['core-team'] || []).forEach(p => addPerson('core-team', p));

  // Repo docs
  const rd = repo.documentation || {};
  val('rd-contributing', rd['contributing-guide']);
  val('rd-security-policy', rd['security-policy']);
  val('rd-governance', rd.governance);
  val('rd-review-policy', rd['review-policy']);
  val('rd-dep-policy', rd['dependency-management-policy']);

  // License
  const lic = repo.license || {};
  val('r-license-expr', lic.expression);
  val('r-license-url', lic.url);

  // Release
  const rel = repo.release || {};
  check('rel-automated', rel['automated-pipeline']);
  val('rel-changelog', rel.changelog);

  // Distribution points
  clearList('dist-points');
  (rel['distribution-points'] || []).forEach(dp => addDistPoint(dp));

  // Security
  const sec = repo.security || {};
  const assess = sec.assessments || {};
  const self = assess.self || {};
  val('sa-self-evidence', self.evidence);
  val('sa-self-date', self.date);
  val('sa-self-comment', self.comment);

  // Champions
  clearList('champions');
  (sec.champions || []).forEach(c => addPerson('champions', c));

  // Tools
  clearList('tools');
  (sec.tools || []).forEach(t => addTool(t));
}

// ---- Collect Form ----
function collectForm() {
  const insights = {
    header: {
      'schema-version': v('h-schema-version'),
      'last-updated': v('h-last-updated'),
      'last-reviewed': v('h-last-reviewed'),
      url: v('h-url'),
      comment: v('h-comment')
    },
    project: {
      name: v('p-name'),
      homepage: v('p-homepage') || undefined,
      funding: v('p-funding') || undefined,
      roadmap: v('p-roadmap') || undefined,
      steward: v('p-steward-uri') ? {uri: v('p-steward-uri'), comment: v('p-steward-comment')} : undefined,
      administrators: collectPersons('admins'),
      documentation: cleanObj({
        'detailed-guide': v('pd-detailed-guide'),
        'code-of-conduct': v('pd-code-of-conduct'),
        'release-process': v('pd-release-process'),
        'support-policy': v('pd-support-policy')
      }),
      repositories: collectRepos(),
      'vulnerability-reporting': {
        'reports-accepted': c('vr-reports-accepted'),
        'bug-bounty-available': c('vr-bug-bounty'),
        'bug-bounty-program': v('vr-bug-bounty-url') || undefined,
        policy: v('vr-policy') || undefined
      }
    },
    repository: {
      url: v('r-url'),
      status: v('r-status'),
      'bug-fixes-only': false,
      'accepts-change-request': c('r-accepts-cr'),
      'accepts-automated-change-request': c('r-accepts-auto-cr'),
      'no-third-party-packages': c('r-no-third-party'),
      'core-team': collectPersons('core-team'),
      documentation: cleanObj({
        'contributing-guide': v('rd-contributing'),
        'security-policy': v('rd-security-policy'),
        governance: v('rd-governance'),
        'review-policy': v('rd-review-policy'),
        'dependency-management-policy': v('rd-dep-policy')
      }),
      license: v('r-license-expr') ? {expression: v('r-license-expr'), url: v('r-license-url')} : undefined,
      release: collectRelease(),
      security: collectSecurity()
    }
  };
  return insights;
}

function collectRelease() {
  const dp = collectDistPoints();
  const rel = {
    'automated-pipeline': c('rel-automated'),
    changelog: v('rel-changelog') || undefined,
    'distribution-points': dp.length ? dp : undefined
  };
  return cleanObj(rel);
}

function collectSecurity() {
  const sec = {};
  // Assessments
  if (v('sa-self-evidence') || v('sa-self-comment')) {
    sec.assessments = {
      self: cleanObj({
        evidence: v('sa-self-evidence'),
        date: v('sa-self-date'),
        comment: v('sa-self-comment')
      })
    };
  }
  // Champions
  const champs = collectPersons('champions');
  if (champs.length) sec.champions = champs;
  // Tools
  const tools = collectTools();
  if (tools.length) sec.tools = tools;
  return Object.keys(sec).length ? sec : undefined;
}

// ---- Person Lists ----
function addPerson(listId, data) {
  const list = document.getElementById(listId + '-list');
  const idx = list.children.length;
  const d = data || {};
  const div = document.createElement('div');
  div.className = 'list-item';
  div.innerHTML =
    '<button class="btn btn-sm remove-btn" onclick="this.parentElement.remove(); scheduleValidation()">- Remove</button>' +
    '<div class="field-row">' +
      '<div class="field"><label>Name</label><input type="text" data-field="name" value="' + esc(d.name) + '" oninput="scheduleValidation()" /></div>' +
      '<div class="field"><label>Email</label><input type="text" data-field="email" value="' + esc(d.email) + '" oninput="scheduleValidation()" /></div>' +
    '</div>' +
    '<div class="field-row">' +
      '<div class="field"><label>Social</label><input type="text" data-field="social" value="' + esc(d.social) + '" oninput="scheduleValidation()" /></div>' +
      '<div class="checkbox-field"><input type="checkbox" data-field="primary" ' + (d.primary ? 'checked' : '') + ' onchange="scheduleValidation()" /><label>Primary</label></div>' +
    '</div>';
  list.appendChild(div);
}

function collectPersons(listId) {
  const items = document.querySelectorAll('#' + listId + '-list .list-item');
  const arr = [];
  items.forEach(item => {
    const name = item.querySelector('[data-field="name"]').value;
    const email = item.querySelector('[data-field="email"]').value;
    if (!name && !email) return;
    const p = {name: name, email: email || undefined};
    const social = item.querySelector('[data-field="social"]').value;
    if (social) p.social = social;
    p.primary = !!item.querySelector('[data-field="primary"]').checked;
    arr.push(p);
  });
  return arr;
}

// ---- Repo Lists ----
function addRepo(data) {
  const list = document.getElementById('repos-list');
  const d = data || {};
  const div = document.createElement('div');
  div.className = 'list-item';
  div.innerHTML =
    '<button class="btn btn-sm remove-btn" onclick="this.parentElement.remove(); scheduleValidation()">- Remove</button>' +
    '<div class="field-row">' +
      '<div class="field"><label>Name</label><input type="text" data-field="name" value="' + esc(d.name) + '" oninput="scheduleValidation()" /></div>' +
      '<div class="field"><label>URL</label><input type="text" data-field="url" value="' + esc(d.url) + '" oninput="scheduleValidation()" /></div>' +
    '</div>' +
    '<div class="field"><label>Comment</label><input type="text" data-field="comment" value="' + esc(d.comment) + '" oninput="scheduleValidation()" /></div>';
  list.appendChild(div);
}

function collectRepos() {
  const items = document.querySelectorAll('#repos-list .list-item');
  const arr = [];
  items.forEach(item => {
    const name = item.querySelector('[data-field="name"]').value;
    const url = item.querySelector('[data-field="url"]').value;
    if (!name && !url) return;
    arr.push({name: name, url: url, comment: item.querySelector('[data-field="comment"]').value || undefined});
  });
  return arr.length ? arr : undefined;
}

// ---- Distribution Points ----
function addDistPoint(data) {
  const list = document.getElementById('dist-points-list');
  const d = data || {};
  const div = document.createElement('div');
  div.className = 'list-item';
  div.innerHTML =
    '<button class="btn btn-sm remove-btn" onclick="this.parentElement.remove(); scheduleValidation()">- Remove</button>' +
    '<div class="field-row">' +
      '<div class="field"><label>URI</label><input type="text" data-field="uri" value="' + esc(d.uri) + '" oninput="scheduleValidation()" /></div>' +
      '<div class="field"><label>Comment</label><input type="text" data-field="comment" value="' + esc(d.comment) + '" oninput="scheduleValidation()" /></div>' +
    '</div>';
  list.appendChild(div);
}

function collectDistPoints() {
  const items = document.querySelectorAll('#dist-points-list .list-item');
  const arr = [];
  items.forEach(item => {
    const uri = item.querySelector('[data-field="uri"]').value;
    if (!uri) return;
    arr.push({uri: uri, comment: item.querySelector('[data-field="comment"]').value || undefined});
  });
  return arr;
}

// ---- Security Tools ----
function addTool(data) {
  const list = document.getElementById('tools-list');
  const d = data || {};
  const integ = d.integration || {};
  const div = document.createElement('div');
  div.className = 'list-item';
  div.innerHTML =
    '<button class="btn btn-sm remove-btn" onclick="this.parentElement.remove(); scheduleValidation()">- Remove</button>' +
    '<div class="field-row">' +
      '<div class="field"><label>Name</label><input type="text" data-field="name" value="' + esc(d.name) + '" oninput="scheduleValidation()" /></div>' +
      '<div class="field"><label>Type</label>' +
        '<select data-field="type">' +
          '<option value="SAST"' + (d.type==='SAST'?' selected':'') + '>SAST</option>' +
          '<option value="SCA"' + (d.type==='SCA'?' selected':'') + '>SCA</option>' +
          '<option value="DAST"' + (d.type==='DAST'?' selected':'') + '>DAST</option>' +
          '<option value="fuzzing"' + (d.type==='fuzzing'?' selected':'') + '>Fuzzing</option>' +
          '<option value="other"' + (d.type==='other'?' selected':'') + '>Other</option>' +
        '</select>' +
      '</div>' +
    '</div>' +
    '<div class="field-row">' +
      '<div class="checkbox-field"><input type="checkbox" data-field="ci" ' + (integ.ci?'checked':'') + ' /><label>CI</label></div>' +
      '<div class="checkbox-field"><input type="checkbox" data-field="adhoc" ' + (integ.adhoc?'checked':'') + ' /><label>Ad Hoc</label></div>' +
      '<div class="checkbox-field"><input type="checkbox" data-field="release" ' + (integ.release?'checked':'') + ' /><label>Release</label></div>' +
    '</div>';
  list.appendChild(div);
}

function collectTools() {
  const items = document.querySelectorAll('#tools-list .list-item');
  const arr = [];
  items.forEach(item => {
    const name = item.querySelector('[data-field="name"]').value;
    if (!name) return;
    arr.push({
      name: name,
      type: item.querySelector('[data-field="type"]').value,
      rulesets: ['default'],
      results: {},
      integration: {
        adhoc: item.querySelector('[data-field="adhoc"]').checked,
        ci: item.querySelector('[data-field="ci"]').checked,
        release: item.querySelector('[data-field="release"]').checked
      }
    });
  });
  return arr;
}

// ---- Preview ----
async function previewYAML() {
  const data = collectForm();
  setStatus('Generating preview...', true);
  try {
    const resp = await fetch('/api/preview', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data)
    });
    const result = await resp.json();
    if (!resp.ok) throw new Error(result.error);
    document.getElementById('yamlOutput').textContent = result.yaml;
    setStatus('', false);
  } catch (e) {
    setStatus('', false);
    showToast(e.message, 'error');
  }
}

// ---- Validate ----
// ---- Generate File ----
async function generateFile() {
  const errorCount = window._validationErrorCount || 0;
  if (errorCount > 0) {
    showConfirmDialog(
      'Generate with errors?',
      'There are ' + errorCount + ' validation error(s). The generated file may not conform to the OSSF Security Insights spec. Continue anyway?',
      function() { doGenerate(); }
    );
    return;
  }
  doGenerate();
}

async function doGenerate() {
  const data = collectForm();
  data.outputPath = v('output-path') || '';
  setStatus('Generating file...', true);

  try {
    const resp = await fetch('/api/generate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data)
    });
    const result = await resp.json();
    if (!resp.ok) throw new Error(result.error);

    setStatus('', false);
    showToast(result.message, 'success');
  } catch (e) {
    setStatus('', false);
    showToast(e.message, 'error');
  }
}

function showConfirmDialog(title, message, onConfirm) {
  const overlay = document.createElement('div');
  overlay.className = 'dialog-overlay';
  overlay.innerHTML =
    '<div class="dialog-box">' +
      '<h3>' + escHtml(title) + '</h3>' +
      '<p>' + escHtml(message) + '</p>' +
      '<div class="dialog-actions">' +
        '<button class="btn" id="dialog-cancel">Cancel</button>' +
        '<button class="btn btn-primary" id="dialog-confirm">Generate Anyway</button>' +
      '</div>' +
    '</div>';
  document.body.appendChild(overlay);
  overlay.querySelector('#dialog-cancel').onclick = function() { overlay.remove(); };
  overlay.querySelector('#dialog-confirm').onclick = function() { overlay.remove(); onConfirm(); };
  overlay.addEventListener('click', function(e) { if (e.target === overlay) overlay.remove(); });
}

// ---- Helpers ----
function v(id) { const el = document.getElementById(id); return el ? el.value.trim() : ''; }
function c(id) { const el = document.getElementById(id); return el ? el.checked : false; }
function val(id, value) { const el = document.getElementById(id); if (el && value) el.value = value; }
function check(id, value) { const el = document.getElementById(id); if (el) el.checked = !!value; }
function clearList(id) { document.getElementById(id + '-list').innerHTML = ''; }
function esc(s) { return (s || '').replace(/"/g, '&quot;').replace(/</g, '&lt;'); }
function escHtml(s) { return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function g(obj, path) {
  return path.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : ''), obj);
}
function cleanObj(obj) {
  const clean = {};
  let hasVal = false;
  for (const [k, v] of Object.entries(obj)) {
    if (v) { clean[k] = v; hasVal = true; }
  }
  return hasVal ? clean : undefined;
}

// ---- Inline Validation ----
const urlPattern = /^https?:\/\/[^\s]+$/;
const urlFieldIds = [
  'h-url', 'p-homepage', 'p-funding', 'p-roadmap', 'p-steward-uri',
  'pd-detailed-guide', 'pd-code-of-conduct', 'pd-release-process', 'pd-support-policy',
  'vr-bug-bounty-url', 'vr-policy',
  'r-url', 'rd-contributing', 'rd-security-policy', 'rd-governance', 'rd-review-policy', 'rd-dep-policy',
  'r-license-url', 'rel-changelog', 'sa-self-evidence'
];

function validateUrls() {
  let hasError = false;
  // Static URL fields
  urlFieldIds.forEach(id => {
    const val = v(id);
    if (val && !urlPattern.test(val)) {
      annotateField(id, 'Must be a valid URL (https://...)', 'error');
      hasError = true;
    }
  });
  // Dynamic URL fields in list items (repos, distribution points)
  document.querySelectorAll('#repos-list [data-field="url"], #dist-points-list [data-field="url"]').forEach(input => {
    const val = input.value.trim();
    if (val && !urlPattern.test(val)) {
      const field = input.closest('.field') || input.parentElement;
      if (field) {
        field.classList.add('has-error');
        const msg = document.createElement('div');
        msg.className = 'field-error';
        msg.textContent = 'Must be a valid URL (https://...)';
        field.appendChild(msg);
      }
      hasError = true;
    }
  });
  return hasError;
}

function validatePrimaryConstraints() {
  // Warn if multiple persons are marked as primary in a section
  // (CUE schema requires primary: bool but allows all false; spec recommends at most one true)
  ['admins', 'core-team', 'champions'].forEach(listId => {
    const items = document.querySelectorAll('#' + listId + '-list .list-item');
    if (items.length === 0) return;
    let primaryCount = 0;
    items.forEach(item => {
      if (item.querySelector('[data-field="primary"]').checked) primaryCount++;
    });
    if (primaryCount > 1) {
      annotateSection(listId + '-list', 'Only one entry should be marked as primary', 'warning');
    }
  });
}

let validationTimer = null;
function scheduleValidation() {
  clearTimeout(validationTimer);
  validationTimer = setTimeout(inlineValidate, 800);
}

// Map CUE error paths to form field IDs
const pathToFieldMap = {
  'header."schema-version"': 'h-schema-version',
  'header."last-updated"': 'h-last-updated',
  'header."last-reviewed"': 'h-last-reviewed',
  'header.url': 'h-url',
  'header.comment': 'h-comment',
  'project.name': 'p-name',
  'project.homepage': 'p-homepage',
  'project.steward.uri': 'p-steward-uri',
  'project.documentation."detailed-guide"': 'pd-detailed-guide',
  'project.documentation."code-of-conduct"': 'pd-code-of-conduct',
  'project.documentation."release-process"': 'pd-release-process',
  'project.documentation."support-policy"': 'pd-support-policy',
  'project."vulnerability-reporting"."reports-accepted"': 'vr-reports-accepted',
  'project."vulnerability-reporting".policy': 'vr-policy',
  'repository.url': 'r-url',
  'repository.status': 'r-status',
  'repository."accepts-change-request"': 'r-accepts-cr',
  'repository."accepts-automated-change-request"': 'r-accepts-auto-cr',
  'repository.documentation."contributing-guide"': 'rd-contributing',
  'repository.documentation."security-policy"': 'rd-security-policy',
  'repository.documentation.governance': 'rd-governance',
  'repository.documentation."review-policy"': 'rd-review-policy',
  'repository.documentation."dependency-management-policy"': 'rd-dep-policy',
  'repository.license.expression': 'r-license-expr',
  'repository.license.url': 'r-license-url',
  'repository.release."automated-pipeline"': 'rel-automated',
  'repository.release.changelog': 'rel-changelog',
  'repository.security.assessments.self.evidence': 'sa-self-evidence',
  'repository.security.assessments.self.date': 'sa-self-date',
  'repository.security.assessments.self.comment': 'sa-self-comment',
};

// Map array/section paths to list container IDs for errors on list items
const sectionMap = {
  'project.administrators': 'admins-list',
  'project.repositories': 'repos-list',
  'repository."core-team"': 'core-team-list',
  'repository.release."distribution-points"': 'dist-points-list',
  'repository.security.champions': 'champions-list',
  'repository.security.tools': 'tools-list',
};

// Map warning paths (exact) to field IDs — only for leaf fields, not parent objects
const warningFieldMap = {
  'project.vulnerability-reporting.policy': 'vr-policy',
  'repository.documentation.security-policy': 'rd-security-policy',
  'repository.documentation.contributing-guide': 'rd-contributing',
};

// Map warning paths to section containers for parent object warnings
const warningSectionMap = {
  'project.documentation': 'pd-detailed-guide',
  'repository.release': 'rel-automated',
};

function clearFieldAnnotations() {
  document.querySelectorAll('.field-error, .field-warning, .section-error, .section-warning').forEach(e => e.remove());
  document.querySelectorAll('.has-error, .has-warning').forEach(e => {
    e.classList.remove('has-error', 'has-warning');
  });
  const sticky = document.getElementById('stickyErrorBanner');
  if (sticky) sticky.innerHTML = '';
}

function annotateField(fieldId, message, type) {
  const input = document.getElementById(fieldId);
  if (!input) return false;
  const field = input.closest('.field') || input.parentElement;
  if (!field) return false;
  field.classList.add(type === 'error' ? 'has-error' : 'has-warning');
  const msg = document.createElement('div');
  msg.className = type === 'error' ? 'field-error' : 'field-warning';
  msg.textContent = message;
  field.appendChild(msg);
  return true;
}

function annotateSection(containerId, message, type) {
  const container = document.getElementById(containerId);
  if (!container) return false;
  const section = container.closest('.section');
  if (!section) return false;
  // Add message after the section title
  const existing = section.querySelector('.section-' + type);
  if (existing) {
    // Append to existing annotation
    existing.textContent += '; ' + message;
    return true;
  }
  const msg = document.createElement('div');
  msg.className = 'section-' + type;
  msg.textContent = message;
  const title = section.querySelector('.section-title');
  if (title) {
    title.after(msg);
  } else {
    section.prepend(msg);
  }
  return true;
}

function matchErrorToField(errorMsg) {
  // CUE errors look like: #SecurityInsights.header."last-reviewed": incomplete value ...
  const m = errorMsg.match(/#SecurityInsights\.(.+?):\s*(.+)/);
  if (!m) return null;
  const path = m[1];
  const detail = m[2];

  // Check direct field matches first
  for (const [pattern, fieldId] of Object.entries(pathToFieldMap)) {
    if (path === pattern || path.startsWith(pattern + '.')) {
      return { type: 'field', fieldId: fieldId, detail: detail };
    }
  }

  // Check section/array matches (e.g. project.administrators.0.name)
  for (const [pattern, containerId] of Object.entries(sectionMap)) {
    const normalized = pattern.replace(/"/g, '');
    const pathNorm = path.replace(/"/g, '');
    if (pathNorm.startsWith(normalized + '.') || pathNorm === normalized) {
      // Extract a human-readable detail from the array path
      const suffix = pathNorm.slice(normalized.length);
      const itemMatch = suffix.match(/^\.(\d+)\.(.+)/);
      let label = detail;
      if (itemMatch) {
        label = itemMatch[2] + ': ' + detail;
      }
      return { type: 'section', containerId: containerId, detail: label };
    }
  }

  return null;
}

function matchWarningToField(warnMsg) {
  // Warnings look like: recommended field 'repository.documentation.security-policy' is not set
  const m = warnMsg.match(/recommended field '(.+?)' is not set/);
  if (!m) return null;
  const path = m[1];

  // Check exact leaf field matches
  if (warningFieldMap[path]) {
    return { type: 'field', fieldId: warningFieldMap[path] };
  }

  // Check parent object warnings (e.g. 'project.documentation' when no docs at all)
  if (warningSectionMap[path]) {
    return { type: 'field', fieldId: warningSectionMap[path] };
  }

  return null;
}

async function inlineValidate() {
  const el = document.getElementById('inlineValidation');
  const sticky = document.getElementById('stickyErrorBanner');
  if (!el) return;
  clearFieldAnnotations();
  if (sticky) sticky.innerHTML = '';
  // Client-side URL validation (instant feedback)
  const urlErrors = validateUrls();
  validatePrimaryConstraints();
  const data = collectForm();
  try {
    const previewResp = await fetch('/api/preview', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data)
    });
    const previewData = await previewResp.json();
    if (!previewResp.ok) throw new Error(previewData.error);

    const resp = await fetch('/api/validate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({yaml: previewData.yaml})
    });
    const result = await resp.json();
    if (!resp.ok) throw new Error(result.error);

    // Collect all matched annotations for the sticky banner
    const errorAnnotations = [];
    const warningAnnotations = [];
    let unmatchedErrors = [];
    let unmatchedWarnings = [];

    (result.Errors || []).forEach(e => {
      const match = matchErrorToField(e);
      if (match && match.type === 'field') {
        annotateField(match.fieldId, match.detail, 'error');
        errorAnnotations.push({ fieldId: match.fieldId, label: fieldLabel(match.fieldId), detail: match.detail });
      } else if (match && match.type === 'section') {
        annotateSection(match.containerId, match.detail, 'error');
        errorAnnotations.push({ fieldId: match.containerId, label: sectionLabel(match.containerId), detail: match.detail });
      } else {
        unmatchedErrors.push(e);
      }
    });
    (result.Warnings || []).forEach(w => {
      const match = matchWarningToField(w);
      if (match && match.type === 'field') {
        const input = document.getElementById(match.fieldId);
        const isEmpty = input && (input.type === 'checkbox' ? false : !input.value.trim());
        if (isEmpty) {
          annotateField(match.fieldId, 'Recommended', 'warning');
          warningAnnotations.push({ fieldId: match.fieldId, label: fieldLabel(match.fieldId) });
        }
      } else {
        unmatchedWarnings.push(w);
      }
    });

    // Update global error count for generate confirmation
    window._validationErrorCount = (result.Errors || []).length;
    window._validationWarningCount = (result.Warnings || []).length;

    // Build sticky error banner at top of editor
    if (sticky) {
      let shtml = '';
      const totalErrors = (result.Errors || []).length;
      if (totalErrors > 0) {
        shtml += '<div class="sticky-errors"><div class="sticky-title">\u274c ' + totalErrors + ' error(s) found</div><div class="sticky-list">';
        // Deduplicate by fieldId for clickable links
        const seen = new Set();
        errorAnnotations.forEach(a => {
          if (!seen.has(a.fieldId)) {
            seen.add(a.fieldId);
            shtml += '<span class="sticky-link" onclick="scrollToField(\'' + a.fieldId + '\')">' + escHtml(a.label) + '</span>';
          }
        });
        unmatchedErrors.forEach(e => {
          shtml += '<span style="color:var(--red)">\u2022 ' + escHtml(e) + '</span>';
        });
        shtml += '</div></div>';
      }
      if (warningAnnotations.length > 0 || unmatchedWarnings.length > 0) {
        const totalWarn = warningAnnotations.length + unmatchedWarnings.length;
        shtml += '<div class="sticky-warnings" style="' + (totalErrors > 0 ? 'margin-top:8px;' : '') + '"><div class="sticky-title">\u26a0\ufe0f ' + totalWarn + ' warning(s)</div></div>';
      }
      sticky.innerHTML = shtml;
    }

    // Bottom summary banner — only show unmatched items
    let html = '';
    if (result.Valid && (!result.Warnings || !result.Warnings.length)) {
      html = '<div class="inline-banner pass"><div class="banner-title">\u2705 Validation passed</div></div>';
    } else if (!result.Valid) {
      if (unmatchedErrors.length) {
        html = '<div class="inline-banner fail"><div class="banner-title">\u274c ' + unmatchedErrors.length + ' unresolved error(s)</div>';
        unmatchedErrors.forEach(e => { html += '<div class="banner-item">\u2022 ' + escHtml(e) + '</div>'; });
        html += '</div>';
      }
    }
    if (unmatchedWarnings.length) {
      html += '<div class="inline-banner warn" style="margin-top:8px"><div class="banner-title">\u26a0\ufe0f ' + unmatchedWarnings.length + ' warning(s)</div>';
      unmatchedWarnings.forEach(w => { html += '<div class="banner-item">\u2022 ' + escHtml(w) + '</div>'; });
      html += '</div>';
    }
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = '<div class="inline-banner fail"><div class="banner-item">' + escHtml(e.message) + '</div></div>';
    window._validationErrorCount = 1;
  }
}

function scrollToField(fieldId) {
  // Switch to editor tab if not already there
  const editorTab = document.getElementById('tab-editor');
  if (editorTab && !editorTab.classList.contains('active')) {
    switchTab('editor');
  }
  const el = document.getElementById(fieldId);
  if (!el) return;
  setTimeout(() => {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    const target = el.closest('.field') || el.closest('.section') || el;
    target.style.transition = 'box-shadow 0.3s';
    target.style.boxShadow = '0 0 0 2px var(--accent)';
    setTimeout(() => { target.style.boxShadow = ''; }, 1500);
  }, 50);
}

function fieldLabel(fieldId) {
  const el = document.getElementById(fieldId);
  if (!el) return fieldId;
  const field = el.closest('.field');
  if (field) {
    const lbl = field.querySelector('label');
    if (lbl) return lbl.textContent.trim();
  }
  return fieldId;
}

function sectionLabel(containerId) {
  const el = document.getElementById(containerId);
  if (!el) return containerId;
  const section = el.closest('.section');
  if (section) {
    const title = section.querySelector('.section-title');
    if (title) return title.textContent.trim();
  }
  return containerId;
}

// Attach auto-validation to all static form fields
window.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('#tab-editor input, #tab-editor select, #tab-editor textarea').forEach(function(el) {
    el.addEventListener('input', scheduleValidation);
    el.addEventListener('change', scheduleValidation);
  });
});
</script>
</body>
</html>`
