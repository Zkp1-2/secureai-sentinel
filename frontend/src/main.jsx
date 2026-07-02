import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AlertTriangle,
  BarChart3,
  BookOpen,
  Brain,
  CheckCircle2,
  ClipboardList,
  Database,
  FileJson,
  FileText,
  Shield,
  History,
  Save,
  Ticket,
  Upload,
  Workflow,
  Zap,
} from 'lucide-react';
import './style.css';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

const SAMPLE_CASES = [
  {
    title: 'SQL Injection Login Endpoint',
    label: 'SQL Injection',
    text: 'A public web application has a SQL injection vulnerability in the login form. An unauthenticated attacker can bypass authentication and access sensitive user records from the database. The system does not use parameterized queries and database permissions are overly broad.',
  },
  {
    title: 'Stored XSS Profile Page',
    label: 'XSS',
    text: "A web application reflects user input directly into the profile page without output encoding. An attacker can inject JavaScript that executes in another user's browser and steals session cookies. There is no Content Security Policy.",
  },
  {
    title: 'Weak Authentication Admin Portal',
    label: 'Weak Auth',
    text: 'The admin portal does not enforce multi-factor authentication. Passwords are weak and there is no account lockout after repeated failed login attempts. An attacker may brute-force administrator accounts and gain access to sensitive configuration settings.',
  },
  {
    title: 'SSRF URL Preview Feature',
    label: 'SSRF',
    text: 'A URL preview feature accepts any webhook URL and the server fetches the address directly. An attacker can access internal endpoints and the cloud metadata service at 169.254.169.254.',
  },
  {
    title: 'RCE Unsafe Deserialization',
    label: 'RCE',
    text: 'A backend service performs unsafe deserialization of untrusted data. Attackers may achieve remote code execution and execute commands on the server. The service runs with broad privileges.',
  },
  {
    title: 'Mini Trivy JSON Example',
    label: 'Trivy JSON',
    text: 'Scanner Report Type: Trivy\nFinding 1: Vulnerable Dependency CVE-2024-12345 in openssl\nSeverity: Critical\nPackage: openssl\nDescription: outdated vulnerable dependency with known vulnerability and fixed version available.\nRecommendation: upgrade openssl to patched version.',
  },
];

function Badge({ severity }) {
  const className = `badge badge-${String(severity || 'unknown').toLowerCase()}`;
  return <span className={className}>{severity || 'Unknown'}</span>;
}

function Card({ icon, title, children, wide = false }) {
  return (
    <section className={`card ${wide ? 'wide' : ''}`}>
      <div className="card-title">
        {icon}
        <h2>{title}</h2>
      </div>
      {children}
    </section>
  );
}

function ProgressBar({ value }) {
  const safe = Math.max(0, Math.min(100, Number(value || 0)));
  return <div className="progress"><span style={{ width: `${safe}%` }} /></div>;
}

function Sidebar({ activeSection, onNavigate }) {
  const items = [
    { id: 'analysis', label: 'Analysis' },
    { id: 'workspace', label: 'Workspace' },
    { id: 'tickets', label: 'Tickets' },
    { id: 'benchmark', label: 'Benchmark' },
  ];

  return (
    <aside className="side-rail">
      <button className="rail-brand rail-brand-button" onClick={() => onNavigate('top')} type="button">
        <div className="rail-logo"><Shield size={26} /></div>
        <div>
          <strong>SecureAI</strong>
          <span>Sentinel</span>
        </div>
      </button>
      <nav className="rail-nav" aria-label="Main navigation">
        {items.map((item) => (
          <button
            key={item.id}
            type="button"
            className={activeSection === item.id ? 'active' : ''}
            onClick={() => onNavigate(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>
      <div className="rail-card">
        <small>System mode</small>
        <strong>Local RAG + Multi-Agent</strong>
        <p>LLM optional. Scanner parsers and SQLite workspace enabled.</p>
      </div>
      <div className="rail-status">
        <span className="status-dot" /> Backend ready
      </div>
    </aside>
  );
}

function App() {
  const [title, setTitle] = useState(SAMPLE_CASES[0].title);
  const [text, setText] = useState(SAMPLE_CASES[0].text);
  const [result, setResult] = useState(null);
  const [benchmark, setBenchmark] = useState(null);
  const [loading, setLoading] = useState(false);
  const [benchmarkLoading, setBenchmarkLoading] = useState(false);
  const [fileLoading, setFileLoading] = useState(false);
  const [error, setError] = useState('');
  const [useLLM, setUseLLM] = useState(false);
  const [ticket, setTicket] = useState(null);
  const [projects, setProjects] = useState([]);
  const [projectName, setProjectName] = useState('Demo Security Review');
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [saveMessage, setSaveMessage] = useState('');
  const [analysisHistory, setAnalysisHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [savedAnalysisId, setSavedAnalysisId] = useState('');
  const [statusOwner, setStatusOwner] = useState('Security Team');
  const [statusMessage, setStatusMessage] = useState('');
  const [activeFileName, setActiveFileName] = useState('');

  const categories = useMemo(() => result?.findings?.map((f) => f.category).join(', ') || 'None yet', [result]);
  const inputPreview = result?.metadata?.input_preview || text;

  function navigateTo(sectionId) {
    const fallbackMap = { tickets: result || ticket ? 'tickets-section' : 'findings-section' };
    const targetId = sectionId === 'top' ? 'top-section' : (fallbackMap[sectionId] || `${sectionId}-section`);
    const element = document.getElementById(targetId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function loadSample(sample) {
    setTitle(sample.title);
    setText(sample.text);
    setResult(null);
    setTicket(null);
    setError('');
    setActiveFileName('');
    setSavedAnalysisId('');
    setStatusMessage('');
  }

  async function analyze() {
    setLoading(true);
    setError('');
    setResult(null);
    setTicket(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, text, use_llm: useLLM }),
      });
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.detail || 'Analysis failed');
      }
      const data = await response.json();
      setResult(data);
      setText(data.metadata?.input_preview || text);
      setSavedAnalysisId('');
      setStatusMessage('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function analyzeFile(file) {
    if (!file) return;
    setFileLoading(true);
    setError('');
    setResult(null);
    setTicket(null);
    try {
      const form = new FormData();
      form.append('file', file);
      const response = await fetch(`${API_BASE_URL}/api/analyze-file?use_llm=${useLLM}`, { method: 'POST', body: form });
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.detail || 'File analysis failed');
      }
      const data = await response.json();
      setTitle(data.title);
      setText(data.metadata?.input_preview || `Analyzed uploaded file: ${file.name}`);
      setActiveFileName(file.name);
      setResult(data);
      setSavedAnalysisId('');
      setStatusMessage('');
    } catch (err) {
      setError(err.message);
    } finally {
      setFileLoading(false);
    }
  }

  async function runBenchmark() {
    setBenchmarkLoading(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE_URL}/api/benchmark?use_llm=${useLLM}`);
      if (!response.ok) throw new Error('Benchmark failed');
      setBenchmark(await response.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setBenchmarkLoading(false);
    }
  }

  async function loadProjects() {
    setSaveMessage('');
    const response = await fetch(`${API_BASE_URL}/api/projects`);
    if (response.ok) {
      const data = await response.json();
      setProjects(data);
      setSaveMessage(`Loaded ${data.length} project(s).`);
    } else {
      setSaveMessage('Could not load projects.');
    }
  }

  async function createProject() {
    setSaveMessage('');
    const response = await fetch(`${API_BASE_URL}/api/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: projectName, description: 'Created from SecureAI Sentinel dashboard' }),
    });
    if (!response.ok) return setSaveMessage('Could not create project.');
    const project = await response.json();
    setProjects([project, ...projects]);
    setSelectedProjectId(String(project.id));
    setSaveMessage(`Created project #${project.id}`);
    setAnalysisHistory([]);
  }

  async function saveCurrentAnalysis() {
    if (!result || !selectedProjectId) return setSaveMessage('Select or create a project first.');
    const response = await fetch(`${API_BASE_URL}/api/analyses`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: Number(selectedProjectId), analysis: result }),
    });
    if (!response.ok) return setSaveMessage('Could not save analysis.');
    const saved = await response.json();
    setSavedAnalysisId(String(saved.id));
    setSaveMessage(`Saved analysis #${saved.id} to project #${saved.project_id}`);
    await loadAnalyses(saved.project_id);
  }

  async function loadAnalyses(projectId = selectedProjectId) {
    if (!projectId) return setSaveMessage('Select a project before loading analyses.');
    setHistoryLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/analyses?project_id=${projectId}`);
      if (!response.ok) throw new Error('Could not load saved analyses.');
      const data = await response.json();
      setAnalysisHistory(data);
      setSaveMessage(`Loaded ${data.length} saved analysis record(s).`);
    } catch (err) {
      setSaveMessage(err.message);
    } finally {
      setHistoryLoading(false);
    }
  }

  async function openAnalysis(analysisId) {
    if (!analysisId) return;
    setSaveMessage('');
    setStatusMessage('');
    const response = await fetch(`${API_BASE_URL}/api/analyses/${analysisId}`);
    if (!response.ok) return setSaveMessage('Could not open saved analysis.');
    const data = await response.json();
    setResult(data);
    setTitle(data.title || 'Saved Analysis');
    setText(data.metadata?.input_preview || data.summary || 'Loaded saved analysis');
    setSavedAnalysisId(String(analysisId));
    setActiveFileName(data.metadata?.source?.source_filename || '');
    setTicket(null);
    setSaveMessage(`Opened saved analysis #${analysisId}.`);
  }

  async function updateFindingStatus(findingIndex, status) {
    if (!savedAnalysisId) {
      setStatusMessage('Save the current analysis before changing finding status.');
      return;
    }
    const response = await fetch(`${API_BASE_URL}/api/findings/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis_id: Number(savedAnalysisId), finding_index: findingIndex, status, owner: statusOwner }),
    });
    if (!response.ok) {
      setStatusMessage('Could not update finding status.');
      return;
    }
    setResult((current) => {
      if (!current) return current;
      const findings = current.findings.map((finding, idx) => idx === findingIndex ? { ...finding, status, remediation_owner: statusOwner } : finding);
      return { ...current, findings };
    });
    setStatusMessage(`Finding #${findingIndex + 1} marked as ${status}.`);
  }

  async function createTicket(findingIndex = 0) {
    if (!result) return;
    const response = await fetch(`${API_BASE_URL}/api/tickets/remediation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis: result, finding_index: findingIndex, owner: 'Security Team', due_days: result.risk.severity === 'Critical' ? 3 : 7 }),
    });
    if (!response.ok) return setError('Ticket generation failed');
    setTicket(await response.json());
  }

  function downloadText(filename, content, type = 'text/plain') {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="app-shell modern-shell no-rail" id="top-section">
        <header className="topbar">
          <div>
            <p className="eyebrow">Practical AI Vulnerability Triage Platform</p>
            <h1>SecureAI Sentinel</h1>
          </div>
          <div className="topbar-actions">
            <span className="top-pill">V3.2.7 Balanced UI</span>
            <span className="top-pill">FastAPI · React</span>
          </div>
        </header>

        <section className="hero-panel">
          <div className="hero-copy">
            <div className="hero-icon"><Shield size={36} /></div>
            <div>
              <h2>AI security triage for scanner reports and vulnerability reviews.</h2>
              <p>Ingest scanner outputs, retrieve security knowledge, reason about attack paths, score risk with CVSS-style signals, manage findings, and export remediation tickets.</p>
            </div>
          </div>
          <div className="hero-badges">
            <span>Scanner Parsers</span><span>Local RAG</span><span>Multi-Agent</span><span>CVSS-style Risk</span><span>Ticket Export</span><span>SQLite Workspace</span>
          </div>
        </section>


        {result && (
          <section className="summary-strip">
            <div><small>Risk</small><strong>{result.risk.severity}</strong><span>{result.risk.score}/100</span></div>
            <div><small>Findings</small><strong>{result.findings.length}</strong><span>{categories}</span></div>
            <div><small>Priority</small><strong>{result.risk.priority || 'Review'}</strong><span>{result.risk.remediation_sla || 'Manual review'}</span></div>
            <div><small>Parser</small><strong>{result.metadata?.source?.scanner || result.metadata?.source?.parser || 'manual'}</strong><span>{result.metadata?.version || 'analysis ready'}</span></div>
          </section>
        )}

        <div className="grid top-grid">
          <div id="analysis-section" className="scroll-anchor"><Card icon={<Brain size={20} />} title="Security Case Input" wide>
            <div className="toolbar modern-toolbar">
              <div className="sample-row">
                {SAMPLE_CASES.map((sample) => (
                  <button key={sample.label} className="chip sample-chip" onClick={() => loadSample(sample)}>{sample.label}</button>
                ))}
              </div>
              <label className="toggle"><input type="checkbox" checked={useLLM} onChange={(e) => setUseLLM(e.target.checked)} /> Use LLM</label>
            </div>
            <label>Case title</label>
            <input value={title} onChange={(e) => setTitle(e.target.value)} />
            <label>Vulnerability description / security report / extracted file preview</label>
            <textarea value={text} onChange={(e) => setText(e.target.value)} />
            <div className="button-row action-row">
              <button className="primary-action" onClick={analyze} disabled={loading}>{loading ? 'Analyzing...' : 'Run Multi-Agent Analysis'}</button>
              <label className="upload-button"><Upload size={16} /> {fileLoading ? 'Uploading...' : 'Analyze File'}<input type="file" accept=".txt,.md,.log,.json,.csv,.pdf,.xml" onChange={(e) => analyzeFile(e.target.files?.[0])} /></label>
            </div>
            <p className="muted helper-text">Supported inputs: plain reports, PDFs, OWASP ZAP JSON, Trivy JSON, Semgrep JSON, Nmap XML, and generic scanner CSV.</p>
            {(activeFileName || result?.metadata?.source?.parser) && <p className="source-note">Source: {activeFileName || 'manual input'} · Parser: {result?.metadata?.source?.scanner || result?.metadata?.source?.parser || 'manual-text'}</p>}
            {error && <p className="error">{error}</p>}
          </Card></div>

          <div className="side-stack">
            <Card icon={<AlertTriangle size={20} />} title="Risk Score">
              {!result ? (
                <div className="empty-state"><AlertTriangle size={28} /><p>Run an analysis to generate risk, priority, and SLA.</p></div>
              ) : (
                <div className="risk-box">
                  <div className="score">{result.risk.score}<span>/100</span></div>
                  <ProgressBar value={result.risk.score} />
                  <Badge severity={result.risk.severity} />
                  <p>{result.risk.rationale}</p>
                  <small>Priority: {result.risk.priority} · SLA: {result.risk.remediation_sla}</small>
                  <small>Detected: {categories}</small>
                </div>
              )}
            </Card>

            <div id="workspace-section" className="scroll-anchor"><Card icon={<Database size={20} />} title="Workspace">
              <label>Project name</label>
              <input value={projectName} onChange={(e) => setProjectName(e.target.value)} />
              <div className="button-row compact-actions">
                <button className="secondary" onClick={createProject}>Create Project</button>
                <button className="secondary" onClick={loadProjects}>Load Projects</button>
              </div>
              <label>Selected project</label>
              <select value={selectedProjectId} onChange={(e) => { setSelectedProjectId(e.target.value); setSavedAnalysisId(''); setAnalysisHistory([]); }}>
                <option value="">Select project...</option>
                {projects.map((p) => <option key={p.id} value={p.id}>#{p.id} {p.name}</option>)}
              </select>
              <div className="button-row compact-actions">
                <button className="secondary" onClick={saveCurrentAnalysis} disabled={!result}><Save size={15} /> Save</button>
                <button className="secondary" onClick={() => loadAnalyses()} disabled={!selectedProjectId || historyLoading}><History size={15} /> {historyLoading ? 'Loading...' : 'History'}</button>
              </div>
              {savedAnalysisId && <p className="source-note">Active saved analysis: #{savedAnalysisId}</p>}
              {analysisHistory.length > 0 && (
                <div className="history-list">
                  {analysisHistory.slice(0, 5).map((item) => (
                    <button key={item.id} className="history-item" onClick={() => openAnalysis(item.id)}>
                      <span>#{item.id} {item.title}</span>
                      <small>{item.severity} · {item.score}/100</small>
                    </button>
                  ))}
                </div>
              )}
              {saveMessage && <p className="muted">{saveMessage}</p>}
            </Card></div>
          </div>
        </div>

        {!result && (
          <section className="empty-dashboard">
            <div><Brain size={22} /><strong>1. Analyze</strong><p>Paste a case or upload scanner output.</p></div>
            <div><BookOpen size={22} /><strong>2. Retrieve</strong><p>Ground findings in local OWASP, MITRE, and CVE-style context.</p></div>
            <div><Ticket size={22} /><strong>3. Act</strong><p>Export remediation tickets and save analysis history.</p></div>
          </section>
        )}

        {result && (
          <div className="results">
            <div id="findings-section" className="scroll-anchor wide-wrapper"><Card icon={<Shield size={20} />} title="Detected Findings" wide>
              <div className="status-owner-row"><label>Finding owner</label><input value={statusOwner} onChange={(e) => setStatusOwner(e.target.value)} /></div>
              {statusMessage && <p className="source-note">{statusMessage}</p>}
              <div className="list">
                {result.findings.map((finding, idx) => (
                  <div className="item finding-card" key={idx}>
                    <div className="item-head"><strong>{finding.category}</strong><Badge severity={finding.severity_hint} /></div>
                    <p>{finding.explanation}</p>
                    <small>{finding.cwe ? `${finding.cwe} · ` : ''}{finding.owasp || 'No OWASP mapping'} · Confidence {Number(finding.confidence).toFixed(2)}</small>
                    <small>Status: {finding.status || 'Needs Review'}</small>
                    <small>Evidence: {finding.evidence?.length ? finding.evidence.join(', ') : 'Review required'}</small>
                    {finding.evidence_refs?.length > 0 && <div className="evidence-box">{finding.evidence_refs.slice(0, 3).map((ref, i) => <small key={i}>↳ {ref.locator}: {ref.excerpt}</small>)}</div>}
                    <div className="finding-actions">
                      <button className="secondary mini" onClick={() => createTicket(idx)}><Ticket size={14} /> Create Ticket</button>
                      {['Confirmed', 'False Positive', 'Accepted Risk', 'Fixed', 'Needs Review'].map((status) => (
                        <button key={status} className="ghost mini" onClick={() => updateFindingStatus(idx, status)}>{status}</button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Card></div>

            <Card icon={<AlertTriangle size={20} />} title="CVSS-style Risk Vector">
              <div className="vector-grid">
                {Object.entries(result.risk.vector || {}).map(([key, value]) => (
                  <div key={key}><small>{key.replaceAll('_', ' ')}</small><strong>{value}</strong></div>
                ))}
              </div>
            </Card>

            <Card icon={<Workflow size={20} />} title="Potential Attack Path">
              <ol>
                {result.attack_path.map((step, idx) => <li key={idx}>{step}</li>)}
              </ol>
            </Card>

            <Card icon={<CheckCircle2 size={20} />} title="Defense Recommendations">
              <ul>
                {result.defenses.map((defense, idx) => <li key={idx}>{defense}</li>)}
              </ul>
            </Card>

            <Card icon={<ClipboardList size={20} />} title="Executive Actions">
              <ul>
                {result.executive_actions.map((action, idx) => <li key={idx}>{action}</li>)}
              </ul>
            </Card>

            <Card icon={<BookOpen size={20} />} title="Retrieved Knowledge">
              <div className="list compact-list">
                {result.retrieved_knowledge.map((item, idx) => (
                  <div className="item" key={idx}>
                    <strong>{item.source} / {item.section}</strong>
                    <small>Relevance score: {Number(item.score).toFixed(2)}</small>
                    <p>{item.content}</p>
                  </div>
                ))}
              </div>
            </Card>

            <Card icon={<Zap size={20} />} title="Evaluation Signals">
              <div className="metric-grid">
                <div><span>{Number(result.evaluation.retrieval_coverage).toFixed(2)}</span><small>Retrieval coverage</small></div>
                <div><span>{Number(result.evaluation.confidence).toFixed(2)}</span><small>Confidence</small></div>
                <div><span className="metric-text">{result.metadata?.source?.scanner || result.metadata?.source?.parser || 'manual'}</span><small>Input parser</small></div>
              </div>
              <p>{result.evaluation.hallucination_guardrail}</p>
              <small>{result.evaluation.consistency_note}</small>
              <small>Input preview: {inputPreview.slice(0, 220)}{inputPreview.length > 220 ? '...' : ''}</small>
              <div className="trace-box">
                {result.traces.map((trace, idx) => <small key={idx}>• {trace.agent}: {trace.output_summary}</small>)}
              </div>
            </Card>

            {ticket && (
              <div id="tickets-section" className="scroll-anchor wide-wrapper"><Card icon={<Ticket size={20} />} title="Remediation Ticket Export" wide>
                <p><strong>{ticket.title}</strong></p>
                <small>Labels: {ticket.labels.join(', ')} · Assignee: {ticket.assignee}</small>
                <button className="secondary" onClick={() => downloadText('secureai-remediation-ticket.md', ticket.body_markdown, 'text/markdown')}>Download Ticket Markdown</button>
                <pre>{ticket.body_markdown}</pre>
              </Card></div>
            )}

            <Card icon={<FileText size={20} />} title="Final Report" wide>
              <div className="button-row">
                <button className="secondary" onClick={() => downloadText('secureai-sentinel-report.md', result.final_report, 'text/markdown')}>Download Markdown</button>
                <button className="secondary" onClick={() => downloadText('secureai-sentinel-result.json', JSON.stringify(result, null, 2), 'application/json')}><FileJson size={16} /> Download JSON</button>
              </div>
              <pre>{result.final_report}</pre>
            </Card>
          </div>
        )}

        <section className="benchmark-section scroll-anchor" id="benchmark-section">
          <Card icon={<BarChart3 size={20} />} title="Research Benchmark" wide>
            <p className="muted">Run the built-in curated evaluation set. These metrics are for local regression testing and README documentation, not a claim of real-world scanner accuracy.</p>
            <button onClick={runBenchmark} disabled={benchmarkLoading}>{benchmarkLoading ? 'Running benchmark...' : 'Run Benchmark'}</button>
            {benchmark && (
              <div className="benchmark-box">
                <div className="metric-grid">
                  <div><span>{benchmark.total_cases}</span><small>Cases</small></div>
                  <div><span>{benchmark.average_category_recall}</span><small>Avg category recall</small></div>
                  <div><span>{benchmark.severity_pass_rate}</span><small>Severity pass rate</small></div>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Case</th><th>Detected</th><th>Recall</th><th>Severity</th><th>Pass</th></tr></thead>
                    <tbody>
                      {benchmark.results.map((row) => (
                        <tr key={row.case_id}>
                          <td>{row.title}</td>
                          <td>{row.detected_categories.join(', ')}</td>
                          <td>{row.category_recall}</td>
                          <td>{row.predicted_severity}</td>
                          <td>{row.severity_pass ? '✅' : '⚠️'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </Card>
        </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
