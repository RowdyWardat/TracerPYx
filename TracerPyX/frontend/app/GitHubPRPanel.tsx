"use client";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, ExternalLink, Github, GitPullRequest, LoaderCircle, LockKeyhole, RefreshCw, Search, ShieldCheck, X } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
type GitHubStatus = { configured: boolean; connected: boolean; login: string | null; app_install_url: string | null; configuration_message: string | null; required_permissions: Record<string, string> };
type Repo = { id: number; full_name: string; private: boolean; html_url: string; default_branch?: string; description?: string; installed: boolean };
type PR = { number: number; title: string; state: string; draft: boolean; html_url: string; author: string; base_branch: string; head_branch: string; base_sha: string; head_sha: string; head_repository?: string | null };
type PRFinding = { finding_id: string; title: string; file?: string | null; line?: number | null; code_snippet?: string | null; category?: string; severity?: string; severity_basis?: string; confidence?: string; confidence_basis?: string; reachability_confidence?: string; classification: string; classification_explanation: string; line_in_pr_diff: boolean; review_commentable: boolean; reachability: string; reachability_explanation: string; call_path?: string[]; taint_analysis?: { status: string; explanation: string }; exploitability?: string; evidence: string[]; remediation?: string; remediation_example?: string | null; github_url?: string; source?: string; package?: string; declared_version?: string; cwe?: string[] };
type PRReport = { repository: { full_name: string; private: boolean; html_url: string }; pull_request: PR & { body?: string; head_repository?: string }; base_sha: string; head_sha: string; changed_files: { path: string; previous_path?: string; status: string; additions: number; deletions: number; binary_or_patch_unavailable: boolean; diff_complete: boolean; patch?: string }[]; diff_complete: boolean; dependency_changes?: { added: Dependency[]; removed: Dependency[]; version_changed: { name: string; base: Dependency; head: Dependency }[] }; findings: PRFinding[]; fixed_findings: PRFinding[]; summary: Record<string, number>; coverage: { base_python_files: number; head_python_files: number; base_configuration_files: string[]; head_configuration_files: string[]; configuration_analysis: string }; analysis_warnings: string[]; head_analysis: { manifests: { path: string; type: string }[]; graph: { node_count: number; edge_count: number; entry_points: string[] }; analysis_diagnostics: { advisory_lookup?: string } }; base_analysis: { analysis_diagnostics: { advisory_lookup?: string } } };
type Dependency = { name: string; version: string; source: string; usage: string };
type Job = { job_id: string; status: string; stage: string; stage_order: string[]; result?: PRReport | null; error?: string | null };

const stageLabels: Record<string, string> = {
  fetching_repository: "Fetching repository metadata", resolving_commits: "Resolving pinned PR commits",
  detecting_changed_files: "Detecting changed files and diff anchors", building_project_context: "Building base and head project context",
  base_parsing_python_files: "Parsing base Python files", base_building_call_graph: "Building the base call graph",
  base_running_vulnerability_detection: "Scanning base vulnerabilities and dependencies",
  base_running_reachability_analysis: "Checking base reachability (taint tracking unavailable)",
  head_parsing_python_files: "Parsing head Python files", head_building_call_graph: "Building the head call graph",
  head_running_vulnerability_detection: "Scanning head vulnerabilities and dependencies",
  head_running_reachability_analysis: "Checking head reachability (taint tracking unavailable)",
  comparing_base_and_head: "Comparing base and head findings", generating_final_report: "Generating the report", complete: "Analysis complete"
};

async function api(path: string, init: RequestInit = {}) {
  const response = await fetch(API + path, { ...init, credentials: "include", headers: { ...(init.body ? { "Content-Type": "application/json" } : {}), ...(init.headers || {}) } });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && typeof window !== "undefined") window.dispatchEvent(new Event("tracerpyx:github-disconnected"));
  if (!response.ok) throw Object.assign(new Error(data.detail || "GitHub request failed."), { status: response.status });
  return data;
}

export default function GitHubPRPanel() {
  const [status, setStatus] = useState<GitHubStatus | null>(null);
  const [statusBusy, setStatusBusy] = useState(true);
  const [query, setQuery] = useState("");
  const [repositories, setRepositories] = useState<Repo[]>([]);
  const [repoBusy, setRepoBusy] = useState(false);
  const [repository, setRepository] = useState<Repo | null>(null);
  const [prState, setPrState] = useState("open");
  const [pulls, setPulls] = useState<PR[]>([]);
  const [pullBusy, setPullBusy] = useState(false);
  const [pull, setPull] = useState<PR | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [report, setReport] = useState<PRReport | null>(null);
  const [error, setError] = useState("");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [publishSummary, setPublishSummary] = useState(true);
  const [publishBusy, setPublishBusy] = useState(false);
  const [publishMessage, setPublishMessage] = useState("");

  async function refreshStatus() {
    setStatusBusy(true);
    try { setStatus(await api("/api/github/auth/status")); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not check GitHub connection."); }
    finally { setStatusBusy(false); }
  }
  useEffect(() => {
    void refreshStatus();
    const onDisconnected = () => setStatus(s => s ? { ...s, connected: false, login: null } : s);
    window.addEventListener("tracerpyx:github-disconnected", onDisconnected);
    const params = new URLSearchParams(window.location.search);
    if (params.has("github")) {
      if (params.get("github") === "error") setError("GitHub authorization did not complete. Check the App callback configuration and try again.");
      window.history.replaceState({}, "", window.location.pathname);
    }
    return () => window.removeEventListener("tracerpyx:github-disconnected", onDisconnected);
  }, []);

  async function searchRepositories() {
    setError(""); setRepoBusy(true); setRepositories([]); setRepository(null); setPull(null); setPulls([]); setReport(null); setJob(null);
    try { const data = await api("/api/github/repositories?q=" + encodeURIComponent(query.trim())); setRepositories(data.repositories || []); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not list repositories."); }
    finally { setRepoBusy(false); }
  }
  async function chooseRepository(repo: Repo) {
    setRepository(repo); setPull(null); setReport(null); setJob(null); setPulls([]); setError(""); setPullBusy(true);
    const [owner, name] = repo.full_name.split("/");
    try { const data = await api(`/api/github/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/pull-requests?state=${prState}`); setPulls(data.pull_requests || []); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not list pull requests."); }
    finally { setPullBusy(false); }
  }
  async function changePRState(value: string) {
    setPrState(value); setReport(null); setJob(null); setError("");
    if (!repository) return;
    const [owner, name] = repository.full_name.split("/"); setPullBusy(true); setPull(null);
    try { const data = await api(`/api/github/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/pull-requests?state=${value}`); setPulls(data.pull_requests || []); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not list pull requests."); }
    finally { setPullBusy(false); }
  }
  async function selectPullRequest(item: PR) {
    if (!repository) return;
    setDetailBusy(true); setError(""); setReport(null); setJob(null);
    const [owner, name] = repository.full_name.split("/");
    try {
      const detail = await api(`/api/github/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/pull-requests/${item.number}`);
      setPull({ ...item, ...detail });
    } catch (e) { setError(e instanceof Error ? e.message : "Could not load pull request details."); }
    finally { setDetailBusy(false); }
  }
  async function startAnalysis(forceRefresh = false) {
    if (!repository || !pull) return;
    setError(""); setPublishMessage(""); setReport(null); setSelectedIds([]);
    try {
      const created = await api("/api/github/analyze", { method: "POST", body: JSON.stringify({ repository: repository.full_name, number: pull.number, force_refresh: forceRefresh }) });
      setJob({ job_id: created.job_id, status: created.status, stage: created.stage, stage_order: [] });
    } catch (e) { setError(e instanceof Error ? e.message : "Could not start PR analysis."); }
  }
  useEffect(() => {
    if (!job?.job_id || ["complete", "failed", "cancelled"].includes(job.status)) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next: Job = await api(`/api/github/jobs/${job.job_id}`);
        if (!active) return;
        setJob(next);
        if (next.status === "complete" && next.result) { setReport(next.result); setSelectedIds([]); return; }
        if (["failed", "cancelled"].includes(next.status)) { setError(next.error || "PR analysis did not complete."); return; }
      } catch (e) {
        if (!active) return;
        setError(e instanceof Error ? e.message : "Analysis status could not be refreshed.");
        const code = (e as Error & { status?: number }).status;
        if (code === 401 || code === 404) return;
      }
      if (active) timer = setTimeout(poll, 1500);
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [job?.job_id, job?.status]);

  async function cancelJob() {
    if (!job) return;
    try { await api(`/api/github/jobs/${job.job_id}/cancel`, { method: "POST" }); setJob({ ...job, status: "cancelling" }); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not cancel analysis."); }
  }
  async function disconnect() {
    try { await api("/api/github/auth/disconnect", { method: "POST" }); setStatus(s => s ? { ...s, connected: false, login: null } : s); setRepositories([]); setRepository(null); setPulls([]); setPull(null); setReport(null); setJob(null); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not disconnect GitHub."); }
  }
  async function publish() {
    if (!job || selectedIds.length === 0 && !publishSummary) return;
    setPublishBusy(true); setPublishMessage(""); setError("");
    try {
      const result = await api(`/api/github/jobs/${job.job_id}/publish`, { method: "POST", body: JSON.stringify({ finding_ids: selectedIds, publish_summary: publishSummary }) });
      setPublishMessage(`Published ${result.inline_published} inline comments; updated ${result.inline_updated} existing comments; marked ${result.inline_resolved} fixed comments${result.summary_published ? result.summary_updated ? "; updated the PR summary." : "; posted the PR summary." : "."}`);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not publish review comments."); }
    finally { setPublishBusy(false); }
  }
  function toggleFinding(id: string) { setSelectedIds(ids => ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id]); }
  const commentable = useMemo(() => report?.findings.filter(f => f.review_commentable) || [], [report]);
  const currentStage = job?.stage_order?.length ? job.stage_order.indexOf(job.stage) : -1;
  const running = !!job && ["queued", "running", "cancelling"].includes(job.status);

  return <section className="github-card">
    <div className="github-heading"><div className="github-icon"><Github size={19}/></div><div><div className="eyebrow">GITHUB INTEGRATION</div><h2>Analyze a pull request</h2><p>Scan the full head and base snapshots, then compare findings against the actual PR diff.</p></div>
      <div className={status?.connected ? "github-connected" : "github-disconnected"}>{statusBusy ? "Checking connection…" : status?.connected ? <><CheckCircle2 size={14}/>Connected as {status.login}</> : "Not connected"}</div></div>
    {!status?.connected ? <div className="github-connect-row"><div><b>Connect GitHub</b><span>{status?.configuration_message || "Authorization uses a GitHub App. Tokens stay encrypted on the backend."}</span></div><button className="primary" disabled={statusBusy || !status?.configured} onClick={() => { window.location.href = API + "/api/github/auth/start"; }}><Github size={15}/>Connect GitHub</button></div> : <>
      <div className="github-controls"><form onSubmit={e => { e.preventDefault(); void searchRepositories(); }}><label htmlFor="repo-search">Repository search</label><div className="github-search"><Search size={15}/><input id="repo-search" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search installed repositories or public GitHub repos"/><button className="subtle" type="submit" disabled={repoBusy}>{repoBusy ? <LoaderCircle className="spin" size={14}/> : "Search"}</button></div></form>
        {repositories.length > 0 && <div className="github-repo-list" role="listbox" aria-label="Repositories">{repositories.map(repo => <button key={repo.id} className={repository?.id === repo.id ? "github-repo selected" : "github-repo"} onClick={() => void chooseRepository(repo)}><span><b>{repo.full_name}</b><small>{repo.private ? <><LockKeyhole size={11}/> Private</> : "Public"}{!repo.installed && repo.private ? " · App installation required" : ""}</small></span><ChevronRightIcon/></button>)}</div>}
        {repository && <div className="github-pr-select"><div className="pr-toolbar"><div><b>Pull requests in {repository.full_name}</b><small>{repository.private ? "Private repository" : "Public repository"} · {repository.default_branch ? `default ${repository.default_branch}` : ""}</small></div><select value={prState} onChange={e => void changePRState(e.target.value)} aria-label="Pull request state"><option value="open">Open PRs</option><option value="closed">Closed PRs</option><option value="all">All PRs</option></select></div>
          {pullBusy ? <InlineLoading text="Loading pull requests…"/> : pulls.length ? <div className="github-pr-list">{pulls.map(item => <button key={item.number} className={pull?.number === item.number ? "github-pr selected" : "github-pr"} onClick={() => void selectPullRequest(item)}><span className="pr-number">#{item.number}</span><span className="pr-main"><b>{item.title}</b><small>{item.head_branch} → {item.base_branch} · {item.author} · {item.state}{item.draft ? " · Draft" : ""}</small><small className="sha-line">base {item.base_sha.slice(0, 12)} · head {item.head_sha.slice(0, 12)}</small></span><ChevronRightIcon/></button>)}</div> : <div className="github-empty">No pull requests returned for this state.</div>}
        </div>}
      </div>
      {pull && <div className="selected-pr"><div><div className="selected-pr-title"><GitPullRequest size={16}/><b>#{pull.number} {pull.title}</b><span className={pull.state === "open" ? "pr-state open" : "pr-state"}>{pull.state}{pull.draft ? " · draft" : ""}</span></div><p>{pull.head_branch} ({pull.head_repository || repository?.full_name}) → {pull.base_branch} · by {pull.author}</p><p className="sha-line">Base {pull.base_sha} · Head {pull.head_sha}</p><a href={pull.html_url} target="_blank" rel="noreferrer">Open pull request <ExternalLink size={12}/></a></div><div className="selected-pr-actions"><button className="primary" disabled={running || detailBusy} onClick={() => void startAnalysis()}><ShieldCheck size={15}/>Analyze PR</button>{report && <button className="subtle" disabled={running || detailBusy} onClick={() => void startAnalysis(true)}><RefreshCw size={13}/>Refresh analysis</button>}</div></div>}
      <div className="github-footer"><span>App permissions: metadata read, contents read, pull requests read; pull requests write is used only when you publish.</span><button className="subtle" onClick={() => void disconnect()}><X size={13}/>Disconnect</button></div>
    </>}
    {status?.app_install_url && status.connected && <div className="install-note">Install the TracerPyX GitHub App on private repositories and any private fork you want to analyze. <a href={status.app_install_url} target="_blank" rel="noreferrer">Manage installations <ExternalLink size={11}/></a></div>}
    {error && <div className="github-error"><AlertTriangle size={15}/><span>{error}</span><button onClick={() => setError("")} aria-label="Dismiss error"><X size={13}/></button></div>}
    {running && job && <div className="job-progress"><div className="job-current"><LoaderCircle size={17} className="spin"/><div><b>{job.status === "queued" ? "Analysis queued" : stageLabels[job.stage] || job.stage}</b><small>{job.status === "queued" ? "Waiting for an analysis worker." : "Pinned to the selected base and head commit SHAs."}</small></div><button className="subtle" onClick={() => void cancelJob()}>Cancel</button></div><div className="stage-grid">{STAGES.map((stage, i) => <span className={job.status === "complete" || i < currentStage ? "stage done" : stage === job.stage ? "stage current" : "stage"} key={stage}><i/>{stageLabels[stage]}</span>)}</div></div>}
    {report && job && <PRResults report={report} selectedIds={selectedIds} toggleFinding={toggleFinding} commentableCount={commentable.length} publishSummary={publishSummary} setPublishSummary={setPublishSummary} onPublish={() => void publish()} publishBusy={publishBusy} publishMessage={publishMessage} />}
  </section>;
}

const STAGES = ["fetching_repository", "resolving_commits", "detecting_changed_files", "building_project_context", "base_parsing_python_files", "base_building_call_graph", "base_running_vulnerability_detection", "base_running_reachability_analysis", "head_parsing_python_files", "head_building_call_graph", "head_running_vulnerability_detection", "head_running_reachability_analysis", "comparing_base_and_head", "generating_final_report"];
function ChevronRightIcon() { return <span className="repo-chevron">›</span>; }
function InlineLoading({ text }: { text: string }) { return <div className="github-empty"><LoaderCircle size={14} className="spin"/>{text}</div>; }

function PRResults({ report, selectedIds, toggleFinding, commentableCount, publishSummary, setPublishSummary, onPublish, publishBusy, publishMessage }: { report: PRReport; selectedIds: string[]; toggleFinding: (id: string) => void; commentableCount: number; publishSummary: boolean; setPublishSummary: (value: boolean) => void; onPublish: () => void; publishBusy: boolean; publishMessage: string }) {
  const counts = report.summary;
  const dependencyRows: { kind: string; item: Dependency; before?: Dependency }[] = report.dependency_changes ? [
    ...report.dependency_changes.added.map(item => ({ kind: "Added", item })),
    ...report.dependency_changes.removed.map(item => ({ kind: "Removed", item })),
    ...report.dependency_changes.version_changed.map(change => ({ kind: "Version changed", item: change.head, before: change.base })),
  ] : [];
  return <div className="pr-report"><div className="pr-report-head"><div><div className="eyebrow">PINNED ANALYSIS REPORT</div><h3>{report.repository.full_name} · PR #{report.pull_request.number}</h3><p>{report.pull_request.title}</p></div><a href={report.pull_request.html_url} target="_blank" rel="noreferrer">Open PR <ExternalLink size={12}/></a></div>
    <div className="commit-pair"><span>Base <code>{report.base_sha}</code></span><span>Head <code>{report.head_sha}</code></span><span>{report.changed_files.length} changed files · {report.coverage.head_python_files} head Python files</span></div>
    <div className="pr-stats"><PRStat label="Total findings" value={counts.total_findings || 0}/><PRStat label="Introduced" value={counts.introduced || 0} tone="danger"/><PRStat label="Worsened" value={counts.worsened || 0} tone="danger"/><PRStat label="Fixed" value={counts.fixed || 0} tone="good"/><PRStat label="Pre-existing" value={counts.pre_existing || 0}/><PRStat label="Uncertain attribution" value={counts.uncertain_attribution || 0}/><PRStat label="Critical / high" value={`${counts.critical || 0} / ${counts.high || 0}`} tone="danger"/><PRStat label="Medium / low" value={`${counts.medium || 0} / ${counts.low || 0}`}/><PRStat label="Dependency advisories" value={counts.dependency_advisories || 0}/><PRStat label="Source findings" value={counts.source_findings || 0}/><PRStat label="Confirmed reachable" value={counts.confirmed_reachable || 0} tone="danger"/><PRStat label="Uncertain reachability" value={counts.potentially_reachable_or_uncertain || 0}/></div>
    <div className="pr-coverage"><b>Coverage</b><span>{report.head_analysis.graph.node_count} graph nodes · {report.head_analysis.graph.edge_count} edges · {report.head_analysis.graph.entry_points.length} detected entry points · {report.head_analysis.manifests.length} manifests</span><span>OSV base/head: {report.base_analysis.analysis_diagnostics.advisory_lookup || "unknown"} / {report.head_analysis.analysis_diagnostics.advisory_lookup || "unknown"}</span><small>Source-to-sink taint flow is not implemented. A reachable sink does not establish attacker-controlled input or exploitability.</small></div>
    {report.dependency_changes && <details className="changed-files dependency-changes"><summary>Dependency changes: +{report.dependency_changes.added.length} added · −{report.dependency_changes.removed.length} removed · {report.dependency_changes.version_changed.length} version changes</summary>
      {dependencyRows.map((change, index) => <p key={`${change.item.name}-${index}`}><b>{change.kind}:</b> <code>{change.item.name}</code> {change.before ? <>{change.before.version} → </> : null}{change.item.version} <small>({change.item.source}; {change.item.usage.replaceAll("_", " ")}; import match is not proof of installed runtime use or actual execution)</small></p>)}
      {!report.dependency_changes.added.length && !report.dependency_changes.removed.length && !report.dependency_changes.version_changed.length && <p>No exact static dependency changes were detected. Non-exact or dynamic declarations appear in coverage warnings.</p>}
    </details>}
    {report.analysis_warnings.length > 0 && <details className="pr-warnings"><summary><AlertTriangle size={14}/> {report.analysis_warnings.length} coverage warnings</summary>{report.analysis_warnings.map((warning, i) => <p key={i}>{warning}</p>)}</details>}
    <div className="pr-findings-head"><div><h4>Findings at the PR head</h4><p>Select findings to include as inline review comments. Only added lines with valid diff anchors are eligible.</p></div><span>{report.findings.length} findings</span></div>
    {!report.findings.length ? <div className="github-empty">No findings were produced by the supported analysis checks. Review coverage notes before interpreting this as safe.</div> : <div className="pr-findings">{report.findings.map(f => <article className="pr-finding" key={f.finding_id}>
      <div className="pr-finding-top">{f.review_commentable && <input type="checkbox" checked={selectedIds.includes(f.finding_id)} onChange={() => toggleFinding(f.finding_id)} aria-label={`Select ${f.title} for review comment`}/>}<span className={`severity ${f.severity || "unknown"}`}>{f.severity || "unknown"}</span><span className={`classification ${f.classification}`}>{f.classification.replaceAll("_", " ")}</span><b>{f.title}</b><span className="confidence">pattern {f.confidence || "unknown"} · reach {f.reachability_confidence || "unknown"}</span></div>
      <div className="pr-finding-location">{f.file ? <><code>{f.file}:{f.line || "?"}</code>{f.line_in_pr_diff ? <span className="diff-anchor">Added diff line</span> : <span>Not on an added line · summary only</span>}</> : <span>{f.package} {f.declared_version || ""} · dependency advisory</span>}{f.github_url && <a href={f.github_url} target="_blank" rel="noreferrer">Open at head <ExternalLink size={11}/></a>}</div>
      <p className="classification-explanation">{f.classification_explanation}</p>
      {f.code_snippet && <pre className="pr-code">{f.code_snippet}</pre>}
      <details><summary>Evidence, reachability, and remediation</summary><p><b>Pattern confidence:</b> {f.confidence}. {f.confidence_basis}</p><p><b>Reachability:</b> {f.reachability} ({f.reachability_confidence}). {f.reachability_explanation}</p>{f.call_path?.length ? <p><b>Call path:</b> <code>{f.call_path.join(" → ")}</code></p> : null}<p><b>Taint:</b> {f.taint_analysis?.explanation || "No taint path was established."}</p><p><b>Exploitability:</b> {f.exploitability || "Not established."}</p>{f.evidence.map((item, i) => <small className="pr-evidence" key={i}>{item}</small>)}{f.remediation && <p><b>Remediation:</b> {f.remediation}</p>}{f.remediation_example && <pre className="pr-code">{f.remediation_example}</pre>}{f.severity_basis && <small>{f.severity_basis}</small>}</details>
    </article>)}</div>}
    {report.fixed_findings.length > 0 && <details className="fixed-findings"><summary>{report.fixed_findings.length} base findings absent at head</summary>{report.fixed_findings.map(f => <p key={f.finding_id}><b>{f.classification.replaceAll("_", " ")}</b> · {f.file ? `${f.file}:${f.line || "?"}` : f.package} · {f.title} — {f.classification_explanation}</p>)}</details>}
    <details className="changed-files"><summary>Changed files and available diff patches ({report.changed_files.length}){!report.diff_complete ? " · some patches unavailable" : ""}</summary>{report.changed_files.map(file => <details key={file.path} className="changed-file"><summary><code>{file.path}</code><span>{file.status} · +{file.additions} / −{file.deletions}{file.binary_or_patch_unavailable ? " · patch unavailable or binary" : ""}</span></summary>{file.patch && <pre>{file.patch}</pre>}</details>)}</details>
    <div className="publish-review"><label><input type="checkbox" checked={publishSummary} onChange={e => setPublishSummary(e.target.checked)}/> Publish or update PR summary comment</label><button className="primary" disabled={publishBusy || selectedIds.length === 0 && !publishSummary} onClick={onPublish}>{publishBusy ? <LoaderCircle size={14} className="spin"/> : <GitPullRequest size={14}/>}Publish selected review</button><small>{selectedIds.length} selected · {commentableCount} findings have valid inline anchors. Publishing requires the GitHub App installed with Pull requests write permission.</small>{publishMessage && <span className="publish-success"><CheckCircle2 size={14}/>{publishMessage}</span>}</div>
  </div>;
}
function PRStat({ label, value, tone = "" }: { label: string; value: string | number; tone?: string }) { return <div className="pr-stat"><span>{label}</span><b className={tone}>{value}</b></div>; }
