# PRD: Enhanced Reporting & Multi-Target Scanning

**Version**: 1.1.0  
**Status**: Implemented (6/7 features)  
**Date**: 2026-08-30  
**Last Updated**: 2026-08-30  
**Author**: Cyense Team  
**Related PRDs**: 
- ci-compliance-reporting.md (CVSS, SARIF, Coverage, Diff-scope, Scan modes)
- github-repo-audit.md (GitHub repository scanning)
- cli-experience.md (CLI interface)

## Implementation Status

### ✅ Implemented (6/7)

1. **Local Web Viewer** - `app/interface/viewer/` (static HTML/JS/CSS dashboard)
   - Interactive findings table with severity filtering and search
   - Detail modal with CVSS/CWE metadata
   - Blue theme consistent with CLI
   - Disk fallback for scan data after service restart

2. **PDF Report Generation** - `app/report/pdf_report.py`
   - Uses `reportlab` library
   - Compliance-ready format with CVSS scores
   - Lazy import to avoid service startup dependency

3. **CSV Export** - `app/report/csv_export.py`
   - Spreadsheet-friendly format with severity/CVSS columns
   - UTF-8 encoding for international characters

4. **Multi-Target Scanning** - `app/services/multi_scan.py`
   - Batch submission through existing worker queue (serial execution, not parallel)
   - Supports github/local/url target types
   - Parses targets from file or CLI args
   - Precedence: target-level config > common config > defaults

5. **Enhanced CLI Commands** - `app/cli/main.py`
   - `cyense view [scan_id]` - Open web viewer in browser
   - `cyense history` - List past scans with status
   - `cyense compare <a> <b>` - Diff two scan reports (added/removed/changed findings)
   - `cyense export csv|pdf <scan_id>` - Download CSV/PDF

6. **Configuration Persistence** - `app/core/config_store.py`
   - Atomic writes with 0o600 permissions (secure)
   - Stores in `~/.cyense/config.json`
   - CLI commands: `config get|set|list|reset`
   - Config precedence: CLI flag > env var > config file > default

### ⏸️ Deferred (1/7)

7. **Scan Resume** - NOT IMPLEMENTED
   - **Rationale**: Requires significant worker state machine changes (checkpoint/resume logic)
   - **Alternative**: Current `JobStore` + `reports/` disk persistence allows re-reading past scans
   - **Future consideration**: Add checkpoint serialization to `app/core/state.py` if user demand exists

### Architecture Notes

- All features maintain Cyense's core principles: **no LLM, deterministic, read-only**
- Multi-target scans execute serially through the existing worker queue (not parallel)
- Web viewer uses vanilla JS (no React/Vue build step) for simplicity
- PDF generation is optional (`reportlab` not required for service startup)

## 1. Executive Summary

PRD ini mengimplementasikan 7 fitur tambahan dari Strix yang belum tercakup di `ci-compliance-reporting.md`:

1. **Local Web Viewer** - Dashboard interaktif untuk melihat hasil scan
2. **PDF Report Generation** - Laporan compliance/audit dalam format PDF
3. **CSV Export** - Export data untuk analisis dan integrasi
4. **Multi-Target Scanning** - Scan multiple repos/targets secara paralel
5. **Enhanced CLI Commands** - `view`, `history`, `compare`
6. **Configuration Persistence** - Simpan preferensi user
7. **Scan Resume** - Lanjutkan scan yang terinterupsi

Semua fitur mengikuti prinsip Cyense: **no LLM, deterministic, read-only**.

## 2. Motivation

### 2.1 Why These Features?

Dari analisis Strix (v1.5.3), fitur-fitur ini memberikan nilai tinggi:

| Feature | Strix Implementation | Cyense Gap | Value |
|---------|---------------------|------------|-------|
| Web Viewer | Vite+React dashboard | Hanya CLI + JSON/MD | Interactive exploration |
| PDF Reports | reportlab+pypdf | Tidak ada | Compliance/audit |
| CSV Export | vulnerabilities.csv | Tidak ada | Data analysis |
| Multi-Target | Parallel scans | Single target only | Efficiency |
| CLI Enhancements | view, history, resume | Basic commands | UX |
| Config Persistence | ~/.strix/cli-config.json | Env vars only | Convenience |
| Scan Resume | SQLite sessions | Tidak ada | Reliability |

### 2.2 User Stories

1. **Security Analyst**: "Saya ingin melihat hasil scan di web dashboard yang interaktif, bisa filter by severity, click untuk lihat detail, dan export ke PDF untuk laporan ke management."

2. **DevOps Engineer**: "Saya perlu scan 5 microservices sekaligus di CI/CD pipeline dan bandingkan hasilnya dengan scan sebelumnya."

3. **Compliance Officer**: "Saya butuh laporan PDF dengan CVSS scores dan remediation steps untuk audit SOC 2."

4. **Developer**: "Scan saya terinterupsi karena network issue, saya ingin resume dari titik terakhir tanpa harus scan ulang dari awal."

## 3. Features Specification

### 3.1 Local Web Viewer

**Objective**: Provide interactive dashboard to explore scan results.

**Implementation**:
- FastAPI endpoint: `GET /scans/{scan_id}/viewer`
- Serve static HTML/JS/CSS (no build step required)
- Client-side rendering with vanilla JS (no React/Vue to avoid build complexity)
- Features:
  - Severity breakdown (Critical/High/Medium/Low)
  - Filterable findings table
  - Finding detail modal with code snippets
  - CVSS breakdown
  - Coverage visualization
  - Export buttons (PDF, CSV, SARIF)

**File Structure**:
```
dev/main/app/api/viewer.py          # FastAPI routes
dev/main/app/interface/viewer/
  ├── static/
  │   ├── index.html
  │   ├── style.css
  │   └── app.js
  └── __init__.py
```

**API Endpoints**:
```python
GET /scans/{scan_id}/viewer          # Serve dashboard
GET /scans/{scan_id}/viewer/data     # JSON data for dashboard
```

**CLI Command**:
```bash
cyense view <scan_id>                # Open dashboard in browser
cyense view --latest                 # View most recent scan
cyense view --port 8080              # Custom port
```

### 3.2 PDF Report Generation

**Objective**: Generate compliance-ready PDF reports.

**Implementation**:
- Use `reportlab` library (same as Strix)
- Template: Executive summary → Findings table → Detailed findings → Remediation
- Include:
  - CVSS scores and vectors
  - CWE references
  - Code snippets (syntax highlighted)
  - Severity badges (color-coded)
  - Company logo (configurable)
  - Timestamp and scan metadata

**File Structure**:
```
dev/main/app/report/pdf_report.py    # PDF generation
dev/main/app/report/templates/
  └── default.pdf                    # Template (optional)
```

**Dependencies**:
```
reportlab>=4.0
pypdf>=3.0
```

**API Endpoint**:
```python
GET /scans/{scan_id}/report/pdf      # Download PDF
```

**CLI Command**:
```bash
cyense report pdf <scan_id> -o report.pdf
cyense report pdf <scan_id> --template custom.pdf
```

### 3.3 CSV Export

**Objective**: Export findings for data analysis and integration.

**Implementation**:
- Standard CSV format (RFC 4180)
- Columns:
  - finding_id, rule, severity, cvss_score, cvss_vector, cwe
  - title, description, location (file:line), snippet
  - remediation, confidence, verified_at
- UTF-8 encoding with BOM (for Excel compatibility)

**File Structure**:
```
dev/main/app/report/csv_export.py    # CSV generation
```

**API Endpoint**:
```python
GET /scans/{scan_id}/export/csv      # Download CSV
```

**CLI Command**:
```bash
cyense export csv <scan_id> -o findings.csv
cyense export csv <scan_id> --include-remediation
```

### 3.4 Multi-Target Scanning

**Objective**: Scan multiple repositories/targets in parallel.

**Implementation**:
- Accept list of targets in scan request
- Run scans in parallel (configurable concurrency)
- Aggregate results with target metadata
- Support mixed target types (GitHub repos, local dirs, URLs)

**API Changes**:
```python
# New field in ScanRequest
targets: list[dict]  # [{type: "github", url: "..."}, {type: "local", path: "..."}]

# Response includes per-target results
{
  "scan_id": "abc123",
  "targets": [
    {"id": "target_1", "type": "github", "url": "...", "status": "completed", "findings": [...]},
    {"id": "target_2", "type": "local", "path": "...", "status": "failed", "error": "..."}
  ],
  "aggregated": {
    "total_findings": 42,
    "by_severity": {...},
    "by_target": {...}
  }
}
```

**CLI Command**:
```bash
cyense scan multi targets.txt                    # Scan from file
cyense scan multi repo1 repo2 repo3              # Scan multiple repos
cyense scan multi --file targets.txt --concurrency 3
```

**targets.txt Format**:
```
# One target per line
github:https://github.com/org/repo1
github:https://github.com/org/repo2
local:/path/to/project
url:https://api.example.com
```

### 3.5 Enhanced CLI Commands

#### 3.5.1 `cyense view`

Open web dashboard for scan results.

```bash
cyense view <scan_id>                # Open specific scan
cyense view --latest                 # Open most recent
cyense view --port 8080              # Custom port
cyense view --no-browser             # Don't auto-open browser
```

#### 3.5.2 `cyense history`

List past scans with summary.

```bash
cyense history                       # List all scans
cyense history --limit 10            # Last 10 scans
cyense history --status completed    # Filter by status
cyense history --format table        # Table output (default)
cyense history --format json         # JSON output
```

**Output**:
```
Scan ID     Status      Targets  Findings  Created
-------     ------      -------  --------  -------
abc123      completed   3        42        2026-08-30 14:22:01
def456      failed      1        -         2026-08-30 13:15:30
ghi789      running     2        15        2026-08-30 12:00:00
```

#### 3.5.3 `cyense compare`

Compare two scans side-by-side.

```bash
cyense compare <scan1> <scan2>       # Compare two scans
cyense compare <scan1> <scan2> --diff-only  # Show only differences
cyense compare <scan1> <scan2> --format json
```

**Output**:
```
Finding                Scan 1 (abc123)    Scan 2 (def456)
-------                ---------------    ---------------
CY001 @ api.py:42      High (6.5)         High (6.5) ✓
XS004 @ login.js:15    -                  Critical (9.8) ⚠ NEW
CY003 @ user.py:88     Medium (4.3)       -              ⚠ REMOVED

Summary:
  Scan 1: 10 findings (2 critical, 3 high, 5 medium)
  Scan 2: 11 findings (3 critical, 3 high, 5 medium)
  New: 1, Removed: 1, Unchanged: 9
```

### 3.6 Configuration Persistence

**Objective**: Save user preferences to avoid repeating flags.

**Implementation**:
- Config file: `~/.cyense/config.json`
- Permissions: `0o600` (same as Strix's secret_files.py)
- Atomic writes (tempfile + replace)
- Schema validation with Pydantic

**Config Schema**:
```python
class CyenseConfig(BaseModel):
    api_url: str = "http://localhost:8000"
    default_scan_mode: str = "standard"
    default_scope_mode: str = "auto"
    default_output_format: str = "json"
    viewer_port: int = 8080
    auto_open_viewer: bool = True
    github_token: Optional[str] = None  # encrypted
    telemetry_enabled: bool = False
```

**File Structure**:
```
dev/main/app/config/
  ├── __init__.py
  ├── persistence.py    # Load/save config
  └── schema.py         # Config schema
```

**CLI Commands**:
```bash
cyense config set api_url http://localhost:9000
cyense config set default_scan_mode deep
cyense config get api_url
cyense config list
cyense config reset
```

### 3.7 Scan Resume

**Objective**: Resume interrupted scans from last checkpoint.

**Implementation**:
- Save scan state to `reports/{scan_id}/state.json` periodically
- State includes:
  - Current phase (resolve/analyze/verify/report)
  - Completed targets (for multi-target)
  - Completed rules
  - Partial findings
- On resume, load state and continue from checkpoint
- State file format: JSON with version field for migrations

**API Changes**:
```python
# ScanRequest
resume_from: Optional[str]  # scan_id to resume from

# ScanResponse
resumed_from: Optional[str]  # original scan_id
checkpoint: Optional[dict]   # current state
```

**CLI Command**:
```bash
cyense scan github <url> --resume <scan_id>  # Resume interrupted scan
cyense scan resume <scan_id>                  # Shortcut
```

## 4. Architecture

### 4.1 Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                      CLI Layer                          │
│  view | history | compare | config | multi | resume    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    API Layer                            │
│  /viewer | /report/pdf | /export/csv | /scans/multi    │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  Service Layer                          │
│  ViewerService | PDFService | CSVService | MultiScan   │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  Data Layer                             │
│  ReportState | ConfigStore | ScanHistory               │
└─────────────────────────────────────────────────────────┘
```

### 4.2 File Structure

```
dev/main/app/
├── api/
│   ├── viewer.py              # Web viewer endpoints
│   └── export.py              # CSV/PDF export endpoints
├── report/
│   ├── pdf_report.py          # PDF generation
│   ├── csv_export.py          # CSV generation
│   └── templates/
│       └── default.pdf        # PDF template
├── interface/
│   └── viewer/
│       ├── static/
│       │   ├── index.html
│       │   ├── style.css
│       │   └── app.js
│       └── __init__.py
├── config/
│   ├── __init__.py
│   ├── persistence.py         # Config load/save
│   └── schema.py              # Config schema
└── services/
    ├── viewer_service.py      # Viewer logic
    ├── multi_scan.py          # Multi-target scanning
    └── scan_history.py        # Scan history management
```

## 5. Implementation Plan

### 5.1 Phase 1: Core Infrastructure (Week 1)

**Week 1**:
- [ ] Set up viewer static files (HTML/CSS/JS)
- [ ] Implement `/scans/{scan_id}/viewer` endpoint
- [ ] Basic dashboard with findings table
- [ ] Severity filtering
- [ ] Finding detail modal

**Deliverable**: Working web viewer with basic functionality

### 5.2 Phase 2: Export Formats (Week 2)

**Week 2**:
- [ ] Implement PDF generation with reportlab
- [ ] PDF template with CVSS/CWE
- [ ] CSV export with all fields
- [ ] API endpoints for PDF/CSV
- [ ] CLI commands: `report pdf`, `export csv`

**Deliverable**: PDF and CSV export working

### 5.3 Phase 3: Multi-Target & History (Week 3)

**Week 3**:
- [ ] Multi-target scan API
- [ ] Parallel execution with concurrency control
- [ ] Result aggregation
- [ ] Scan history storage
- [ ] CLI: `scan multi`, `history`

**Deliverable**: Multi-target scanning and history

### 5.4 Phase 4: Advanced Features (Week 4)

**Week 4**:
- [ ] Scan comparison logic
- [ ] Configuration persistence
- [ ] Scan resume with checkpoints
- [ ] CLI: `compare`, `config`, `resume`
- [ ] Documentation and examples

**Deliverable**: All features complete

## 6. Dependencies

### 6.1 New Dependencies

```toml
[project.dependencies]
reportlab = ">=4.0"
pypdf = ">=3.0"
```

### 6.2 Existing Dependencies (Already Used)

- `fastapi` - API framework
- `pydantic` - Config schema
- `rich` - CLI tables and formatting
- `typer` - CLI framework

## 7. Testing Strategy

### 7.1 Unit Tests

```python
# test_pdf_report.py
def test_pdf_generation():
    report = {...}
    pdf_bytes = generate_pdf(report)
    assert pdf_bytes.startswith(b'%PDF')

# test_csv_export.py
def test_csv_export():
    findings = [...]
    csv_content = export_csv(findings)
    assert "finding_id,rule,severity" in csv_content

# test_multi_scan.py
def test_multi_target_aggregation():
    results = [...]
    aggregated = aggregate_results(results)
    assert aggregated["total_findings"] == 42
```

### 7.2 Integration Tests

```python
# test_viewer_integration.py
def test_viewer_endpoint():
    response = client.get("/scans/abc123/viewer")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text

# test_scan_resume.py
def test_scan_resume():
    # Create interrupted scan
    scan_id = create_scan()
    interrupt_scan(scan_id)
    
    # Resume
    resumed = resume_scan(scan_id)
    assert resumed["resumed_from"] == scan_id
    assert resumed["status"] == "completed"
```

### 7.3 E2E Tests

```bash
# Test full workflow
cyense scan github https://github.com/test/repo
cyense view --latest
cyense report pdf abc123 -o report.pdf
cyense export csv abc123 -o findings.csv
cyense history --limit 5
cyense compare abc123 def456
```

## 8. Security & Ethics

### 8.1 Security Considerations

1. **Viewer Authentication**: 
   - Optional basic auth for viewer
   - Token-based access for shared dashboards
   - CORS restrictions

2. **Config Secrets**:
   - GitHub tokens encrypted at rest
   - Config file permissions `0o600`
   - No secrets in logs

3. **PDF/CSV Injection**:
   - Sanitize all user-provided content
   - Escape special characters
   - Validate file paths

### 8.2 Ethical Guidelines

1. **Multi-Target Scanning**:
   - Require explicit permission for each target
   - Rate limiting to avoid overwhelming targets
   - Respect robots.txt for URL targets

2. **Scan Resume**:
   - Clear indication when resuming
   - User confirmation for long-running scans
   - Timeout handling

## 9. Performance Considerations

### 9.1 Multi-Target Concurrency

```python
# Default: 3 concurrent scans
DEFAULT_CONCURRENCY = 3

# Configurable via CLI
cyense scan multi targets.txt --concurrency 5

# Or config
cyense config set default_concurrency 5
```

### 9.2 Viewer Performance

- Lazy load findings (pagination)
- Virtual scrolling for large finding lists
- Cache dashboard data (5 min TTL)
- Compress JSON responses (gzip)

### 9.3 PDF Generation

- Async generation (don't block API)
- Progress callback for large reports
- Memory-efficient (stream pages)

## 10. Migration & Compatibility

### 10.1 Backward Compatibility

- All new features are additive
- Existing API endpoints unchanged
- Old scan results still viewable
- Config file optional (env vars still work)

### 10.2 Data Migration

```python
# If config schema changes
def migrate_config(old_config: dict) -> dict:
    if "version" not in old_config:
        old_config["version"] = "1.0"
    return old_config
```

## 11. Documentation

### 11.1 User Documentation

- Web viewer usage guide
- PDF/CSV export examples
- Multi-target scanning tutorial
- Configuration reference
- CLI command reference

### 11.2 Developer Documentation

- API endpoint specs
- Viewer customization guide
- Plugin architecture (future)
- Contributing guidelines

## 12. Future Enhancements (Out of Scope)

These features are noted but not in this PRD:

1. **Real-time Dashboard** - WebSocket for live updates
2. **Scan Scheduling** - Cron-like scheduled scans
3. **Notification System** - Email/Slack alerts
4. **Custom Report Templates** - User-defined PDF templates
5. **Scan Annotations** - User comments on findings
6. **Vulnerability Tracking** - Integration with Jira/GitHub Issues
7. **Trend Analysis** - Historical charts and metrics
8. **Role-Based Access** - Multi-user support
9. **Scan Policies** - Custom rule configurations
10. **Plugin System** - Third-party extensions

## 13. Success Metrics

### 13.1 Adoption Metrics

- % of users using web viewer
- % of scans exported to PDF/CSV
- % of multi-target scans
- % of resumed scans

### 13.2 Performance Metrics

- Viewer load time < 2s
- PDF generation < 30s for 100 findings
- Multi-target scan time < 2x single target
- Config load time < 100ms

### 13.3 User Satisfaction

- Viewer usability score > 4/5
- Export format satisfaction > 4/5
- CLI command discoverability > 80%

## 14. References

1. Strix Web Viewer: https://github.com/usestrix/strix/tree/main/strix/interface/viewer
2. Strix PDF Generation: https://github.com/usestrix/strix/blob/main/strix/interface/viewer/report_pdf.py
3. Strix Multi-Target: https://github.com/usestrix/strix/blob/main/strix/core/runner.py
4. Strix Config: https://github.com/usestrix/strix/blob/main/strix/config/settings.py
5. reportlab Documentation: https://docs.reportlab.com/
6. SARIF Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## 15. Appendices

### A. Example Viewer Screenshot

```
┌─────────────────────────────────────────────────────────┐
│  Cyense Scan Results - abc123                           │
├─────────────────────────────────────────────────────────┤
│  Summary                                                │
│  ┌─────────────┬─────────────┬─────────────┐           │
│  │  Critical   │    High     │   Medium    │           │
│  │      2      │      5      │     12      │           │
│  └─────────────┴─────────────┴─────────────┘           │
├─────────────────────────────────────────────────────────┤
│  Filter: [All ▼]  Search: [________________]           │
├─────────────────────────────────────────────────────────┤
│  ID      Rule    Severity  CVSS  Location              │
│  ───     ────    ────────  ────  ────────              │
│  1       CY001   High      6.5   api.py:42             │
│  2       XS004   Critical  9.8   login.js:15           │
│  3       CY003   Medium    4.3   user.py:88            │
│  ...                                                    │
└─────────────────────────────────────────────────────────┘
```

### B. Example PDF Report Structure

```
┌─────────────────────────────────────────┐
│  Cyense Security Assessment Report      │
│  Generated: 2026-08-30 14:22:01 UTC     │
├─────────────────────────────────────────┤
│  Executive Summary                      │
│  - 19 findings discovered               │
│  - 2 critical, 5 high, 12 medium        │
│  - Top risk: IDOR vulnerabilities        │
├─────────────────────────────────────────┤
│  Findings Overview                      │
│  [Severity breakdown chart]             │
│  [CVSS distribution chart]              │
├─────────────────────────────────────────┤
│  Detailed Findings                      │
│  1. CY001 - Unscoped .get()             │
│     Severity: High (6.5)                │
│     Location: api.py:42                 │
│     Code: [snippet]                     │
│     Remediation: [steps]                │
│  ...                                    │
├─────────────────────────────────────────┤
│  Remediation Priorities                 │
│  1. Fix IDOR issues (critical)          │
│  2. Address XSS vulnerabilities (high)  │
│  3. Review access controls (medium)     │
└─────────────────────────────────────────┘
```

### C. Example CSV Format

```csv
finding_id,rule,severity,cvss_score,cvss_vector,cwe,title,description,location,snippet,remediation,confidence,verified_at
F001,CY001,high,6.5,CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N,CWE-639,Unscoped .get() on invoice_id,Direct database lookup using user-controlled parameter without ownership check,app/api/invoices.py:42,"invoice = Invoice.objects.get(id=request.GET['id'])",Add user ownership check,0.95,2026-08-30T14:22:01Z
F002,XS004,critical,9.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,CWE-95,eval() on user input,Direct code execution of user-controlled input,app/views/search.js:15,"eval(req.query.expr)",Replace with safe parser,0.98,2026-08-30T14:22:02Z
```

---

**End of PRD**
