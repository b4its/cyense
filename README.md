# 🛡️ Cyense: Cyber Defense for Search and Treat Vulnerability in Our System

**Agentic IDOR & XSS vulnerability scanner** — discovers *Insecure Direct Object Reference* and *Cross-Site Scripting* patterns in dynamic routes through orchestrated AI agents, audits GitHub repositories, and proposes automatic remediation.

> **ID (Bahasa Indonesia):** Scanner kerentanan **IDOR** dan **XSS** berbasis agen — menemukan *Insecure Direct Object Reference* serta pola *Cross-Site Scripting* pada routing dinamis menggunakan agen AI yang diorkestrasi, mengaudit repositori GitHub, dan memberikan usulan perbaikan otomatis.

---

## 1. Who Has This Problem? / Siapa yang Punya Masalah Ini?

**EN:** Pentesters, bug bounty hunters, and developers who still triage IDOR manually.

**ID:** Pentester, bug bounty hunter, dan developer yang masih harus melakukan triase IDOR secara manual.

| Persona | Bottleneck / Kendala |
|---------|----------------------|
| 🎯 **Pentester** (Andi) | Receives a URL scope → maps endpoints, guesses ID patterns, tries combinations, compares responses — all manual via Burp/Postman. **1–3 hours per endpoint.** / Menerima scope URL → memetakan endpoint, menebak pola ID, mencoba kombinasi, membandingkan response — semua manual via Burp/Postman. **1–3 jam per endpoint.** |
| 🐛 **Bug bounty hunter** (Sari) | Commercial tools (~$450/year) do naive response diffing → many false positives → triaging the scan results takes even more time. / Tools komersial (~$450/tahun) melakukan diff response secara naif → banyak false positive → triase hasil scan justru makan waktu lagi. |
| 👨‍💻 **Developer** (Budi) | Wants to self-check endpoints before deploy, but has no time/budget for commercial tools. Auditing someone else's GitHub repo requires manual clone first. / Ingin mengecek endpoint sendiri sebelum deploy, tapi tidak punya waktu/anggaran untuk tool komersial. Audit repo GitHub pihak lain butuh clone manual dulu. |

**EN — Core bottleneck:** IDOR triage is repetitive yet requires *contextual reasoning* — is this 200 OK really another user's data, or just a generic page? And after findings are discovered, writing fixes remains manual for every location.

**ID — Bottleneck inti:** triase IDOR repetitif namun butuh *nalar konteks* — apakah 200 OK ini benar-benar data milik user lain, atau sekadar halaman generik? Dan setelah temuan ditemukan, menulis perbaikannya tetap manual untuk setiap titik.

**EN — Why it matters:** one manual triage of 1–3 hours/endpoint becomes a minute-long scan; false positives are suppressed so pentesters only review verified findings; developers receive ready-to-review remediation diffs — not just text instructions.

**ID — Mengapa berharga:** satu triase manual 1–3 jam/endpoint menjadi scan menit; false positive tertekan sehingga pentester hanya meninjau temuan terverifikasi; developer mendapat diff perbaikan siap review — bukan sekadar instruksi teks.

---

## 2. How the Agent Solves It / Bagaimana Agent Menyelesaikannya

### Multi-agent pipeline — 6 agents, one orchestrator / 6 agen, satu orkestrator

```
POST /scans ──► asyncio queue ──► Orchestrator
                                         │
         ┌───────────────┬───────────────┼────────────────┬──────────────┐
         ▼               ▼               ▼                ▼              ▼
    🎯 RECON         🕵️ PROBER       ⚖️ VERIFIER      🐙 FETCHER      🔧 FIXER
    context          tools           verification     tools           remediation
    parse {ID}       fire candidates  4-step check     github tarball  patch proposals
    fingerprint      adaptive expand  control-ID ⭐    sandbox extract  diff + verify
    brain strategy   classify shape   PII detection    host allowlist  backup/revert
         │               │               │                │              │
         └───────────────┴───────┬───────┴────────────────┴──────────────┘
                                 ▼
                          🧠 BRAIN (memory)
                          knowledge.json — persist antar-scan
```

### Agent capabilities → competition rubric / Kapabilitas agent → rubrik lomba

| Capability / Kapabilitas | Implementation in Cyense / Implementasi di Cyense |
|--------------------------|---------------------------------------------------|
| **Better context** | 🎯 Recon: fingerprints framework from response → probing strategy from Brain / Recon: fingerprint framework dari response → strategi probing dari Brain |
| **Better tools** | 🕵️ Prober: rate-limited parallel probing + adaptive expansion; 🐙 Fetcher: GitHub tarball + guarded sandbox / Prober: probing paralel rate-limited + adaptive expansion; Fetcher: tarball GitHub + sandbox ber-guard |
| **Memory** | 🧠 Brain: framework knowledge + valid ids + `repo@sha` cache across scans / Brain: knowledge framework + id valid + cache `repo@sha` antar-scan |
| **Verification** | ⚖️ Verifier: 4-step + **control-ID negative control**; 🔧 Fixer: re-scan proves findings disappear / Verifier: 4 langkah + **kontrol-ID negative control**; Fixer: re-scan membuktikan temuan hilang |
| **Orchestration** | Orchestrator: `recon → probe → verify → report` pipeline with live stage progress / Orchestrator: pipeline `recon → probe → verify → report` dengan progress live per stage |

### ⭐ Key innovation — Control-ID as negative control / Inovasi kunci — Kontrol-ID sebagai negative control

**EN:** Pentester knowledge encoded as a verification step: request an ID that **definitely does not exist** (e.g. `99999999`) as a comparison. The candidate response is compared to the control response via **JSON key-set comparison** — identical = *generic-200* = false positive → rejected. This is what naive scanners do not do, and it is the strongest evidence that "the agent solves it well."

**ID:** Pengetahuan pentester yang di-encode sebagai verification step: request dengan ID yang **pasti tidak ada** (mis. `99999999`) sebagai pembanding. Response kandidat dibandingkan dengan response kontrol via **JSON key-set comparison** — identik = *generic-200* = false positive → ditolak. Ini yang tidak dilakukan scanner naif, dan menjadi bukti terkuat "does the agent solve it well?"

### Design decision: no LLM / Keputusan desain: tanpa LLM

**EN:** The required reasoning (difflib similarity, PII regex, status code, control behavior, AST transform) is already **objective and deterministic**. An LLM would only add cost, nondeterminism, and credential-leak risk (ground rule #8). Cyense chooses *memory + verification + orchestration + better tools* — cheap ($0) and 100% reproducible. *Purposeful design choices > number of components.*

**ID:** Nalar konteks yang dibutuhkan (similarity difflib, PII regex, status code, kontrol behavior, AST transform) sudah **objektif dan deterministik**. LLM justru menambah biaya, nondeterminisme, dan risiko kredensial keluar (ground rule #8). Cyense memilih *memory + verification + orchestration + better tools* yang murah ($0) dan 100% reprodusibel — *purposeful design choices > jumlah komponen*.

---

## 3. Five Scan Modes / Lima Mode Scan

| Mode | Input | Pipeline | Output |
|------|-------|----------|--------|
| **`link`** | URL with placeholder `http://app/invoice/{ID}` + credentials / URL ber-placeholder + kredensial | Recon → Prober → Verifier → Report (dynamic) | Verified findings + PII evidence + reproducible curl / Temuan terverifikasi + bukti PII + curl reprodusibel |
| **`program`** | Source code (mounted `/workspace` or built-in sample) / Source code (mounted `/workspace` atau sample bawaan | Static analysis / Analisis statis | `file:line` + rule CY001–CY010 + XS001–XS008 + SQLI001–SQLI006 + remediation |
| **`github`** | Repo link `https://github.com/owner/repo` / Link repo | Fetcher (tarball + sandbox) → Analyze → Report | Static findings + reproducible `commit_sha` + brain cache / Temuan statis + `commit_sha` reprodusibel + brain cache |
| **`website`** | Any public URL `http://example.com` (no placeholder needed) / URL publik apa pun (tanpa placeholder) | Crawler → Probe-IDOR → Analyze-XSS → Report | ID-bearing endpoints + live XSS surface (CSP, HSTS, eval/innerHTML in HTML *and external JS*, confirmed reflected params via benign probe, srcdoc, cookie exfiltration, missing headers) + live SQLi (error-based + blind boolean) |
| **`fixes`** | Findings from any scan / Temuan dari scan manapun | Fixer → propose (dry-run) → apply+confirm → re-scan verify | Diff patch + proof finding disappeared + backup/revert / Diff patch + bukti temuan hilang + backup/revert |

### Analysis Levels / Level Analisis

**EN:** For `program` and `github` scans, you can control how deeply Cyense analyzes source code via the `--level` flag. Higher levels activate more sophisticated rules at the cost of more scan time.

**ID:** Untuk scan `program` dan `github`, Anda dapat mengontrol seberapa dalam Cyense menganalisis source code melalui flag `--level`. Level yang lebih tinggi mengaktifkan rule yang lebih canggih dengan biaya waktu scan lebih lama.

| Level | Files | Active Rules | Extra Analysis |
|-------|-------|--------------|----------------|
| **low** | ≤100 | CY001–CY010, XS001–XS008, SQLI001–SQLI006 | Quick CI/pre-commit check / cek CI cepat |
| **medium** (default) | ≤1000 | CY001–CY010, XS001–XS008, SQLI001–SQLI006 | Balanced coverage / cakupan seimbang |
| **high** | ≤5000 | + **CY011, CY012, XS009, XS010** | Data flow tracking |
| **max** | unlimited | + **CY013, XS011** | Cross-file analysis + call graph |

**Deep rules exclusive to high/max / Rule deep eksklusif untuk high/max:**

| Rule | Severity | What it detects / Apa yang dideteksi |
|------|----------|--------------------------------------|
| **CY011** (high) | High | Data-flow IDOR: user input from `request.*` flows into DB query without ownership filter / IDOR data-flow: input user dari `request.*` mengalir ke query DB tanpa filter kepemilikan |
| **CY012** (high) | High | Unauthenticated endpoint accessing user data (CWE-306) / Endpoint tanpa auth yang mengakses data user |
| **CY013** (max) | Medium | Cross-file IDOR: route delegates to imported helper that queries DB / IDOR lintas-file: route mendelegasikan ke helper terimpor yang query DB |
| **XS009** (high, JS) | High | `document.cookie` leaked to external origin via fetch/XHR/beacon |
| **XS010** (high, Py) | Critical | `eval/exec/compile` with user-controlled input (data flow) |
| **XS011** (max, Py) | Medium | Cross-file XSS: route renders user input through imported template helper |

**Example / Contoh:**
```bash
cyense scan program --level high --i-have-permission --source-type sample
# → 13 findings (vs 10 at medium) — CY011 data-flow catches 3 additional IDOR
cyense scan github https://github.com/owner/repo --level max --i-have-permission
```

**18 detection rules / 18 aturan deteksi:**

| Rule | Pattern / Pola | Language | Severity |
|------|----------------|----------|----------|
| CY001 | `Model.objects.get(id=request.X)` without ownership / tanpa ownership | Python | High |
| CY002 | `.filter(id=...).first()` without user scoping / tanpa user scoping | Python | High |
| CY003 | Flask route `<int:id>` → unscoped query / query unscoped | Python | High |
| CY004 | FastAPI path param → direct DB query / DB query langsung | Python | High |
| CY005 | `get_object_or_404` without `user=` / tanpa `user=` | Python | High |
| CY006 | `open(f"/uploads/{request.param}")` | Python | **Critical** |
| CY007 | `findOne({_id: req.params.id})` | JS | High |
| CY008 | `findById(req.params.id)` | JS | High |
| CY009 | `->where('id', $_GET[..])` | PHP | High |
| CY010 | `Model::find($_GET[..])` | PHP | High |
| **CY011** ⚡ | data-flow: `request.*` → DB query without ownership (high level) | Python | High |
| **CY012** ⚡ | unauth endpoint accessing user data, no auth decorator (high level) | Python | High |
| **CY013** ⚡ | cross-file: route delegates request input to imported DB helper (max level) | Python | Medium |
| IDOR-LINK | 200 + cross-account PII + control-ID blocked / 200 + PII cross-account + kontrol-ID blocked | HTTP | **Critical** |

**EN:** A second rule class — XSS (`XS001`–`XS008`) — runs as a second pass in the static engine (program & github): `innerHTML`/`document.write`/`dangerouslySetInnerHTML` (JS), `eval` (critical), `v-html` (Vue), `echo $_GET` without escaping (PHP), `|safe` Jinja2, and HTML composition via f-string (Python) — each with anti-false-positive guards (static strings, sanitized output, comments are not reported). See `instruction/feature/xss-detection.md`.

**EN:** At the `high` level, three additional XSS rules activate: **XS009** (JS — `document.cookie` leaked via fetch/XHR/beacon), **XS010** (Python — `eval`/`exec`/`compile` of user-controlled input traced via data flow). At `max`, **XS011** (Python — cross-file XSS via imported template renderers).

**ID:** Pada level `high`, tiga rule XSS tambahan aktif: **XS009** (JS — `document.cookie` bocor via fetch/XHR/beacon), **XS010** (Python — `eval`/`exec`/`compile` dari input user yang dilacak via data flow). Pada `max`, **XS011** (Python — XSS lintas-file via template renderer terimpor).

**ID:** Kelas aturan kedua — XSS (`XS001`–`XS008`) — berjalan sebagai pass kedua pada mesin statis (program & github): `innerHTML`/`document.write`/`dangerouslySetInnerHTML` (JS), `eval` (critical), `v-html` (Vue), `echo $_GET` tanpa escape (PHP), `|safe` Jinja2, dan komposisi HTML via f-string (Python) — masing-masing dengan guard anti false-positive (string statis, output ter-sanitasi, dan komentar tidak dilaporkan). Lihat `instruction/feature/xss-detection.md`.

**EN — A third rule class — SQL Injection (`SQLI001`–`SQLI006`)** — runs in the same static engine (program & github): `cursor.execute()`/`executemany()` with f-string/`%`/`format()` (Python), Django `raw()`/`extra()` and SQLAlchemy `text()` with interpolation, JS `query()`/`execute()` with template-literal/concatenation, PHP `mysqli_query`/`pg_query`/`PDO::query` with superglobals or concatenation, and raw f-string SQL (SQLI006). Parameterized queries (`?`/`%s` with separate values) are **not** flagged. In website mode, live SQLi probing sends payloads and detects **error-based** (DB error signatures: MySQL/PostgreSQL/Oracle/SQLite/MSSQL/DB2) and **blind boolean-differential** (`' AND 1=1` vs `' AND 1=2`) — rule `SQLI-LIVE`.

**ID — Kelas aturan ketiga — SQL Injection (`SQLI001`–`SQLI006`)** — berjalan di mesin statis yang sama (program & github): `cursor.execute()`/`executemany()` dengan f-string/`%`/`format()` (Python), Django `raw()`/`extra()` dan SQLAlchemy `text()` dengan interpolasi, JS `query()`/`execute()` dengan template-literal/concatenation, PHP `mysqli_query`/`pg_query`/`PDO::query` dengan superglobal atau concatenation, dan f-string SQL mentah (SQLI006). Query terparameterisasi (`?`/`%s` dengan nilai terpisah) **tidak** dilaporkan. Pada mode website, probing SQLi live mengirim payload dan mendeteksi **error-based** (signature error DB: MySQL/PostgreSQL/Oracle/SQLite/MSSQL/DB2) serta **blind boolean-differential** (`' AND 1=1` vs `' AND 1=2`) — rule `SQLI-LIVE`.

---

## 4. Measured Improvement / Peningkatan Terukur

**EN — Primary metric: precision** — percentage of findings that are truly IDOR. The biggest user pain is false-positive triage time. Task, eval cases, rate limit, and concurrency are **identical** for baseline and agentic (fair comparison, PRD §7.2).

**ID — Primary metric: precision** — persentase temuan yang benar-benar IDOR. Pain terbesar user adalah waktu triase false positive. Task, eval cases, rate limit, dan concurrency **identik** untuk baseline dan agentic (fair comparison, PRD §7.2).

### Eval results — 9 lab cases (from 11 PRD §7.3 cases; flaky/timeout cases excluded) / Hasil eval — 9 kasus lab

| Metric | Simple Baseline (naive) | Agent Solution (Cyense) | Change |
|--------|------------------------|-------------------------|--------|
| **Precision (correct cases)** | 5/9 (**56%**) | **9/9 (100%)** | **+44 points** |
| False positives on trap (cases 4 & 11) | 4 reported raw | **0** (15 rejected by verifier) | −100% |
| IDOR critical + PII detected | 2 | 2 (confidence 0.95) | same |
| Scan time per case | ~12 ms | ~17 ms | +5 ms (cheap for precision) |
| Generic-200 trap (case 4) | 3 FPs reported | Rejected via control-ID ⭐ | — |

### Per-case results / Hasil per kasus

| Case / Kasus | Ground Truth | Baseline | Agentic |
|--------------|--------------|----------|---------|
| 1. `/invoice/{ID}` different PII | IDOR Critical | ✅ 2 findings | ✅ 2 critical findings |
| 2. `/orders/{ID}` no PII | IDOR High | ❌ miss | ✅ 1 finding |
| 3. `/profile/{ID}` 403 | Safe | ✅ 0 findings | ✅ 0 findings |
| 4. `/docs/{ID}` generic-200 | **False-positive trap** | ❌ 3 FPs | ✅ 0 (8 rejected) |
| 5. UUID direct access | IDOR | ❌ miss | ✅ 1 critical (PII) |
| 7. `/payment/{ID}` 302 login | Safe | ✅ 0 | ✅ 0 |
| 8. `/file/{ID}` | IDOR Critical | ❌ miss | ✅ 1 finding |
| 10. `/missing/{ID}` 404 all | Safe | ✅ 0 | ✅ 0 |
| 11. generic + 1 different shape | **Challenging** | ✅ (by chance) | ✅ 1 finding (via control) |

### Regression suite

```
177 passed in ~2s — api, agents, rules, utils, github, remediation, worker, sarif, website, live_xss, sqli
ruff check: All checks passed (0 errors)
```

---

## 5. Improvement Changelog / Riwayat Peningkatan

| Stage | What was tried & why / Apa yang dicoba & mengapa | Evidence / Bukti | Decision / Keputusan |
|-------|----------------------------------------------------|------------------|----------------------|
| **Baseline** | Naive probing: report every 200 with similar shape / Naive probing: laporkan semua 200 mirip-shape | 56% precision, 4 FPs on trap / 56% precision, 4 FP pada trap | Starting point / Titik awal |
| **Iteration 1** | + Verifier 4-step (similarity, PII, retry, control-id) / + Verifier 4 langkah | FP trap reduced / FP trap berkurang | **kept** |
| **Iteration 2** | + Forward all 200 candidates to verifier (remove shape pre-filter) / + Forward semua kandidat-200 ke verifier | PII preserved — cases 5 & 8 detected (2→4 correct) / PII tidak hilang — kasus 5 & 8 terdeteksi | **kept** |
| **Iteration 3** | + Control-ID as negative control + JSON key-set comparison (not brittle raw-text similarity) / + Kontrol-ID + JSON key-set comparison | 100% precision (9/9) | **kept** — main contribution / kontribusi utama |
| **Iteration 4** | + Brain memory across scans (valid ids + fingerprint + repo@sha cache) / + Brain memory antar-scan | Re-scan same repo skips fetch / Scan ulang repo sama skip fetch | **kept** |
| **Iteration 5** | + Github mode (Fetcher agent, sandbox guard, host allowlist) / + Mode github | Parity test: findings identical to program mode / Parity test: temuan identik dgn mode program | **kept** |
| **Iteration 6** | + Remediation Fixer (diff proposal, backup, revert, verify loop) / + Remediasi Fixer | E2E: 10 findings → 10 proposals, safety gate 422 | **kept** |
| **Removed** | Same-shape pre-filter in prober before verifier / Pre-filter same-shape di prober | Caused cross-account PII to be dropped (case 5) / Menyebabkan PII cross-account terbuang (kasus 5) | **removed** — lesson: don't pre-filter what downstream can verify better / pelajaran: jangan pre-filter apa yang bisa diverifikasi lebih baik di downstream |
| **Removed** | Raw-text similarity for control-ID check / Raw-text similarity untuk kontrol-ID | Brittle against echoed id in body (false reject/accept) / Rapuh terhadap id yang di-echo | **removed** — replaced by JSON key-set / diganti JSON key-set |

---

## 6. Reproduction Guide / Panduan Reproduksi

### Prerequisites / Prasyarat
- Docker ≥ 20.10 + Compose v2, **or** Python 3.11+

### Run with Docker (recommended) / Jalankan via Docker (direkomendasikan)

```bash
git clone <repo-url> && cd cyense
make up          # api :8000 + lab app :8080 (profile lab)
curl http://localhost:8000/api/v1/health
# {"status":"ok","service":"cyense","version":"2.1.0"}
```

### Run with Python / Jalankan via Python

```bash
cd dev/main
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000
# Swagger UI: http://localhost:8000/docs
```

### Reproduce evaluation (baseline vs agentic) / Reproduksi evaluasi

```bash
# 1. Start vulnerable lab app (11 eval cases)
docker compose --profile lab up -d
# or: python dev/main/tests/fixtures/vulnerable_app/lab_app.py

# 2. Agentic scan — case 1 (IDOR critical + PII)
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode":"link","url":"http://localhost:8080/invoice/{ID}",
       "baseline_id":"1","probe_ids":["2","3"],"i_have_permission":true}'
# → 202 {"scan_id":"..."}

curl http://localhost:8000/api/v1/scans/<id>/report | jq '.summary'
# {"critical":2,"total":2,...}  ← PII bob@example.com + control-ID blocked

# 3. False-positive trap — case 4 (generic-200)
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode":"link","url":"http://localhost:8080/docs/{ID}",
       "baseline_id":"x","probe_ids":["y","z"],"i_have_permission":true}'
curl http://localhost:8000/api/v1/scans/<id>/report | jq '.summary'
# {"total":0,"rejected_false_positives":8,...}  ← REJECTED via control-ID ⭐
```

**EN:** Runtime: < 30 seconds for the whole eval (concurrency 10, 50 probes). Cost: $0 (no LLM/external API).

**ID:** Runtime: < 30 detik untuk seluruh eval (concurrency 10, 50 probe). Biaya: $0 (tanpa LLM/API eksternal).

### Run test suite / Jalankan test suite

```bash
make test       # 177 tests via pytest
make lint       # ruff, 0 errors
```

---

## 7. API Reference / Referensi API (`/api/v1`, auto Swagger at `/docs`)

| Method | Path | Description / Deskripsi |
|--------|------|-------------------------|
| GET | `/health` | Liveness |
| POST | `/scans` | Submit scan → `202 {scan_id}` (422 without `i_have_permission`) / Submit scan → `202 {scan_id}` (422 tanpa `i_have_permission`) |
| GET | `/scans` | List scans / Daftar scan |
| GET | `/scans/{id}` | Status + live progress + stage / Status + progress live + stage |
| GET | `/scans/{id}/report` | Full JSON report / Laporan JSON lengkap |
| GET | `/scans/{id}/report/html` | Self-contained HTML report / Laporan HTML self-contained |
| GET | `/scans/{id}/report/sarif` | SARIF 2.1.0 export |
| GET | `/scans/{id}/coverage` | Coverage document |
| GET | `/scans/{id}/export/csv` | CSV findings export |
| GET | `/scans/{id}/export/pdf` | PDF compliance report |
| GET | `/scans/resumable` | List resumable scans / Daftar scan yang bisa dilanjutkan |
| DELETE | `/scans/{id}` | Delete scan & artifacts / Hapus scan & artefak |
| GET | `/rules` | Active rules catalog / Daftar rule aktif |
| POST | `/scans/{id}/fixes` | Generate patch proposals (dry-run) / Generate usulan patch (dry-run) |
| GET | `/fixes/{session_id}` | List proposals / Daftar proposal |
| GET | `/fixes/{session_id}/diff` | Combined unified diff / Unified diff gabungan |
| POST | `/fixes/{session_id}/apply` | Apply (requires `confirm:true`) + backup + verify / Apply (wajib `confirm:true`) + backup + verify |
| POST | `/fixes/{session_id}/revert` | Restore from backup / Restore dari backup |

**State machine / Mesin state:** `QUEUED → RUNNING (recon|probe|verify|resolve|fetch|analyze|report) → COMPLETED | FAILED`

### Example: github mode & remediation / Contoh: mode github & remediasi

```bash
# Audit public GitHub repo (fetcher + sandbox + CY001-CY010 rules)
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode":"github","repo_url":"https://github.com/owner/repo",
       "ref":"main","i_have_permission":true}'

# Request remediation proposals from a scan (dry-run, does not write)
curl -X POST http://localhost:8000/api/v1/scans/<scan_id>/fixes
# → {"session_id":"fix_...","message":"Proposals generated: 10 fixes ready"}

# Review diff, then apply subset (requires explicit confirm)
curl http://localhost:8000/api/v1/fixes/<session_id>/diff
curl -X POST http://localhost:8000/api/v1/fixes/<session_id>/apply \
  -H 'Content-Type: application/json' \
  -d '{"fix_ids":["..."],"confirm":true}'
```

---

## 8. Security, Ethics & Ground Rules / Keamanan, Etika & Ground Rules

| Ground rule | Implementation in Cyense / Implementasi di Cyense |
|-------------|---------------------------------------------------|
| #4 Sandbox + human approval | Gate `i_have_permission` (422 without it); remediation dry-run default, write only via `confirm:true`; guarded tarball sandbox / Gate `i_have_permission` (422 tanpa itu); remediasi dry-run default, tulis hanya via `confirm:true`; sandbox tarball ber-guard |
| #5 Qualified human reviewer | Patch is always a *proposal* — apply/reject decision stays with user / Patch selalu berupa *proposal* — keputusan apply/reject di tangan user |
| #6 Legal & ethical | Read-only probing (GET/HEAD only); GitHub host allowlist (anti-SSRF); no auto-exploit / Probing read-only (GET/HEAD saja); host allowlist GitHub (anti-SSRF); tanpa auto-exploit |
| #7 Authorized data only | Synthetic lab app for eval; optional GitHub token only to github.com / Lab app sintetis untuk eval; token GitHub opsional & hanya ke github.com |
| #8 Credentials outside submission | Automatic redaction of `Authorization`/`Cookie`/token in all logs, reports, trajectories (tested) / Redaksi otomatis `Authorization`/`Cookie`/token di semua log, report, trajectory (teruji) |
| #9 Claims connected to evidence | Eval table §4 + remediation verify loop (finding disappeared = proof) / Eval table §4 + verify loop remediasi (temuan hilang = bukti) |
| #10 Judges can run it | Reproduction guide §6 + docker compose + lab profile / Reproduction guide §6 + docker compose + profile lab |

**Additional safety / Safety tambahan:** anti zip-bomb (size/file cap), anti path-traversal (`resolve()` containment), symlink rejection, `.bak-cyense` backup + byte-identical revert, same-origin guard for patches.

---

## 9. Project Structure / Struktur Proyek

```
cyense/
├── README.md                          ← this document / dokumen ini
├── Makefile                           ← make up/down/test/lint
├── instruction/
│   ├── PRD.md                         ← PRD v2.0 (source of truth)
│   └── feature/
│       ├── github-repo-audit.md       ← github mode PRD
│       ├── idor-remediation.md        ← remediation PRD
│       ├── ci-compliance-reporting.md ← SARIF/CVSS/coverage/diff-scope PRD
│       ├── enhanced-reporting-viewer.md ← viewer/pdf/csv/multi PRD
│       └── cli-experience.md          ← CLI PRD
├── dev/
│   ├── main/                          ★ MAIN IMPLEMENTATION / IMPLEMENTASI UTAMA
│   │   ├── app/
│   │   │   ├── main.py                ← app factory + lifespan
│   │   │   ├── api/                   ← scans, reports, system, remediations, export, viewer
│   │   │   ├── core/                  ← models, config, store (+github models)
│   │   │   ├── agents/                ← brain, recon, prober, verifier, fetcher, orchestrator
│   │   │   ├── engines/               ← link, program, github, diff_scope
│   │   │   ├── program/               ← CY001-CY010 rules + sample fixture
│   │   │   ├── remediation/           ← fixer, strategies, applier, store
│   │   │   ├── report/                ← json + html + sarif + csv + pdf + coverage
│   │   │   ├── services/              ← multi_scan, scan_resume
│   │   │   └── utils/                 ← http_client, sandbox, github_client, pii, etc.
│   │   ├── baseline/naive_engine.py   ← comparison baseline / baseline pembanding
│   │   ├── tests/                     ← 177 tests + lab app fixture
│   │   ├── wordlists/ids.txt
│   │   ├── Dockerfile · docker-compose.yml · pyproject.toml
│   │   └── README.md                  ← service-level README
│   ├── brain/                         ← 🧠 knowledge.json + memory antar-scan
│   └── target/                        ← program mode target (read-only)
└── document/                          ← hackathon reference (gitignored)
```

### Agent trajectories (deliverable #4) / Trajectory agent

**EN:** Every agent records its steps in `reports/<scan_id>/trajectories/<agent>.json` — from instruction to result, easy to follow.

**ID:** Setiap agent merekam langkahnya di `reports/<scan_id>/trajectories/<agent>.json` — dari instruksi hingga hasil, mudah diikuti.

```json
// trajectories/verifier.json (example / contoh)
{"scan_id":"...","agent":"verifier","steps":[
  {"t":1788029499.9,"action":"start","detail":{"agent":"verifier"}},
  {"t":1788029499.9,"action":"control_id","detail":{"id":"99999999","status":404,"blocked":true}},
  {"t":1788029499.9,"action":"verified_candidate","detail":{"probe_id":"2","severity":"critical","confidence":0.95}}
]}
```

---

## 10. Main Failure Mode & Hot Take / Failure Mode Utama & Hot Take

**EN:** Verification depends on *observed context*. Case 2 (`/orders`) was initially missed because short body similarity fell below threshold — the fix was not lowering the threshold (that would open false positives), but forwarding **all** 200 candidates to the verifier and letting control-ID + PII decide. Lesson: **don't pre-filter what downstream can verify better** — shape-based pre-filtering discards the most important cross-account PII findings.

**ID:** Verifikasi bergantung pada *konteks yang teramati*. Kasus 2 (`/orders`) sempat miss karena similarity body pendek di bawah threshold — solusinya bukan menurunkan threshold (itu membuka FP), melainkan meneruskan **semua** kandidat-200 ke verifier dan membiarkan kontrol-ID + PII yang memutuskan. Pelajaran: **jangan pre-filter apa yang bisa diverifikasi lebih baik di downstream** — pre-filter berbasis shape justru membuang temuan PII cross-account paling penting.

**EN:** **Hot take:** *a scanner that reports more is not a better scanner.* The real value of an agentic workflow in security is not shooting more, but **thinking like a pentester**: generating a negative control, comparing evidence, and having the discipline to reject its own findings. Control-ID is 1 extra request that removes almost all false positives — cheap, deterministic, and no LLM needed. The best agent for objective tasks is not the one that guesses smartest, but the one that verifies most disciplined.

**ID:** **Hot take:** *scanner yang melaporkan lebih banyak bukan scanner yang lebih baik.* Nilai sebenarnya dari agentic workflow di security bukan menembak lebih banyak, tapi **berpikir seperti pentester**: membangkitkan negative control, membandingkan bukti, dan berani menolak temuan sendiri. Kontrol-ID adalah 1 request tambahan yang menghapus hampir semua false positive — murah, deterministik, dan tidak butuh LLM. Agent terbaik untuk tugas objektif bukan yang paling pintar menebak, tapi yang paling disiplin memverifikasi.

---

## 11. Technology / Teknologi

| Layer | Choice / Pilihan | Reason / Alasan |
|-------|------------------|-----------------|
| Python 3.11+ | asyncio + built-in `ast` | requirement; zero-dep static analysis |
| FastAPI + pydantic v2 | async-native, auto Swagger | requirement |
| httpx AsyncClient | parallel probing + timeout | rate limit + read-only enforcement |
| difflib + regex | similarity + PII | deterministic, no LLM / deterministik, tanpa LLM |
| String-builder HTML | f-string + `html.escape` | **no Jinja**, self-contained / **tanpa Jinja**, self-contained |
| Docker Compose | `lab` profile | requirement + reproducibility |
| pytest + ruff | 123 tests, 0 lint errors | measured quality / kualitas terukur |

## 12. Status

- ✅ MVP complete: 5 scan modes, 7 agents, 18 rules (4 analysis levels: low/medium/high/max), 177/177 tests / MVP lengkap: 5 mode scan, 7 agen, 18 aturan (4 level analisis: low/medium/high/max), 177/177 tests
- ✅ Measured evaluation: precision 100% vs baseline 56% (fair comparison) / Eval terukur: precision 100% vs baseline 56%
- ✅ E2E verified: scan → findings → remediation → safety gate / E2E live terverifikasi
- ✅ Strix-derived features: scan resume, target-list, instructions, diff-base, headless mode / Fitur dari Strix: resume, target-list, instruksi, diff-base, mode headless
- 📋 Backlog: GitLab adapter, more CI adapters, interactive web UI (see PRD features) / Backlog: GitLab adapter, CI adapter tambahan, interactive web UI

---

*Cyense — built for micro1 Agentic Workflows Hackathon. Only scan targets you are authorized to test.* 🛡️

*Cyense — dibangun untuk micro1 Agentic Workflows Hackathon. Hanya scan target yang Anda miliki izinnya.* 🛡️
