# 🛡️ Cyense — Cyber Insight Engine

**Agentic IDOR & XSS vulnerability scanner** for pentesters, bug bounty hunters, and developers.

Cyense discovers **IDOR** (*Insecure Direct Object Reference*) and **XSS** (*Cross-Site Scripting*) vulnerabilities in **link** targets (dynamic probing) or **program** targets (static source analysis) — with layered verification that suppresses false positives, not just a naive 200-OK scanner.

> **ID (Bahasa Indonesia):** Scanner kerentanan **IDOR** dan **XSS** berbasis agen untuk pentester, bug bounty hunter, dan developer. Cyense menemukan kerentanan *Insecure Direct Object Reference* dan *Cross-Site Scripting* pada target **link** (probing dinamis) atau **program** (analisis statis source code) — dengan *verification berlapis* yang menekan false positive, bukan sekadar scanner 200-OK naif.

> ⚠️ **Ethics / Etika:** Only scan targets you are authorized to test. Every scan request must include `i_have_permission: true` (rejected `422` otherwise). Probing is read-only (GET/HEAD only), and all credentials are redacted in logs & reports.
> / Hanya scan target yang Anda miliki izinnya. Setiap request scan wajib menyertakan `i_have_permission: true` (ditolak `422` jika tidak). Probing read-only (GET/HEAD saja) dan semua kredensial di-redact di log & laporan.

---

## Architecture / Arsitektur (multi-agent pipeline)

```
POST /scans (mode=link)
      │
      ▼
🎯 RECON ── parse placeholder {ID}/{UID}/{GUID}/{EMAIL}, fingerprint framework,
│           consult probing strategy from 🧠 Brain
▼
🕵️ PROBER ── generate id candidates (increment/wordlist/adaptive), fire parallel
│            with rate limit, classify response
▼
⚖️ VERIFIER ── 4-step verification per candidate:
│      1. similarity vs baseline
│      2. cross-account PII (email/phone belonging to another user)
│      3. retry consistency
│      4. CONTROL-ID: definitely-nonexistent id as negative control —
│         response identical to control = generic-200 = false positive → rejected
▼
REPORT ── JSON + HTML self-contained (string-builder, no template engine),
          trajectory log per agent, update Brain
```

**EN — Key innovation:** control-ID as *negative control*. Naive scanners report every 200-OK that looks similar; Cyense compares the candidate response with the control-id response (JSON key-set comparison) so *generic-200* endpoints are detected and rejected. On the lab eval set: **precision 100% (agentic) vs 56% (naive baseline)** — see §Evaluation.

**ID — Inovasi kunci:** kontrol-ID sebagai *negative control*. Scanner naif melaporkan setiap 200-OK yang mirip; Cyense membandingkan response kandidat dengan response kontrol-id (JSON key-set comparison) sehingga endpoint *generic-200* terdeteksi dan ditolak. Pada eval set lab: **precision 100% (agentic) vs 56% (baseline naif)** — lihat §Evaluasi.

---

## Running / Menjalankan

### Docker (recommended) / Docker (direkomendasikan)

```bash
cd dev/main
docker compose up -d          # api service on :8000
curl http://localhost:8000/api/v1/health
```

The vulnerable lab app (for demo/integration test) runs with the `lab` profile:

**EN:** The vulnerable lab app (for demo/integration test) runs with the `lab` profile.

**ID:** Lab app rentan (untuk demo/integration test) berjalan dengan profile `lab`.

```bash
docker compose --profile lab up -d
# lab app at http://localhost:8080 (eval cases PRD §7.3)
```

### Without Docker (Python 3.11+) / Tanpa Docker

```bash
cd dev/main
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

Swagger UI: `http://localhost:8000/docs`

---

## Usage / Penggunaan

### LINK mode — dynamic probing / Mode LINK — probing dinamis

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "link",
    "url": "http://localhost:8080/invoice/{ID}",
    "headers": {"Authorization": "Bearer <account-A-token>"},
    "cookies": {"session_uid": "101"},
    "baseline_id": "1",
    "probe_ids": ["2", "3"],
    "i_have_permission": true
  }'
# → 202 {"scan_id": "..."}

curl http://localhost:8000/api/v1/scans/<scan_id>          # status + summary
curl http://localhost:8000/api/v1/scans/<scan_id>/report    # JSON report
curl http://localhost:8000/api/v1/scans/<scan_id>/report/html -o report.html
```

### PROGRAM mode — static analysis / Mode PROGRAM — analisis statis

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode": "program", "lang": "python", "source_type": "sample", "i_have_permission": true}'
```

**EN:** `source_type: "mounted"` analyzes code in the `/workspace` volume (read-only). Rules: `CY001`–`CY006` (Python AST), `CY007`–`CY010` (JS/PHP regex). Full list: `GET /api/v1/rules`.

**ID:** `source_type: "mounted"` menganalisis kode di volume `/workspace` (read-only). Rules: `CY001`–`CY006` (Python AST), `CY007`–`CY010` (JS/PHP regex). Daftar lengkap: `GET /api/v1/rules`.

### GITHUB mode / Mode GITHUB

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "github",
    "repo_url": "https://github.com/owner/repo",
    "ref": "main",
    "i_have_permission": true
  }'
```

**EN:** Additional options: `--diff-base origin/main` for PR diff-scope, `--scan-mode quick|standard|deep`, `--scope-mode auto|full|diff`, `--instruction "focus on IDOR"`.

**ID:** Opsi tambahan: `--diff-base origin/main` untuk PR diff-scope, `--scan-mode quick|standard|deep`, `--scope-mode auto|full|diff`, `--instruction "focus on IDOR"`.

### Resume an interrupted scan / Melanjutkan scan yang terinterupsi

```bash
# via CLI / via CLI
cyense scan resume <scan_id>

# or attach --resume to any scan command / atau lampirkan --resume ke perintah scan mana saja
cyense scan github https://github.com/owner/repo --resume <scan_id> --i-have-permission
```

### CI / quality gate

```bash
summary=$(curl -s http://localhost:8000/api/v1/scans/<id> | jq .summary)
# fail build if critical+high > 0
# gagalkan build jika critical+high > 0
```

---

## API (PRD §4.3)

| Method | Path | Description / Deskripsi |
|--------|------|-------------------------|
| GET | `/api/v1/health` | Liveness |
| POST | `/api/v1/scans` | Submit scan → `202 {scan_id}` (422 without `i_have_permission`) / Submit scan → `202 {scan_id}` (422 tanpa `i_have_permission`) |
| GET | `/api/v1/scans` | List scans / Daftar scan |
| GET | `/api/v1/scans/{id}` | Status, progress, active stage / Status, progress, stage aktif |
| GET | `/api/v1/scans/{id}/report` | Full JSON report / Laporan JSON lengkap |
| GET | `/api/v1/scans/{id}/report/html` | Self-contained HTML report / Laporan HTML self-contained |
| GET | `/api/v1/scans/{id}/report/sarif` | SARIF 2.1.0 export |
| GET | `/api/v1/scans/{id}/coverage` | Coverage document |
| GET | `/api/v1/scans/{id}/export/csv` | CSV findings export |
| GET | `/api/v1/scans/{id}/export/pdf` | PDF compliance report |
| GET | `/api/v1/scans/resumable` | List resumable scans / Daftar scan yang bisa dilanjutkan |
| DELETE | `/api/v1/scans/{id}` | Delete scan / Hapus scan |
| GET | `/api/v1/rules` | Active rules catalog / Daftar rule aktif |
| POST | `/api/v1/scans/{id}/fixes` | Generate patch proposals (dry-run) / Generate usulan patch (dry-run) |
| GET | `/api/v1/fixes/{session_id}` | List proposals / Daftar proposal |
| GET | `/api/v1/fixes/{session_id}/diff` | Combined unified diff / Unified diff gabungan |
| POST | `/api/v1/fixes/{session_id}/apply` | Apply (requires `confirm:true`) + backup + verify / Apply (wajib `confirm:true`) + backup + verify |
| POST | `/api/v1/fixes/{session_id}/revert` | Restore from backup / Restore dari backup |

State machine / Mesin state: `QUEUED → RUNNING (recon|probe|verify|resolve|fetch|analyze|report) → COMPLETED | FAILED`.

---

## CLI Commands / Perintah CLI

```bash
cyense scan github <repo_url>    # GitHub repo audit / audit repo GitHub
cyense scan program              # Local source audit / audit source lokal
cyense scan link <url>           # Dynamic IDOR probing / probing IDOR dinamis
cyense scan website <url>        # Public website crawl (IDOR + XSS) / crawl website publik
cyense scan resume <scan_id>     # Resume interrupted scan / lanjutkan scan
cyense scan multi <targets.txt>  # Multi-target scan from file / multi-target dari file
cyense report <scan_id>          # Re-render old report / render ulang laporan
cyense list                      # Recent scans table / tabel scan terakhir
cyense history                   # Scan history + filter / riwayat scan + filter
cyense compare <a> <b>           # Diff two scan reports / diff dua laporan
cyense view [scan_id]            # Open web viewer / buka web viewer
cyense export csv|pdf <id>       # Download CSV/PDF / unduh CSV/PDF
cyense config get|set|list|reset # CLI preferences / preferensi CLI
cyense rules                     # Active rules catalog / katalog aturan
cyense fix <scan_id>             # Propose remediation patches / usulan remediasi
cyense version                   # CLI + service version / versi CLI + service
```

Global options / Opsi global: `--api-url`, `--no-color`, `--ascii`, `--quiet`, `--json`, `--non-interactive` (`-n` for CI/headless), `--timeout`.

---

## CLI Usage Tutorial / Tutorial Penggunaan CLI

> **EN:** This section shows how to run the CLI from inside the API container (`make cli-shell`) or via `make cli ARGS="..."`. All commands assume `make up` has been run first.
>
> **ID:** Bagian ini menunjukkan cara menjalankan CLI dari dalam container API (`make cli-shell`) atau via `make cli ARGS="..."`. Semua perintah diasumsikan `make up` sudah dijalankan.

### ⚠️ Common Mistakes / Kesalahan Umum

| ❌ Wrong / Salah | ✅ Correct / Benar | Why / Kenapa |
|---|---|---|
| `python -m app.cli.main --https://example.com` | `python -m app.cli.main scan link "http://example.com/{ID}" --i-have-permission` | `--` prefix is for options, not commands / prefix `--` untuk option, bukan perintah |
| `python -m app.cli.main --api-url https://github.com/owner/repo` | `python -m app.cli.main scan github https://github.com/owner/repo --i-have-permission` | `--api-url` is the Cyense service URL (default `localhost:8000`), not the scan target / `--api-url` adalah URL service Cyense, bukan target scan |
| `python -m app.cli.main github ...` | `python -m app.cli.main scan github ...` | Missing `scan` subcommand group / subcommand `scan` kurang |
| `python -m app.cli.main scan github URL` | `python -m app.cli.main scan github URL --i-have-permission` | `--i-have-permission` is mandatory (422 otherwise) / `--i-have-permission` wajib (422 jika tidak) |

### 1️⃣ Audit a GitHub Repository / Audit Repositori GitHub

**EN:** Scan any public (or private with token) GitHub repo for IDOR & XSS.

**ID:** Scan repo GitHub publik (atau privat dengan token) untuk IDOR & XSS.

```bash
# From host / Dari host:
make cli ARGS="scan github https://github.com/b4its/finready-latest --i-have-permission"

# Inside make cli-shell:
python -m app.cli.main scan github https://github.com/b4its/finready-latest --i-have-permission

# With GitHub token for private repos / Dengan token untuk repo privat:
make cli ARGS="scan github https://github.com/owner/private-repo --i-have-permission --token ghp_xxx"

# Limit scope to a subfolder / Batasi ke subfolder:
make cli ARGS="scan github https://github.com/owner/repo --i-have-permission --subdir src/"

# Force diff-scope against main branch / Paksa diff-scope terhadap branch main:
make cli ARGS="scan github https://github.com/owner/repo --i-have-permission --scope-mode diff --diff-base origin/main"
```

### 2️⃣ Scan a URL / Link (Dynamic IDOR Probing) / Scan URL/Link (Probing IDOR Dinamis)

**EN:** Probe a live endpoint with placeholder `{ID}`. The agent substitutes the placeholder with candidate IDs and verifies which return cross-account data.

**ID:** Probe endpoint live dengan placeholder `{ID}`. Agent mengganti placeholder dengan ID kandidat dan memverifikasi mana yang mengembalikan data lintas akun.

```bash
# Basic example with example.com / Contoh dasar dengan example.com:
make cli ARGS='scan link "http://example.com/api/users/{ID}" --i-have-permission'

# With auth credentials / Dengan kredensial auth:
make cli ARGS='scan link "http://example.com/api/invoice/{ID}" --i-have-permission --baseline-id 101 --probe-ids 102,103'

# Inside make cli-shell:
python -m app.cli.main scan link "http://example.com/users/{ID}" \
    --i-have-permission \
    --baseline-id 1 \
    --probe-ids 2,3,4
```

**EN — Placeholders supported:** `{ID}`, `{UID}`, `{GUID}`, `{EMAIL}`. At least one must appear in the URL.

**ID — Placeholder yang didukung:** `{ID}`, `{UID}`, `{GUID}`, `{EMAIL}`. Minimal satu harus ada di URL.

### 3️⃣ Scan a Public Website / Scan Website Publik

**EN:** Give Cyense any public URL (no `{ID}` placeholder needed) and the crawler will discover pages, identify ID-bearing endpoints, and analyze every HTML response for XSS surface. All crawling is same-domain and read-only (HTTP GET).

**ID:** Berikan Cyense URL publik apa pun (tanpa placeholder `{ID}`) dan crawler akan menemukan halaman, mengidentifikasi endpoint ber-ID, dan menganalisis setiap response HTML untuk permukaan XSS. Seluruh crawling bersifat same-domain dan read-only (HTTP GET).

```bash
# Basic scan / Scan dasar:
make cli ARGS="scan website http://example.com --i-have-permission"

# With custom crawl limits / Dengan batasan crawl khusus:
make cli ARGS="scan website http://example.com --i-have-permission --max-depth 3 --max-pages 100"

# Throttle requests to be polite / Batasi request agar sopan:
make cli ARGS="scan website http://example.com --i-have-permission --rate-limit 5"
```

**EN — What it finds:**
- **IDOR-WEBSITE**: Endpoints with numeric ID parameters (candidates for IDOR)
- **XS-LIVE-001/002**: Missing or weak Content-Security-Policy
- **XS-LIVE-003–016**: Dangerous JS patterns in served pages (eval, innerHTML, document.write, etc.)
- **XS-LIVE-017**: Possibly reflected query parameters (reflected XSS signal)
- **XS-LIVE-011/012**: Missing security headers (nosniff, clickjacking protection)

**ID — Apa yang ditemukan:**
- **IDOR-WEBSITE**: Endpoint dengan parameter ID numerik (kandidat IDOR)
- **XS-LIVE-001/002**: Content-Security-Policy hilang atau lemah
- **XS-LIVE-003–016**: Pola JS berbahaya di halaman (eval, innerHTML, document.write, dll.)
- **XS-LIVE-017**: Kemungkinan parameter ter-refleksi (sinyal reflected XSS)
- **XS-LIVE-011/012**: Security header hilang (nosniff, proteksi clickjacking)

### 4️⃣ Analyze Local Source Code / Analisis Source Code Lokal

**EN:** Scan Python/JS/PHP files mounted at `/workspace` (or the built-in sample).

**ID:** Scan file Python/JS/PHP yang di-mount di `/workspace` (atau sample bawaan).

```bash
# Built-in sample / Sample bawaan:
make cli ARGS="scan program --i-have-permission --source-type sample"

# With language override / Dengan override bahasa:
make cli ARGS="scan program --i-have-permission --lang js"
```

### 5️⃣ View Results / Lihat Hasil

```bash
# List all scans / Daftar semua scan:
make cli ARGS="list"

# Show detailed report / Tampilkan laporan detail:
make cli ARGS="report <scan_id>"

# Open web viewer in browser / Buka web viewer di browser:
make cli ARGS="view <scan_id>"
# Or latest scan / Atau scan terbaru:
make cli ARGS="view --latest"

# Export findings as CSV / Ekspor temuan sebagai CSV:
make cli ARGS="export csv <scan_id> --out findings.csv"

# Export as PDF (compliance report) / Ekspor sebagai PDF (laporan compliance):
make cli ARGS="export pdf <scan_id> --out report.pdf"

# Compare two scans / Bandingkan dua scan:
make cli ARGS="compare <old_scan_id> <new_scan_id>"

# History with filter / Riwayat dengan filter:
make cli ARGS="history --status completed --limit 10"
```

### 6️⃣ Remediation / Remediasi

```bash
# Generate patch proposals (dry-run, does not write) / Generate usulan patch (dry-run):
make cli ARGS="fix <scan_id>"

# Inside cli-shell, apply patches via API / Di dalam cli-shell, apply patch via API:
python -m app.cli.main fix <scan_id>
# Then call POST /api/v1/fixes/<session_id>/apply with confirm=true
```

### 7️⃣ Full Workflow Example / Contoh Workflow Lengkap

```bash
# Step 1: Start services / Mulai services
make up

# Step 2: Scan a public GitHub repo / Scan repo GitHub publik
make cli ARGS="scan github https://github.com/octocat/Hello-World --i-have-permission"
# Note the scan_id from the output / Catat scan_id dari output

# Step 3: View findings / Lihat temuan
make cli ARGS="list"
make cli ARGS="report <scan_id>"

# Step 4: Open interactive dashboard / Buka dashboard interaktif
make cli ARGS="view <scan_id>"

# Step 5: Export for compliance / Ekspor untuk compliance
make cli ARGS="export csv <scan_id> --out findings.csv"
make cli ARGS="export pdf <scan_id> --out compliance.pdf"

# Step 6: Propose fixes / Usulkan perbaikan
make cli ARGS="fix <scan_id>"

# Step 7: Cleanup / Bersihkan
make down
```

---

## Evaluation / Evaluasi (PRD §7)

**EN:** Eval set: 9 link cases on the vulnerable lab app (from 11 PRD §7.3 cases; flaky/timeout cases excluded below), identical task for both engines, same rate limit & concurrency.

**ID:** Eval set: 9 kasus link di atas lab app rentan (dari 11 kasus PRD §7.3; kasus flaky/timeout dikesampingkan dari hasil berikut), task identik untuk kedua engine, rate limit & concurrency sama.

| Metric | Baseline (naive) | Cyense (agentic) |
|--------|-----------------|------------------|
| Correct cases / Kasus benar | 5/9 | **9/9** |
| Precision | 56% | **100%** |
| False positives reported (trap cases 4 & 11) | 4 | **0** (15 rejected by verifier) |
| IDOR critical detected + PII | 2 | 2 (confidence 0.95) |
| Scan time per case | ~12 ms | ~17 ms |

**Improvement changelog / Riwayat peningkatan:**

| Stage | Change / Perubahan | Evidence / Bukti |
|-------|--------------------|------------------|
| Baseline | naive probing, report every 200 similar-shape / naive probing, laporkan semua 200 mirip-shape | 56% precision, FP on trap |
| Iteration 1 | Verifier 4-step (similarity, PII, retry, control-id) / Verifier 4 langkah | FP trap reduced |
| Iteration 2 | forward all 200 candidates to verifier (no pre-filter) / forward semua kandidat-200 ke verifier | PII preserved (case 5) |
| Iteration 3 | control-id as negative control + JSON key-set comparison / kontrol-id + JSON key-set comparison | 100% precision |

Trajectory log for each agent is stored in `reports/<scan_id>/trajectories/*.json`.

---

## Reproduction from clean environment / Reproduksi dari clean environment

```bash
git clone <repo> && cd cyense/dev/main
docker compose up -d --wait
curl -s http://localhost:8000/api/v1/health        # {"status":"ok",...}
docker compose --profile lab up -d vulnerable-app
# run program eval:
curl -X POST localhost:8000/api/v1/scans -H 'Content-Type: application/json' \
  -d '{"mode":"program","source_type":"sample","i_have_permission":true}'
```

Unit & integration tests:

```bash
pip install -e ".[dev]" && pytest tests/ -v
```

---

## Configuration / Konfigurasi (env, prefix `CYENSE_`)

| Variable | Default | Description / Deskripsi |
|----------|---------|-------------------------|
| `MAX_CONCURRENCY` | 10 | Max parallel requests / request paralel maksimum |
| `RATE_LIMIT` | 50 | Delay between requests (per second) / jeda antar-request (per detik) |
| `SIMILARITY_THRESHOLD` | 0.80 | Similarity verification threshold / ambang similarity verification |
| `CONTROL_ID` | 99999999 | Control id (definitely nonexistent) / id kontrol (pasti tidak ada) |
| `PROBE_MAX` | 50 | Spread of increment id candidates / sebaran kandidat id increment |
| `REPORTS_DIR` / `BRAIN_DIR` / `WORKSPACE_DIR` | — | Volume paths / path volume |

See `.env.example` / Lihat `.env.example`.

---

## Structure / Struktur

```
dev/main/
├── app/
│   ├── main.py                ← app factory + lifespan
│   ├── api/                   ← scans, reports, system, remediations, export, viewer
│   ├── core/                  ← models, config, store
│   ├── agents/                ← brain, recon, prober, verifier, fetcher, orchestrator
│   ├── engines/               ← link, program, github, diff_scope
│   ├── program/               ← rules CY001-CY010 + sample fixture
│   ├── remediation/           ← fixer, strategies, applier, store
│   ├── report/                ← json + html + sarif + csv + pdf + coverage
│   ├── services/              ← multi_scan, scan_resume
│   └── utils/                 ← http_client, sandbox, github_client, pii, etc.
├── baseline/naive_engine.py   ← comparison baseline / baseline pembanding
├── tests/                     ← 51 tests + lab app fixture
├── wordlists/ids.txt
├── Dockerfile · docker-compose.yml · pyproject.toml
└── README.md                  ← this file / file ini
```

---

## Recent additions / Penambahan terbaru

- **Strix-derived features / Fitur dari Strix:**
  - `scan resume <scan_id>` — resume interrupted scans from checkpoint / melanjutkan scan dari checkpoint
  - `scan multi <targets.txt>` — batch multi-target scanning / batch multi-target
  - `--instruction` / `--instruction-file` — custom testing focus / fokus testing khusus
  - `--diff-base <ref>` — explicit diff-scope base for PR scans / base diff-scope eksplisit
  - `-n` / `--non-interactive` — headless CI mode / mode headless untuk CI
  - SARIF 2.1.0, CVSS v3.1, coverage.json, CSV/PDF export, web viewer

---

*Cyense — Cyber Insight Engine. Only scan targets you are authorized to test.* 🛡️

*Cyense — Cyber Insight Engine. Hanya scan target yang Anda miliki izinnya.* 🛡️
