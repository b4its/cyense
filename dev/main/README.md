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
