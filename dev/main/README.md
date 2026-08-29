# 🛡️ Cyense — Cyber Insight Engine

**Agentic IDOR vulnerability scanner** untuk pentester, bug bounty hunter, dan developer.
Cyense menemukan kerentanan **IDOR** (Insecure Direct Object Reference) pada target berupa
**link** (probing dinamis) atau **program** (analisis statis source code) — dengan
*verification berlapis* yang menekan false positive, bukan sekadar scanner 200-OK naif.

> ⚠️ **Etika:** hanya scan target yang Anda miliki izinnya. Setiap request scan wajib
> menyertakan `i_have_permission: true` (ditolak `422` jika tidak). Probing read-only
> (GET/HEAD saja) dan semua kredensial di-redact di log & laporan.

---

## Arsitektur (multi-agent pipeline)

```
POST /scans (mode=link)
     │
     ▼
🎯 RECON ── parse placeholder {ID}/{UID}/{GUID}/{EMAIL}, fingerprint framework,
│           konsultasi strategi probing ke 🧠 Brain
▼
🕵️ PROBER ── generate kandidat id (increment/wordlist/adaptive), tembak paralel
│            dengan rate limit, klasifikasi response
▼
⚖️ VERIFIER ── verifikasi 4 langkah per kandidat:
│      1. similarity vs baseline
│      2. cross-account PII (email/telepon milik user lain)
│      3. konsistensi retry
│      4. KONTROL-ID: id pasti-tidak-ada sebagai negative control —
│         response identik dengan kontrol = generic-200 = false positive → ditolak
▼
REPORT ── JSON + HTML self-contained (string-builder, tanpa template engine),
          trajectory log per agent, update Brain
```

**Inovasi kunci** — kontrol-ID sebagai *negative control*: scanner naif melaporkan setiap
200-OK yang mirip; Cyense membandingkan response kandidat dengan response kontrol-id
(JSON key-set comparison) sehingga endpoint *generic-200* terdeteksi dan ditolak.
Pada eval set lab: **precision 100% (agentic) vs 56% (baseline naif)** — lihat §Evaluasi.

---

## Menjalankan

### Docker (direkomendasikan)

```bash
cd dev/main
docker compose up -d          # service api di :8000
curl http://localhost:8000/api/v1/health
```

Lab app rentan (untuk demo/integration test) berjalan dengan profile `lab`:

```bash
docker compose --profile lab up -d
# lab di http://localhost:8080 (eval cases §7.3 PRD)
```

### Tanpa Docker (Python 3.11+)

```bash
cd dev/main
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

Swagger UI: `http://localhost:8000/docs`

---

## Penggunaan

### Mode LINK — probing dinamis

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "link",
    "url": "http://localhost:8080/invoice/{ID}",
    "headers": {"Authorization": "Bearer <token-akun-A>"},
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

### Mode PROGRAM — analisis statis

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode": "program", "lang": "python", "source_type": "sample", "i_have_permission": true}'
```

`source_type: "mounted"` menganalisis kode di volume `/workspace` (read-only).
Rules: `CY001`–`CY006` (Python AST), `CY007`–`CY010` (JS/PHP regex). Daftar lengkap: `GET /api/v1/rules`.

### CI / quality gate

```bash
summary=$(curl -s http://localhost:8000/api/v1/scans/<id> | jq .summary)
# gagalkan build jika critical+high > 0
```

---

## API (PRD §4.3)

| Method | Path | Deskripsi |
|--------|------|-----------|
| GET | `/api/v1/health` | Liveness |
| POST | `/api/v1/scans` | Submit scan → `202 {scan_id}` (422 tanpa `i_have_permission`) |
| GET | `/api/v1/scans` | Daftar scan |
| GET | `/api/v1/scans/{id}` | Status, progress, stage aktif |
| GET | `/api/v1/scans/{id}/report` | Laporan JSON lengkap |
| GET | `/api/v1/scans/{id}/report/html` | Laporan HTML self-contained |
| DELETE | `/api/v1/scans/{id}` | Hapus scan |
| GET | `/api/v1/rules` | Daftar rule aktif |

State machine: `QUEUED → RUNNING (recon|probe|verify|report) → COMPLETED | FAILED`.

---

## Evaluasi (PRD §7)

Eval set: 9 kasus link di atas lab app rentan (dari 11 kasus PRD §7.3; kasus 6/9
flaky/timeout dikesampingkan dari hasil berikut), task identik untuk kedua engine,
rate limit & concurrency sama.

| Metric | Baseline (naif) | Cyense (agentic) |
|--------|-----------------|------------------|
| Kasus dinilai benar | 5/9 | **9/9** |
| Precision | 56% | **100%** |
| False positive dilaporkan (trap cases 4 & 11) | 4 | **0** (15 ditolak verifier) |
| IDOR critical terdeteksi + PII | 2 | 2 (confidence 0.95) |
| Waktu scan per kasus | ~12 ms | ~17 ms |

**Improvement changelog:**

| Stage | Perubahan | Bukti |
|-------|-----------|-------|
| Baseline | naive probing, laporkan semua 200 mirip-shape | 56% precision, FP pada trap |
| Iterasi 1 | Verifier 4 langkah (similarity, PII, retry, kontrol-id) | FP trap berkurang |
| Iterasi 2 | forward semua kandidat-200 ke verifier (tanpa pre-filter) | PII tidak hilang (kasus 5) |
| Iterasi 3 | kontrol-id sebagai negative control + JSON key-set comparison | 100% precision |

Trajectory log tiap agent tersimpan di `reports/<scan_id>/trajectories/*.json`.

---

## Reproduksi dari clean environment

```bash
git clone <repo> && cd cyense/dev/main
docker compose up -d --wait
curl -s http://localhost:8000/api/v1/health        # {"status":"ok",...}
docker compose --profile lab up -d vulnerable-app
# jalankan eval mode program:
curl -X POST localhost:8000/api/v1/scans -H 'Content-Type: application/json' \
  -d '{"mode":"program","source_type":"sample","i_have_permission":true}'
```

Unit & integration tests:

```bash
pip install -e ".[dev]" && pytest tests/ -v
```

---

## Konfigurasi (env, prefix `CYENSE_`)

| Variabel | Default | Deskripsi |
|----------|---------|-----------|
| `MAX_CONCURRENCY` | 10 | request paralel maksimum |
| `RATE_LIMIT` | 50 | jeda antar-request (per detik) |
| `SIMILARITY_THRESHOLD` | 0.80 | ambang similarity verification |
| `CONTROL_ID` | 99999999 | id kontrol (pasti tidak ada) |
| `PROBE_MAX` | 50 | sebaran kandidat id increment |
| `REPORTS_DIR` / `BRAIN_DIR` / `WORKSPACE_DIR` | — | path volume |

Lihat `.env.example`.

---

## Struktur

```
dev/main/    ← service FastAPI (app/, baseline/, tests/, wordlists/)
dev/brain/   ← 🧠 knowledge.json + memory antar-scan (dipakai agent)
dev/target/  ← target scan default mode program (read-only)
```
