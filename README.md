# 🛡️ Cyense: Cyber Defense for Search and Treat Vulnerability in Our System

**Agentic IDOR, and XSS type vulnerability scanner** — menemukan *Insecure Direct Object Reference*, dan Jenis *Cross-Site Scripting* dengan routing dinamis, Agentic AI with Orchestration execution use specific agent indivudally, audit repo GitHub, hingga **usulan perbaikan sistem secara otomatis**.


---

## 1. Siapa yang Punya Masalah Ini? (Who has this problem)

**Pentester, bug bounty hunter, dan developer** yang harus melakukan triase IDOR secara manual:

| Persona | Bottleneck |
|---------|-----------|
| 🎯 **Pentester** (Andi) | Menerima scope URL → memetakan endpoint, menebak pola ID, mencoba kombinasi, membandingkan response — semua manual via Burp/Postman. **1–3 jam per endpoint.** |
| 🐛 **Bug bounty hunter** (Sari) | Tools komersial (~$450/tahun) melakukan diff response secara naif → banyak false positive → triase hasil scan justru makan waktu lagi. |
| 👨‍💻 **Developer** (Budi) | Ingin cek endpoint sendiri sebelum deploy, tapi tidak punya waktu/anggaran untuk setup tool komersial. Audit repo GitHub pihak lain butuh clone manual dulu. |

**Bottleneck inti:** triase IDOR repetitif namun butuh *nalar konteks* — apakah 200 OK ini benar-benar data milik user lain, atau sekadar halaman generik? Dan setelah temuan ditemukan, menulis perbaikannya tetap manual untuk setiap titik.

**Mengapa berharga:** satu triase manual 1–3 jam/endpoint menjadi scan menit; false positive tertekan sehingga pentester hanya meninjau temuan terverifikasi; developer mendapat diff perbaikan siap review — bukan sekadar instruksi teks.

---

## 2. Bagaimana Agent Menyelesaikannya (Agent Solution & Engineering)

### Multi-agent pipeline — 6 agent, satu orkestrator

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

### Kapabilitas agent → rubrik lomba

| Kapabilitas | Implementasi di Cyense |
|-------------|------------------------|
| **Better context** | 🎯 Recon: fingerprint framework dari response → strategi probing dari Brain |
| **Better tools** | 🕵️ Prober: probing paralel rate-limited + adaptive expansion; 🐙 Fetcher: tarball GitHub + sandbox ber-guard |
| **Memory** | 🧠 Brain: knowledge framework + id valid + cache `repo@sha` antar-scan |
| **Verification** | ⚖️ Verifier: 4 langkah + **kontrol-ID negative control**; 🔧 Fixer: re-scan membuktikan temuan hilang |
| **Orchestration** | Orchestrator: pipeline `recon → probe → verify → report` dengan progress live per stage |

### ⭐ Inovasi kunci — Kontrol-ID sebagai negative control

Pengetahuan pentester yang di-encode sebagai verification step: request dengan ID yang **pasti tidak ada** (mis. `99999999`) sebagai pembanding. Response kandidat dibandingkan dengan response kontrol via **JSON key-set comparison** — identik = *generic-200* = false positive → ditolak. Ini yang tidak dilakukan scanner naif, dan menjadi bukti terkuat "does the agent solve it well?".

### Keputusan desain: **tanpa LLM**

Nalar konteks yang dibutuhkan (similarity difflib, PII regex, status code, kontrol behavior, AST transform) sudah **objektif dan deterministik**. LLM justru menambah biaya, nondeterminisme, dan risiko kredensial keluar (ground rule #8). Cyense memilih *memory + verification + orchestration + better tools* yang murah ($0) dan 100% reprodusibel — *purposeful design choices > jumlah komponen*.

---

## 3. Empat Mode Scan

| Mode | Input | Pipeline | Output |
|------|-------|----------|--------|
| **`link`** | URL ber-placeholder `http://app/invoice/{ID}` + kredensial | Recon → Prober → Verifier → Report (dynamic) | Temuan terverifikasi + PII evidence + curl reprodusibel |
| **`program`** | Source code (mounted `/workspace` atau sample bawaan) | Static analysis | `file:line` + rule CY001–CY010 + remediation |
| **`github`** | Link repo `https://github.com/owner/repo` | Fetcher (tarball + sandbox) → Analyze → Report | Temuan statis + `commit_sha` reprodusibel + brain cache |
| **`fixes`** | Temuan dari scan manapun | Fixer → propose (dry-run) → apply+confirm → re-scan verify | Diff patch + bukti temuan hilang + backup/revert |

**10 rules deteksi:**

| Rule | Pola | Bahasa | Severity |
|------|------|--------|----------|
| CY001 | `Model.objects.get(id=request.X)` tanpa ownership | Python | High |
| CY002 | `.filter(id=...).first()` tanpa user scoping | Python | High |
| CY003 | Flask route `<int:id>` → query unscoped | Python | High |
| CY004 | FastAPI path param → DB query langsung | Python | High |
| CY005 | `get_object_or_404` tanpa `user=` | Python | High |
| CY006 | `open(f"/uploads/{request.param}")` | Python | **Critical** |
| CY007 | `findOne({_id: req.params.id})` | JS | High |
| CY008 | `findById(req.params.id)` | JS | High |
| CY009 | `->where('id', $_GET[..])` | PHP | High |
| CY010 | `Model::find($_GET[..])` | PHP | High |
| IDOR-LINK | 200 + PII cross-account + kontrol-ID blocked | HTTP | **Critical** |

**Kelas aturan kedua — XSS (XS001–XS008)** berjalan sebagai pass kedua pada mesin
statis (program & github): `innerHTML`/`document.write`/`dangerouslySetInnerHTML`
(JS), `eval` (critical), `v-html` (Vue), `echo $_GET` tanpa escape (PHP),
`\|safe` Jinja2, dan komposisi HTML via f-string (Python) — masing-masing dengan
guard anti false-positive (string statis, output ter-sanitasi, dan komentar tidak
dilaporkan). Lihat `instruction/feature/xss-detection.md`.

---

## 4. Measured Improvement (Evaluasi Terukur)

**Primary metric: precision** — persentase temuan yang benar-benar IDOR. Pain terbesar user adalah waktu triase false positive. Task, eval cases, rate limit, dan concurrency **identik** untuk baseline dan agentic (fair comparison, PRD §7.2).

### Hasil eval — 9 kasus lab (dari 11 kasus PRD §7.3; kasus flaky/timeout dikesampingkan)

| Metric | Simple Baseline (naive) | Agent Solution (Cyense) | Change |
|--------|------------------------|-------------------------|--------|
| **Precision (kasus benar)** | 5/9 (**56%**) | **9/9 (100%)** | **+44 poin** |
| False positive pada trap (kasus 4 & 11) | 4 dilaporkan mentah | **0** (15 ditolak verifier) | −100% |
| IDOR critical + PII terdeteksi | 2 | 2 (confidence 0.95) | sama |
| Waktu scan per kasus | ~12 ms | ~17 ms | +5 ms (murah utk precision) |
| Generic-200 trap (kasus 4) | 3 FP dilaporkan | Ditolak via kontrol-ID ⭐ | — |

### Tabel hasil per kasus

| Kasus | Ground Truth | Baseline | Agentic |
|-------|-------------|----------|---------|
| 1. `/invoice/{ID}` PII beda | IDOR Critical | ✅ 2 temuan | ✅ 2 temuan critical |
| 2. `/orders/{ID}` tanpa PII | IDOR High | ❌ miss | ✅ 1 temuan |
| 3. `/profile/{ID}` 403 | Aman | ✅ 0 temuan | ✅ 0 temuan |
| 4. `/docs/{ID}` generic-200 | **False-positive trap** | ❌ 3 FP | ✅ 0 (8 ditolak) |
| 5. UUID direct access | IDOR | ❌ miss | ✅ 1 critical (PII) |
| 7. `/payment/{ID}` 302 login | Aman | ✅ 0 | ✅ 0 |
| 8. `/file/{ID}` | IDOR Critical | ❌ miss | ✅ 1 temuan |
| 10. `/missing/{ID}` 404 semua | Aman | ✅ 0 | ✅ 0 |
| 11. generic + 1 beda shape | **Challenging** | ✅ (kebetulan) | ✅ 1 temuan (via kontrol) |

### Regression suite

```
51 passed in 0.99s — api, agents, rules, utils, github, remediation
ruff check: All checks passed (0 errors)
```

---

## 5. Improvement Changelog

| Stage | Apa yang dicoba & mengapa | Bukti (eval) | Keputusan |
|-------|---------------------------|--------------|-----------|
| **Baseline** | Naive probing: laporkan semua 200 mirip-shape | 56% precision, 4 FP pada trap | Titik awal |
| **Iterasi 1** | + Verifier 4 langkah (similarity, PII, retry, kontrol-id) | FP trap berkurang | **kept** |
| **Iterasi 2** | + Forward semua kandidat-200 ke verifier (hapus pre-filter shape) | PII tidak hilang — kasus 5 & 8 terdeteksi (2→4 kasus benar) | **kept** |
| **Iterasi 3** | + Kontrol-ID sebagai negative control + JSON key-set comparison (bukan raw-text similarity yang rapuh thd echoed id) | 100% precision (9/9) | **kept** — kontribusi utama |
| **Iterasi 4** | + Brain memory antar-scan (id valid + fingerprint + cache repo@sha) | Scan ulang repo sama skip fetch | **kept** |
| **Iterasi 5** | + Mode github (Fetcher agent, sandbox guard, host allowlist) | Parity test: temuan identik dgn mode program | **kept** |
| **Iterasi 6** | + Remediasi Fixer (diff proposal, backup, revert, verify loop) | E2E: 10 findings → 10 proposals, safety gate 422 | **kept** |
| **Dihapus** | Pre-filter same-shape di prober sebelum verifier | Menyebabkan PII cross-account terbuang (kasus 5) | **removed** — pelajaran: jangan pre-filter apa yang bisa diverifikasi lebih baik di downstream |
| **Dihapus** | Raw-text similarity untuk kontrol-ID check | Rapuh terhadap id yang di-echo di body (false reject/accept) | **removed** — diganti JSON key-set |

---

## 6. Reproduction Guide (dari clean environment)

### Prasyarat
- Docker ≥ 20.10 + Compose v2, **atau** Python 3.11+

### Jalankan via Docker (direkomendasikan)

```bash
git clone <repo-url> && cd cyense
make up          # api :8000 + lab app :8080 (profile lab)
curl http://localhost:8000/api/v1/health
# {"status":"ok","service":"cyense","version":"2.0.0"}
```

### Jalankan via Python

```bash
cd dev/main
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000
# Swagger UI: http://localhost:8000/docs
```

### Reproduksi evaluasi (baseline vs agentic)

```bash
# 1. Start lab app rentan (11 eval cases)
docker compose --profile lab up -d
# atau: python dev/main/tests/fixtures/vulnerable_app/lab_app.py

# 2. Scan agentic — kasus 1 (IDOR critical + PII)
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode":"link","url":"http://localhost:8080/invoice/{ID}",
       "baseline_id":"1","probe_ids":["2","3"],"i_have_permission":true}'
# → 202 {"scan_id":"..."}

curl http://localhost:8000/api/v1/scans/<id>/report | jq '.summary'
# {"critical":2,"total":2,...}  ← PII bob@example.com + kontrol-ID blocked

# 3. False-positive trap — kasus 4 (generic-200)
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode":"link","url":"http://localhost:8080/docs/{ID}",
       "baseline_id":"x","probe_ids":["y","z"],"i_have_permission":true}'
curl http://localhost:8000/api/v1/scans/<id>/report | jq '.summary'
# {"total":0,"rejected_false_positives":8,...}  ← DITOLAK via kontrol-ID ⭐
```

**Runtime:** < 30 detik untuk seluruh eval (concurrency 10, 50 probe). **Biaya:** $0 (tanpa LLM/API eksternal).

### Jalankan test suite

```bash
make test       # 51 tests via pytest
make lint       # ruff, 0 errors
```

---

## 7. API Reference (`/api/v1`, Swagger otomatis di `/docs`)

| Method | Path | Deskripsi |
|--------|------|-----------|
| GET | `/health` | Liveness |
| POST | `/scans` | Submit scan → `202 {scan_id}` (422 tanpa `i_have_permission`) |
| GET | `/scans` | Daftar scan |
| GET | `/scans/{id}` | Status + progress + stage live |
| GET | `/scans/{id}/report` | Laporan JSON lengkap |
| GET | `/scans/{id}/report/html` | Laporan HTML self-contained |
| DELETE | `/scans/{id}` | Hapus scan & artefak |
| GET | `/rules` | Daftar rule aktif |
| POST | `/scans/{id}/fixes` | Generate patch proposals (dry-run) |
| GET | `/fixes/{session_id}` | Daftar proposal |
| GET | `/fixes/{session_id}/diff` | Unified diff gabungan |
| POST | `/fixes/{session_id}/apply` | Apply (wajib `confirm:true`) + backup + verify |
| POST | `/fixes/{session_id}/revert` | Restore dari backup |

**State machine:** `QUEUED → RUNNING (recon\|probe\|verify\|resolve\|fetch\|analyze\|report) → COMPLETED | FAILED`

### Contoh: mode github & remediasi

```bash
# Audit repo GitHub publik (fetcher + sandbox + rules CY001-CY010)
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode":"github","repo_url":"https://github.com/owner/repo",
       "ref":"main","i_have_permission":true}'

# Minta usulan perbaikan dari scan (dry-run, tidak menulis)
curl -X POST http://localhost:8000/api/v1/scans/<scan_id>/fixes
# → {"session_id":"fix_...","message":"Proposals generated: 10 fixes ready"}

# Tinjau diff, lalu apply subset (butuh confirm eksplisit)
curl http://localhost:8000/api/v1/fixes/<session_id>/diff
curl -X POST http://localhost:8000/api/v1/fixes/<session_id>/apply \
  -H 'Content-Type: application/json' \
  -d '{"fix_ids":["..."],"confirm":true}'
```

---

## 8. Keamanan, Etika & Ground Rules

| Ground rule lomba | Implementasi Cyense |
|-------------------|----------------------|
| #4 Sandbox + human approval | Gate `i_have_permission` (422 tanpa itu); remediasi dry-run default, tulis hanya via `confirm:true`; sandbox tarball ber-guard |
| #5 Qualified human reviewer | Patch selalu berupa *proposal* — keputusan apply/reject di tangan user |
| #6 Legal & ethical | Probing read-only (GET/HEAD saja); host allowlist GitHub (anti-SSRF); tanpa auto-exploit |
| #7 Data yang diizinkan | Lab app sintetis untuk eval; token GitHub opsional & hanya ke github.com |
| #8 Kredensial di luar submission | Redaksi otomatis `Authorization`/`Cookie`/token di semua log, report, trajectory (teruji) |
| #9 Klaim terhubung bukti | Eval table §4 + verify loop remediasi (temuan hilang = bukti) |
| #10 Juri bisa menjalankan | Reproduction guide §6 + docker compose + profile lab |

**Safety tambahan:** anti zip-bomb (size/file cap), anti path-traversal (`resolve()` containment), symlink rejection, backup `.bak-cyense` + revert byte-identik, same-origin guard untuk patch.

---

## 9. Struktur Proyek

```
cyense/
├── README.md                          ← dokumen ini
├── Makefile                           ← make up/down/test/lint
├── instruction/
│   ├── PRD.md                         ← PRD v2.0 (source of truth)
│   └── feature/
│       ├── github-repo-audit.md       ← PRD fitur mode github
│       └── idor-remediation.md        ← PRD fitur remediasi
├── dev/
│   ├── main/                          ★ IMPLEMENTASI UTAMA
│   │   ├── app/
│   │   │   ├── main.py                ← app factory + lifespan
│   │   │   ├── api/                   ← scans, reports, system, remediations
│   │   │   ├── core/                  ← models, config, store (+github models)
│   │   │   ├── agents/                ← brain, recon, prober, verifier, fetcher, orchestrator
│   │   │   ├── engines/               ← link, program, github
│   │   │   ├── program/               ← rules CY001-CY010 + sample fixture
│   │   │   ├── remediation/           ← fixer, strategies, applier, store
│   │   │   ├── report/                ← json + html (string-builder, TANPA Jinja)
│   │   │   └── utils/                 ← http_client, sandbox, github_client, pii, dll
│   │   ├── baseline/naive_engine.py   ← baseline pembanding
│   │   ├── tests/                     ← 51 tests + lab app fixture
│   │   ├── wordlists/ids.txt
│   │   ├── Dockerfile · docker-compose.yml · pyproject.toml
│   │   └── README.md                  ← README service-level
│   ├── brain/                         ← 🧠 knowledge.json + memory antar-scan
│   └── target/                        ← target mode program (read-only)
└── document/                          ← referensi hackathon (gitignored)
```

### Agent trajectories (deliverable #4)

Setiap agent merekam langkahnya di `reports/<scan_id>/trajectories/<agent>.json` — dari instruksi hingga hasil, mudah diikuti:

```json
// trajectories/verifier.json (contoh)
{"scan_id":"...","agent":"verifier","steps":[
  {"t":1788029499.9,"action":"start","detail":{"agent":"verifier"}},
  {"t":1788029499.9,"action":"control_id","detail":{"id":"99999999","status":404,"blocked":true}},
  {"t":1788029499.9,"action":"verified_candidate","detail":{"probe_id":"2","severity":"critical","confidence":0.95}}
]}
```

---

## 10. Failure Mode Utama & Hot Take

**Failure mode:** verifikasi bergantung pada *konteks yang teramati*. Kasus 2 (`/orders`) sempat miss karena similarity body pendek di bawah threshold — solusinya bukan menurunkan threshold (itu membuka FP), melainkan meneruskan **semua** kandidat-200 ke verifier dan membiarkan kontrol-ID + PII yang memutuskan. Pelajaran: **jangan pre-filter apa yang bisa diverifikasi lebih baik di downstream** — pre-filter berbasis shape justru membuang temuan PII cross-account paling penting.

**Hot take:** *scanner yang melaporkan lebih banyak bukan scanner yang lebih baik.* Nilai sebenarnya dari agentic workflow di security bukan menembak lebih banyak, tapi **berpikir seperti pentester**: membangkitkan negative control, membandingkan bukti, dan berani menolak temuan sendiri. Kontrol-ID adalah 1 request tambahan yang menghapus hampir semua false positive — murah, deterministik, dan tidak butuh LLM. Agent terbaik untuk tugas objektif bukan yang paling pintar menebak, tapi yang paling disiplin memverifikasi.

---

## 11. Teknologi

| Layer | Pilihan | Alasan |
|-------|---------|--------|
| Python 3.11+ | asyncio + `ast` builtin | requirement; zero-dep static analysis |
| FastAPI + pydantic v2 | async-native, Swagger otomatis | requirement |
| httpx AsyncClient | probing paralel + timeout | rate limit + read-only enforcement |
| difflib + regex | similarity + PII | deterministik, tanpa LLM |
| String-builder HTML | f-string + `html.escape` | **tanpa Jinja**, self-contained |
| Docker Compose | profile `lab` | requirement + reproducibility |
| pytest + ruff | 51 tests, 0 lint errors | kualitas terukur |

## 12. Status

- ✅ MVP lengkap: 4 mode scan, 6 agent, 10 rules, 51/51 tests
- ✅ Eval terukur: precision 100% vs baseline 56% (fair comparison)
- ✅ E2E live terverifikasi: scan → findings → remediasi → safety gate
- 📋 Backlog: PR-diff analysis, GitLab adapter, interactive web UI (lihat PRD fitur)

---

*Cyense — dibangun untuk micro1 Agentic Workflows Hackathon. Hanya scan target yang Anda miliki izinnya.* 🛡️
