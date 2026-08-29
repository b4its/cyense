# PRD — Cyense: Agentic IDOR Vulnerability Scanner

> **Product Requirements Document** | Versi 2.0
> **Kompetisi:** micro1 Agentic Workflows Hackathon (lihat `document/`)
> **Bahasa Implementasi:** Python 3.11+ (FastAPI), dibungkus Docker Compose
> **Lokasi Implementasi Utama:** `dev/main/` · Otak agent di `dev/brain/` · Target scan & eval di `dev/target/`

---

## 0. Mengapa PRD Ini Berubah (v1.1 → v2.0)

Setelah dokumen kompetisi berhasil dianalisis, terkonfirmasi bahwa ini adalah **Agentic Workflows Hackathon** dengan rubrik penilaian 100 poin:

| Kriteria | Poin | Implikasi untuk Cyense |
|----------|------|------------------------|
| Problem & User Value | 15 | User & bottleneck harus spesifik dan nyata |
| **Agent Solution & Engineering** | **30** | **Wajib penggunaan agent yang purposeful** |
| End-to-End Quality | 20 | Output yang "layak ditandatangani manusia" |
| Measured Improvement | 15 | Wajib baseline + metric + changelog berbukti |
| Reproducibility | 15 | Reproduction guide dari clean environment |
| Hot Take / Insights | 5 | Failure mode → pelajaran praktis |

**PRD v1.1 (FastAPI scanner biasa) tidak memenuhi kriteria #2 (Agent Solution, 30 poin)** karena tidak memiliki komponen agent sama sekali. Maka v2.0 mengubah arsitektur menjadi **multi-agent orchestration**, sambil mempertahankan keputusan teknis yang sudah disepakati: Python, FastAPI, Docker Compose, tanpa Jinja, dua mode input (link & program), implementasi utama di `dev/main/`.

---

## 1. Ringkasan Eksekutif

**Cyense** (Cyber Insight Engine) adalah **platform agentic untuk menemukan kerentanan IDOR** (Insecure Direct Object Reference) — kerentanan di mana aplikasi mengizinkan akses data user lain hanya dengan mengubah nilai ID di URL, parameter, header, atau body request.

### 1.1 Siapa yang Punya Masalah, dan Bottleneck-nya

**Pentester & bug bounty hunter** (individu maupun tim kecil) melakukan triase IDOR secara manual:

- Mereka menerima scope (URL endpoint, source code) lalu harus **memetakan endpoint, menebak pola ID, mencoba kombinasi, membandingkan response** — semua manual via Burp Suite/Postman.
- Satu sesi triase IDOR manual: **1–3 jam per endpoint**, repetitif dan mudah terlewat.
- Tools komersial (Burp Pro ~$450/tahun, extension Autorize) melakukan diff response secara naif → **banyak false positive** sehingga triase hasil scan justru makan waktu lagi.
- Developer yang ingin mengecek endpoint sendiri tidak punya anggaran/waktu untuk setup tool komersial.

**Bottleneck inti:** triase IDOR itu repetitif namun butuh *nalar konteks* — apakah 200 OK ini benar-benar data milik user lain, atau sekadar halaman generik? Pola kerja yang cocok untuk **agent dengan tool + verification + memory**, bukan scanner regex naif.

### 1.2 Solusi: 4 Agent dalam Satu Pipeline

Platform API berbasis Python (FastAPI) + Docker Compose dengan **4 agent yang berkolaborasi**:

| Agent | Lokasi | Peran | Kapabilitas Agent (map ke rubrik) |
|-------|--------|-------|-----------------------------------|
| 🧠 **Brain** | `dev/brain/` | Memory & knowledge base: pola ID valid, fingerprint framework, heuristik per-framework, akumulasi temuan antar-scan | **Memory** |
| 🎯 **Recon** | `dev/main/` | Memetakan target: parse placeholder, fingerprint framework dari response, rekomendasi strategi probing | **Better context** |
| 🕵️ **Prober** | `dev/main/` | Menembak request paralel dengan ID kandidat (increment, wordlist, adaptive) | **Better tools** |
| ⚖️ **Verifier** | `dev/main/` | Verifikasi tiap kandidat temuan (similarity, PII cross-account, retry konsistensi, **kontrol-ID check**) | **Verification** |

**Orchestrator** (di `dev/main/`) menjalankan pipeline `Recon → Prober → Verifier → Report`, dengan Brain dipanggil di setiap stage.

> **Catatan desain (jawaban untuk kriteria "Does the agent solve it well?"):** agent di sini **tidak memakai LLM eksternal**. Nalar konteks yang dibutuhkan (similarity, PII matching, status code, kontrol behavior) sudah objektif dan deterministik — LLM justru menambah biaya, nondeterminisme, dan risiko kredensial keluar (ground rule #8). Cyense memilih kombinasi **memory + verification + orchestration + better tools** yang objektif, murah ($0), dan 100% reproducible. Ini keputusan sadar yang akan dibela di laporan: *purposeful design choices > jumlah komponen* (persis redaksi rubrik).

### 1.3 Nilai Utama

- ✅ **Agent yang menalar, bukan scanner naif** — kontrol-ID check & verifikasi menekan false positive
- ✅ Zero-install (cukup Docker), API-first (Swagger otomatis `/docs`)
- ✅ 2 mode input: **link** (URL) & **program** (source code)
- ✅ Laporan JSON + HTML self-contained (string-builder, tanpa Jinja) + bukti curl reprodusibel
- ✅ Human-in-the-loop: gate `i_have_permission` (ground rule #4, #6, #8)
- ✅ Trajectory logging otomatis per agent (deliverable #4 kompetisi)

---

## 2. Goal & Non-Goal

### 2.1 Goals (MVP)

1. Multi-agent pipeline (Recon → Prober → Verifier, Brain sebagai shared memory).
2. Mode LINK: probing dinamis URL placeholder + verifikasi kontekstual.
3. Mode PROGRAM: analisis statis AST Python (CY001–CY006) + heuristik JS/PHP.
4. Trajectory logging otomatis (JSON per stage per agent).
5. **Baseline comparison bawaan**: engine `baseline` (probing naif tanpa verification) vs engine `agentic` — task & eval cases identik.
6. Laporan JSON + HTML + API status/summary.
7. Semua jalan via `docker compose up`.

### 2.2 Non-Goals (MVP)

- ❌ LLM eksternal (lihat catatan desain §1.2)
- ❌ Full fuzzing / kerentanan lain (XSS, SQLi, RCE)
- ❌ Frontend SPA (hanya HTML report statis, tanpa Jinja)
- ❌ Deep static analysis selain Python (JS/PHP regex heuristik saja)
- ❌ Auto-exploit yang merusak data (read-only GET/HEAD)
- ❌ Multi-tenant auth pada Cyense sendiri

> ⚠️ **Etika:** hanya scan target yang diizinkan; `i_have_permission: true` wajib (422 jika tidak); probing read-only; kredensial selalu redacted di log & laporan.

---

## 3. Personas & User Stories

### 3.1 Persona

| Persona | Kebutuhan |
|---------|-----------|
| **Pentester** (Andi, solo) | Submit URL klien via Swagger/curl → dapat temuan IDOR terverifikasi, bukan daftar raw false positive |
| **Bug bounty hunter** (Sari, part-time) | Triase program bounty di sela waktu; output bisa langsung dilampirkan ke report dengan bukti curl |
| **Developer** (Budi) | Upload zip source → daftar endpoint rawan IDOR sebelum deploy |
| **DevOps** (Rara) | API untuk quality gate di CI |

### 3.2 User Stories

1. Sebagai pentester, saya memasukkan URL placeholder `{ID}`; Recon mengenali pola, Prober menembak ID kandidat, Verifier menyaring false positive → saya hanya meninjau temuan confidence ≥ 0.8.
2. Sebagai bounty hunter, saya memberikan 2 kredensial (akun A & B); pipeline mencoba akses resource milik B dengan sesi A → 200 + PII B → temuan Critical + curl reprodusibel.
3. Sebagai reviewer, tiap temuan menyertakan **alasan Verifier menerimanya** (similarity, PII, konsistensi retry, kontrol-ID blocked) → saya bisa cepat percaya atau menolak.
4. Sebagai developer, saya upload zip; agent menandai `User.objects.get(id=req.id)` tanpa cek ownership.
5. Sebagai DevOps, saya poll `GET /scans/{id}` di CI; build gagal jika `critical+high > 0`.

---

## 4. Spesifikasi Fungsional

### 4.1 Mode LINK (Dynamic Analysis)

**Input (`POST /api/v1/scans`, `mode: "link"`):**

| Field | Tipe | Default | Keterangan |
|-------|------|---------|-----------|
| `mode` | `"link"` | — | wajib |
| `url` | HttpUrl | — | boleh mengandung `{ID}` `{UID}` `{GUID}` `{EMAIL}` |
| `headers` | dict[str,str] | `{}` | mis. Authorization |
| `cookies` | dict[str,str] | `{}` | sesi |
| `baseline_id` | str | null | ID milik sendiri sebagai pembanding |
| `probe_ids` | list[str] \| `"auto"` | `"auto"` | kandidat ID untuk probing |
| `method` | GET/HEAD | GET | read-only saja |
| `i_have_permission` | bool | false | **harus true, selain itu 422** |

**Pipeline agentic (background worker):**

```
POST /scans (mode=link)
     │
     ▼
┌──────────────────────────────────────────────────────────────┐
│ STAGE 1 — RECON (agent, context)                             │
│  • Parse URL, deteksi placeholder                            │
│  • Fetch baseline (ID milik sendiri) → fingerprint           │
│    (server header, framework dari body, content-type)        │
│  • Brain: cek pengetahuan framework (mis. "Django REST       │
│    biasanya pk numeric") → strategi probing                  │
│  • Output: profil target + strategi                          │
└──────────────┬───────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────┐
│ STAGE 2 — PROBE (agent + tool httpx async)                   │
│  • Generate ID kandidat:                                     │
│      - increment/decrement baseline (±1..±50)                │
│      - wordlist (wordlists/ids.txt)                          │
│      - adaptive: pola valid ditemukan → expand sekitarnya    │
│  • Fire paralel (max N concurrent + rate limit)              │
│  • Klasifikasi tiap response: same-shape / different-shape / │
│    blocked (403/401) / error                                 │
│  • Brain: simpan ID valid + pola yang ditemukan              │
└──────────────┬───────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────┐
│ STAGE 3 — VERIFY (agent)                                     │
│  Untuk tiap kandidat (200 + shape mirip baseline):           │
│    1. Similarity vs baseline (difflib ≥ 0.85)                │
│    2. Cross-account PII (email/phone/nama ≠ baseline)        │
│    3. Konsistensi: ulang request 2× → hasil sama?            │
│    4. KONTROL-ID: request ID jelas-tidak-ada (mis.           │
│       99999999) → harus 404/403. Jika juga 200 berarti       │
│       "generic-200" → FALSE POSITIVE → tolak                 │
│  • Output: temuan terverifikasi + confidence + alasan        │
└──────────────┬───────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────┐
│ STAGE 4 — REPORT                                             │
│  • Scoring severity → JSON + HTML (string-builder)           │
│  • Trajectory log JSON per stage per agent                   │
│  • Update Brain                                              │
└──────────────────────────────────────────────────────────────┘
```

**Klasifikasi (mode LINK):**

| Sinyal | Confidence → Severity |
|--------|----------------------|
| PII user lain + kontrol-ID blocked | 0.95 → **Critical** |
| 200 + similarity ≥ 0.85 + retry konsisten + kontrol-ID blocked | 0.80 → **High** |
| 200 + similarity ≥ 0.85 tapi retry tidak konsisten | 0.50 → **Medium (manual review)** |
| 200 tapi kontrol-ID juga 200 (generic-200) | 0.10 → **Ditolak (false positive)** |
| 403/401/redirect ke login | 0.00 → aman |

> **Inovasi kunci — Kontrol-ID Check:** request dengan ID yang pasti tidak ada untuk membedakan "server mengembalikan 200 untuk semua ID" (generic-200) vs "server benar-benar mengembalikan data objek". Ini pengetahuan pentester yang di-encode sebagai verification step — hal yang **tidak dilakukan scanner naif** dan menjadi bukti terkuat untuk kriteria "Does the agent solve it well?".

### 4.2 Mode PROGRAM (Static Analysis)

**Input (`POST /api/v1/scans`, `mode: "program"`):**

| Field | Tipe | Keterangan |
|-------|------|-----------|
| `mode` | `"program"` | wajib |
| `lang` | python / js / php | default python |
| `source.type` | `mounted` / `sample` | `mounted` = path di `/workspace` (read-only); `sample` = lab bawaan; upload zip via multipart terpisah |
| `i_have_permission` | bool | wajib true |

**Rules Python (AST):**

| Rule ID | Pola | Severity |
|---------|------|----------|
| `CY001` | `Model.objects.get(id=request.X)` tanpa ownership check | High |
| `CY002` | `Model.objects.filter(id=...).first()` tanpa `user_id` | High |
| `CY003` | Flask `@app.route` + `<int:id>` + query tanpa ownership | High |
| `CY004` | FastAPI path param → DB query langsung | High |
| `CY005` | `get_object_or_404(Model, pk=...)` tanpa `user=request.user` | High |
| `CY006` | `open(f"/uploads/{req.param}")` | Critical |
| `CY007` (JS, regex) | `findOne({_id: req.params.id})` tanpa `userId` | High |

Antarmuka rule:

```python
class IdorRule(Protocol):
    rule_id: str
    severity: Severity
    def check(self, node: ast.AST, ctx: FileContext) -> list[Finding]: ...
```

### 4.3 API Interface (`/api/v1`)

| Method | Path | Deskripsi |
|--------|------|-----------|
| GET | `/health` | Liveness |
| POST | `/scans` | Submit job scan → `202 {scan_id}` |
| GET | `/scans` | Daftar scan |
| GET | `/scans/{id}` | Status + progress + stage aktif |
| GET | `/scans/{id}/report` | Laporan JSON lengkap |
| GET | `/scans/{id}/report/html` | Laporan HTML self-contained |
| DELETE | `/scans/{id}` | Hapus scan & artefak |
| GET | `/rules` | Daftar rule aktif |

State machine: `QUEUED → RUNNING (stage: recon|probe|verify|report) → COMPLETED | FAILED`.

### 4.4 Laporan

**JSON** (`GET /scans/{id}/report`): struktur `meta` / `summary` / `findings[]` — tiap finding memuat `finding_id`, `rule`, `severity`, `confidence`, `title`, `evidence` (request/response yang **redacted**), `verification` (alasan Verifier: similarity score, PII match, retry result, kontrol-ID result), `remediation`, curl reprodusibel (mode LINK).

**HTML** (`GET /scans/{id}/report/html`): **string-builder Python murni** (f-string + `html.escape`) — **tanpa Jinja / template engine**, self-contained CSS inline, berisi ringkasan severity, tabel findings yang bisa di-expand, badge REPRODUCE dengan curl.

---

## 5. Arsitektur Teknis

### 5.1 Diagram Komponen

```
                 ┌────────────────────────────────────────────────────┐
                 │                  Docker Compose                    │
                 │                                                    │
┌──────────┐     │  ┌──────────────────────────────────────────────┐  │
│  Client  │     │  │       Service: api  (dev/main)  FastAPI      │  │
│ curl/CI/ │────▶│  │  /scans  /reports  /rules  /health           │  │
│ browser  │     │  └───────────────┬──────────────────────────────┘  │
└──────────┘     │                  ▼                                  │
                 │        ┌──────────────────┐                         │
                 │        │ Job Queue        │                         │
                 │        │ (asyncio.Queue)  │                         │
                 │        └────────┬─────────┘                         │
                 │                 ▼                                   │
                 │        ┌──────────────────┐    ┌──────────────┐     │
                 │        │  Orchestrator    │◀──▶│   🧠 BRAIN   │     │
                 │        │  (pipeline)      │    │ (dev/brain/) │     │
                 │        └───┬──────┬───────┘    │ knowledge.   │     │
                 │            ▼      ▼            │ json + memory│     │
                 │     ┌────────┐ ┌──────────┐    └──────────────┘     │
                 │     │ RECON  │ │ PROBER   │                         │
                 │     │ agent  │ │ agent    │                         │
                 │     └────────┘ └────┬─────┘                         │
                 │                     ▼                               │
                 │              ┌────────────┐                         │
                 │              │  VERIFIER  │                         │
                 │              │   agent    │                         │
                 │              └─────┬──────┘                         │
                 │                    ▼                                │
                 │          ┌──────────────────┐                       │
                 │          │ Report Builder   │                       │
                 │          │ JSON + HTML      │                       │
                 │          │ (string-builder) │                       │
                 │          └──────────────────┘                       │
                 │                                                     │
                 │  Volumes:                                           │
                 │   ./reports  → /app/reports                         │
                 │   ../brain   → /app/brain                           │
                 │   ../target  → /workspace:ro (mode program)         │
                 │                                                     │
                 │  ┌──────────────────────────────────────────────┐   │
                 │  │ vulnerable-app (profile: lab) — Flask app    │   │
                 │  │ rentan IDOR untuk demo + integration test    │   │
                 │  └──────────────────────────────────────────────┘   │
                 └────────────────────────────────────────────────────┘
```

### 5.2 Struktur Folder

```
cyense/
├── instruction/
│   └── PRD.md                        ← dokumen ini
├── document/                         ← referensi hackathon
├── dev/
│   ├── main/                         ← ★ IMPLEMENTASI UTAMA (FastAPI service)
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml        ← service api (+ lab profile)
│   │   ├── .env.example
│   │   ├── requirements.txt
│   │   ├── pyproject.toml
│   │   ├── README.md
│   │   ├── app/
│   │   │   ├── main.py               ← app factory + lifespan + routers
│   │   │   ├── api/
│   │   │   │   ├── scans.py          ← POST/GET/DELETE /scans
│   │   │   │   ├── reports.py        ← report JSON/HTML
│   │   │   │   └── system.py         ← /health, /rules
│   │   │   ├── core/
│   │   │   │   ├── models.py         ← Pydantic: ScanRequest, Finding, Severity...
│   │   │   │   ├── config.py         ← pydantic-settings (CYENSE_*)
│   │   │   │   └── store.py          ← job store (in-memory + JSON dump)
│   │   │   ├── agents/
│   │   │   │   ├── base.py           ← AgentResult, TrajectoryRecorder, base class
│   │   │   │   ├── orchestrator.py   ← pipeline Recon→Probe→Verify→Report
│   │   │   │   ├── recon.py          ← RECON agent
│   │   │   │   ├── prober.py         ← PROBER agent
│   │   │   │   └── verifier.py       ← VERIFIER agent (kontrol-ID check)
│   │   │   ├── engines/
│   │   │   │   ├── link_engine.py    ← dynamic probing
│   │   │   │   └── program_engine.py ← static analysis entry
│   │   │   ├── program/
│   │   │   │   ├── python_rules.py   ← AST rules CY001–CY006
│   │   │   │   └── regex_rules.py    ← JS/PHP heuristics
│   │   │   ├── report/
│   │   │   │   ├── json_report.py
│   │   │   │   └── html_report.py    ← string-builder (TANPA Jinja)
│   │   │   ├── worker.py             ← background scan runner (asyncio queue)
│   │   │   └── utils/
│   │   │       ├── http_client.py    ← httpx.AsyncClient + rate limit + redact
│   │   │       ├── similarity.py     ← difflib SequenceMatcher
│   │   │       ├── pii.py            ← regex email/phone
│   │   │       └── logger.py
│   │   ├── wordlists/
│   │   │   └── ids.txt
│   │   ├── baseline/                 ← ★ BASELINE ENGINE (untuk pengukuran)
│   │   │   └── naive_engine.py       ← probing naif tanpa verification/kontrol-ID
│   │   ├── tests/
│   │   │   ├── test_api.py
│   │   │   ├── test_agents.py
│   │   │   ├── test_program_rules.py
│   │   │   └── fixtures/
│   │   │       └── vulnerable_app/
│   │   └── reports/                  ← output (volume, gitignored)
│   ├── brain/                        ← 🧠 BRAIN agent (memory & knowledge)
│   │   ├── knowledge.json            ← fingerprint framework → strategi probing
│   │   └── README.md                 ← kontrak data Brain
│   └── target/                       ← target scan default (mode program, ro)
```

### 5.3 Tech Stack

| Layer | Teknologi | Alasan |
|-------|-----------|--------|
| Bahasa | **Python 3.11** | requirement utama; asyncio + ast builtin |
| Web framework | **FastAPI** | requirement; async-native, Swagger `/docs` otomatis |
| Validasi | **pydantic v2** + pydantic-settings | model request/response + env config |
| HTTP client | **httpx** AsyncClient | probing async + timeout/retry |
| Static analysis | **ast** builtin | zero-dep |
| Report HTML | **string-builder** (f-string + html.escape) | **tanpa Jinja**, self-contained |
| Job store | in-memory + JSON dump ke volume | cukup untuk MVP, tanpa DB |
| Testing | pytest + pytest-asyncio + httpx test client | unit + integration |
| Container | Docker Compose | requirement utama |
| Linting | ruff | cepat |

### 5.4 Docker Compose (sketsa)

```yaml
services:
  api:
    build: .
    image: cyense-api:2.0.0
    ports: ["8000:8000"]
    volumes:
      - ./reports:/app/reports
      - ../brain:/app/brain
      - ../target:/workspace:ro
    environment:
      - CYENSE_LOG_LEVEL=INFO
      - CYENSE_MAX_CONCURRENCY=10
      - CYENSE_RATE_LIMIT=50
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request as u; u.urlopen('http://localhost:8000/api/v1/health')"]
      interval: 30s
      timeout: 5s
      retries: 3

  vulnerable-app:
    build: ./tests/fixtures/vulnerable_app
    profiles: ["lab"]
    ports: ["8080:8080"]
```

**Keputusan desain:**
- Service long-running `api`; scan dieksekusi worker background (asyncio queue) → API tetap responsif.
- `dev/brain/` di-mount sebagai volume → memory agent persist antar-restart & terlihat di repo.
- `dev/target/` read-only → service tidak pernah memodifikasi kode user.
- Profile `lab` (vulnerable-app) untuk demo & integration test, tidak jalan default.
- Tanpa DB eksternal (in-memory + JSON dump) → minimal dependensi, mudah direproduksi.

### 5.5 Dockerfile (sketsa)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY baseline/ ./baseline/
COPY wordlists/ ./wordlists/
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 6. Data Model (Pydantic, sketsa)

```python
class Severity(str, Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"

class ScanStatus(str, Enum):
    QUEUED = "queued"; RUNNING = "running"; COMPLETED = "completed"; FAILED = "failed"

class LinkScanRequest(BaseModel):
    mode: Literal["link"]
    url: HttpUrl
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    baseline_id: str | None = None
    probe_ids: list[str] | Literal["auto"] = "auto"
    method: Literal["GET", "HEAD"] = "GET"
    i_have_permission: bool = False   # divalidasi: harus True

class VerificationEvidence(BaseModel):
    similarity: float | None = None       # vs baseline
    pii_matches: list[str] = []           # PII user lain
    retry_consistent: bool | None = None  # hasil 2x request
    control_id_blocked: bool | None = None# kontrol-ID 403/404?
    notes: str = ""

class Finding(BaseModel):
    finding_id: str
    rule: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    title: str
    description: str
    evidence: dict          # request/response REDACTED
    verification: VerificationEvidence
    remediation: str
    location: str | None = None   # mode program: "file.py:42"
```

---

## 7. Evaluasi & Pengukuran (Wajib Kompetisi)

> Bagian ini menjawab rubrik **Measured Improvement (15 poin)** dan panduan "How to evaluate your solution".

### 7.1 Primary Metric

**Precision IDOR pada eval set** — persentase temuan yang benar-benar IDOR (temuan true-positive / total temuan dilaporkan), karena pain terbesar user adalah *waktu triase false positive*. Metrik pendukung: recall (temuan IDOR nyata yang terdeteksi), waktu triase per endpoint, jumlah request yang dipakai.

### 7.2 Baseline (Fair Comparison)

| | Baseline | Cyense (Agentic) |
|---|----------|------------------|
| Engine | `baseline/naive_engine.py` | pipeline Recon→Probe→Verify |
| Strategi | fire semua kandidat ID, laporkan semua 200 yang shape-nya mirip | + fingerprint, adaptive probing, verifikasi 4 langkah, kontrol-ID |
| Task & eval cases | **identik** | **identik** |
| Sumber daya | jumlah request sama-sama dibatasi rate limit & concurrency yang sama | sama |

### 7.3 Eval Set (≥ 10 kasus + 1 challenging)

Dibangun di atas `vulnerable-app` (profile lab) yang punya kombinasi endpoint aman/rentan:

| # | Kasus | Ground Truth |
|---|-------|--------------|
| 1 | `/invoice/{ID}` — akses objek lain berhasil, PII beda | IDOR Critical |
| 2 | `/orders/{ID}` — 200 + data objek lain, tanpa PII | IDOR High |
| 3 | `/profile/{ID}` — 403 untuk ID lain | Aman |
| 4 | `/docs/{ID}` — generic-200 untuk SEMUA ID (termasuk ngawur) | **False-positive trap** |
| 5 | `/api/v2/user/{UID}` (UUID) — enumerasi tidak feasible tapi akses langsung bisa | IDOR High |
| 6 | `/invoice/{ID}` retry tidak konsisten (flaky mock) | Ambiguous |
| 7 | `/payment/{ID}` — 302 ke login | Aman |
| 8 | `/file/{ID}` — IDOR + path traversal | Critical |
| 9 | Endpoint lambat (timeout) | Error handling |
| 10 | 404 untuk semua ID | Aman |
| 11 (challenging) | Kombinasi: generic-200 TAPI ada 1 ID yang beda shape | Harus ketemu via kontrol-ID + similarity, bukan dilaporkan mentah |

### 7.4 Tabel Hasil (format laporan, diisi saat implementasi)

| Metric | Baseline | Agentic | Δ |
|--------|----------|---------|---|
| Precision | TBD | TBD | TBD |
| Recall | TBD | TBD | TBD |
| Waktu triase/endpoint (est. manual review temuan) | TBD | TBD | TBD |
| False positive dilaporkan | TBD | TBD | TBD |

### 7.5 Improvement Changelog (template, diisi selama iterasi)

| Stage | Apa yang dicoba & mengapa | Bukti (eval) | Keputusan |
|-------|---------------------------|--------------|-----------|
| Baseline | naive probing + report semua mirip-shape | TBD | titik awal |
| Iterasi 1 | + Verifier 4 langkah (similarity, PII, retry, kontrol-ID) | TBD | kept/revised |
| Iterasi 2 | + Brain memory antar-scan (fingerprint → strategi) | TBD | kept/revised |
| Iterasi 3 | + adaptive probing (expand sekitar ID valid) | TBD | kept/revised |
| Final | gabungan yang terbukti bekerja | TBD | kontribusi utama |

---

## 8. Roadmap Implementasi

### Fase 1 — Fondasi Service (0.5 hari)
- [ ] Skeleton `dev/main/` (pyproject, requirements, Dockerfile, compose, healthcheck)
- [ ] FastAPI app + router + `/health` + pydantic models + job store + worker (asyncio queue)
- [ ] Gate `i_have_permission` (422)

### Fase 2 — Engine LINK + Baseline (1 hari)
- [ ] http_client (rate limit, retry, redaction header)
- [ ] `baseline/naive_engine.py` — dulu! (jadi pembanding terukur)
- [ ] `agents/recon.py`, `agents/prober.py` (placeholder parsing, ID generator, adaptive)
- [ ] `agents/verifier.py` — 4 langkah verifikasi + kontrol-ID
- [ ] Integration test vs vulnerable-app

### Fase 3 — Engine PROGRAM (1 hari)
- [ ] Upload zip → sandbox; walker `.py/.js/.php`
- [ ] AST rules CY001–CY006 + regex JS/PHP
- [ ] Unit tests per rule

### Fase 4 — Reporting + Brain (0.5 hari)
- [ ] JSON report + HTML string-builder (tanpa Jinja)
- [ ] `dev/brain/knowledge.json` + integrasi memory
- [ ] Trajectory recorder per agent

### Fase 5 — Evaluasi & Deliverables (0.5–1 hari)
- [ ] Jalankan eval set (11 kasus) pada baseline & agentic → isi tabel §7.4
- [ ] Isi improvement changelog §7.5 dengan bukti nyata
- [ ] Reproduction guide dari clean environment
- [ ] Rekam agent trajectories (fitur logging → file JSON deliverable)
- [ ] Video 5 menit (problem → baseline → demo → hasil → changelog)
- [ ] README + hot take

**Total estimasi: ± 4 hari**

---

## 9. Non-Functional Requirements

| Aspek | Requirement |
|-------|-------------|
| Performa | 50 probing ≤ 30 detik (concurrency 10); static scan 10k LOC ≤ 10 detik; API p99 < 100 ms (non-scan) |
| Keamanan service | Redaksi otomatis `Authorization`/`Cookie` di semua log & laporan; upload ke sandbox + size limit; read-only probing |
| Etika & legal | Gate `i_have_permission`; hanya target berizin — ground rule #4, #6, #8 |
| Portability | Docker ≥ 20.10 + Compose v2 |
| Observability | Log terstruktur per stage; progress via API; trajectory JSON; Swagger `/docs` |
| Determinisme | Laporan sorted keys; eval deterministik (tanpa LLM) |
| Robustness | Kegagalan scan tidak menjatuhkan service; timeout per request |

---

## 10. Kriteria Sukses (Acceptance Criteria)

1. ✅ `docker compose up -d` sukses; `GET /api/v1/health` → 200.
2. ✅ Scan link vs vulnerable-app: status QUEUED→RUNNING→COMPLETED; mendeteksi IDOR Critical + PII di evidence.
3. ✅ Kasus #4 (generic-200 trap): baseline melaporkan false positive, **Cyense menolaknya** via kontrol-ID → terbukti di tabel §7.4.
4. ✅ Mode program mendeteksi ≥ 4 dari 6 rules CY001–CY006 di fixture.
5. ✅ Report JSON + HTML tersedia; HTML tanpa aset eksternal; **tanpa library template** di requirements.txt.
6. ✅ Kredensial redacted di semua output.
7. ✅ Tanpa `i_have_permission` → 422.
8. ✅ Trajectory JSON per agent terekam di `reports/<scan_id>/trajectories/`.
9. ✅ Eval table §7.4 & changelog §7.5 terisi data nyata; baseline & agentic dijalankan pada cases yang sama.
10. ✅ Orang lain bisa reproduksi dari clean environment hanya dengan README + Docker.

---

## 11. Risiko & Mitigasi

| Risiko | Dampak | Mitigasi |
|--------|--------|----------|
| False positive mode LINK | User tidak percaya tool | Kontrol-ID check + similarity threshold + klasifikasi manual-review |
| Target punya rate limit/WAF | Scan gagal | Rate limit konservatif + backoff; concurrency configurable |
| AST salah konteks | FP statis | Confidence medium + exclude pattern |
| Kredensial bocor | Keamanan | Redaction otomatis di semua output |
| Zip bomb / path traversal upload | Kompromi service | Size limit, sandbox, validasi path, timeout ekstraksi |
| In-memory store hilang saat restart | Job hilang | Dump JSON ke volume (MVP acceptable) |
| Juri menganggap "tanpa LLM = bukan agent" | Skor Agent Solution | Definisi agent = komponen menalar dengan tool+memory+verification (rubrik sendiri menyebut "better context or tools"); buktikan via kontrol-ID & eval table |
| Waktu hackathon | Scope creep | Patuhi non-goals; prioritas: pipeline LINK + eval terukur dulu |

---

## 12. Deliverables Kompetisi (Mapping)

| Deliverable (dari PDF) | Status di Cyense |
|------------------------|------------------|
| 1. Kode + Improvement Changelog | repo `dev/main/` + §7.5 |
| 2. Reproduction guide | README `dev/main/` (setup clean env, perintah persis baseline & agentic & eval, versi, runtime) |
| 3. Video ≤ 5 menit | alur: masalah → baseline → demo end-to-end → perbandingan → changelog |
| 4. Agent trajectories | recorder otomatis (Fase 4) → `reports/<scan_id>/trajectories/*.json` |

Ground rules yang dipatuhi: sandbox + human approval (`i_have_permission`), legal & etis (read-only, berizin), tanpa kredensial dalam submission (redaction), klaim terhubung bukti (eval table), juri bisa menjalankan (reproduction guide + profile lab).

---

## 13. Changelog PRD

| Versi | Perubahan |
|-------|-----------|
| 1.0 | CLI (Typer) + laporan file + Jinja2 |
| 1.1 | API service (FastAPI) di `dev/main/`; Jinja dihapus → string-builder; job queue/worker; upload sandbox; `i_have_permission` |
| 2.0 | **Analisis PDF kompetisi → arsitektur diubah menjadi multi-agent**: Brain (`dev/brain/`, memory), Recon, Prober, Verifier (verification + kontrol-ID check), Orchestrator; baseline engine untuk fair comparison; eval set 11 kasus + metric + improvement changelog template; trajectory logging; mapping deliverables kompetisi; keputusan no-LLM didokumentasikan |

---

*Dokumen ini adalah source of truth implementasi. Perubahan scope wajib diperbarui di sini lebih dulu.*
