# PRD Fitur — Audit IDOR & XSS dari Link GitHub Repository (mode `github`)

> **Feature PRD** | Versi 2.0 | Status: implemented
> **Parent PRD:** `instruction/PRD.md` (v2.0) — dokumen ini adalah *addendum*, bukan pengganti
> **Nama fitur:** GitHub Repository Audit — **jalur input utama Cyense**
> **Lokasi implementasi:** `dev/main/app/agents/fetcher.py`, `dev/main/app/engines/github_engine.py`
> **Fitur turunan yang bekerja di atas jalur ini:** `xss-detection.md`, `idor-remediation.md`, `xss-remediation.md`

---

## 0. Ringkasan Satu Paragraf

**Fokus utama Cyense adalah mengaudit repository GitHub milik orang lain** — bukan
memindai kode di ekosistem lokal sendiri. Alurnya satu langkah: user **menempel
link repository GitHub** (mis. `https://github.com/owner/repo` atau varian
`/tree/{ref}`), sistem **fetch** source code-nya (tarball codeload) ke dalam
sandbox read-only, lalu **mencari kerentanan IDOR (CY001–CY010) dan XSS
(XS001–XS008)** pada kode hasil fetch tersebut. Nilai utamanya: auditor,
maintainer, dan pemilik program bounty dapat memeriksa kualitas keamanan repo
publik (atau repo privat yang diberi akses) **tanpa clone manual** — cukup tempel
link, dapat laporan berisi `file:line` untuk dua kelas kerentanan sekaligus,
dengan bukti commit SHA agar reprodusibel. Mode `program` (source lokal
mounted/sample) tetap tersedia sebagai jalur sekunder untuk testing/demo, tetapi
bukan fokus produk.

---

## 1. Latar Belakang & Masalah

### 1.1 Kondisi sebelum fitur ini

Satu-satunya jalur input static analysis adalah mode `program`:

| `source_type` | Sumber | Keterbatasan |
|---------------|--------|--------------|
| `mounted` | folder di volume `/workspace` (read-only) | user harus clone + mount manual |
| `sample` | fixture bawaan | hanya untuk demo/test |

Artinya untuk mengaudit **repo GitHub orang lain**, alur user adalah:

```
clone repo orang lain → taruh di dev/target/ (atau mount) → submit scan mode=program
```

Itu **4 langkah manual** yang menghadang persona Developer (Budi), Pentester
(Andi), dan maintainer yang "cuma mau cek cepat": PRD induk §3.1 menargetkan
zero-friction, tetapi friction justru paling terasa di langkah pertama (clone +
mount) — dan untuk repo orang lain, clone menambah beban disk lokal tanpa nilai.

### 1.2 Mengapa ini cocok untuk Cyense

- **Reuse penuh engine yang sudah teruji**: rules IDOR CY001–CY006 (AST Python),
  CY007–CY010 (regex JS/PHP), dan XSS XS001–XS008 tidak perlu diubah — yang baru
  hanyalah *cara source diperoleh*. Ini memperkecil risiko regresi.
- **Menambah satu kapabilitas agent yang purposeful**: agent **🐙 Fetcher**
  menambah kapabilitas *better tools* (akses source code jarak jauh + sandbox),
  konsisten dengan definisi agent di PRD induk (tool + memory + verification).
- **Skenario nyata bug bounty**: banyak program bounty menyertakan repo
  open-source milik vendor sebagai scope; auditor memetakan endpoint rawan IDOR
  dan sink XSS dari kode **sebelum** dynamic testing — cukup dengan link.

### 1.3 Persona & user story yang dilayani

| Persona (PRD induk §3.1) | Story |
|--------------------------|-------|
| **Pentester** (Andi) | "Saya menerima scope bounty berupa repo open-source vendor; saya tempel linknya, pilih branch, dan dapat peta titik rawan IDOR + XSS — tanpa clone manual." |
| **Pentester / auditor kontrak** | "Saya dapat izin mengaudit repo privat klien; saya beri token read-only baca-saja, Cyense mengunduh, menganalisis, dan **token tidak pernah muncul di laporan/log**." |
| **Researcher keamanan** | "Saya ingin membandingkan postur keamanan beberapa repo publik sebelum memilih target review — tiap repo cukup satu link." |
| **Developer** (Budi) | "Saya mengaudit repo dependensi/library pihak ketiga yang saya pakai — tempel link, lihat apakah pola IDOR/XSS ada di dalamnya." |
| **Maintainer OSS** | "Saya ingin tahu apakah PR terakhir menambah pola IDOR/XSS di repo publik saya — cukup link, tanpa setup apa pun." |

---

## 2. Goal & Non-Goal

### 2.1 Goals (MVP)

1. `POST /api/v1/scans` menerima `mode: "github"` dengan field `repo_url` —
   **jalur utama input sistem**.
2. Agent 🐙 **Fetcher**: resolve `owner/repo@ref` → unduh **tarball** (codeload) →
   ekstrak ke sandbox → serahkan ke `program_engine` yang sudah ada.
3. **Guard keamanan** wajib (lihat §6): host allowlist, size cap, file cap,
   anti path-traversal, anti symlink, token selalu redacted.
4. Laporan memuat metadata repo (`owner`, `repo`, `ref`, `commit_sha`) dan
   `location` berupa `path:line` **relatif terhadap root repo**.
5. Deteksi bahasa otomatis (py/js/php) dengan override manual.
6. **Cakupan kerentanan: IDOR (CY001–CY010) dan XSS (XS001–XS008)** — kedua
   kelas aturan berjalan pada kode hasil fetch dalam satu scan (lihat
   `xss-detection.md`; parameter `scan_types` default `["idor","xss"]`).
7. Trajectory JSON untuk agent Fetcher (deliverable #4 kompetisi tetap jalan).
8. Brain memory: catat `repo@sha` yang sudah discan → scan ulang pada SHA sama
   bisa dilewati (dengan flag `force`).

### 2.2 Non-Goals (MVP)

- ❌ **PR-diff analysis** (analisis hanya file yang berubah pada sebuah Pull
  Request) — valuable tapi butuh API diff + hunk mapping; masuk roadmap §10.
- ❌ Clone via protokol `git` (SSH/HTTPS git protocol) — cukup tarball HTTP;
  menghindari dependensi git binary di dalam container.
- ❌ Host selain GitHub (GitLab/Bitbucket) — arsitektur `fetcher` dibuat pluggable,
  tapi MVP hanya github.com.
- ❌ Kerentanan selain IDOR dan XSS (SQLi/RCE dsb. tetap non-goal PRD induk).
- ❌ Menulis ke repo (comment PR, issue, fix) — Cyense **selalu read-only**
  terhadap GitHub; remediasi bekerja pada salinan sandbox dan mengembalikan
  diff kepada user (lihat `idor-remediation.md`/`xss-remediation.md`).

---

## 3. Spesifikasi Fungsional

### 3.1 Input (`POST /api/v1/scans`, `mode: "github"`)

| Field | Tipe | Default | Keterangan |
|-------|------|---------|-----------|
| `mode` | `"github"` | — | wajib |
| `repo_url` | str | — | `https://github.com/{owner}/{repo}`; varian `/tree/{ref}` dan `/blob/{ref}/{path}` juga diterima dan di-parse |
| `ref` | str | null | branch/tag/commit; kosong = default branch (dari API metadata) |
| `subdir` | str | null | batasi analisis ke subfolder (mis. `backend/app`) |
| `lang` | `python`/`js`/`php`/`auto` | `auto` | deteksi dari dominasi ekstensi file |
| `github_token` | str | null | **alternatif**: env `CYENSE_GITHUB_TOKEN`; selalu redacted |
| `force` | bool | false | abaikan memory Brain "sudah discan di SHA ini" |
| `i_have_permission` | bool | false | **harus true → selain itu 422** (gate sama seperti mode lain) |

**Validasi tambahan (422 bila melanggar):**

- `repo_url` **harus** host-nya `github.com` — host lain ditolak (guard SSRF, §6.1).
- `repo_url` tidak mengandung karakter kontrol (aturan sama dengan mode `link`).
- `subdir` tidak boleh absolute atau mengandung `..`.

### 3.2 Pipeline (4 stage, konsisten dengan state machine PRD induk)

```
POST /scans (mode=github)
     │
     ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 1 — RESOLVE (agent 🐙 Fetcher)                              │
│  • Parse repo_url → owner, repo, ref?, path?                     │
│  • GET api.github.com/repos/{owner}/{repo}  (metadata)           │
│      → default_branch, size (KB), private?, full_name            │
│  • Guard: size > CYENSE_GITHUB_MAX_MB → FAILED (sebelum unduh)   │
│  • HEAD codeload tarball ref → confirm ada                       │
│  • Brain: recall "repo sudah discan @sha?" → skip bila sama &    │
│    bukan force (status COMPLETED dengan laporan dari cache)      │
│  Output: {owner, repo, ref, sha, size_kb, lang_hint}             │
└──────────────┬───────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 2 — FETCH & SANDBOX (agent 🐙 Fetcher)                      │
│  • GET codeload.github.com/{owner}/{repo}/tar.gz/{ref}           │
│    (Authorization hanya bila token ada; host github.com saja)    │
│  • Ekstraksi streaming ke reports/<scan_id>/src/ dengan guard:   │
│      - total bytes ter-unzip ≤ cap (anti zip-bomb)               │
│      - jumlah file ≤ cap                                         │
│      - tolak entry: path absolut, "..", symlink, device          │
│      - timeout ekstraksi; gagal → FAILED, sandbox dibersihkan    │
│  • Filter: sisakan hanya *.py *.js *.ts *.php                    │
│ Output: {files_kept, bytes, tree_root}                           │
└──────────────┬───────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 3 — ANALYZE (reuse program_engine — TANPA perubahan rule)   │
│  • Deteksi bahasa: hitung ekstensi → dominan (atau override)     │
│  • run_program_scan(lang, source_dir=sandbox, scan_id,           │
│        scan_types=["idor","xss"])                                │
│      → pass IDOR: CY001–CY010 (python AST + js/php regex)        │
│      → pass XSS:  XS001–XS008 (js/php/py regex + guards)         │
│  • location dinormalisasi: path relatif root repo + ":line"      │
│ Output: findings[] (IDOR + XSS) pada kode hasil fetch            │
└──────────────┬───────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────┐
│ STAGE 4 — REPORT                                                  │
│  • meta.repo = {owner, repo, ref, commit_sha, url}               │
│  • summary + findings + evidence redacted (aturan sama)          │
│  • Brain: remember "repo@sha discan, N temuan"                   │
│  • Trajectory fetcher.json di trajectories/                      │
└──────────────────────────────────────────────────────────────────┘
```

> **Keputusan desain — tarball, bukan `git clone`:** endpoint codeload tarball
> tidak dihitung terhadap rate limit API (60 req/jam tanpa token), tidak butuh
> binary `git` di image, dan tetap reprodusibel karena kita menyimpan `commit_sha`
> dari metadata API sebelum unduh. Kelemahannya (tidak bisa pin ke commit via
> shallow clone murah) dinetralkan dengan cap ukuran + penyimpanan SHA di meta.

### 3.3 Contoh request

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "github",
    "repo_url": "https://github.com/acme/checkout-service",
    "ref": "main",
    "subdir": "backend",
    "i_have_permission": true
  }'
# → 202 {"scan_id": "..."}

curl http://localhost:8000/api/v1/scans/<id>/report
# meta.repo = {"owner":"acme","repo":"checkout-service","ref":"main",
#              "commit_sha":"9f2c…","url":"https://github.com/acme/checkout-service"}
# findings[].location = "backend/api/invoices.py:42"
```

### 3.4 Perubahan API lain

| Method | Path | Perubahan |
|--------|------|-----------|
| GET | `/api/v1/rules` | tidak berubah (rule sama; mode baru hanya *source provider*) |
| GET | `/scans` / `/scans/{id}` | `mode: "github"` muncul di listing; `stage` baru: `resolve\|fetch\|analyze\|report` |
| GET | `/scans/{id}/report` | `meta.repo` baru untuk mode github |
| GET | `/scans/{id}/report/html` | badge metadata repo (owner/repo@short-sha) di header laporan |

State machine PRD induk `QUEUED → RUNNING → COMPLETED | FAILED` **tidak berubah**;
hanya nilai `stage` untuk mode github yang berbeda dari mode `link`.

---

## 4. Model Data (sketsa Pydantic)

```python
class GithubScanRequest(BaseModel):
    mode: Literal["github"]
    repo_url: str                      # divalidasi: host github.com, tanpa kontrol char
    ref: str | None = None
    subdir: str | None = None
    lang: Literal["python", "js", "php", "auto"] = "auto"
    github_token: str | None = None    # redacted di semua output
    force: bool = False
    i_have_permission: bool = False    # gate wajib true

    @field_validator("repo_url")
    def _github_host_only(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            raise ValueError("repo_url must be an https://github.com/... link")
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
            raise ValueError("repo_url must not contain control characters")
        return v


class RepoMeta(BaseModel):
    owner: str
    repo: str
    ref: str
    commit_sha: str
    url: str
    size_kb: int | None = None
    lang_detected: str | None = None
```

`ScanRequest = LinkScanRequest | ProgramScanRequest | GithubScanRequest`
(field `mode` bertindak sebagai discriminator pada Pydantic v2).

---

## 5. Arsitektur & Integrasi dengan Kode yang Ada

| Komponen baru/berubah | Lokasi | Peran |
|------------------------|--------|-------|
| 🐙 **FetcherAgent** | `app/agents/fetcher.py` (baru) | resolve + fetch + sandbox; trajectory sendiri |
| **GithubEngine** | `app/engines/github_engine.py` (baru) | orchestrate resolve→fetch→analyze(reuse program_engine)→report |
| `GithubScanRequest` | `app/core/models.py` (tambah) | + `RepoMeta` |
| Worker | `app/worker.py` (tambah 1 branch) | `mode == "github"` → github_engine dengan `on_stage` callback (pola yang sama dengan mode link) |
| Sandbox dir | `reports/<scan_id>/src/` | gitignored (sudah tercakup `reports/`); dihapus oleh DELETE (mekanisme `discard` yang sudah ada) |
| Brain | `dev/brain/knowledge.json` → `memory[host=github.com/{owner}/{repo}]` | simpan `{last_sha, findings_count, scanned_at}` |
| Config | `app/core/config.py` | `CYENSE_GITHUB_MAX_MB` (default 50), `CYENSE_GITHUB_MAX_FILES` (default 3000), `CYENSE_GITHUB_TIMEOUT` (default 60s), `CYENSE_GITHUB_TOKEN` (opsional) |

**Prinsip integrasi:** rules, report builder, store, state machine, redaction,
dan trajectory infrastructure **tidak diubah**. Fitur ini menambah *source
provider* jarak jauh — jalur input utama sistem — sehingga parity hasil dengan
jalur lokal (`program`) dapat diuji secara eksak (§8): kode yang sama harus
menghasilkan temuan IDOR + XSS yang sama di mana pun asalnya.

---

## 5.1 Posisi Jalur Input (fokus produk)

```
                     ┌────────────────────────────────────────┐
   JALUR UTAMA  ───► │ mode=github: link repo GitHub orang    │  ◄─ fokus
   (fetch remote)    │ lain → fetch tarball → sandbox         │
                     │ → analisis IDOR + XSS                  │
                     └────────────────────────────────────────┘
   JALUR SEKUNDER    mode=program: source lokal (mounted/sample)
   (lokal/ekosistem  → analisis IDOR + XSS — dipakai untuk demo,
    sendiri)          testing, dan parity; bukan fokus produk
   JALUR DYNAMIC     mode=link: probing HTTP live (bukan static)
```

---

## 6. Keamanan, Etika & Robustness (wajib)

### 6.1 Guard SSRF / host allowlist

Fetcher hanya boleh menghubungi:

```
https://api.github.com
https://github.com
https://codeload.github.com
https://raw.githubusercontent.com   (opsional, fase lanjutan)
```

Redirect diikuti **hanya jika tujuan tetap di allowlist** (codeload kadang
me-redirect antar-host github). Ini mencegah mode github menjadi gadget SSRF
yang men-fetch URL internal.

### 6.2 Anti zip-bomb / path traversal

Ekstraksi `tar.gz` dilakukan **streaming dengan akumulator guard**:

- batas total ter-unzip (`CYENSE_GITHUB_MAX_MB`) — tolak & bersihkan sandbox;
- batas jumlah file;
- **tolak** entry: absolute path, komponen `..`, symlink/hardlink, device node;
- timeout per ekstraksi; kegagalan guard → `FAILED` dengan alasan eksplisit.

### 6.3 Token & kredensial

- Token dari request **tidak pernah** masuk log, trajectory, store dump, atau
  laporan — melewati `redact.py` yang sudah ada (tambah `github_token` ke
  `SENSITIVE_KEYS`).
- Prioritas sumber token: request field > env `CYENSE_GITHUB_TOKEN` > anonim
  (60 req/jam, cukup untuk 1 metadata call per scan).
- Token **hanya** dikirim ke host allowlist §6.1.

### 6.4 Etika & legal — mengaudit repo milik orang lain

Karena fokus utama Cyense adalah repo **milik orang lain**, etika adalah
syarat produk, bukan catatan kaki:

- Tetap dipintu `i_have_permission` (konsistensi UX + ground rule kompetisi
  #4/#6); pesan error 422 menjelaskan bahwa hanya target berizin yang boleh.
- **Repo publik orang lain**: analisis statis kode yang sudah publik untuk
  keperluan riset/audit keamanan adalah use case yang sah (setara membaca kode
  itu sendiri); Cyense tidak pernah mengeksekusi kode hasil fetch dan tidak
  pernah melakukan probing aktif ke infrastruktur pemilik repo. Batas ini
  ditegaskan di README dan di setiap laporan.
- **Repo privat orang lain**: hanya bisa diakses jika token milik user sendiri
  punya akses — Cyense tidak pernah minta/menyimpan kredensial pihak ketiga;
  tanggung jawab kepatuhan ada pada pemilik token (ditegaskan di README +
  response error).
- **Scope undangan**: bila repo privat diberikan via kolaborator/token
  fine-grained read-only, tetap disarankan dokumentasikan izin di luar sistem.
- Fetch read-only; Cyense tidak pernah menulis apa pun ke GitHub (tidak ada
  comment PR, issue, atau push) — ground rule #4 tetap terjaga.
- Rate limit dipatuhi (§6.5) — menghormati layanan GitHub sebagai sumber data.

### 6.5 Rate limit & error paths (semua → FAILED dengan pesan jelas, tidak pernah crash)

| Kondisi | Deteksi | Perilaku |
|---------|---------|----------|
| repo tidak ada / privat tanpa token | API 404 | FAILED: "repo not found or private (provide a read-only token)" |
| rate limit | 403 + `X-RateLimit-Remaining: 0` | FAILED + saran: "set CYENSE_GITHUB_TOKEN, retry after Ns" |
| repo terlalu besar | `size` metadata > cap | FAILED **sebelum** unduh |
| tarball > cap saat streaming | guard §6.2 | FAILED + sandbox dibersihkan |
| ref tidak ada | codeload 404 | FAILED: "ref not found" |
| bukan repo kode (0 file target) | filter §3.2 | COMPLETED dengan `total: 0` + catatan di meta |

---

## 7. Pengujian (tanpa network di CI)

Semua test **hermetik** — tidak memanggil github.com:

1. **Unit — parser URL**: `/repo`, `/repo/tree/v1.2`, `/repo/blob/sha/path.py`,
   host salah, scheme http → 422.
2. **Unit — sandbox**: tarball sintetis (dibuat on-the-fly via `tarfile`) berisi
   (a) file normal, (b) `../evil.py`, (c) symlink, (d) 10k file kecil, (e) bomb
   rasio 1000× → guard menolak (b)(c)(d)(e) dan menerima (a).
3. **Unit — deteksi bahasa**: dominasi ekstensi; fallback `auto` → python.
4. **Integration — github_engine via transport palsu**: `HttpClient` dipatch
   (pola yang sama dengan `test_agents.py`) ke server ASGI kecil yang meniru
   endpoint metadata + codeload → parity test.
5. **Parity test (acceptance)**: source yang sama discan via `mode=program`
   (fixture sample) dan via `mode=github` (dari transport palsu) → set
   `finding_id`-normalized **identik**.
6. **Redaction test**: scan dengan `github_token` → grep seluruh report.json,
   store.json, trajectories/*.json → token tidak muncul.
7. **Rate limit test**: transport menjawab 403 + header rate limit → status
   FAILED + pesan saran token.

---

## 8. Kriteria Sukses (Acceptance Criteria)

1. ✅ `POST /scans` `mode=github` pada repo publik (via mock) → 202 →
   COMPLETED dengan `meta.repo.commit_sha` terisi.
2. ✅ Temuan identik dengan mode `program` untuk source yang sama (parity).
3. ✅ Host non-github → 422; `http://` → 422.
4. ✅ Tarball berisi `../` atau symlink → FAILED, tidak ada file keluar sandbox.
5. ✅ Repo > cap ukuran → FAILED **sebelum** unduh tarball.
6. ✅ `github_token` tidak pernah muncul di output apa pun (uji grep).
7. ✅ 403 rate limit → FAILED dengan pesan aksi (pasang token / retry).
8. ✅ Trajectory `fetcher.json` terekam di `reports/<id>/trajectories/`.
9. ✅ `DELETE /scans/{id}` menghapus sandbox source (reuse `discard`).
10. ✅ Scan ulang `repo@sha` sama tanpa `force` → COMPLETED dari cache Brain
    tanpa fetch ulang (tercatat di trajectory sebagai `cache_hit`).

---

## 9. Risiko & Mitigasi

| Risiko | Dampak | Mitigasi |
|--------|--------|----------|
| GitHub rate limit (60/jam anonim) | Scan gagal batch | 1 call metadata per scan + tarball codeload bebas kuota; token opsional; pesan error actionable |
| Repo monorepo raksasa | Timeout / disk | cap ukuran + cap file + `subdir` filter |
| Konten repo jahat (symlink, bomb) | Path traversal / disk penuh | guard §6.2 streaming |
| Misuse: mengaudit repo orang lain tanpa izin | Etika/legal | gate `i_have_permission` + dokumentasi; analisis statis kode yang diunduh, tanpa probing ke aplikasi live |
| Flaky network | FAILED mengganggu | timeout + retry sederhana (reuse pola http_client); error eksplisit |
| CI memanggil internet | Test tidak deterministik | semua test via mock transport (§7) — nol network |

---

## 10. Roadmap Implementasi

| Fase | Isi | Estimasi |
|------|-----|----------|
| 1 | `GithubScanRequest` + parser URL + guard + unit tests | 0.5 hari |
| 2 | FetcherAgent (resolve + sandbox streaming) + unit tests tarball | 1 hari |
| 3 | GithubEngine + worker branch + `meta.repo` + parity test | 0.5 hari |
| 4 | Token redaction + rate-limit paths + brain cache (skip same-sha) | 0.5 hari |
| 5 | README + eval manual (repo lab publik) + trajectory verifikasi | 0.5 hari |
| Lanjutan | PR-diff mode (analisis hanya file berubah pada PR), GitLab adapter | backlog |

---

## 11. Open Questions

1. Apakah `subdir` cukup, atau perlu glob filter (mis. `**/api/**`) di MVP?
   → Proposal: `subdir` dulu; glob menyusul bila ada permintaan nyata.
2. Cache Brain per `repo@sha`: simpan report penuh atau hanya pointer
   `scan_id` sebelumnya? → Proposal: simpan `scan_id` + `findings_count`;
   report lama tetap bisa diakses via scan_id (hindari duplikasi artefak).
3. Perlu dukungan commit SHA langsung sebagai `ref` (bukan branch)? → Ya,
   gratis dari codeload (`tar.gz/<sha>` valid); didokumentasikan sebagai
   cara paling reprodusibel.

---

## 12. Changelog Fitur

| Versi | Perubahan |
|-------|-----------|
| 1.0 | Draft awal: mode `github`, agent Fetcher, sandbox guard, reuse program engine, parity test, brain cache same-sha |
| 2.0 | **Reposisi sebagai jalur input UTAMA sistem**: fokus produk adalah fetch repo GitHub orang lain → cari IDOR **dan** XSS (XS001–XS008 ikut berjalan pada kode hasil fetch); mode program (ekosistem sendiri) diturunkan menjadi jalur sekunder untuk demo/testing; etika repo-orang-lain diperluas §6.4; contoh curl dan pipeline di-update |

---

*Addendum ini tunduk pada PRD induk (`instruction/PRD.md`). Aturan konflik: PRD
induk menang untuk hal yang tidak diatur di sini (etika, redaction, state machine,
gaya commit).*
