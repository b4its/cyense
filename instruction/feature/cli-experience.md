# PRD Fitur — CLI Experience: Antarmuka Terminal Profesional & Elegan (`cyense`)

> **Feature PRD** | Versi 1.1 | Status: implemented
> **Parent PRD:** `instruction/PRD.md` (v2.0) — dokumen ini adalah *addendum*, bukan pengganti
> **Fitur terkait:** `instruction/feature/github-repo-audit.md` (jalur input utama yang dibungkus CLI ini), `xss-detection.md`, `idor-remediation.md`, `xss-remediation.md`
> **Nama fitur:** CLI Experience — *presentation layer* di atas service FastAPI
> **Lokasi implementasi:** `dev/main/app/cli/` (baru), `dev/main/app/report/md_report.py` (baru)

---

## 0. Ringkasan Satu Paragraf

Cyense hari ini hanya bisa dipakai lewat `curl` + polling manual ke FastAPI —
friksi yang menutupi kualitas engine di baliknya. Fitur ini menambahkan **CLI
`cyense`** sebagai *thin client* ke API yang sudah ada (bukan mesin kedua):
satu perintah `cyense scan <repo-url>` menampilkan **tiga blok log yang mengalir
secara live** — (1) log repository yang sedang dianalisis beserta progres tiap
stage, (2) log setiap vulnerability yang berhasil ditemukan saat ditemukan, dan
(3) panel saran perbaikan terprioritas yang diagregasi dari temuan — lalu
menuliskan **laporan akhir `.md`** yang siap ditempel ke issue/PR/dokumen audit.
Seluruh tampilan memakai **sistem warna berdominasi biru** yang konsisten
(deep navy → primary blue → accent → soft), dengan warna non-biru dipakai
**hanya** sebagai badge severity agar identitas visual tetap terjaga. Tidak ada
satu pun aturan deteksi, engine, atau state machine yang berubah — CLI murni
lapisan presentasi.

---

## 1. Latar Belakang & Masalah

### 1.1 Kondisi sebelum fitur ini

Cyense **tidak memiliki CLI sama sekali**. Bukti di kode:

| Fakta | Lokasi |
|-------|--------|
| Tidak ada `cli.py` / `__main__.py` / `[project.scripts]` | `dev/main/pyproject.toml` |
| Dependensi hanya `fastapi`, `pydantic`, `pydantic-settings`, `httpx`, `uvicorn` | `dev/main/pyproject.toml:9-15` |
| Tidak ada import `typer` / `click` / `rich` / `argparse` di seluruh `app/` | — |
| `Makefile` hanya punya target docker/pytest/ruff | `Makefile` |
| **Tidak ada renderer Markdown** — hanya `json_report.py` dan `html_report.py` | `dev/main/app/report/` |

Akibatnya alur pemakaian nyata hari ini adalah:

```bash
make up                                        # 1. jalankan service
curl -X POST .../api/v1/scans -d '{...}'       # 2. submit, catat scan_id manual
curl .../api/v1/scans/<id>                     # 3. poll berulang-ulang sendiri
curl .../api/v1/scans/<id>/report | jq         # 4. baca JSON mentah
# 5. tidak ada .md — harus disalin/diformat manual untuk laporan audit
```

Lima langkah manual, tanpa umpan balik progres, dan **output akhir untuk manusia
tidak tersedia** (JSON mentah bukan artefak audit; HTML tidak bisa ditempel ke
issue GitHub). Ini bertabrakan langsung dengan target zero-friction PRD induk
§3.1 — friksi justru menumpuk di titik terakhir, saat nilai produk seharusnya
tersampaikan.

### 1.2 Mengapa CLI dihidupkan kembali — dan kali ini berbeda

PRD induk §13 (changelog, `instruction/PRD.md:620-621`) mencatat CLI berbasis
Typer pernah ada di **v1.0**,
lalu **dihapus** di v1.1 saat arsitektur pindah ke service FastAPI. Menghidupkan
kembali CLI karena itu butuh justifikasi eksplisit agar tidak mengulang kesalahan
yang sama:

| Aspek | CLI v1.0 (dihapus) | CLI v2.x (fitur ini) |
|-------|--------------------|----------------------|
| Peran | **Pemilik** pipeline — memanggil engine langsung | **Client** — bicara ke API lewat HTTP |
| Logic deteksi | Ada di jalur CLI | Nol; semua tetap di `app/engines/` + `app/program/` |
| Risiko divergensi | Tinggi (dua jalur eksekusi) | **Nihil** (satu jalur: worker) |
| Rendering laporan | Jinja2 | Tanpa template engine (konsisten `html_report.py:1-7`) |
| Konsekuensi dihapus | Fitur ikut hilang | Hanya tampilan hilang; engine utuh |

(Baris pertama tabel merujuk `instruction/PRD.md:620`; kolom v1.1 merujuk
`instruction/PRD.md:621` — "Jinja dihapus → string-builder".)

Keputusan arsitektural kunci: **CLI tidak boleh mengimpor apa pun dari
`app/engines/`, `app/agents/`, atau `app/program/`.** Ia hanya memanggil
`POST /api/v1/scans`, `GET /api/v1/scans/{id}`, dan `GET /api/v1/scans/{id}/report`.
Dengan begitu CLI tidak akan pernah menjadi sumber kebenaran kedua, dan
menghapusnya suatu saat tidak menghilangkan kapabilitas apa pun.

### 1.3 Persona & user story yang dilayani

| Persona (PRD induk §3.1) | Story |
|--------------------------|-------|
| **Pentester** (Andi) | "Saya tempel link repo scope bounty, lihat temuan mengalir satu per satu di terminal, lalu lampirkan `.md`-nya ke laporan klien — tanpa menyusun ulang JSON." |
| **Developer** (Budi) | "Saya jalankan `cyense scan` di pipeline CI; kalau ada temuan `high`, build saya merah dengan alasan yang bisa dibaca reviewer." |
| **Maintainer OSS** | "Saya ingin ringkasan yang bisa langsung saya tempel jadi GitHub issue — Markdown, bukan HTML, bukan JSON." |
| **Auditor kontrak** | "Laporan `.md` harus deterministik supaya bisa saya diff antar-scan dan buktikan apa yang berubah." |
| **Juri kompetisi** | "Saya ingin melihat kemampuan agent dalam satu layar terminal, bukan membaca dump JSON 2000 baris." |

---

## 2. Goal & Non-Goal

### 2.1 Goals (MVP)

1. Binary `cyense` tersedia via `[project.scripts]`, dengan subcommand:
   `scan`, `report`, `list`, `rules`, `fix`, `version`.
2. **Sistem desain biru** yang konsisten dan terdokumentasi (§3.1) — satu
   sumber token warna di `app/cli/theme.py`, tidak ada hex tersebar.
3. **Log analisis repository live**: identitas repo (owner/repo@ref, commit SHA,
   ukuran, bahasa terdeteksi) + timeline stage `resolve → fetch → analyze →
   report` dengan spinner, timestamp, dan elapsed per-stage.
4. **Log vulnerability**: setiap temuan dirender saat terdeteksi, lalu
   diringkas dalam tabel akhir (`RULE | SEVERITY | CONF | LOCATION | TITLE`).
5. **Panel saran perbaikan**: agregasi field `remediation` per-rule, diurutkan
   berdasarkan prioritas (§3.5), dipisah *quick win* vs *structural fix*.
6. **Laporan akhir `.md`** via `app/report/md_report.py` (baru) — GitHub-flavored,
   deterministik, path default `reports/<scan_id>/report.md`.
7. **Exit code CI-friendly** (§3.7) + flag `--fail-on <severity>`.
8. **Degradasi anggun**: `NO_COLOR`, non-TTY (pipe/CI), terminal < 80 kolom,
   dan terminal tanpa dukungan Unicode → tetap terbaca.
9. Redaksi kredensial tetap berlaku pada output terminal **dan** file `.md`.

### 2.2 Non-Goals (MVP)

- ❌ **TUI interaktif** (panel navigasi, keybinding, mouse) — CLI ini *streaming
  log*, bukan aplikasi layar penuh; TUI masuk backlog §10.
- ❌ **Logic deteksi/analisis di dalam CLI** — dilarang keras (§1.2).
- ❌ **Mode offline tanpa service** — CLI selalu butuh API endpoint (opsi
  auto-spawn uvicorn lokal ada di §11 sebagai open question, bukan MVP).
- ❌ Emoji dekoratif di badan output — emoji hanya boleh muncul sebagai penanda
  agent (🧠🎯🕵️⚖️🐙🔧) yang sudah jadi konvensi kode, itupun opsional dan
  otomatis mati di mode ASCII.
- ❌ Menulis apa pun ke GitHub (comment/issue/push) — ground rule #4 PRD induk.
- ❌ Format ekspor selain `.md` (PDF/SARIF/CSV) — backlog §10.
- ❌ Warna kustom per-user / tema selain biru — satu identitas visual saja.

---

## 3. Spesifikasi Fungsional

### 3.1 Design System — Palet & Tipografi

**Prinsip:** biru adalah warna *sistem* (struktur, label, progres, aksen);
warna non-biru **hanya** dipakai untuk badge severity. Rasio target ≥ 85%
glyph berwarna adalah turunan biru/netral.

#### 3.1.1 Token warna (sumber tunggal: `app/cli/theme.py`)

| Token | Hex | ANSI 256 fallback | Dipakai untuk |
|-------|-----|-------------------|---------------|
| `navy.deep` | `#0B1F3A` | 17 | latar banner, garis pemisah tebal |
| `blue.primary` | `#1D4ED8` | 27 | judul panel, border aktif, nama command |
| `blue.accent` | `#3B82F6` | 33 | stage aktif, spinner, bar progres terisi |
| `blue.soft` | `#93C5FD` | 111 | label field, key pada key-value |
| `blue.mist` | `#DBEAFE` | 189 | teks sekunder, hint |
| `ink` | `#E2E8F0` | 253 | teks utama |
| `muted` | `#64748B` | 245 | timestamp, elapsed, path, bar kosong |
| `rule.line` | `#1E3A5F` | 24 | garis pemisah tipis |
| `ok` | `#22D3EE` | 51 | **cyan** (bukan hijau) — stage selesai, ✔ |

> **Catatan desain:** simbol sukses memakai **cyan** (`#22D3EE`), bukan hijau
> konvensional. Alasannya cyan berada di keluarga biru sehingga tidak memecah
> identitas visual, sementara tetap kontras terhadap `blue.accent`.

#### 3.1.2 Badge severity (satu-satunya pengecualian warna)

Nilai diselaraskan dengan `html_report.py:14-20` agar terminal, HTML, dan
Markdown menampilkan bahasa visual yang sama.

| Severity | Warna badge | Glyph | Hex acuan (`html_report.py`) |
|----------|-------------|-------|------------------------------|
| `critical` | merah tua, teks putih | `██` | `#7f1d1d` |
| `high` | oranye bakar | `▓▓` | `#c2410c` |
| `medium` | amber | `▒▒` | `#a16207` |
| `low` | **biru** (`blue.primary`) | `░░` | `#1d4ed8` |
| `info` | abu (`muted`) | `··` | `#374151` |

Badge dirender sebagai teks kapital berlatar warna, lebar tetap 10 kolom
(`  CRITICAL  `) supaya kolom tabel tidak bergoyang.

#### 3.1.3 Tipografi & glyph

| Elemen | Aturan |
|--------|--------|
| Judul panel | KAPITAL, `bold`, `blue.primary`, spasi antar-huruf 1 (`C Y E N S E`) hanya di banner |
| Label field | `blue.soft`, rata kanan pada lebar 14 kolom |
| Nilai | `ink`, `bold` untuk angka penting |
| Timestamp | `muted`, format `HH:MM:SS` |
| Path/kode | `blue.mist` dengan latar `navy.deep` (gaya inline-code) |
| Box drawing | `╭ ─ ╮ │ ╰ ╯ ├ ┤` (rounded) |
| Marker | `▸` stage aktif, `✔` selesai, `✖` gagal, `⚠` peringatan, `•` butir |
| Spinner | `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` (braille), interval 80 ms, warna `blue.accent` |

#### 3.1.4 Matriks degradasi (wajib diuji — §7)

| Kondisi | Deteksi | Perilaku |
|---------|---------|----------|
| `NO_COLOR` di-set (spesifikasi no-color.org) | env | semua warna mati, struktur & indentasi tetap |
| `--no-color` | flag | sama seperti di atas; flag menang atas env |
| stdout bukan TTY (pipe/CI) | `sys.stdout.isatty()` | warna mati, spinner→baris statis, progress bar→baris `stage: analyze (75%)` |
| `CYENSE_CLI_ASCII=1` atau encoding non-UTF8 | env / `sys.stdout.encoding` | glyph Unicode → ASCII (`+-|`, `>`, `[ok]`, `[!]`, `[x]`) |
| Lebar < 80 kolom | `shutil.get_terminal_size()` | tabel → daftar vertikal; banner → satu baris |
| Lebar < 40 kolom | idem | mode ultra-ringkas: hanya stage + hitungan severity |
| `--quiet` | flag | hanya baris ringkasan akhir + path artefak |
| `--json` | flag | **nol** dekorasi; JSON murni ke stdout (dapat di-pipe ke `jq`) |

### 3.2 Peta Perintah

```
cyense [OPSI GLOBAL] <command> [ARGS]
```

**Opsi global**

| Flag | Default | Keterangan |
|------|---------|-----------|
| `--api-url` | `http://localhost:8000` | env: `CYENSE_API_URL` |
| `--no-color` | false | matikan warna |
| `--ascii` | false | paksa glyph ASCII |
| `--quiet` / `-q` | false | ringkas |
| `--json` | false | output JSON mentah |
| `--timeout` | `300` | detik, batas total menunggu scan |

**Subcommand**

| Command | Sinopsis | Endpoint yang dipakai |
|---------|----------|----------------------|
| `scan github <repo_url>` | audit repo GitHub (**jalur utama**) | `POST /scans` mode `github` |
| `scan program` | audit source lokal (`--source-type mounted\|sample`) | `POST /scans` mode `program` |
| `scan link <url>` | probing IDOR dinamis | `POST /scans` mode `link` |
| `report <scan_id>` | render ulang laporan scan lama | `GET /scans/{id}/report` |
| `list` | tabel scan terakhir | `GET /scans` |
| `rules` | katalog CY001–CY010 + XS001–XS008 | `GET /rules` |
| `fix <scan_id>` | usulan patch remediasi | `POST /scans/{id}/fixes` |
| `version` | versi CLI + versi service | `GET /health` |

**Flag `scan github`** (memetakan 1:1 ke `GithubScanRequest`,
`app/core/models_github.py:11-19`)

| Flag | Field request |
|------|---------------|
| `--ref` | `ref` |
| `--subdir` | `subdir` |
| `--lang` | `lang` (`python\|js\|php\|auto`) |
| `--token` | `github_token` (**tidak pernah dirender/ditulis**, §6.2) |
| `--force` | `force` |
| `--i-have-permission` | `i_have_permission` (**wajib**, §6.1) |

**Flag output**

| Flag | Default | Keterangan |
|------|---------|-----------|
| `--out <path>` | `reports/<scan_id>/report.md` | tujuan file `.md` |
| `--no-md` | false | jangan tulis `.md` |
| `--fail-on <sev>` | `none` | exit 1 bila ada temuan ≥ severity ini |
| `--min-severity <sev>` | `info` | sembunyikan temuan di bawah ini (tampilan saja; `.md` tetap lengkap) |

### 3.3 Anatomi Layar — Mockup

Contoh berikut adalah kontrak visual `cyense scan github` pada terminal 100
kolom, TTY berwarna.

#### Blok 1 — Banner & identitas target

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  C Y E N S E   ·  Cyber Insight Engine                              v2.0.0    │
│  Audit statis IDOR & XSS untuk repository GitHub                              │
╰──────────────────────────────────────────────────────────────────────────────╯

  TARGET
  ────────────────────────────────────────────────────────────────────────────
       repository  acme/checkout-service
              ref  main
           commit  9f2c1a7b
            subdir  backend
          ukuran  4.2 MB
          bahasa  python (auto-detect)
          scan_id  47b7de1d8e3a
```

Sumber data: `meta.repo` dari report (`github_engine.py:123-130`) dan
`scan_id` dari respons `POST /scans` (`app/api/scans.py:21`). Field yang belum
tersedia saat banner dirender ditampilkan `—` lalu diperbarui in-place setelah
stage `resolve` selesai.

#### Blok 2 — Log proses analisis repository

```
  ANALISIS
  ────────────────────────────────────────────────────────────────────────────
  ✔ 14:22:01  resolve    metadata repo diambil · default_branch=main       0.42s
  ✔ 14:22:02  fetch      tarball diekstrak · 214 file dipertahankan        1.86s
  ▸ 14:22:04  analyze    ⠹ memindai backend/api/invoices.py                     
    14:22:—   report     menunggu

  ████████████████████████████░░░░░░░░░░░░░░░░  75%   analyze
```

Aturan render:

- Satu baris per stage; baris stage aktif menampilkan spinner + pesan terakhir
  dari `events[]` (`app/api/scans.py:56`).
- Stage selesai → `✔` warna `ok`, elapsed dikunci (`muted`, rata kanan).
- Stage gagal → `✖` merah + alasan dari field `error`.
- Progress bar memakai `progress` dari `GET /scans/{id}`; terisi `blue.accent`,
  kosong `muted`.
- **Catatan implementasi:** untuk mode `github`, `GithubEngine` hanya memanggil
  `_notify` untuk `resolve`, `analyze`, `report` (`github_engine.py:55,88,98`)
  sementara worker sudah memetakan `fetch: 50` (`app/worker.py:77`). Akibatnya
  progres melompat 25 → 75 dan baris `fetch` tidak pernah aktif. Ini **bug
  progres yang harus diperbaiki bersamaan** dengan fitur ini — lihat §9.

#### Blok 3 — Log vulnerability yang ditemukan

Setiap temuan dirender segera setelah tersedia (streaming saat stage `report`),
bukan menunggu semuanya selesai:

```
  TEMUAN
  ────────────────────────────────────────────────────────────────────────────
   ██ CRITICAL   CY004   conf 0.95
      Query tanpa filter kepemilikan pada endpoint invoice
      ↳ backend/api/invoices.py:42
        db.query(Invoice).filter(Invoice.id == invoice_id).first()

   ▓▓ HIGH       XS002   conf 0.88
      innerHTML diisi nilai dari location.hash tanpa sanitasi
      ↳ frontend/static/js/render.js:118
        el.innerHTML = decodeURIComponent(location.hash.slice(1))

   ░░ LOW        CY009   conf 0.61
      Parameter id diteruskan langsung ke query builder
      ↳ backend/legacy/reports.php:77
```

Lalu tabel rekapitulasi saat scan selesai:

```
  RINGKASAN TEMUAN
  ────────────────────────────────────────────────────────────────────────────
   RULE    SEVERITY    CONF   LOCATION                            TITLE
   ─────   ─────────   ────   ─────────────────────────────────   ──────────────
   CY004   CRITICAL    0.95   backend/api/invoices.py:42          Query tanpa …
   CY001   HIGH        0.90   backend/api/orders.py:88            Objek diambil…
   XS002   HIGH        0.88   frontend/static/js/render.js:118    innerHTML dii…
   XS005   MEDIUM      0.72   templates/profile.html:31           Autoescape di…
   CY009   LOW         0.61   backend/legacy/reports.php:77       Parameter id …

   critical 1  ·  high 2  ·  medium 1  ·  low 1  ·  info 0  ·  total 5
   214 file dipindai dalam 3.41s
```

Sumber: `findings[]` dan `summary` dari report; urutan mengikuti pengurutan
engine (`severity` lalu `-confidence`, `app/agents/orchestrator.py:129`) — CLI
**tidak mengurutkan ulang** agar konsisten dengan JSON/HTML.

#### Blok 4 — Panel saran perbaikan

```
  SARAN PERBAIKAN
  ────────────────────────────────────────────────────────────────────────────
   1  ● PRIORITAS 1 · CY004 · 1 temuan · critical
      Tambahkan filter kepemilikan pada query, mis.
      `filter(Invoice.owner_id == current_user.id)`, bukan hanya filter by id.
      Terdampak: backend/api/invoices.py:42

   2  ● PRIORITAS 2 · XS002 · 1 temuan · high
      Ganti `innerHTML` dengan `textContent`, atau sanitasi via DOMPurify
      sebelum menyisipkan nilai yang berasal dari URL.
      Terdampak: frontend/static/js/render.js:118

   3  ○ QUICK WIN · XS005 · 1 temuan · medium
      Aktifkan autoescape pada environment template dan hapus filter `|safe`
      pada variabel yang berasal dari input pengguna.
      Terdampak: templates/profile.html:31

   Jalankan `cyense fix 47b7de1d8e3a` untuk melihat usulan patch otomatis.
```

Aturan agregasi dijelaskan di §3.5.

#### Blok 5 — Footer artefak

```
  ────────────────────────────────────────────────────────────────────────────
   ✔ Laporan Markdown   reports/47b7de1d8e3a/report.md
     Laporan JSON       reports/47b7de1d8e3a/report.json
     Laporan HTML       http://localhost:8000/api/v1/scans/47b7de1d8e3a/report/html
     Trajectories       reports/47b7de1d8e3a/trajectories/

   Selesai dalam 3.41s · exit 1 (--fail-on=high terpenuhi)
```

#### Contoh kegagalan (mis. rate limit GitHub)

```
  ANALISIS
  ────────────────────────────────────────────────────────────────────────────
  ✖ 14:22:01  resolve    gagal                                             0.31s

  ⚠  SCAN GAGAL
     GitHub API rate limit terlampaui (403).
     Saran: set CYENSE_GITHUB_TOKEN atau ulangi dalam 812 detik.

   exit 2
```

Pesan diambil apa adanya dari field `error` (`app/api/scans.py:55`) — CLI tidak
menerjemahkan ulang agar pesan engine tetap menjadi sumber kebenaran.

### 3.4 Spesifikasi Laporan Markdown (`.md`)

Modul baru `app/report/md_report.py` dengan API sejajar `html_report.py`:

```python
def render_markdown_report(report: dict[str, Any]) -> str: ...
def dump_markdown_report(report: dict[str, Any], path: Path) -> None: ...
```

**Aturan wajib:**

- **Tanpa template engine** — f-string murni, konsisten dengan
  `html_report.py:1-7` (Jinja dilarang oleh PRD induk).
- **Deterministik**: urutan bagian, urutan temuan, dan format angka tetap;
  satu-satunya sumber non-determinisme (waktu render) diletakkan pada satu
  field front-matter agar `diff` antar-scan tetap bermakna.
- **GitHub-flavored**: tabel pipa, fenced code block dengan bahasa, anchor
  heading yang stabil.
- **Redaksi** dijalankan sebelum serialisasi (§6.2).

**Kerangka dokumen yang dihasilkan:**

```markdown
---
tool: cyense
version: 2.0.0
scan_id: 47b7de1d8e3a
mode: github
generated_at: 2026-08-31T14:22:05Z
repository: acme/checkout-service
ref: main
commit_sha: 9f2c1a7b
severity_counts: { critical: 1, high: 2, medium: 1, low: 1, info: 0 }
---

# Laporan Audit Keamanan — acme/checkout-service

## 1. Ringkasan Eksekutif
<paragraf otomatis: N temuan pada M file; kelas kerentanan yang muncul;
 severity tertinggi; satu kalimat rekomendasi utama>

## 2. Target yang Dianalisis
| Field | Nilai |          <- owner, repo, ref, commit_sha, url, ukuran, bahasa,
                             scan_id, engine, durasi, jumlah file

## 3. Ringkasan Temuan
| Severity | Jumlah |       <- + baris total
| Rule | Jumlah | Severity | Kelas |   <- rekap per-rule (IDOR/XSS)

## 4. Detail Temuan
### 4.1 [CRITICAL] CY004 — <judul>
- **Finding ID**, **Rule**, **Severity**, **Confidence**, **Lokasi**
- **Deskripsi**
- **Bukti** (fenced code block; untuk mode link: request/response ter-redaksi)
- **Verifikasi** (similarity, retry_consistent, control_id_blocked, notes)
- **Remediasi** (teks dari field `remediation`)
### 4.2 ... (satu subbagian per temuan, urutan sama dengan JSON)

## 5. Rekomendasi Perbaikan (terprioritas)
### 5.1 Prioritas 1 — <rule> (<n> temuan)
   - Tindakan, file terdampak, estimasi effort
### 5.2 Quick Wins
### 5.3 Perbaikan Struktural

## 6. Catatan Metodologi & Batasan
   <read-only, statis, tanpa eksekusi kode, potensi FP, cakupan rule>

## 7. Lampiran — Referensi Aturan
| Rule | Kelas | Deskripsi singkat |   <- hanya rule yang muncul di scan ini
```

Bagian 3, 4, dan 5 memetakan langsung ke tiga blok terminal (§3.3 blok 2–4),
sehingga apa yang dilihat di terminal identik dengan yang tersimpan.

### 3.5 Algoritma Prioritas Saran Perbaikan

Panel §3.3 blok 4 dan bagian §5 laporan `.md` memakai agregasi yang sama:

1. **Kelompokkan** `findings[]` berdasarkan `rule`.
2. **Skor** tiap kelompok:
   `skor = bobot_severity_maks × confidence_maks × log2(1 + jumlah_temuan)`
   dengan `bobot_severity = {critical: 100, high: 50, medium: 20, low: 5, info: 1}`.
3. **Urutkan** menurun; seri diputus oleh `rule` (leksikografis) demi determinisme.
4. **Klasifikasikan**:
   - `QUICK WIN` — semua temuan pada satu file **dan** severity ≤ `medium`;
   - `STRUKTURAL` — temuan tersebar di ≥ 3 file **atau** severity `critical`;
   - selain itu `PRIORITAS <n>`.
5. **Teks tindakan** diambil dari field `remediation` temuan berskor tertinggi
   dalam kelompok (`app/core/models.py:108`). CLI **tidak** mengarang teks baru —
   ini menjaga konsistensi dengan laporan JSON/HTML dan mencegah CLI menjadi
   sumber saran kedua.
6. **Daftar terdampak** memakai `location` (`models.py:109`, format `path:line`),
   maksimal 5 entri, sisanya diringkas `… dan N lainnya`.

### 3.6 Strategi Polling & Streaming

CLI tidak punya WebSocket/SSE untuk disadap, sehingga memakai polling adaptif:

| Aspek | Nilai |
|-------|-------|
| Endpoint | `GET /api/v1/scans/{id}` |
| Interval | 250 ms selama 10 detik pertama, lalu 500 ms, maksimum 1 s |
| Sumber baris log | delta `events[]` (kirim hanya yang belum dirender) |
| Sumber progres | `stage` + `progress` |
| Terminal | `status ∈ {completed, failed}` |
| Batas waktu | `--timeout` (default 300 s) → exit 3 + saran cek service |

**Fallback pengambilan laporan** — `worker.result()` menyimpan report di memori
(`app/worker.py:139`) sehingga `GET /scans/{id}/report` mengembalikan 404
setelah service restart. Bila terjadi, CLI membaca berkas
`reports/<scan_id>/report.json` yang ditulis `_dump_report` (`app/worker.py:184`)
jika direktori tersebut terjangkau secara lokal, dan memberi tahu pengguna bahwa
laporan berasal dari disk.

### 3.7 Exit Code

| Code | Makna | Kondisi |
|------|-------|---------|
| `0` | Bersih | scan `completed`, tidak ada temuan ≥ `--fail-on` |
| `1` | Temuan melewati ambang | ada temuan ≥ `--fail-on` (default `none` → tidak pernah aktif) |
| `2` | Scan gagal | status `failed` (rate limit, repo tidak ada, guard sandbox, dll.) |
| `3` | Kesalahan CLI/koneksi | service tidak terjangkau, timeout, argumen tidak valid, 422 |
| `130` | Dibatalkan pengguna | `SIGINT` — spinner dihentikan, kursor dipulihkan, artefak parsial disebutkan |

---

## 4. Model Data (sketsa Pydantic)

```python
# app/cli/models.py

class CliConfig(BaseModel):
    api_url: str = "http://localhost:8000"
    color: bool = True
    ascii_only: bool = False
    quiet: bool = False
    json_out: bool = False
    timeout: float = 300.0
    width: int = 100                       # hasil shutil.get_terminal_size()


class RenderContext(BaseModel):
    """State yang dipegang renderer selama polling berlangsung."""
    scan_id: str
    mode: Literal["github", "program", "link"]
    stages: list[str]                      # urutan stage sesuai mode
    current_stage: str | None = None
    progress: int = 0
    stage_started: dict[str, float] = {}
    stage_elapsed: dict[str, float] = {}
    rendered_events: int = 0               # penanda delta events[]
    rendered_findings: set[str] = set()    # finding_id yang sudah dicetak


class Recommendation(BaseModel):
    """Hasil agregasi §3.5 — dipakai terminal DAN markdown."""
    rule: str
    severity: Severity
    max_confidence: float
    occurrences: int
    score: float
    category: Literal["priority", "quick_win", "structural"]
    action: str                            # dari Finding.remediation
    affected: list[str]                    # location[], maks 5 + ringkasan


class MarkdownReportOptions(BaseModel):
    out_path: Path
    include_evidence: bool = True
    include_verification: bool = True
    max_evidence_lines: int = 12
    frontmatter: bool = True
```

`Severity` diimpor dari `app/core/models.py:15` — CLI **tidak** mendefinisikan
enum severity sendiri.

---

## 5. Arsitektur & Integrasi dengan Kode yang Ada

### 5.1 Komponen baru

| Komponen | Lokasi | Peran |
|----------|--------|-------|
| Entry point | `app/cli/main.py` (baru) | definisi Typer app + subcommand |
| Tema | `app/cli/theme.py` (baru) | token warna §3.1, deteksi kapabilitas terminal |
| Renderer | `app/cli/renderer.py` (baru) | banner, panel stage, kartu temuan, tabel, panel saran |
| Client | `app/cli/client.py` (baru) | pembungkus `httpx` untuk endpoint `/api/v1/*` + polling §3.6 |
| Agregator | `app/cli/recommend.py` (baru) | algoritma §3.5 (dipakai juga oleh `md_report`) |
| Markdown | `app/report/md_report.py` (baru) | `render_markdown_report` / `dump_markdown_report` |

### 5.2 Perubahan pada berkas yang sudah ada

| Berkas | Perubahan |
|--------|-----------|
| `dev/main/pyproject.toml` | tambah deps `typer>=0.12,<1.0`, `rich>=13.7,<14.0`; tambah blok `[project.scripts] cyense = "app.cli.main:app"`. `packages.find.include` (`pyproject.toml:29`) sudah memakai pola `app*` sehingga `app.cli` otomatis terikut — **tidak perlu diubah** |
| `dev/main/requirements.txt` | tambah `typer`, `rich` |
| `Makefile` | target `cli` (jalankan lokal) dan `demo` (scan repo contoh end-to-end) |
| `app/engines/github_engine.py` | **satu baris**: panggil `await self._notify("fetch")` sebelum ekstraksi agar stage `fetch` tidak terlewat (§9 risiko R2) |
| `README.md` | bagian "Pemakaian CLI" + tangkapan layar output |

### 5.3 Yang TIDAK berubah

Aturan CY001–CY010 & XS001–XS008, `app/engines/*` (kecuali satu baris notifikasi
di atas), `app/agents/*`, `app/core/store.py`, state machine
`QUEUED → RUNNING → COMPLETED|FAILED`, `json_report.py`, `html_report.py`, dan
seluruh kontrak endpoint API. **Tidak ada endpoint baru** — CLI cukup dengan
`events[]`, `stage`, dan `progress` yang sudah disediakan `GET /scans/{id}`
(`app/api/scans.py:47-57`).

### 5.4 Aturan ketergantungan (ditegakkan lewat review & test)

```
app/cli/*  ──HTTP──►  app/api/*  ──►  app/worker.py  ──►  app/engines/*  ──►  app/program/*
    │
    └──import──►  app/core/models.py (Severity saja)  ·  app/report/md_report.py
```

`app/cli/` **dilarang** mengimpor `app.engines`, `app.agents`, `app.program`,
atau `app.worker`. Pelanggaran ditangkap oleh test §7.6.

---

## 6. Keamanan, Etika & Robustness (wajib)

### 6.1 Gate izin tetap berlaku

`--i-have-permission` wajib disertakan; tanpa itu API mengembalikan 422
(`models_github.py:35-42`). CLI **tidak** menyediakan default `true` dan **tidak**
mengingat pilihan pengguna. Pesan 422 dirender apa adanya dalam panel `⚠` disertai
pengingat singkat bahwa hanya target berizin yang boleh dipindai.

### 6.2 Kredensial tidak pernah bocor

- `--token` / `CYENSE_GITHUB_TOKEN`, header, dan cookie **tidak pernah** dicetak
  ke terminal maupun ditulis ke `.md`.
- `md_report.py` menjalankan util redaksi yang sudah ada
  (`app/utils/redact.py`: `redact_headers:23`, `redact_cookies:37`,
  `redact_url_credentials:41`) sebelum serialisasi — sama seperti jalur JSON/HTML.
- `github_token` **belum** ada di `SENSITIVE_KEYS` (`app/utils/redact.py:12`)
  karena redaksi saat ini berbasis nama header, bukan nama field request.
  Selama token tidak pernah masuk ke `report` (dan memang tidak — lihat
  `github_engine.py:61` yang hanya meneruskannya ke fetcher), `.md` aman;
  test §7.5 mengunci properti ini agar tidak regresi.
- Riwayat shell adalah risiko nyata: bila `--token` dipakai, CLI mencetak
  peringatan sekali (`⚠ token diberikan lewat argumen; pertimbangkan env
  CYENSE_GITHUB_TOKEN agar tidak tersimpan di riwayat shell`).
- Test §7.5 melakukan grep terhadap stdout **dan** berkas `.md` untuk memastikan
  token tidak muncul.

### 6.3 Keamanan penulisan berkas

- `--out` di-resolve dan wajib berada di bawah direktori kerja atau
  `settings.reports_dir`; di luar itu ditolak (exit 3). Mencegah `--out
  ../../etc/cron.d/x` pada pemakaian dalam CI.
- Penulisan bersifat atomik (tulis ke `.tmp` lalu `os.replace`) agar berkas
  parsial tidak tertinggal saat proses dibatalkan.
- Berkas `.md` yang sudah ada tidak ditimpa tanpa `--force-out`.

### 6.4 Robustness terminal

- Kursor selalu dipulihkan pada `SIGINT`/exception (context manager, bukan
  `try/except` tersebar).
- Escape sequence tidak boleh berasal dari data eksternal: seluruh nilai yang
  berasal dari repo (nama file, cuplikan kode, judul temuan) melewati
  penyaring karakter kontrol sebelum dirender — mencegah repo jahat menyuntik
  ANSI escape untuk memalsukan output (analog dengan `html.escape` di
  `html_report.py:23`).
- Cuplikan bukti dipotong pada `max_evidence_lines` dan lebar terminal.

### 6.5 Etika

CLI menampilkan baris konteks singkat pada footer laporan dan `.md` §6: analisis
bersifat **statis dan read-only**, kode hasil fetch **tidak pernah dieksekusi**,
dan tidak ada penulisan apa pun ke GitHub — konsisten dengan
`github-repo-audit.md` §6.4 dan ground rule #4/#6.

---

## 7. Pengujian (tanpa network di CI)

1. **Snapshot renderer** — `rich.Console(force_terminal=True, width=100,
   no_color=False)` merekam output ke buffer; dibandingkan dengan berkas
   snapshot untuk banner, panel stage, kartu temuan, tabel, dan panel saran.
2. **Matriks degradasi** — parametrized test untuk `NO_COLOR`, non-TTY,
   `--ascii`, lebar 40/79/100/200 kolom; assertion: tidak ada baris melebihi
   lebar terminal dan tidak ada escape sequence saat warna dimatikan.
3. **Markdown deterministik** — render dua kali dari report fixture yang sama →
   byte-identik kecuali field `generated_at`; struktur heading divalidasi.
4. **Agregasi saran (§3.5)** — fixture dengan seri skor → urutan stabil;
   klasifikasi `quick_win`/`structural` sesuai aturan; `action` benar-benar
   berasal dari `Finding.remediation`.
5. **Redaksi** — scan dengan `--token`, grep stdout + `report.md` → token tidak
   muncul (pola sama dengan test redaksi yang sudah ada).
6. **Batas ketergantungan** — parse AST seluruh modul di `app/cli/` dan pastikan
   tidak ada import `app.engines` / `app.agents` / `app.program` / `app.worker`.
7. **Polling** — `httpx.MockTransport` mengembalikan urutan respons
   `queued → running(resolve) → running(analyze) → completed`; assertion:
   setiap event dirender tepat sekali, tidak ada duplikasi.
8. **Exit code** — matriks §3.7 diverifikasi via `typer.testing.CliRunner`.
9. **Fallback report dari disk** — `GET /report` menjawab 404 sementara
   `reports/<id>/report.json` ada → laporan tetap dirender + peringatan.
10. **Guard `--out`** — path di luar direktori kerja → exit 3, tidak ada berkas
    yang tertulis.

Seluruh test hermetik: **nol** panggilan jaringan, `MockTransport` untuk httpx.

---

## 8. Kriteria Sukses (Acceptance Criteria)

1. ✅ `cyense scan github <url> --i-have-permission` menampilkan banner, log
   stage live, log temuan, panel saran, dan footer artefak dalam satu perintah.
2. ✅ ≥ 85% glyph berwarna pada layar sukses berasal dari palet biru/netral §3.1.1;
   warna non-biru hanya muncul pada badge severity.
3. ✅ Berkas `.md` tertulis di `reports/<scan_id>/report.md` dan memuat ketujuh
   bagian §3.4 dengan front-matter valid.
4. ✅ Dua kali render report fixture yang sama menghasilkan `.md` byte-identik
   kecuali `generated_at`.
5. ✅ `NO_COLOR=1`, pipe ke `cat`, dan lebar 40 kolom semuanya menghasilkan
   output terbaca tanpa escape sequence yang bocor atau baris terpotong.
6. ✅ `--token` tidak pernah muncul di stdout maupun `.md` (uji grep).
7. ✅ Exit code sesuai matriks §3.7; `--fail-on high` pada repo dengan temuan
   `critical` mengembalikan 1.
8. ✅ Scan gagal (mis. 403 rate limit) menampilkan panel `⚠` berisi pesan engine
   apa adanya dan exit 2 — CLI tidak pernah menampilkan traceback Python.
9. ✅ `Ctrl-C` memulihkan kursor, tidak meninggalkan `.md` parsial, exit 130.
10. ✅ Tidak ada modul di `app/cli/` yang mengimpor `app.engines`/`app.agents`/
    `app.program`/`app.worker` (test §7.6).
11. ✅ Stage `fetch` benar-benar aktif pada mode `github` (progres 25 → 50 → 75,
    bukan melompat) setelah perbaikan §5.2.

---

## 9. Risiko & Mitigasi

| ID | Risiko | Dampak | Mitigasi |
|----|--------|--------|----------|
| R1 | Report disimpan di memori (`worker.py:139`); hilang saat service restart | `GET /report` 404 → CLI tampak rusak | Fallback baca `reports/<id>/report.json` (§3.6) + pesan eksplisit |
| R2 | `GithubEngine` tidak pernah memancarkan stage `fetch` (`github_engine.py:55,88`) padahal worker memetakannya (`worker.py:77`) | Progres melompat 25→75; baris `fetch` mati | Tambah satu `_notify("fetch")` (§5.2); dijadikan acceptance #11 |
| R3 | Dua dependensi baru (`typer`, `rich`) memperbesar image | Build lebih lambat | Keduanya pure-Python tanpa dep transitif berat; dipertimbangkan jadi extra `[cli]` bila image jadi masalah |
| R4 | Emoji/box-drawing rusak di Windows CP1252 & CI minimal | Output berantakan | Mode ASCII otomatis via deteksi encoding (§3.1.4), diuji §7.2 |
| R5 | Polling 250 ms membebani service saat banyak CLI paralel | Latensi API naik | Interval adaptif melebar ke 1 s; hanya satu endpoint ringan yang dipanggil |
| R6 | Repo jahat menyuntik ANSI escape lewat nama file/cuplikan kode | Output terminal dipalsukan | Sanitasi karakter kontrol sebelum render (§6.4) |
| R7 | CLI perlahan menumbuhkan logic sendiri (pengulangan kesalahan v1.0) | Divergensi hasil | Larangan import ditegakkan test §7.6; teks saran wajib berasal dari `Finding.remediation` |
| R8 | `--out` dipakai untuk menulis ke path sembarang di CI | Penulisan berkas tak diinginkan | Guard path §6.3 |

---

## 10. Roadmap Implementasi

| Fase | Isi | Estimasi |
|------|-----|----------|
| 1 | Kerangka Typer + `theme.py` + deteksi kapabilitas terminal + `version`/`list`/`rules` | 0.5 hari |
| 2 | `client.py` + polling adaptif + renderer stage (blok 1–2) + perbaikan `_notify("fetch")` | 0.5 hari |
| 3 | Renderer temuan & tabel (blok 3) + `recommend.py` + panel saran (blok 4) | 0.75 hari |
| 4 | `md_report.py` + guard `--out` + footer artefak (blok 5) + exit code | 0.75 hari |
| 5 | Matriks degradasi, snapshot test, test redaksi & batas import, README | 0.5 hari |
| Lanjutan | Ekspor SARIF/PDF, mode TUI, `cyense fix --interactive`, auto-spawn service | backlog |

Total MVP ≈ **3 hari**.

---

## 11. Open Questions

1. Perlukah CLI menjalankan uvicorn in-process bila `--api-url` tidak terjangkau?
   → **Proposal:** tidak untuk MVP; tampilkan pesan `service tidak terjangkau —
   jalankan 'make up'`. Auto-spawn menyamarkan batas client/server dan
   memperumit penanganan siklus hidup.
2. `--fail-on` sebaiknya default `none` atau `high`?
   → **Proposal:** `none`. Default yang bisa memerahkan build orang lain adalah
   kejutan yang buruk; CI menyetel sendiri secara eksplisit.
3. Apakah `.md` perlu menyertakan cuplikan bukti secara penuh?
   → **Proposal:** ya, dibatasi `max_evidence_lines=12`; laporan audit tanpa
   bukti kehilangan sebagian besar nilainya.
4. Satu berkas `.md` atau terpisah per kelas kerentanan (IDOR/XSS)?
   → **Proposal:** satu berkas dengan bagian terpisah; pemisahan berkas
   menyulitkan penempelan ke satu issue.
5. Perlukah `cyense scan` menampilkan ringkasan trajectory agent (deliverable
   kompetisi #4)?
   → **Proposal:** ya, di belakang flag `--show-trajectory`, membaca
   `reports/<id>/trajectories/*.json`; tidak aktif secara default agar layar
   utama tetap ringkas.
6. Nama binary `cyense` atau `cyensectl`?
   → **Proposal:** `cyense` — produk ini bukan pengendali kluster; nama pendek
   lebih baik untuk demo.

---

## 12. Changelog Fitur

| Versi | Perubahan |
|-------|-----------|
| 1.0 | Draft awal: CLI `cyense` sebagai thin client ke FastAPI; design system biru (§3.1); tiga blok log (analisis repo, vulnerability, saran perbaikan); renderer Markdown baru `app/report/md_report.py`; algoritma prioritas saran (§3.5); exit code CI-friendly; perbaikan stage `fetch` yang hilang pada `GithubEngine` |
| 1.1 | **Implemented**: seluruh komponen §5.1 dibangun — `app/cli/` (7 modul: `__init__`, `models`, `theme`, `client`, `recommend`, `renderer`, `main`), `app/report/md_report.py`; bug fix `_notify("fetch")` di `github_engine.py:85`; `pyproject.toml` + `requirements.txt` diperbarui dengan `typer>=0.12` + `rich>=13.7` + `[project.scripts] cyense = "app.cli.main:app"`; Makefile mendapat target `cli` + `demo` |

---

*Addendum ini tunduk pada PRD induk (`instruction/PRD.md`). Aturan konflik: PRD
induk menang untuk hal yang tidak diatur di sini (etika, redaction, state machine,
gaya commit). Batas arsitektural yang tidak boleh dilanggar: CLI adalah lapisan
presentasi — seluruh logic deteksi, verifikasi, dan remediasi tetap berada di
service.*
