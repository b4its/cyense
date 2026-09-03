# Setup Cyense — Panduan Lengkap (Docker, Manual, Makefile)

Panduan ini menjelaskan cara menjalankan **Cyense** dari nol sampai siap dipakai —
baik lewat **CLI** maupun **browser (Web UI)**. Ada tiga cara menjalankan:
**Docker Compose**, **manual (Python virtualenv)**, dan **Makefile** (yang
merupakan wrapper di atas keduanya).

---

## 0. Daftar Isi

1. [Prasyarat](#1-prasyarat)
2. [Struktur direktori penting](#2-struktur-direktori-penting)
3. [Cara A — Docker Compose](#3-cara-a--docker-compose-rekomendasi)
4. [Cara B — Manual (Python venv)](#4-cara-b--manual-python-virtualenv)
5. [Cara C — Makefile](#5-cara-c--makefile)
6. [Memulai lab app rentan (untuk evaluasi)](#6-memulai-lab-app-rentan-untuk-evaluasi)
7. [Menggunakan CLI](#7-menggunakan-cli)
8. [Menggunakan Browser / Web UI](#8-menggunakan-browser--web-ui)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Prasyarat

| Kebutuhan | Versi | Catatan |
|-----------|-------|---------|
| Python | ≥ 3.11 | Wajib untuk cara B, C, dan test suite |
| Docker | ≥ 20.10 | Wajib untuk cara A (Compose v2) |
| Docker Compose | v2 | Dibundel dengan Docker Desktop / plugin compose |
| `make` | — | Untuk cara C (`make ...`) |
| Git | — | Untuk clone repositori |
| Node.js + npm | — | Hanya jika ingin *build ulang* Web UI Svelte dari source |

> **Catatan:** untuk memakai target publik / GitHub, dibutuhkan koneksi internet.
> Semua perintah *scan* wajib menambahkan `--i-have-permission` — gate legal/etis
> (422 tanpa flag ini) sesuai ground rules Cyense.

---

## 2. Struktur direktori penting

```
cyense/
├── Makefile                         ← wrapper (up/down/test/lint/cli/...)
├── setup.md                         ← dokumen ini
├── README.md
├── dev/
│   ├── main/                        ← IMPLEMENTASI UTAMA
│   │   ├── app/
│   │   │   ├── main.py              ← create_app() — FastAPI
│   │   │   ├── cli/                 ← CLI Typer (cyense ...)
│   │   │   └── interface/svelte/    ← Web UI (Svelte, dibuild ke dist/)
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── requirements.txt
│   │   ├── pyproject.toml           ← console script `cyense`
│   │   ├── reports/                 ← artefak scan per-scan (gitignored)
│   │   └── brain/                   ← memori antar-scan (gitignored)
│   ├── brain/                       ← volume knowledge.json
│   └── target/                      ← /workspace (mode program, read-only)
└── reports/                         ← artefak scan (gitignored)
```

Setelah service berjalan, buka browser atau panggil CLI. Keduanya bicara ke API
yang sama (`http://localhost:8000/api/v1`).

---

## 3. Cara A — Docker Compose (rekomendasi)

Cara paling cepat dan hermetik. Menjalankan **api** (+ opsi **vulnerable-app**
di profil `lab`).

### 3.1 Jalankan

```bash
cd cyense
make up
```

`make up` = `docker compose --profile lab up -d --wait api vulnerable-app`.
Alternatif tanpa Makefile:

```bash
cd dev/main
docker compose --profile lab up -d --wait api vulnerable-app
```

Hasilnya:
- **API**: http://localhost:8000 — cek: `curl http://localhost:8000/api/v1/health`
- **Swagger UI**: http://localhost:8000/docs
- **Web UI**: http://localhost:8000/ui
- **Lab app** (target evaluasi): http://localhost:8080

### 3.2 Verifikasi

```bash
curl http://localhost:8000/api/v1/health
# {"status":"ok","service":"cyense","version":"2.1.0"}
```

### 3.3 Menjalankan CLI di dalam container

CLI tidak perlu diinstall di host — jalankan di dalam container API:

```bash
# lewat Makefile:
make cli ARGS="version"
make cli ARGS="scan website http://localhost:8080 --i-have-permission"

# atau langsung:
docker compose exec api python -m app.cli.main version
docker compose exec api python -m app.cli.main list
```

### 3.4 Port custom

Ubahlah port HTTP/AI via environment sebelum `make up`:

```bash
export CYENSE_API_PORT=8100
export CYENSE_LAB_PORT=8081
make up
# API → http://localhost:8100, lab → http://localhost:8081
```

### 3.5 Stop / bersihkan

```bash
make down            # stop + hapus container
make clean           # down + hapus volume + reports lokal
```

---

## 4. Cara B — Manual (Python virtualenv)

Cara ini menjalankan API langsung di host — cocok untuk pengembangan, debug,
atau kalau Docker tidak tersedia.

### 4.1 Clone + siapkan venv

```bash
git clone <repo-url> cyense
cd cyense/dev/main
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

> Untuk tooling pengembangan (pytest, ruff, Flask untuk lab app):
> `pip install -e ".[dev]"` (dari `dev/main`, konfigurasi pyproject).

### 4.2 Jalankan API (uvicorn)

```bash
cd cyense/dev/main
uvicorn app.main:app --host 127.0.0.1 --port 8000
# Swagger: http://127.0.0.1:8000/docs
# Web UI  : http://127.0.0.1:8000/ui
```

Verifikasi di terminal lain:

```bash
curl http://127.0.0.1:8000/api/v1/health
```

### 4.3 Jalankan CLI (host)

Karena `pyproject.toml` mendefinisikan console script `cyense`, setelah venv
diaktifkan:

```bash
cd cyense/dev/main
cyense version
cyense rules
cyense list
```

Atau tanpa install:

```bash
cd cyense/dev/main
python -m app.cli.main version
```

> **Penting:** CLI default-nya memanggil `http://localhost:8000`. Jika API
> berjalan di port lain, gunakan `--api-url`:
> `cyense --api-url http://localhost:8100 list`

### 4.4 Launcher interaktif (Website vs CLI)

```bash
cd cyense/dev/main
python -m app.cli.main launch
# pilih 1) Website  → buka http://127.0.0.1:8000/ui
#       2) CLI      → contoh perintah CLI
```

Launcher men-spawn backend di background bila belum berjalan.

---

## 5. Cara C — Makefile

`make` adalah wrapper di atas Docker (dan ada target untuk venv/langganan tes).
Semua target berjalan dari root repo.

| Target | Perintah | Fungsi |
|--------|----------|--------|
| **Start API + lab** | `make up` | build + `docker compose up -d --wait` |
| **Stop** | `make down` | hentikan container |
| **Clean (data)** | `make clean` | down + volume + reports |
| **Status** | `make ps` | daftar container |
| **Log** | `make logs` / `make logs-api` / `make logs-lab` | ikuti log |
| **Shell API** | `make shell` | bash di dalam container api |
| **Test** | `make test` | pytest (memakai `python3` host) |
| **Lint** | `make lint` | ruff check |
| **Ruff fix** | `make fix` | ruff --fix |
| **Format** | `make format` | ruff format |
| **CLI cepat** | `make cli ARGS="..."` | jalankan `python -m app.cli.main ...` di container |
| **CLI shell** | `make cli-shell` | bash interaktif di container (ketik perintah CLI) |
| **CLI help** | `make cli-help` | `--help` |
| **Demo** | `make demo` | scan repo contoh `octocat/Hello-World` |
| **Launcher** | `make run` | `python -m app.cli.main launch` (host) |
| **Recon** | `make recon URL=https://...` | `cyense cve <url> --i-have-permission` |
| **Install dev** | `make install-dev` | buat venv + `pip install -e "dev/main[dev]"` |

### 5.1 Alur cepat pakai Makefile

```bash
make up                     # 1) hidupkan API + lab
make cli ARGS="version"     # 2) cek CLI di container
make demo                   # 3) demo scan GitHub repo
make cli ARGS="list"        # 4) lihat hasil scan
make down                   # 5) matikan
```

### 5.2 `make test` / `make lint` (host)

`make test` dan `make lint` memakai Python host (bukan container). Pastikan
dependensi dev terinstall:

```bash
make install-dev            # membuat ./venv (root) + install dev/main[dev]
make test
make lint
```

Agar `make test` memakai venv root, aktifkan dulu `source venv/bin/activate`
(atau pastikan `python3` mengarah ke interpreter dengan dep terinstall).

---

## 6. Memulai lab app rentan (untuk evaluasi)

Lab app (`dev/main/tests/fixtures/vulnerable_app/lab_app.py`) berisi 11 kasus
IDOR (invoice, orders, profile/docs trap, uuid, file, flaky, payment, slow,
missing, mixed) + XSS/SQLi surface — target aman untuk menguji scanner.

| Cara | Perintah |
|------|----------|
| Docker (profil lab) | `make up` (otomatis menyala di :8080) |
| Manual (Flask) | `cd dev/main && python tests/fixtures/vulnerable_app/lab_app.py` → :8080 |

Contoh scan agentic ke lab:

```bash
# CLI (dari container):
make cli ARGS="scan link http://localhost:8080/invoice/{ID} --i-have-permission"

# langsung lewat API:
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode":"link","url":"http://localhost:8080/invoice/{ID}","i_have_permission":true}'
```

---

## 7. Menggunakan CLI

Format umum: `cyense <command> [options]`. Nilai `--i-have-permission` wajib
untuk semua perintah yang melakukan scanning.

### 7.1 Perintah dasar

```bash
cyense --help                # semua perintah + flag
cyense version               # versi CLI + service
cyense rules                 # katalog rule aktif (CY/IDOR, XS/XSS, SQLI, CWE, OWASP, OSINT, RE)
cyense list                  # daftar scan terakhir
cyense history --status completed
cyense view <scan_id>        # buka viewer browser
cyense report <scan_id>      # render ulang laporan
cyense coverage <scan_id>    # dokumen coverage
cyense delete <scan_id> --confirm
```

### 7.2 Mode scan

```bash
cyense scan website http://example.com --i-have-permission
cyense scan domain example.com --i-have-permission
cyense scan link http://app/invoice/{ID} --i-have-permission
cyense scan program --i-have-permission --source-type sample
cyense scan github https://github.com/octocat/Hello-World --i-have-permission
cyense scan api swagger.yaml --base-url http://localhost:8080 --i-have-permission

# varian fokus
cyense cve http://example.com --i-have-permission
cyense recon http://example.com --i-have-permission      # osint/revier/OWASP + discovery
cyense routes http://example.com --i-have-permission
```

### 7.3 Remediasi (fix)

```bash
cyense fix <scan_id>                       # generate proposal patch
cyense fix-diff <session_id>               # lihat unified diff
cyense fix-apply <session_id> FIX_ID --confirm
cyense fix-revert <session_id> --confirm
```

### 7.4 Crypto toolbelt (offline, tanpa service)

```bash
cyense crypt hash 'hello' --algo sha256
cyense crypt identify 5d41402abc4b2a76b9719d911017c592
cyense crypt aes encrypt 'rahasia' --key 0123456789abcdef0123456789abcdef -m gcm
cyense crypt blowfish encrypt 'x' --key key123 -m cbc
cyense crypt twofish encrypt 'x' --key 0123456789abcdef -m cbc
cyense crypt chacha encrypt 'x' --key kkkkk... --nonce 12345678
cyense crypt salsa encrypt 'x' --key ... --nonce 12345678
cyense crypt rc4 encrypt 'x' --key rc4k
cyense crypt rsa generate --bits 2048
cyense crypt ecc generate
cyense crypt kdf 'password' --algo pbkdf2 --length 32
cyense crypt random 16
```

### 7.5 Alur lengkap end-to-end

```bash
make up
make cli ARGS="cve http://localhost:8080 --i-have-permission"
SID=$(make cli ARGS="list" | tail -1 | awk '{print $1}')
make cli ARGS="report $SID"
make cli ARGS="view $SID --no-browser"
```

---

## 8. Menggunakan Browser / Web UI

Ada dua antarmuka web:
1. **Svelte Web UI** — http://localhost:8000/ui (dashboard, daftar scan, detail
   scan dengan pipeline + temuan, halaman rules).
2. **Viewer per-scan** — http://localhost:8000/api/v1/viewer/<scan_id>
   (laporan + trajectories agent).

### 8.1 Syarat

- Service API berjalan (salah satu cara A/B/C).
- **Web UI** memakai bundle Svelte yang sudah di-*build* di
  `app/interface/svelte/dist/` (sudah ter-commit). Jika ingin membangun ulang
  dari source:

  ```bash
  cd dev/main/app/interface/svelte
  npm install
  npm run build        # menulis ke dist/ (basis /ui/)
  ```

  Hasil build disajikan otomatis oleh endpoint `/ui`.

### 8.2 Menggunakan

1. Buka http://localhost:8000/ui di browser.
2. **Dashboard** — ringkasan scan terbaru.
3. **Scan Library** — daftar scan; isi URL + pilih mode (`website`, `domain`,
   `link`, `program (sample)`, `github`) lalu klik **Scan**.
4. Klik sebuah scan → **ScanDetail**: pipeline stage, checklist progres,
   coverage, dan temuan terklasifikasi (CVE, teknologi, port, secret, OSINT,
   RE, OWASP, Nikto/Nuclei, XSS, SQLi, IDOR, routing).
5. Halaman **Rules** — katalog rule aktif dari `/api/v1/rules`.

### 8.3 Membuka viewer per-scan dari CLI

```bash
cyense view <scan_id>             # membuka browser
cyense view --latest              # scan terbaru
cyense view <scan_id> --no-browser  # hanya cetak URL
```

URL viewer: `http://localhost:8000/api/v1/viewer/<scan_id>`.

---

## 9. Troubleshooting

| Gejala | Penyebab / Solusi |
|--------|-------------------|
| `422 Unprocessable` saat submit scan | Tambahkan `--i-have-permission` / `"i_have_permission": true` — gate wajib. |
| `/ui` mengembalikan 503 | Bundle Svelte `dist/` belum ada; jalankan `npm run build` di `app/interface/svelte`. |
| `Connection refused` pada CLI | API belum hidup; jalankan `make up` atau `uvicorn app.main:app`, atau `--api-url` ke port yang benar. |
| `ModuleNotFoundError` saat manual | Dependensi belum terinstall: `pip install -r requirements.txt` (dan `pip install -e ".[dev]"` untuk tes). |
| Port 8000/8080 sudah terpakai | Pakai `CYENSE_API_PORT` / `CYENSE_LAB_PORT` (Docker) atau ubah `--port` (manual). |
| `make test` pakai Python salah | Aktifkan venv host yang berisi flask/pytest/ruff, atau `make install-dev`. |
| Scan GitHub lambat / gagal | Pastikan internet + `--token` GITHUB bila men-scan repo privat (token hanya ke github.com). |
| Banyaknya temuan discovery tak muncul di CLI | Gunakan `cyense recon <url> --i-have-permission` (menampilkan OSINT/RE/OWASP/HARVEST/... di tabel discovery). |

### Daftar perintah referensi cepat

```bash
make up
make cli ARGS="version"
make cli ARGS="scan website http://example.com --i-have-permission"
make cli ARGS="list"
make down

# manual
source dev/main/.venv/bin/activate
cd dev/main && uvicorn app.main:app --port 8000
cd dev/main && python -m app.cli.main scan website http://example.com --i-have-permission
```

---

*Cyense — hanya scan target yang Anda miliki izinnya (ground rule #4/#6/#7). 🛡️*