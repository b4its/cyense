# PRD Fitur — Lapis Metodologi OSINT Radar di /tools (Workflows + Pivot Map + Catatan Risiko)

> **Feature PRD** | Versi 1.0 | Status: implemented
> **Parent PRD:** `instruction/PRD.md` — dokumen ini adalah *addendum*, bukan pengganti
> **Sumber konten:** "Dokumentasi Implementasi & Penerapan Fitur — osintradar.com/tools", analisis independen v1.0 (8 Sep 2026) atas `/tools` (20 halaman, 346 tool, 21 kategori), `/categories`, `/workflows`, `/free-tools`, `/about`, `/responsible-use`, `sitemap.xml`
> **Lokasi implementasi:** `dev/main/app/program/osintradar_methodology.py`, `dev/main/app/program/tools_catalog.py`, `dev/main/app/api/system.py` (`GET /tools`), `dev/main/app/interface/svelte/src/routes/Tools.svelte`, `dev/main/app/interface/svelte/src/app.css`

---

## 0. Ringkasan Satu Paragraf

Analisis OSINT Radar menegakkan satu pembedaan yang sebelumnya tidak tersajikan di UI Cyense:
pustaka 346 tool adalah **katalog terkurasi** (tool dieksekusi di situs pihak ketiga),
sedangkan *fitur fungsional* platform sendiri hanyalah **pivot map**, **workflows
investigatif**, **case file**, dan **Toolbench**. Addendum ini memindahkan lapis
metodologi ("Lapis A") tersebut ke halaman `/#/tools`: tab **Workflows** dengan 6
kerangka investigasi berlangkah (tool tiap langkah tertaut ke drawer katalog), filter
pivot **"Saya punya"** berbasis kosakata 12 identifier (`you_have` yang sudah ada di
data mirror), **catatan keterbatasan + kelas risiko** di tiap judul kategori OSINT,
serta **Reporting Checkpoints** dan **skala keyakinan** 4- level di drawer workflow.
Murni data + presentation layer — tidak ada engine, aturan deteksi, atau state machine
scan yang berubah.

---

## 1. Latar Belakang & Masalah

### 1.1 Kondisi sebelum fitur ini

| Fakta | Lokasi |
|-------|--------|
| Katalog sudah memuat 346 entri OSR + mekanisme aslinya, tetapi hanya bisa dijelajahi *per tool* | `osintradar_tools.py`, panel drawer `99d5095` |
| Tidak ada jalan masuk "mulai dari pertanyaan investigatif" — padahal itu jawaban inti OSINT Radar atas katalog datar | — |
| Kosakata pivot (`you_have`/`you_get`) tersimpan per tool tetapi tidak dapat difilter dari UI | data mirror |
| Catatan risiko & keterbatasan (biometrik, offensif, privacy tinggi) hanya ada di dokumen analisis, tidak sampai ke pengguna | dokumen ini |

### 1.2 Masalah yang dipecahkan

Katalog tanpa metodologi menghasilkan koleksi link; analis junior tetap tidak tahu
langkah berikutnya. Tiga keputusan desain OSINT Radar yang layak ditiru — pivot model
bertipe, workflow pertanyaan-dulu, dan transparansi keterbatasan/risk — belum hidup di
UI. Fitur ini menerapkan ketiganya apa adanya, termasuk **keterbatasan yang diumumkan
eksplisit** (analisis §4.2: saran pivot site kadang tidak logis; workflow tidak
mengeksekusi apa pun).

---

## 2. Pemetaan Dokumen Analisis → Implementasi

| Bagian dokumen sumber | Elemen | Jatuh ke |
|---|---|---|
| §2.2 A2 — Pivot Map | Kosakata 12 identifier terverifikasi | `PIVOT_TYPES`; chip "Saya punya" di hero `Tools.svelte`; invariant diuji (`have_values ⊆ pivot_codes`) |
| §2.2 A3 — Workflows (6 alur) | `investigate-a-username` … `trace-a-wallet` + peringatan tiap alur | `WORKFLOWS`; tab Workflows + drawer kerangka |
| §2.2 A3 — Reporting Checkpoints | Target value / Source and time / Observed result / Confidence | `REPORTING_CHECKPOINTS`; footer drawer workflow |
| §3.3.3 — Skoring keyakinan | confirmed / probable / lead / disputed + kriteria & contoh | `CONFIDENCE_SCALE`; drawer workflow |
| §2.3 B1–B21 — keterbatasan per kategori | Ringkasan risiko + batasan 21 kategori `osint-*` | `CATEGORY_NOTES`; `.cat-note` + badge risiko di judul grup |
| §4.2 (sedang) — "Tandai kelas risiko" | Kelas risiko per kategori (diterapkan level kategori, bukan per tool) | field `risk` pada objek kategori payload |
| Temuan pembuka — katalog ≠ mesin eksekusi | Disclaimer "tidak ada eksekusi otomatis" di view workflows | teks `.cat-note` view workflows |

**Vocabulary check:** `you_get` mirror memakai item individual ("breach names",
"breach dates", …) persis kosakata output terverifikasi §A2 — tidak ada transformasi.

## 2.1 Yang sengaja TIDAK diterapkan

| Item dokumen | Alasan luar-scope |
|---|---|
| Toolbench (7 utilitas lokal) | Fitur eksekusi nyata; butuh modul produk sendiri (parser header, EXIF, dll.), bukan bagian "terapkan dokumen ke UI". Rekomendasi perluasan (§4.2) dicatat di sini sebagai future work |
| Case File + ekspor terhash | Sudah ada padanan browsing; *hashed export* menuntut pipeline bukti (Evidence Store) — di luar presentation layer |
| §3.1.2 Arsitektur Orkestrator (queue, konektor, Neo4j, WORM) | Panduan untuk membangun mesin eksekusi OSINT; Cyense bukan aggregator OSINT |
| §3.3.1 skema PostgreSQL + `pivot_edges.confidence` | Catalog Cyense pure-Python deterministik; bobot edge butuh kurasi data baru — diusulkan via `CATEGORY_NOTES`/workflow caution sampai ada sumber |
| §3.4.2–3.4.3 gerbang kebijakan & audit | Menyentuh model query/akun yang tidak dimiliki fitur katalog |
| §4.2 API publik read-only JSON | Sudah dipegang oleh `GET /api/v1/tools` |

---

## 3. Desain

```
osintradar_methodology.py   PIVOT_TYPES · WORKFLOWS(6) · REPORTING_CHECKPOINTS
        │                   CONFIDENCE_SCALE · CATEGORY_NOTES(21)
        ▼
tools_catalog()  →  payload /api/v1/tools
        │            categories[] += note?/risk?
        │            + pivot_types · workflows · reporting_checkpoints · confidence_scale
        ▼
Tools.svelte
   ├─ view=tools      →  chip "Saya punya" memfilter you_have; .cat-note per grup
   └─ view=workflows  →  kartu 6 alur → drawer: caution, steps → tool chips
                         (nama tak resolve tampil teks biasa), checkpoints, skala
```

- **Resolusi nama tool:** `step.tools` memakai *display name* katalog (case-insensitive)
  — dijamin test (`references only tools that exist`), jadi chip workflow selalu bisa
  membuka drawer tool yang sama; entri baru tidak memutus link tanpa tertangkap test.
- **Layering drawer:** membuka tool dari workflow menimpa drawer (`selected` menang
  atas `selectedWf`); Esc/backdrop menutup lapis atas dan kembali ke workflow.
- **Deterministik & offline:** sama seperti catalog — tanpa kolom DB, tanpa panggilan
  jaringan; teks Indonesia mengikuti bahasa dokumen sumber agar tidak ada drift makna.

## 4. Validasi

| Uji | Hasil |
|---|---|
| `tests/test_tools_catalog.py::test_methodology_layer_in_payload` — bentuk vocabulary 12-tipe, `you_have ⊆ codes`, 6 slug workflow + seluruh referensi tool resolve, checkpoint & level keyakinan, catatan semua kategori `osint-*` + risiko eksplisit utk 6 kategori sensitif | ✅ 10/10 pass satu file (venv `dev/main`) |
| `vite build` UI | ✅ `index-aqBj1ppc.js` + `index-D740LUWP.css` |
| Smoke headless (chromium, `/#/tools` via server :8123) | ✅ 12 chip; Email → 684→145 tool; tab Workflows → 6 kartu; drawer: 4 langkah + 16 chip tool; overlay tool (IDCrawl) lalu kembali ke workflow; 8 `.cat-note` + 4 badge risiko di halaman 1 |

## 5. Batasan (diumumkan ke pengguna di UI)

Workflows adalah **metodologi terpandu, bukan eksekusi otomatis** — pengguna tetap
menjalankan setiap tool di situs aslinya (cerminan keterbatasan §2.2 A3). Kelas risiko
diberikan **per kategori**, mengikuti rekomendasi per-tool pada §4.2 sebagai future
work; label `you_have` sebuah tool tidak menjamin tool itu sahih untuk identifier
tertentu (batasan pemetaan kasar §A2).
