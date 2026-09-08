# PRD Fitur — Lapis Metodologi OSINT Radar di /tools (Pivot Map + Workflows + Verifikasi + Training)

> **Feature PRD** | Versi 1.2 | Status: implemented
> **Parent PRD:** `instruction/PRD.md` — dokumen ini adalah *addendum*, bukan pengganti
> **Sumber konten:** "Dokumentasi Implementasi & Penerapan Fitur — osintradar.com/tools", analisis independen v1.0 (8 Sep 2026) atas `/tools` (20 halaman, 346 tool, 21 kategori), `/categories`, `/workflows`, `/free-tools`, `/about`, `/responsible-use`, `sitemap.xml`
> **Lokasi implementasi:** `dev/main/app/program/{osintradar_methodology,osintradar_pivot,tools_catalog}.py`, `dev/main/app/api/system.py` (`GET /tools`), `dev/main/app/interface/svelte/src/routes/Tools.svelte`, `dev/main/app/interface/svelte/src/app.css`, `components/{Toolbench,CaseFile,PivotMap}.svelte` + `components/toolbench/*`, `lib/{exif,headers,casefile}.js`

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

Dua lapis awal (Workflows, Pivot, catatan risiko — bagian 2 di atas) diterapkan
lewat view `tools`/`workflows`. **Toolbench dan Case File** — dua lapis
eksekusi/penyimpanan — awalnya dianggap di luar scope *data module*, lalu
diimplementasikan sebagai **fitur UI klien murni** (fase 2, lihat §2.2): tanpa
backend, tanpa akun, tanpa unggah. Yang tersisa di luar scope:

| Item dokumen | Alasan luar-scope |
|---|---|
| §3.1.2 Arsitektur Orkestrator (queue, konektor, Neo4j, WORM) | Panduan untuk membangun mesin eksekusi OSINT; Cyense bukan aggregator OSINT |
| §3.3.1 skema PostgreSQL + `pivot_edges.confidence` | Catalog Cyense pure-Python deterministik; bobot edge butuh kurasi data baru — diusulkan via `CATEGORY_NOTES`/workflow caution sampai ada sumber |
| §3.4.2–3.4.3 gerbang kebijakan & audit | Menyentuh model query/akun yang tidak dimiliki fitur katalog |
| §4.2 API publik read-only JSON | Sudah dipegang oleh `GET /api/v1/tools` |

## 2.2 Fase 2 — Toolbench & Case File (client-side, Lapis A lengkap)

Dokumen membedakan dengan tegas: katalog ≠ mesin eksekusi; satu-satunya "proses
input pengguna" milik platform adalah Toolbench/Case File. Keduanya diterapkan
1:1 di browser — `local · no account · offline-capable` (IP Lookup pengecualian
yang diakui dokumen §A5).

**Toolbench** (`components/Toolbench.svelte` + `toolbench/*`): tab ke-3 di
`/#/tools`.
- `DorkBuilder` — komposisi operator `site:/filetype:/intitle:/inurl:` murni string.
- `IpLookup` — satu panggilan jaringan ke `ipwho.is` (tanpa akun), diberi label
  "butuh jaringan"; sisanya offline.
- `TimestampDecoder` — Unix s/ms, Windows FILETIME, ISO-8601 (BigInt aman).
- `EmailHeaderAnalyzer` — parser RFC 5322 lokal (`lib/headers.js`): unfold
  folded headers, rantai `Received:` (terlama→terbaru), IP per hop + tanda
  privat, verdict SPF/DKIM/DMARC per segmen `;`. Tanpa query DNS live —
  disclaimer di UI (verdict hanya sevalid teks header).
- `ImageMetadata` — EXIF JPEG/GPS + tEXt PNG di browser (`lib/exif.js`,
  DataView, tanpa dependensi) + **SHA-256** file untuk chain-of-custody.
- `UsernameSweep` — membangkitkan ~23 pivot URL; **tidak mengirim permintaan**
  (pola desain offline yang diulas dokumen).
- `HashIdentifier` — tabel panjang/charset/prefiks; bentuk identik (MD5/NTLM/MD4)
  dilaporkan ambigu, bukan diklaim.

**Case File** (`lib/casefile.js` + `components/CaseFile.svelte`): tab ke-4.
Tombol `＋ case` di kartu dan drawer tool; catatan "observed result" per entri;
ekspor **Markdown/JSON**. Setiap ekspor Markdown menyertakan `SHA-256` seluruh
isi laporan (via `crypto.subtle`, bila tersedia) — implementasi rekomendasi
§4.2 "ekspor terhash" tanpa butuh Evidence Store server-side. Persistensi
`localStorage` + disclaimer jujur (hilang saat cache dibersihkan, tak sinkron
antar perangkat).

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
   ├─ view=tools       →  chip "Saya punya" memfilter you_have; .cat-note per grup
   ├─ view=workflows   →  kartu 6 alur → drawer: caution, steps → tool chips
   │                     (nama tak resolve tampil teks biasa), checkpoints, skala
   ├─ view=toolbench   →  Toolbench.svelte: 7 utilitas, masing-masing + Tombol case
   └─ view=casefile    →  CaseFile.svelte (localStorage; ekspor md/json + hash)
```

- **Resolusi nama tool:** `step.tools` memakai *display name* katalog (case-insensitive)
  — dijamin test (`references only tools that exist`), jadi chip workflow selalu bisa
  membuka drawer tool yang sama; entri baru tidak memutus link tanpa tertangkap test.
- **Layering drawer:** membuka tool dari workflow menimpa drawer (`selected` menang
  atas `selectedWf`); Esc/backdrop menutup lapis atas dan kembali ke workflow.
- **Case File**: store reaktif `localStorage` (kuci `cyense.casefile.v1`); tombol
  `＋ case` pada kartu *dan* header drawer tool (`e.stopPropagation()` agar tak
  membuka drawer dari kartu); catatan per entri; ekspor menimbang `crypto.subtle`
  (secure context) untuk hash SHA-256 — fallback eksplisit jika tak tersedia.
- **Deterministik & offline:** sama seperti catalog — tanpa kolom DB; semua toolbench
  berjalan murni klien kecuali IP Lookup (satu panggilan `ipwho.is`, ditandai `net`).
  Parser EXIF/header memakai `DataView`/regex tanpa dependensi.

## 4. Validasi

| Uji | Hasil |
|---|---|
| `tests/test_tools_catalog.py::test_methodology_layer_in_payload` — bentuk vocabulary 12-tipe, `you_have ⊆ codes`, 6 slug workflow + seluruh referensi tool resolve, checkpoint & level keyakinan, catatan semua kategori `osint-*` + risiko eksplisit utk 6 kategori sensitif | ✅ pass |
| `pytest tests -q` (full) + `ruff check` | ✅ 0 gagal · ruff clean |
| `vite build` UI | ✅ `index-Aqv0Q_i8.js` + `index-hLMT1ydR.css` |
| Smoke headless fase 1 (chromium, `/#/tools`) | ✅ 12 chip; Email → 684→145; Workflows → 6 kartu; drawer 4 langkah + chip; 8 `.cat-note` + 4 badge risiko |
| Smoke headless fase 2 (Toolbench) | ✅ Dork `site:example.com "secret" filetype:pdf`; Timestamp s/ms + FILETIME benar (UTC `2024-09-08T01:46:40Z`); Hash 32-hex → 2 kandidat; Username Sweep → 23 URL (github/john_doe123 ✅); Email Header → 2 hop, verdict `spf=pass dkim=fail dmarc=pass`, origin IP diekstrak |
| EXIF unit (fixture JPEG buatan) | ✅ Make/DateTime + GPS `40.446111, -73.983333` + SHA-256 |
| Case File alur | ✅ +case di kartu & drawer; persist `localStorage` lintas reload (2 entri); catatan tersimpan; ekspor Markdown ber-`SHA-256` terverifikasi |

## 5. Batasan (diumumkan ke pengguna di UI)

Workflows adalah **metodologi terpandu, bukan eksekusi otomatis** — pengguna tetap
menjalankan setiap tool di situs aslinya (cerminan keterbatasan §2.2 A3). Kelas risiko
diberikan **per kategori**, mengikuti rekomendasi per-tool pada §4.2 sebagai future
work; label `you_have` sebuah tool tidak menjamin tool itu sahih untuk identifier
tertentu (batasan pemetaan kasar §A2).

Toolbench: EXIF **hanya** segmen standar JPEG/PNG (tak menggantikan exiftool untuk
format eksotik); Email Header tak melakukan validasi DNS/SPF live — verdict hanya
sevalid teks header yang di-paste (bisa dipalsukan). Case File berbasis
`localStorage` — tidak memenuhi chain-of-custody forensik formal; hash SHA-256
berlaku bila `crypto.subtle` tersedia (secure context).
