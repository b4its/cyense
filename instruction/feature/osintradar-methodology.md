# PRD Fitur — Lapis Metodologi OSINT Radar di /tools (Pivot Map + Workflows + Verifikasi + Training)

> **Feature PRD** | Versi 1.7 | Status: implemented
> **Parent PRD:** `instruction/PRD.md` — dokumen ini adalah *addendum*, bukan pengganti
> **Sumber konten:** "Dokumentasi Implementasi & Penerapan Fitur — osintradar.com/tools", analisis independen v1.0 (8 Sep 2026) atas `/tools` (20 halaman, 346 tool, 21 kategori), `/categories`, `/workflows`, `/free-tools`, `/about`, `/responsible-use`, `sitemap.xml`
> **Lokasi implementasi:** `dev/main/app/program/{osintradar_methodology,osintradar_pivot,tools_catalog}.py`, `dev/main/app/api/system.py` (`GET /tools`, `GET /tools/search`), `dev/main/app/interface/svelte/src/routes/Tools.svelte`, `dev/main/app/interface/svelte/src/app.css`, `components/{Toolbench,CaseFile,PivotMap}.svelte` + `components/toolbench/*`, `lib/{exif,headers,casefile,coords,solar,warc,seo}.js`

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
| §2.2 A2 — Pivot Map + §3.3.5 visualisasi | Kosakata 12 identifier + graf SVG node-link (kolom identifier→tool→artefak, edge bezier berarah, semua node klikabel menavigasi hop; toggle Graf/List) | `PIVOT_TYPES`; chip "Saya punya" di hero; invariant diuji (`have_values ⊆ pivot_codes`); `PivotMap.svelte` (`buildGraph(f, tools)` sengaja berargumen — Svelte melacak dep `$:` secara sintaksis, akses via closure tak memicu recompute) |
| §2.2 A3 — Workflows (6 alur; +4 ekspansi fase 4) | `investigate-a-username` … `trace-a-wallet` + peringatan tiap alur | `WORKFLOWS`; tab Workflows + drawer kerangka |
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

## 2.3 Fase 4 — Sisa butir §4.2 yang bisa diterapkan

| Butir §4.2 / §A1 | Implementasi | Lokasi |
|---|---|---|
| Tinggi: API publik read-only JSON + filter facet ala situs (`?category`, `?have=email`, `?page`) | `GET /api/v1/tools/search` — facet `category/have/pricing/access/status/q/page/page_size`, respons ringkas terpaginate (tanpa menggeser payload penuh `/tools` yang dipakai UI/CLI) | `tools_catalog.tools_filtered` + `api/system.py` + test |
| Sedang: nama tool sebagai data terstruktur (microdata SoftwareApplication) | JSON-LD: `CollectionPage`+`ItemList` 24 kartu halaman aktif; drawer terbuka ⇒ `SoftwareApplication`; `<` di-escape | `lib/seo.js` + `Tools.svelte` svelte:head |
| Sedang: perluas workflows 6 → cakupan kategori yang tak punya alur | +4 workflow (triage-a-threat-alert, investigate-a-darkweb-service, track-a-vessel-or-flight, verify-a-public-record) — tiap tool reference tervalidasi test; **badge "ekspansi" jujur** + catatan sumber, karena bukan alur resmi OSINT Radar | `osintradar_methodology.WORKFLOWS` + test slug |
| Sedang: kelas risiko **per tool** | `TOOL_RISK`/`TOOL_RISK_WHY` (27 tool tersorot dokumen: biometrik/offensif/privasi-tinggi/darkweb/ToS/**mati**) di-enrich ke record katalog saat build; badge kartu + drawer (ikon per kelas) | `osintradar_methodology` + enrichment `tools_catalog._all_tools` |
| Sedang: catatan cakupan yurisdiksi | `JURISDICTION` (17 tool region-bound: people-search AS/UK/CA, RIR, dll.) → badge `coverage` di drawer | sama |
| Rendah: +Toolbench (konverter koordinat, chronolocation, WARC check) | **Coordinate Converter** DMS ⇄ desimal ⇄ UTM (Snyder WGS84; inversi = Newton pada *forward series sendiri* ⇒ round-trip ≤1e-13°, 9 vektor teruji); **Chronolocation** (posisi matahari Williams/NOAA: azimuth/elevasi, bayangan/m, solver waktu-untuk-elevasi via scan+bisection — ekuidoksNYC sunrise azimuth terverifikasi 90.08±1.5°, solstis London maks 61.93°; bug nyata dijinakkan: `isFinite(null)===true` ⇒ guard `reverseElevOk` bertipe); **WARC Integrity** (parser ISO-28500 subset, digest deklaratif sha1/sha256 dalam hex/base64/base32/urn diverifikasi ulang via `crypto.subtle`, .warc.gz dilaporkan jujur tanpa parsing). Ketiganya ber-badge "ext" (bukan salah satu 7 asli) | `lib/coords.js`, `lib/solar.js`, `lib/warc.js` + `toolbench/CoordinateConverter/Chronolocation/WarcIntegrity.svelte` |

## 2.4 Fase 6 — Paritas CLI untuk lapis metodologi

Dokumen memuji model "one source, two clients" katalog (CLI + Website);
paritas sebelumnya berhenti di data tool mentah — workflows, pivot, health,
training, risk/coverage **hanya** muncul di web. Fase ini menyambungkan payload
yang sama ke CLI (data tetap satu sumber, tanpa endpoint baru):

| Command / flag | Isi | Sumber data |
|---|---|---|
| `cyense tools workflows` | 10 framework + checkpoints; label "(ekspansi)" untuk 4 Cyense | `payload.workflows` |
| `cyense tools pivot <code> [--detail]` | "saya punya X" → tool penerima (operasional saja); `--detail` output + hop identifier berikutnya | `you_have` / `artefact_types` |
| `cyense tools training` | 20 resources metodologi (fase 7: +10 dari §3.3–3.4) | `payload.training` |
| `list --have --pricing --access --status` | facet penuh ala `/tools/search` (filter sisi klien — mengikuti pola CLI yang sudah ada: fetch satu payload) | payload |
| `info <name>` (diperkaya) | blok baru: *Cara kerja (asli — OSINT Radar)* dengan pivot `you have → you get`, baris **Verifikasi** (status + source), **RISK per tool** (ikon+alasan), **coverage**, **DIPAKAI DALAM WORKFLOW**, **PIVOT LANJUTAN** (artefak→identifier→penerima) | payload per-record |
| `stats` (diperkaya) | strip verifikasi Operational/Unverified/Flagged + jumlah workflows/training | derivasi payload (`_tools_stats`) |

**Bug lama ikut diperbaiki:** `render_tools_stats` diimpor tapi tidak pernah
didefinisikan → `cyense tools stats` crash dengan `ImportError`; kini
didefinisikan (+health strip). `info --json` sebelumnya membuang *seluruh
katalog* — kini hanya record tool (konsisten dengan view manusia).

**Kejujuran arsitektur:** CLI tidak memakai `/tools/search` (fetch penuh +
filter lokal = pola yang sama dipakai `--category/--query/--feature` sejak
awal); payload sudah tunggal. Validasi identifier pivot terjadi *sebelum*
jaringan (test: exit 1 offline untuk kode asing, exit 3 saat service mati).

## 2.5 Fase 7 — Keamanan & Privasi (reference content)

Dokumen analisis memuat §3.4 (keamanan/privasi, kepatuhan regulasi, kontrol
anti-penyalahgunaan) dan §3.3.6 (contoh kontrak deklaratif workflow dengan
blok `policy` hard-gate). Cyense tidak menjalankan konektor OSINT (tidak
punya account model) — tetapi data & prinsip §3.4/§3.3.6 adalah *reference
content* yang layak disajikan di UI (satu sumber = Website/Workflows dan =
CLI `tools safety`).

| Item dok | Implementasi di Cyense |
|---|---|
| §3.4.1 Prinsip data | 5 prinsip: TLS1.3/AES256=baseline bukan pencapaian; minimisasi + hapus di normalisasi; pihak ketiga insidental (kerabat/rekan) → JANGAN simpan, filter di pipeline; kunci di secret manager + rotasi; redaksi log otomatis |
| §3.4.2 Regulasi | 6 regulasi: GDPR (Pasal 9 biometrik), UU PDP 27/2022, CCPA/CPRA, FCRA (people-search ≠ CRA), BIPA, computer-misuse. + aturan lokasi operator-vs-subjek |
| §3.4.3 Kontrol organisasional | RBAC+sod; kasus wajib; log audit append-only; anomali (volume/offhours); gate keras: MENOLAK eksekusi SEBELUM; authorized-assets (tool offensif) |
| | **subject_is_minor = penolakan MUTLAK tanpa override** (kombinasi pengenalan wajah + geolokasi = sangat berbahaya untuk minor; tanpa pengecualian) |
| §3.3.6 Kontrak workflow | Contoh YAML `analyze-an-email` lengkap dengan blok policy + checkpoint (saran bila pengguna membangun executor sendiri) |

**Cyense bukan enforcement:** Cyense tidak menolak query (tidak punya
executor), tapi menyajikan daftar "penolakan wajib" + prinsip data + tabel
regulasi di panel **Etika & Privasi OSINT** dalam Workflows view + CLI
`cyense tools safety`.

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
   ├─ view=workflows   →  kartu 10 alur (6 asli + 4 ekspansi) → drawer: caution, steps → tool chips
   │                     (nama tak resolve tampil teks biasa), checkpoints, skala
   ├─ view=toolbench   →  Toolbench.svelte: 10 utilitas (7 asli + 3 ext), masing-masing + Tombol case
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
| Fase 4 — facet API | ✅ `pytest` baru: `have=email&pricing=Free` subset konsisten; `q=certificate transparency` relevan; `status=Flagged` == 2; halaman 1∩2 kosong & `matched` stabil; have/price tak dikenal → kosong, tanpa crash |
| Fase 4 — workflow 10 & extension flag | ✅ test slug eksak 6+4; `bool(extension)` == anggota 4 baru; semua referensi resolve |
| Fase 4 — JSON-LD | ✅ (headless) `CollectionPage` 24 item/684; buka drawer ⇒ `SoftwareApplication` (name 'whois'); tutup ⇒ kembali CollectionPage; parse JSON sukses |
| Fase 4 — Converter | ✅ node round-trip 9 vektor (termasuk 45,0; NYC; Sydney; London) maksimum error 0; UI: desimal→DMS/UTM ⇄ balik, junk ditolak |
| Fase 4 — risk/coverage | ✅ payload: Face Recognition=biometrik, Gobuster=offensif, InstaLooter=mati, USPS coverage 'AS'; ≥25 label; kartu+drawer badge terverifikasi headless |
| Fase 5 — Chronolocation (solar) | ✅ node: equinox Jakarta noon 83.96° (expect ≈83.8±1), NYC equinox sunrise/sunset azimuth 90.08/270.19 (≈±90/270±1.5), London solstice max elev 61.93 vs 61.94, solver elev=45 round-trip ≤0.01°, polar night = 0 crossing; UI: panel depan + rasio bayangan 2m/2m → 45.00° → 2 kandidat waktu UTC, regresi guard `isFinite(null)` terverifikasi (10 tool, tanpa console error) |
| Fase 5 — WARC integrity | ✅ node fixture 4 record: `ok`(sha1-hex) / `mismatch`(body dirusak) / `ok`(urn:sha1-base32) / `no-digest`; deteksi gzip eksplisit; UI panel + file input render (end-to-end `DataTransfer` terhalang origin browser — logika parser teruji di node) |
| Fase 5b — Graf SVG | ✅ headless: Email → SVG 1 type + 14 tool + 12 artefact + 26 edge; klik node tool ⇒ rebuild (3 input, 4 artefak); klik artefak ⇒ drill ke identifier awal dengan 27 node; 0 console error; fix Bug reaktif: `$: graph = buildGraph()` tak recompute saat focus berubah (dep tak terlacak sintaksis) ⇒ argumen eksplisit `buildGraph(focus, flatTools)` |
| Fase 6 — CLI parity | ✅ CLI 3 cmd baru (`workflows`, `pivot`, `training`); facet `list --have/--pricing/--access/--status`; info diperkaya (pivot asli, verif, risc per tool); stats health; fix `render_tools_stats` (sebelumnya ImportError crash) + `info --json` (sebelumnya 684-dump, kini hanya record tool); test baru CLI exit=1 utk bad identifier (tanpa service) |
| Fase 7 — Safety panel | ✅ 18 data item: 5 prinsip+6 regulasi+6 kontrol+4 refusal (subject_is_minor=MUTLAK); CLI `tools safety` headless exit=0; UI Workflows → SafetyPanel: 15 `.tool-card` (5+6+4), 6-row table, `details.safety-contract` + YAML block + copy btn, 0 console error |

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
