# PRD Fitur — Deteksi XSS pada Repository Hasil Fetch GitHub (XS001–XS008)

> **Feature PRD** | Versi 2.0 | Status: implemented
> **Parent PRD:** `instruction/PRD.md` (v2.0) — addendum, bukan pengganti
> **Fitur terkait:** `instruction/feature/github-repo-audit.md` (**jalur input utama** — fetch repo GitHub orang lain; fitur ini menambah *layer aturan* yang berjalan pada kode hasil fetch)
> **Nama fitur:** XSS Detection (XS001–XS008)
> **Lokasi implementasi:** `dev/main/app/program/xss_rules.py`, integrasi di `program_engine.py`

---

## 0. Ringkasan Satu Paragraf

Menambahkan **kelas aturan kedua** — **XSS (Cross-Site Scripting)** — ke mesin
analisis statis Cyense yang berjalan pada **kode hasil fetch repository GitHub**
(jalur utama). User menempel link repo orang lain → 🐙 Fetcher mengunduh tarball
ke sandbox → `program_engine` menjalankan **dua pass**: IDOR (CY001–CY010) dan
kini XSS (XS001–XS008) — tanpa mengubah pipeline, state machine, atau format
laporan. Nilai utamanya: satu tempel link repo menghasilkan **dua kelas temuan
sekaligus** dengan `file:line`, bukti cuplikan kode, remediasi spesifik per pola,
dan commit SHA reprodusibel — memperluas nilai audit satu permintaan tanpa biaya
integrasi tambahan. Mode `program` (kode lokal ekosistem sendiri) tetap didukung
sebagai jalur sekunder demi demo/testing dan parity, tetapi konteks produk utama
adalah repo hasil fetch remote.

---

## 1. Latar Belakang & Masalah

### 1.1 Kondisi saat ini

Mesin statis Cyense hanya mengenali pola **IDOR** (CY001–CY010). Padahal pada
repo front-end/back-end modern, kerentanan paling umum berikutnya adalah XSS:

| Sumber | Pola berbahaya yang lazim |
|--------|---------------------------|
| React/Next | `dangerouslySetInnerHTML={{ __html: userInput }}` |
| Vue | `<div v-html="userInput">` |
| Vanilla JS | `el.innerHTML = location.hash...`, `document.write(...)` |
| PHP | `echo $_GET['x'];` tanpa `htmlspecialchars` |
| Python/Jinja2 | `render_template_string(v)` / `Markup(v)` / `\|safe` |
| Umum | `eval(...)` pada data yang diawasi penyerang |

Audit manual atas pola-pola ini repetitif dan bentuknya sangat *deterministik*
— persis profil kerja yang cocok untuk mesin regex-guided Cyense (konsisten
keputusan no-LLM, PRD induk §1.2).

### 1.2 Mengapa cocok untuk arsitektur Cyense

- **Zero pipeline change**: mode `github` → sandbox → `program_engine` → report.
  XSS hanya *kumpulan aturan tambahan* yang dieksekusi pada file yang sama.
- **Parity terjaga**: hasil temuan struktur identik dengan IDOR (`Finding`,
  `location`, `remediation`), sehingga laporan, HTML builder, dan remediasi
  dapat langsung mengonsumsinya.
- **Perspektif pentester**: satu pass audit dua kelas kerentanan berbeda →
  nilai per permintaan naik signifikan tanpa biaya kompleksitas baru.

---

## 2. Goal & Non-Goal

### 2.1 Goals (MVP)

1. Delapan aturan XSS deterministik berbasis regex/AST-guided (XS001–XS008).
2. Integrasi ke `program_engine` via parameter `scan_types` — default
   `["idor", "xss"]` agar backward-compatible — sehingga **mode `github`
   (fetch repo GitHub orang lain) otomatis mendeteksi XSS** pada kode hasil
   fetch, tanpa konfigurasi tambahan.
3. `/rules` endpoint menampilkan kategori XSS.
4. Remediasi teks spesifik per aturan (bukan instruksi generik).
5. Test hermetik per aturan: fixture rentan → temuan; fixture bersih → nol.

### 2.2 Non-Goals (MVP)

- ❌ Data-flow/taint analysis penuh (melacak variabel lintas fungsi).
- ❌ XSS berbasis DOM pada bundle JS hasil build (hanya source yang dibaca).
- ❌ CSP bypass / mXSS / encoding- aware bypass — di luar cakupan regex MVP.
- ❌ Remediasi otomatis — dipisah ke `xss-remediation.md` (PRD terpisah;
  temuan XSS tetap punya teks remediasi sejak deteksi).

---

## 3. Matrix Aturan (rule → pola → remediasi)

| Rule | Pola | Bahasa/File | Severity | Remediasi singkat |
|------|------|-------------|----------|-------------------|
| **XS001** | `el.innerHTML = <expr>` (bukan string literal) | js/ts | High | Pakai `textContent`, atau sanitasi dengan DOMPurify sebelum assign |
| **XS002** | `document.write(<expr>)` | js/ts | High | Ganti dengan DOM API (`createElement`/`append`) atau sanitasi |
| **XS003** | `dangerouslySetInnerHTML={{__html: <expr>}}` | js/ts | High | Hapus property; render teks, atau sanitasi via DOMPurify |
| **XS004** | `eval(<expr>)` / `new Function(<expr>)` | js/ts | Critical | Eliminasi eval; pakai `JSON.parse`/peta fungsi |
| **XS005** | `v-html="<expr>"` | html/js (template) | High | Ganti interpolasi `{{ }}`; bila perlu HTML, sanitasi dulu |
| **XS006** | `echo/print $_GET/$_POST/$_REQUEST` tanpa `htmlspecialchars` | php | High | Bungkus output dengan `htmlspecialchars(..., ENT_QUOTES)` |
| **XS007** | `\|safe` pada template Jinja2 untuk data dinamis | py/html | High | Hapus filter `\|safe`; escape default Jinja cukup |
| **XS008** | f-string/`.format`/`%` yang menyusun HTML dengan variabel lalu di-render | py | Medium | Render via template engine (auto-escape), jangan string HTML manual |

**Aturan umum (anti false positive murah):**
- XS001/XS002/XS003 hanya menyala bila RHS **bukan string literal murni**
  (assign konstanta aman tidak dilaporkan).
- XS006 tidak menyala bila baris yang sama mengandung `htmlspecialchars`/
  `htmlentities`/`strip_tags` (sudah di-escape).
- XS008 hanya menyalah bila string memuat tag HTML (`<tag`) dan variabel
  interpolasi — string statis tidak dilaporkan.

---

## 4. Spesifikasi Fungsional

### 4.1 Input — tidak berubah

User cukup menempel **link repo GitHub orang lain** (`mode: "github"`) — tidak
ada field baru. Parameter `scan_types` tersedia di layer engine untuk seleksi
kategori; default-nya sudah `["idor", "xss"]` sehingga fetch repo = audit dua
kelas kerentanan sekaligus. Mode `program` (kode lokal ekosistem sendiri)
memakai request yang sama dan berperilaku identik — jalur sekunder untuk
demo/testing/parity.

### 4.2 Alur eksekusi (dalam satu scan mode github)

```
User tempel link repo ──► 🐙 Fetcher (resolve → tarball → sandbox)
                                   │
                                   ▼
program_engine.run_program_scan(lang, sandbox, scan_id,
                                scan_types=["idor","xss"])
  ├─ pass 1: IDOR rules  (CY001–CY010; python AST + js/php regex)
  └─ pass 2: XSS rules   (XS001–XS008 per tipe file)   ← NEW
        .js/.ts  → XS001–XS005
        .html    → XS005
        .py      → XS007, XS008
        .php     → XS006
```

Hasil kedua pass digabung ke daftar `findings` yang sama → report JSON/HTML
tetap satu format; temuan XSS tampil dengan rule `XS***` dan `location` berupa
path relatif root repo + baris.

### 4.3 Contoh — audit repo frontend orang lain

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"mode":"github","repo_url":"https://github.com/owner/frontend",
       "ref":"main","i_have_permission":true}'
# → 202 {scan_id} → laporan memuat campuran pada KODE HASIL FETCH:
#   {rule:"XS001", location:"src/Comment.tsx:42", severity:"high", ...}
#   {rule:"CY004", location:"api/invoices.py:18", severity:"high", ...}
#   meta.repo.commit_sha → bukti reprodusibilitas
```

---

## 5. Arsitektur & Integrasi

| Komponen | Lokasi | Perubahan |
|----------|--------|-----------|
| **XSS rules** | `app/program/xss_rules.py` (BARU) | pola regex + guard FP + analisis per tipe file |
| **Program engine** | `app/engines/program_engine.py` | tambah pass XSS; parameter `scan_types` |
| **Rules endpoint** | `app/api/system.py` | grup `"xss"` di `/rules` |
| **Tests** | `tests/test_xss_rules.py` (BARU) | unit per rule + integrasi engine |

**Tidak berubah:** mode `github` engine & fetcher, report builder, store,
state machine, worker (temuan mengalir lewat jalur yang sama).

---

## 6. Keamanan & Etika

- Sumber kode tetap dibaca **read-only** dari sandbox (reuse guard zip-bomb/
  traversal mode github). Tidak ada eksekusi kode repo yang dianalisis —
  aturan bekerja murni via *parsing teks*.
- Gate `i_have_permission` dan redaksi kredensial berlaku apa adanya.

---

## 7. Pengujian (hermetik)

1. **Per rule (positif)**: fixture rentan XS001–XS008 → tepat satu temuan per
   fixture dengan rule/line yang benar.
2. **Per rule (negatif)**: variasi aman (string literal, `textContent`,
   `htmlspecialchars`, template escape) → nol temuan.
3. **Integrasi engine**: direktori campuran py/js/php → IDOR dan XSS sama-sama
   dilaporkan; `scan_types=["idor"]` → XSS tidak muncul (backward compatible).
4. **Distribusi per tipe file**: `.py` hanya XS007/8, `.js` XS001–5, dst.
5. **Suite penuh**: semua test lama tetap hijau (parity terjaga).

---

## 8. Kriteria Sukses (Acceptance Criteria)

1. ✅ Scan sample repo dengan pola XSS JS/Python/PHP → XS001–XS008 terdeteksi.
2. ✅ Kode aman (sudah di-escape/literal) → nol temuan (guard FP bekerja).
3. ✅ `/rules` menampilkan grup `xss` dengan 8 aturan.
4. ✅ Temuan XSS berformat identik dengan IDOR (report/HTML langsung kompatibel).
5. ✅ Mode `github` mock-end-to-end menghasilkan temuan XSS dari tarball sandbox.
6. ✅ Semua test lama tetap lulus (tidak ada regresi).

---

## 9. Risiko & Mitigasi

| Risiko | Dampak | Mitigasi |
|--------|--------|----------|
| False positive regex pada kode umum | Triage waktu terbuang | Guard literal/escape per rule; confidence 0.6; severity proporsional |
| False negative pola terobfuscasi | Temuan terlewat | Diposisikan eksplisit sebagai *heuristik MVP*; taint analysis di backlog |
| File HTML raksasa (bundle) | Scan lambat | Reuse pengabaian `dist/build/node_modules` yang sudah ada di engine |

---

## 10. Roadmap Implementasi

| Fase | Isi | Estimasi |
|------|-----|----------|
| 1 | `xss_rules.py` XS001–XS008 + guard FP | 0.5 hari |
| 2 | Integrasi `program_engine` (`scan_types`) | 0.25 hari |
| 3 | `/rules` endpoint + test hermetik | 0.25 hari |

---

## 11. Changelog Fitur

| Versi | Perubahan |
|-------|-----------|
| 1.0 | Draft awal: 8 aturan XSS deterministik, pass kedua pada mesin statis, guard FP, test hermetik |
| 2.0 | **Penyelarasan fokus produk**: konteks utama = kode hasil fetch repo GitHub orang lain (jalur utama per `github-repo-audit.md` v2.0); mode program lokal diturunkan jadi jalur sekunder; non-goal remediasi dirujuk ke PRD `xss-remediation.md`; contoh diperjelas sebagai audit repo remote |

---

*Addendum ini tunduk pada PRD induk (`instruction/PRD.md`). Konflik: PRD induk
menang untuk hal yang tidak diatur di sini. Fitur memperluas cakupan *aturan*,
bukan arsitektur.*
