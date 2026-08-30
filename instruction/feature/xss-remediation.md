# PRD Fitur — Remediasi XSS (Auto-Fix untuk Semua Jenis Temuan XSS)

> **Feature PRD** | Versi 1.0 | Status: draft untuk direview
> **Parent PRD:** `instruction/PRD.md` (v2.0) — addendum, bukan pengganti
> **Fitur terkait:**
> · `instruction/feature/idor-remediation.md` — infrastruktur 🔧 Fixer (store, applier, verify loop, API `/fixes`) yang **dipakai ulang**; PRD itu mencantumkan remediasi XSS sebagai backlog — dokumen ini mengisinya
> · `instruction/feature/xss-detection.md` — sumber temuan `XS001`–`XS008`
> **Nama fitur:** XSS Remediation (semua jenis XSS)
> **Lokasi implementasi (rencana):** `dev/main/app/remediation/xss_strategies.py`, registrasi di `fixer.py`

---

## 0. Ringkasan Satu Paragraf

Memperluas agent 🔧 **Fixer** agar mampu mengusulkan perbaikan deterministik untuk
**seluruh delapan jenis temuan XSS** (`XS001`–`XS008`) yang dihasilkan mode
`program`/`github`. Prinsipnya identik dengan remediasi IDOR: *dry-run by default*
(proposal diff, tanpa tulis), *patch hanya via approval* (`confirm: true`), *backup
wajib + revert*, dan *verify loop* — setelah patch, file di-scan ulang oleh
`xss_rules` dan status `verified` hanya diberikan bila temuan rule tersebut **hilang**
dari hasil re-scan. Tidak ada LLM; setiap strategi adalah transformasi kode
yang shape-nya diketahui; bila konteks tidak memadai (mis. `eval` yang butuh keputusan
semantik), sistem menandai `manual_required` dengan saran — **tidak pernah menebak**.

---

## 1. Latar Belakang & Masalah

### 1.1 Kondisi saat ini

Deteksi XSS sudah berjalan (8 aturan, guard false-positive teruji), tetapi temuan
XSS berhenti di laporan. Sementara itu infrastruktur remediasi IDOR sudah matang:
`FixStore`, applier (backup `*.bak-cyense` + revert byte-identik + same-origin
guard), verify loop re-scan, API `/fixes`, dan trajectory logging — semuanya
*generic terhadap jenis temuan* dan belum menyentuh XSS.

**Kesenjangan:** `FixerAgent` hanya memiliki registry strategi IDOR
(`CY001`–`CY010`). Temuan rule `XS***` jatuh ke jalur `manual_required` generik
tanpa diff yang bisa ditinjau. Padahal sebagian besar pola XSS punya transformasi
aman yang **deterministik**:

| Pola | Transformasi aman yang diketahui |
|------|----------------------------------|
| `el.innerHTML = x` | `el.textContent = x` (render teks) — atau bungkus `DOMPurify.sanitize(x)` bila HTML disengaja |
| `document.write(x)` | tulis via `textContent` pada elemen target |
| `__html: x` (React) | `__html: DOMPurify.sanitize(x)` |
| `v-html="x"` | interpolasi `{{ }}` atau sanitasi terlebih dulu |
| `echo $_GET[k]` (PHP) | `echo htmlspecialchars($_GET[k], ENT_QUOTES)` |
| `x\|safe` (Jinja) | hapus `\|safe` → auto-escape default kembali |
| `eval(x)` | ⚠️ **tidak ada transformasi aman umum** — butuh keputusan semantik |
| f-string HTML | ⚠️ butuh keputusan arsitektur template — saran saja |

### 1.2 Mengapa ini cocok untuk Cyense

- **Infrastruktur 100% reuse** — hanya menambah fungsi strategi per rule ke
  registry yang sudah ada; store/applier/verify/API tidak berubah.
- **Konsisten no-LLM** — semua patch adalah substitusi yang dapat diuji ulang
  secara objektif oleh mesin deteksi yang sama (verify loop).
- **Menutup lingkaran keamanan dua kelas kerentanan** — satu laporan kini bisa
  diakhiri "terverifikasi diperbaiki" untuk IDOR *dan* XSS.

### 1.3 Persona & user story

| Persona | Story |
|---------|-------|
| **Developer** (Budi) | "Repo saya punya 15 temuan XSS; saya tinjau diff, approve 12 yang mekanis, dan re-scan membuktikan keduabelas hilang; 3 sisanya (`eval`) saya tangani manual dengan sarannya." |
| **Maintainer OSS** | "CI menandai temuan XSS baru dan melampirkan proposal patch siap-review sebagai output dry-run." |
| **Pentester** (Andi) | "Laporan klien tidak berhenti di 'rentan' — saya sertakan diff perbaikan yang bisa tim mereka terapkan." |

---

## 2. Goal & Non-Goal

### 2.1 Goals (MVP)

1. **Registry strategi XSS** untuk `XS001`–`XS008` yang terhubung ke
   `FixerAgent` melalui mekanisme yang sama dengan IDOR.
2. Enam strategi auto-patch (XS001–XS003, XS005–XS007) + dua `manual_required`
   berkualitas (XS004, XS008) dengan saran konkret di field `notes`.
3. **Verify loop XSS**: re-scan file dengan `xss_rules` setelah apply;
   `verified` ⇔ temuan rule pada baris target hilang **dan** tidak ada temuan
   XSS *baru* yang muncul akibat patch.
4. Integrasi report: badge `FIXED` juga berlaku untuk temuan XSS.
5. Test hermetik penuh (positif, negatif, guard, revert, verify, API gate).

### 2.2 Non-Goals (MVP)

- ❌ Auto-patch `eval`/`new Function` (XS004) — transformasi yang aman
      memerlukan pemahaman semantik payload; selalu `manual_required`.
- ❌ Auto-patch komposisi HTML f-string (XS008) — pilihan mekanisme render
      (Jinja/template engine) adalah keputusan arsitektur; diberi saran, bukan
      patch.
- ❌ Validasi sintaks JS penuh (tidak ada parser JS dalam dependensi MVP) —
      dikompensasi dengan (a) patch berupa substitusi baris-tunggal terpetakan,
      (b) verify loop regex, (c) revert otomatis bila temuan tidak hilang.
- ❌ DOM-taint analysis, CSP bypass, mXSS (tetap non-goal deteksi juga).

---

## 3. Fix Matrix — Strategi per Jenis XSS

| Rule | Strategi patch (deterministik) | Transformasi | Risk | Auto? |
|------|--------------------------------|--------------|------|-------|
| **XS001** | **textContent-first**: bila nilai tidak tampak ditujukan sbg HTML → `el.innerHTML = x` → `el.textContent = x`; bila baris mengandung penanda HTML-ish (mis. `"<"`, `.html`, `html` di nama variabel) → `el.innerHTML = DOMPurify.sanitize(x)` + komentar `// cyense: fix XS001` | substitusi RHS / LHS | medium | ✅ |
| **XS002** | `document.write(x)` → buat komentar pengganti + saran DOM API: patch aman umum tidak ada tanpa konteks target-node → **saran di notes**, tandai `manual_required` bila tidak ada `document.getElementById/querySelector` di file; bila ada → `el.textContent = x` pada elemen pertama yang terdeteksi | substitusi | medium | ⚠️ kondisional |
| **XS003** | `__html: x` → `__html: DOMPurify.sanitize(x)` (satu baris, idempoten — guard: lewati bila `DOMPurify` sudah ada di baris) | bungkus ekspresi | low | ✅ |
| **XS004** | Tidak pernah auto-patch → `manual_required` + notes: "eliminasi eval — gunakan JSON.parse untuk data, atau map fungsi yang diizinkan" | — | high | ❌ |
| **XS005** | `v-html="x"` → `{{ x }}` bila `x` tampak teks (tanpa indikator HTML), selain itu `v-html="sanitized(x)"` + definisi helper satu baris di notes; guard: lewati bila baris sudah memanggil sanitasi | substitusi atribut | medium | ✅ |
| **XS006** | `echo $_GET[k];` → `echo htmlspecialchars($_GET[k], ENT_QUOTES);` (idempoten; guard existing `htmlspecialchars/htmlentities/strip_tags` dari deteksi tetap berlaku) | bungkus | low | ✅ |
| **XS007** | `x\|safe` → `x` (hapus filter; auto-escape Jinja kembali) — idempoten, guard: komentar di-skip oleh deteksi | hapus token | low | ✅ |
| **XS008** | `manual_required` + notes konkret: "render via template engine: pindahkan html ke template, kirim variabel terpisah, biarkan auto-escape" | — | medium | ❌ |

**Aturan umum (diwarisi PRD remediasi IDOR §3.1):**
- Patch yang tidak dapat dibuktikan aman **tidak diusulkan** — selalu ada
  `manual_required` + alasan.
- Semua patch menyertakan komentar jejak `// cyense: fix XS00x` /
  `# cyense: fix XS00x` / `<!-- cyense: fix XS00x -->` sesuai bahasa.
- Idempotensi: strategi harus no-op pada kode yang sudah mengandung hasil
  patch (dicek sebelum mengusulkan → status `already_secured`).

---

## 4. Spesifikasi Fungsional

### 4.1 Alur (identik dengan remediasi IDOR — hanya sumber temuan beda)

```
POST /api/v1/scans/{scan_id}/fixes            ← tidak berubah; temuan XS***
     │                                          ikut masuk batch proposal
     ▼
FixerAgent: untuk tiap Finding rule XS***:
     registry["XS001".."XS008"] → strategy(finding, source, tree=None)
     → FixProposal{diff, before/after, risk, strategy, notes}
GET  /fixes/{session}/diff                    ← unified diff gabungan (JS+PHP+PY)
POST /fixes/{session}/apply {confirm:true}    ← backup → patch → VERIFY
POST /fixes/{session}/revert                  ← byte-identik restore
```

### 4.2 Verify loop XSS (§2.1.3)

```
apply(fix_id)
  ├─ backup file → file.bak-cyense
  ├─ tulis patch (substitusi baris terpetakan)
  ├─ re-scan file via xss_rules (semua pola XS***)
  ├─ rule target hilang DI BARIS TARGET?
  │     ├─ ya & tanpa temuan XSS baru → FixProposal.verified ✓
  │     ├─ ya tapi muncul temuan XS baru di baris lain → evaluated:
  │     │     temuan baru bukan akibat patch (baru ditemukan)? tetap verified,
  │     │     dicatat di notes; temuan pada baris patch → REVERT + failed
  │     └─ tidak → REVERT otomatis + failed + notes alasan
  └─ simpan bukti (before/after count) di verification
```

### 4.3 Contoh perbaikan yang diharapkan

```diff
# XS006 (php)
- echo $_GET["message"];
+ echo htmlspecialchars($_GET["message"], ENT_QUOTES); // cyense: fix XS006

# XS001 (js, teks)
- el.innerHTML = window.location.hash.slice(1); // cyense: fix XS001
+ el.textContent = window.location.hash.slice(1);

# XS003 (react)
- <C dangerouslySetInnerHTML={{__html: html}} />
+ <C dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} /> // cyense: fix XS003

# XS007 (jinja)
- return render(request, {"body": html|safe})
+ return render(request, {"body": html})   # cyense: fix XS007
```

---

## 5. Arsitektur & Integrasi

| Komponen | Lokasi | Perubahan |
|----------|--------|-----------|
| **XSS strategies** | `app/remediation/xss_strategies.py` (BARU) | 8 fungsi murni `(finding, source) → dict`, satu per rule |
| **Registry** | `app/remediation/fixer.py` | `_load_strategies()` menambah XSS; tree arg diabaikan utk non-Python (sudah didukung) |
| **Verify** | `app/remediation/applier.py` | `verify_after_apply` menerima runner `xss_rules` utk file `.js/.php/.html` (saat ini hanya python path) |
| **Guard baris** | `xss_rules` (deteksi) | dipakai ulang apa adanya sebagai sumber verify |
| **Tests** | `tests/test_xss_remediation.py` (BARU) | per-strategy + verify + revert + API |

**Tidak berubah:** FixStore, API `/fixes`, backup/revert, same-origin guard,
mode scan manapun, report builder (badge `FIXED` sudah generic).

---

## 6. Keamanan & Etika (diwarisi penuh)

1. Dry-run default; tulis hanya `/apply` + `confirm: true` (422 tanpa itu).
2. Backup wajib sebelum tulis; revert selalu tersedia & teruji.
3. Same-origin: hanya file di bawah source root scan (reuse `is_same_origin`).
4. Tanpa auto-commit git / tanpa push; diff siap-paste ke PR.
5. Klaim `verified` hanya setelah re-scan membuktikan (bukti, bukan asumsi).
6. Kredensial tetap redacted di semua output/trajectory.

---

## 7. Pengujian (hermetik)

1. **Per strategy (positif)** — fixture XS001–XS008 → diff persis seperti
   matrix §3 (termasuk komentar jejak dan idempotensi kedua).
2. **Negative / guard** — kode sudah aman → `already_secured`/no-op; XS004 &
   XS008 → `manual_required` dengan notes konkret.
3. **Verify loop** — apply XS006 pada fixture PHP → re-scan → verified;
   patch tiruan yang menyisakan sink → auto-revert + failed.
4. **Revert** — sha256 sebelum/sesudah revert identik.
5. **Same-origin & approval gate** — patch di luar root → 422; apply tanpa
   `confirm` → 422 dan file utuh.
6. **Integrasi API** — scan sample (IDOR+XSS campur) → satu session berisi
   proposal dua kategori; apply subset; report `fix_status: verified`.
7. **Trajectory** — `fixer.json` mencatat step per proposal XSS.

---

## 8. Kriteria Sukses (Acceptance Criteria)

1. ✅ Proposal untuk ≥ 6/8 rule XSS berisi diff konkret; XS004 & XS008
   `manual_required` dengan saran konkret (bukan patch salah).
2. ✅ Apply XS006/XS007/XS003 → verified; re-scan file menunjukkan 0 temuan
   rule target.
3. ✅ Idempotensi: menjalankan strategy pada file hasil patch →
   `already_secured`, tanpa diff baru.
4. ✅ Semua safety gate PRD remediasi IDOR berlaku identik untuk XSS.
5. ✅ Satu session bisa memuat proposal campuran IDOR + XSS dan apply-nya
   bersama (report badge konsisten).
6. ✅ Suite penuh hijau (semua test lama + baru), ruff 0 error.

---

## 9. Risiko & Mitigasi

| Risiko | Dampak | Mitigasi |
|--------|--------|----------|
| Patch JS merusak sintaks | File broken | substitusi baris-tunggal terpetakan; verify regex; revert otomatis; (parser JS di backlog) |
| `textContent` mengubah render HTML yang disengaja | Regresi UX | pilihan sanitize (bukan textContent) bila indikator HTML di baris; diff selalu direview manusia |
| DOMPurify belum terpasang di repo target | Patch mereferensi dependensi | notes eksplisit "install DOMPurify" pada proposal; badge risk medium |
| Salah posisi `document.write` | Patch salah target | kondisional §3 — fallback `manual_required` |
| Stale finding (file berubah) | Patch di baris salah | re-match rule pada baris target sebelum usul (pola IDOR) |

---

## 10. Roadmap Implementasi

| Fase | Isi | Estimasi |
|------|-----|----------|
| 1 | `xss_strategies.py` XS001–XS008 + unit tests (positif/negatif/idempoten) | 0.5 hari |
| 2 | Registrasi ke FixerAgent + verify runner utk js/php/html | 0.5 hari |
| 3 | Integrasi API end-to-end + report badge + trajectory | 0.25 hari |
| 4 | E2E hermetik campuran IDOR+XSS dalam satu session | 0.25 hari |
| Lanjutan | Parser JS ringan utk verify sintaks, auto-fix XS004 bila pattern JSON.parse teridentifikasi | backlog |

---

## 11. Open Questions

1. Helper sanitasi untuk XS005: inline `sanitized(x)` vs menyarankan computed
   property Vue? → Proposal: inline + notes, biarkan developer memindahkan.
2. Apakah XS001 textContent perlu opt-out via flag? → Proposal: tidak —
   reviewer tinggal reject proposal itu; diff selalu eksplisit.
3. Simpan preferensi strategi per-repo di Brain (mis. repo X selalu pilih
   sanitize over textContent)? → Backlog, setelah pola pemakaian terlihat.

---

## 12. Changelog Fitur

| Versi | Perubahan |
|-------|-----------|
| 1.0 | Draft awal: strategi remediasi untuk semua jenis XSS (XS001–XS008), 6 auto-patch + 2 manual_required berkualitas, verify loop berbasis re-scan xss_rules, integrasi penuh infrastruktur Fixer IDOR |

---

*Addendum ini tunduk pada PRD induk (`instruction/PRD.md`) dan melengkapi
`idor-remediation.md` (infrastruktur bersama). Nilai yang dilindungi:*
**read-only until approved · deterministic patches · evidence-based claims ·
never guess what cannot be proven safe.**
