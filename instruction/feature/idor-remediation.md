# PRD Fitur — Remediasi IDOR (Auto-Fix Berbasis Hasil Analisa)

> **Feature PRD** | Versi 2.0 | Status: draft untuk direview
> **Parent PRD:** `instruction/PRD.md` (v2.0) — addendum, bukan pengganti
> **Fitur terkait:** `instruction/feature/github-repo-audit.md` — **jalur input utama**:
> temuan yang diremediasi umumnya berasal dari **fetch repo GitHub orang lain**
> (sandbox `reports/<scan_id>/src/`); mode `program` (kode lokal) adalah sumber
> sekunder; mode `link` tidak di-patch (server jarak jauh)
> **Nama fitur:** IDOR Remediation (patch & verify)
> **Lokasi implementasi (rencana):** `dev/main/app/remediation/`, agent baru **🔧 Fixer**

---

## 0. Ringkasan Satu Paragraf

Menambahkan lapisan **remediasi** di atas laporan scan: dari daftar temuan IDOR
(`Finding[]` dengan `location`, `rule`, `severity`), Cyense menghasilkan **patch
kandidat deterministik** per rule (CY001–CY010) — tanpa LLM — ditampilkan sebagai
**diff sebelum/sesudah**, diuji ulang dengan **re-scan otomatis** untuk membuktikan
temuan hilang, dan **hanya ditulis ke file setelah approval eksplisit** user
(human-in-the-loop). Nilai utamanya: developer tidak hanya tahu *di mana* masalahnya,
tetapi mendapat *perbaikan yang bisa dibuktikan aman* — memangkas waktu triase
temuan → fix dari hitungan jam ke menit.

---

## 1. Latar Belakang & Masalah

### 1.1 Kondisi saat ini

Cyense berhenti di *deteksi*. Tiap `Finding` sudah membawa:

- `location` → `"app/api/invoices.py:42"` (mode program/github) atau URL (mode link)
- `rule` → `CY001`–`CY010` (pola yang persis diketahui)
- `remediation` → **teks instruksi manusia** (mis. "Scope the lookup by the
  authenticated user") — benar, tapi tetap manual

**Bottleneck berikutnya:** developer membaca instruksi itu, lalu tetap harus
menulis perubahan sendiri untuk *setiap temuan*. Pada repo besar (mis. hasil
github-audit dengan 40+ temuan), itu repetitif — dan polanya *deterministik*
per rule: `CY001` selalu "tambahkan filter ownership ke kw lookup", `CY006`
selalu "ganti path f-string dengan lookup allow-list".

### 1.2 Mengapa ini cocok (dan aman) untuk Cyense

- **Polanya deterministik** — remediasi di sini adalah *transformasi kode yang
  diketahui shapenya*, bukan penalaran bebas. Itu membuatnya bisa dilakukan
  tanpa LLM (konsisten keputusan desain PRD induk §1.2) dan **dapat diverifikasi
  secara objektif** (re-scan harus kosong).
- **Keamanan adalah prinsip, bukan opsi**: Cyense sampai hari ini 100% read-only.
  Fitur ini tidak memecahnya — writing hanya terjadi di jalur yang dipisahkan
  dengan **approval + backup + revert** (§6), dan *default-nya adalah dry-run*.
- **Menutup lingkaran agentic**: pipeline sekarang punya **🔧 Fixer** sebagai
  agent dengan kapabilitas *verification* (patch → re-scan → bukti), melengkapi
  Brain (memory), Recon/Prober (tools), Verifier (verification).

### 1.3 Persona & user story

| Persona | Story baru |
|---------|-----------|
| **Developer** (Budi) | "Saya scan repo, klik *propose fixes*, tinjau diff per temuan, approve yang masuk akal, dan code saya di-patch + dibuktikan bebas temuan via re-scan." |
| **Pentester** (Andi) | "Saya serahkan patch kandidat ke klien sebagai rekomendasi konkret — diff siap review, bukan paragraf instruksi." |
| **Maintainer OSS** | "Saya jalankan dry-run di CI: build gagal kalau ada temuan baru tanpa patch yang bisa diusulkan." |

---

## 2. Goal & Non-Goal

### 2.1 Goals (MVP)

1. `POST /api/v1/scan/{scan_id}/fixes` → daftar **proposals** per temuan:
   `{fix_id, rule, target_file, line, patch_preview (diff), risk, reversible}`.
2. **Fixer agent** menghasilkan patch via transformasi AST/line-based
   deterministik per rule (library: `ast` builtin + `libcst`-free pendekatan
   sederhana; lihat §4).
3. **Apply** hanya via `POST /api/v1/fixes/{fix_id}/apply` dengan body
   `{"confirm": true}` + backup otomatis (`*.bak-cyense`) + **re-scan verify**.
4. **Verify loop**: setelah apply, engine menjalankan scan ulang pada file
   ter-remediasi; temuan yang hilang → proposal tercatat `verified`; masih ada →
   `needs_manual_review` + patch dibatalkan otomatis (revert).
5. Batch mode: apply banyak proposal sekaligus dengan pratinjau gabungan.
6. Semua aksi tercatat di trajectory `fixer.json` (deliverable #4).

### 2.2 Non-Goals (MVP)

- ❌ **Tidak pernah menulis tanpa approval** — tidak ada auto-commit ke git,
  tidak ada push ke GitHub, tidak ada patch saat `apply` tanpa `confirm: true`.
- ❌ LLM untuk menulis patch (deterministik saja — konsisten no-LLM).
- ❌ Remediasi mode `link` (server jarak jauh tidak bisa di-patch); mode link
  hanya mendapat *sarana verifikasi ulang*, bukan patch.
- ❌ Refactoring besar (ubah arsitektur auth) — MVP hanya patch *lokal* per
  temuan, lingkup satu fungsi/file.
- ❌ Format non-code (mengedit DB, konfigurasi infrastruktur).

---

## 3. Spesifikasi Fungsional

### 3.1 Fix Matrix (rule → strategi patch)

| Rule | Pola temuan | Strategi patch (deterministik) | Risk |
|------|-------------|-------------------------------|------|
| `CY001` | `Model.objects.get(id=req.X)` tanpa scope | Tambah kw `user_id=<current_user>` atau bungkus dengan cek `obj.owner == request.user` (deteksi variabel user di lingkup fungsi: `request.user`, `current_user`) | low |
| `CY002` | `Model.objects.filter(...).first()` | Sama dengan CY001, pada argumen `filter()` | low |
| `CY003` | Flask route `<int:id>` → query | Sama; jika tidak ada user visible di scope → patch berupa `abort(403)` guard + TODO | medium |
| `CY004` | FastAPI path param → ORM get | Sama dengan CY001; tambah param `current_user: User = Depends(get_current_user)` bila tidak ada | medium |
| `CY005` | `get_object_or_404` tanpa user | Tambah `user=request.user` ke kwargs | low |
| `CY006` | `open(f"/uploads/{req.param}")` | Ganti dengan **allow-list lookup**: `UPLOADS = {..}` dict + `UPLOADS.get(name)` | medium |
| `CY007` | JS `findOne({_id: req.params.id})` | Tambah `userId: req.user.id` ke objek query (regex-based, hanya bila `req.user` ada di file) | low |
| `CY008` | JS `findById(req.params.id)` | Sisipkan cek `.owner` setelah fetch (guard `if (!doc || doc.owner !== req.user.id) return res.sendStatus(404)`) | medium |
| `CY009` | PHP `->where('id', $_GET[..])` | Tambah `->where('user_id', $currentUserId)` bila variabel user terdeteksi | low |
| `CY010` | PHP `Model::find($_GET[..])` | Guard setelah fetch + `abort/404` | medium |
| `IDOR-LINK` | temuan dynamic (URL) | **Tidak dipatch** — hanya dijadikan daftar titik untuk verifikasi ulang via mode link | n/a |

**Aturan umum:**
- Patch yang *tidak bisa dibuktikan aman* (mis. tidak ada variabel user di
  scope, AST tidak bisa di-parse) **tidak diusulkan** → temuan ditandai
  `manual_required` dengan alasan. Cyense **tidak pernah menebak**.
- Semua patch menambah komentar `# cyense: fix <rule>` untuk traceability.

### 3.2 API (`/api/v1`)

| Method | Path | Deskripsi |
|--------|------|-----------|
| POST | `/scans/{id}/fixes` | Generate proposals (dry-run, **tidak menulis**) → `202 {fix_session_id, proposals[]}` |
| GET | `/fixes/{session_id}` | Daftar proposal + status (`proposed\|applied\|verified\|reverted\|rejected`) |
| GET | `/fixes/{session_id}/diff` | Diff gabungan (unified diff, siap paste ke PR) |
| POST | `/fixes/{session_id}/apply` | Body `{"fix_ids": [...], "confirm": true}` → apply + backup + re-scan verify |
| POST | `/fixes/{session_id}/revert` | Restore dari backup `.bak-cyense` (selalu tersedia) |

**State machine proposal:** `proposed → applied → verified | reverted`
dan `proposed → rejected (oleh user, tanpa tulis)`.

### 3.3 Contoh alur end-to-end

```bash
# 1. dari scan yang ada, minta proposals (dry-run)
curl -X POST localhost:8000/api/v1/scans/<scan_id>/fixes
# → 202 {"fix_session_id": "fs1a2b", "proposals": [
#   {"fix_id":"fx01","rule":"CY001","risk":"low",
#    "patch_preview":"- inv = Invoice.objects.get(id=request.GET['id'])\n
#                     + inv = Invoice.objects.get(id=request.GET['id'], user_id=request.user.id)",...}
# ]}

# 2. tinjau diff gabungan
curl localhost:8000/api/v1/fixes/fs1a2b/diff

# 3. apply subset + verify otomatis
curl -X POST localhost:8000/api/v1/fixes/fs1a2b/apply \
  -H 'Content-Type: application/json' \
  -d '{"fix_ids":["fx01","fx02"],"confirm":true}'
# → {"applied":["fx01"],"verified":["fx01"],"failed":[],
#    "rescan":{"total":0}}   ← temuan hilang = bukti
```

### 3.4 Perubahan report (penanda remediasi)

`Finding` mendapat field opsional `fix_status: null | "proposed" | "applied" |
"verified"`, dan report HTML menambah badge `FIXED` pada temuan terverifikasi —
sehingga laporan akhir bisa *ditandatangani* dengan bukti re-scan.

---

## 4. Teknik Patching (tanpa LLM, dua tingkat presisi)

### 4.1 Tingkat 1 — AST-guided, line-surgical (utama)

1. Parse file → `ast` (sudah dipakai rules; zero-dep).
2. Temukan node target dari `Finding.location` (file:line) — cocokkan ulang
   rule yang sama di baris itu sehingga patch **selalu berbasis temuan yang
   masih valid** (bukan baris basi dari scan lama).
3. Rekonstruksi statement dengan `ast.unparse()` + modifikasi kw/args
   (mis. tambah `user_id=request.user.id`).
4. Simpan hanya *rentang baris node* yang berubah → diff minimal.

### 4.2 Tingkat 2 — Line-based (fallback utk JS/PHP yang regex-based)

1. Baca file, terapkan substitusi regex rule yang sama (dari
   `program/regex_rules.py`) pada baris target.
2. Insert guard multi-baris bila strategi mengharuskan (CY008/CY010).

### 4.3 Verify loop (bukti keamanan)

```
apply(fix_ids, confirm=true)
  ├─ backup file → file.bak-cyense
  ├─ tulis patch
  ├─ re-scan file (AST/regex, engine yang sama)
  ├─ temuan di file hilang? → verified ✓
  ├─ temuan masih ada / file rusak (syntax error)? → REVERT otomatis + failed
  └─ simpan hasil rescan sebagai bukti di report
```

Re-scan setelah patch adalah **verifikasi objektif** — pola yang sama dengan
filosofi kontrol-ID pada mode link: jangan percaya patch, *buktikan*.

---

## 5. Arsitektur & Integrasi

| Komponen | Lokasi | Peran |
|----------|--------|-------|
| 🔧 **FixerAgent** | `app/remediation/fixer.py` | kumpulkan temuan → proposals; trajectory sendiri |
| **Fix strategies** | `app/remediation/strategies.py` | registry `{rule_id: strategy_fn}` — satu fungsi murni per rule |
| **Patch applier** | `app/remediation/apply.py` | backup, tulis, revert (semua I/O file terpusat di sini — audit mudah) |
| **Rescan verifier** | `app/remediation/verify.py` | panggil `program_engine.run_program_scan` pada 1 file/dir |
| **FixStore** | `app/core/fix_store.py` | in-memory + JSON dump (pola sama dengan JobStore) |
| API | `app/api/fixes.py` | router baru, dipasang di `main.py` |
| Model | `app/core/models.py` | `FixProposal`, `FixSession`, `FixStatus` |
| Report | `app/report/html_report.py` | badge `FIXED` / `PATCH PROPOSED` |

**Tidak berubah:** rules deteksi, mode link/github, state machine scan, store
scan. Fitur ini *ortogonal* dan hanya konsumen laporan.

---

## 6. Keamanan & Etika (wajib — prinsip read-only dilindungi)

1. **Dry-run by default.** Tidak ada endpoint yang menulis file kecuali
   `/apply` dengan `confirm: true` eksplisit (bukan default).
2. **Backup wajib sebelum tulis** (`<file>.bak-cyense`); `/revert` selalu
   tersedia dan diuji.
3. **Sandbox same-origin**: hanya file di bawah source root milik scan yang
   boleh dipatch — untuk **jalur utama (mode github): sandbox
   `reports/<id>/src/`** berisi salinan repo hasil fetch; untuk jalur
   sekunder (mode program): scope `/workspace` — path traversal ditolak
   (guard `Path.resolve().is_relative_to(root)`).
4. **No-auto-commit, no-push — khususnya pada repo milik orang lain.**
   Cyense tidak pernah menjalankan `git commit`/push dan tidak pernah
   menulis apa pun ke GitHub. Patch pada kode hasil fetch diterapkan pada
   **salinan sandbox milik sistem**; output untuk user adalah **diff
   (`/fixes/{id}/diff`) siap-paste ke PR/clone miliknya sendiri** — repo
   asli pemilik tidak pernah disentuh.
5. **Re-scan sebelum klaim**: proposal hanya berstatus `verified` setelah
   re-scan membuktikan temuan hilang. Tidak ada klaim tanpa bukti (ground
   rule kompetisi).
6. **Path encoding**: semua target path tervalidasi absolut + relatif ke
   source root, anti-symlink (reuse guard `sandbox.py`).

---

## 7. Pengujian (hermetik)

1. **Unit per strategy** — input: cuplikan kode rentan (fixture per rule
   CY001–CY010) → output patch → assert diff persis seperti yang diharapkan.
2. **Unit negative** — kode tanpa variabel user di scope → `manual_required`,
   bukan patch andalan.
3. **Unit applier** — backup dibuat, file berubah, revert mengembalikan
   byte-identik (hash compare).
4. **Verify loop** — apply pada fixture → re-scan → `verified`; simulasi patch
   merusak (inject syntax error via strategy tiruan) → auto-revert + `failed`.
5. **Same-origin guard** — usulkan patch di luar source root → ditolak 422.
6. **API** — alur penuh: scan fixture → fixes → diff → apply+confirm → report
   berisi `fix_status: verified`, temuan = 0.
7. **Approval gate** — `/apply` tanpa `confirm: true` → 422, file tidak berubah.
8. **Trajectory** — `fixer.json` terekam dengan step per proposal.

---

## 8. Kriteria Sukses (Acceptance Criteria)

1. ✅ `POST /scans/{id}/fixes` pada fixture vulnerable (CY001–CY006) → proposals
   untuk ≥ 5/6 rule; tanpa penulisan file (byte-identik sebelum/sesudah).
2. ✅ `/apply` dengan `confirm: true` + subset `fix_ids` → file ter-patch,
   backup ada, re-scan menghasilkan `total: 0` → semua `verified`.
3. ✅ `/apply` tanpa `confirm` → 422 dan file tetap utuh.
4. ✅ `/revert` mengembalikan file byte-identik (sha256 compare).
5. ✅ Patch di luar source root → 422 (same-origin guard).
6. ✅ Strategy dengan konteks tak memadai → `manual_required` + alasan, bukan
   patch salah.
7. ✅ Report HTML menampilkan badge `FIXED` + bukti re-scan.
8. ✅ `fixer.json` trajectory per session; semua token/kredensial tetap redacted.
9. ✅ Semua test hermetik (tanpa network, tanpa git).

---

## 9. Risiko & Mitigasi

| Risiko | Dampak | Mitigasi |
|--------|--------|----------|
| Patch salah konteks (AST mismatch) | Kode rusak | re-match rule di baris target sebelum patch; verify loop + auto-revert |
| User mengharapkan auto-commit | Ekspektasi meleset | Non-goal eksplisit + README; diff bisa di-paste ke PR |
| File berubah sejak scan (stale) | Patch di baris salah | re-match AST wajib; mismatch → `stale_finding`, minta scan ulang |
| Patch konflik batch (2 fix di 1 baris) | Apply gagal | deteksi overlap antar fix_ids → tolak overlap, apply sisanya |
| Disk penuh saat backup | Tulis gagal | pre-check ruang + gagal-aman (tidak menulis) |
| Kepercayaan: "apakah patch aman?" | Adopsi rendah | diff + bukti re-scan + revert; bukti selalu dilampirkan |

---

## 10. Roadmap Implementasi

| Fase | Isi | Estimasi |
|------|-----|----------|
| 1 | Model `FixProposal/FixSession` + `FixStore` + registry strategies | 0.5 hari |
| 2 | Strategies CY001–CY006 (Python, AST-guided) + unit tests | 1 hari |
| 3 | Strategies CY007–CY010 (JS/PHP, line-based) + unit tests | 0.5 hari |
| 4 | Applier (backup/revert/same-origin) + verify loop + tests | 0.5 hari |
| 5 | API router `/fixes` + worker integration + report badge | 0.5 hari |
| 6 | E2E alur lengkap + trajectory + README | 0.5 hari |
| Lanjutan | Git branch suggestions, PR comment export, interactive web UI | backlog |

---

## 11. Open Questions

1. Format diff: unified diff cukup, atau perlu side-by-side di HTML? → Proposal:
   unified untuk API, side-by-side dirender dari unified di HTML.
2. Batas ukuran file yang boleh di-patch? → Proposal: reuse `github_max_files`
   dan tolak file > 1MB (`CYENSE_FIX_MAX_FILE_KB`, default 1024).
3. Apakah `/fixes` perlu auth terpisah dari gate scan? → Proposal: tidak di
   MVP — sama-sama local service; approval eksplisit adalah kontrol utama.

---

## 12. Changelog Fitur

| Versi | Perubahan |
|-------|-----------|
| 1.0 | Draft awal: Fixer agent, fix matrix CY001–CY010, dry-run→apply→verify→(revert), backup wajib, same-origin guard, bukti re-scan, tanpa LLM, tanpa auto-commit |
| 2.0 | **Penyelarasan fokus produk**: sumber temuan utama = repo GitHub orang lain hasil fetch (sandbox `reports/<id>/src/`); mode program diturunkan jadi sumber sekunder; diperjelas bahwa patch pada kode hasil fetch terjadi di salinan sandbox dan output user berupa diff (repo pemilik tidak pernah disentuh) |

---

*Addendum ini tunduk pada PRD induk (`instruction/PRD.md`). Aturan konflik: PRD
induk menang untuk hal yang tidak diatur di sini (etika, redaction, state machine,
gaya commit). Nilai yang dilindungi fitur ini: **read-only until approved,
deterministic patches, evidence-based claims**.*
