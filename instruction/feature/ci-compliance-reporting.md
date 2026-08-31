# PRD Fitur — CI/CD & Compliance Reporting: SARIF, CVSS, Coverage, Diff-Scope, Scan Mode

> **Feature PRD** | Versi 1.0 | Status: planned
> **Parent PRD:** `instruction/PRD.md` (v2.0) — dokumen ini adalah *addendum*, bukan pengganti
> **Fitur terkait:**
> · `instruction/feature/cli-experience.md` — CLI `cyense` yang menjadi *surface* utama fitur ini
> · `instruction/feature/github-repo-audit.md` — jalur input utama (repo hasil fetch) yang di-scope oleh diff-mode
> · `instruction/feature/xss-detection.md`, `idor-remediation.md`, `xss-remediation.md` — sumber temuan yang diberi CVSS & diekspor
> **Nama fitur:** CI/CD & Compliance Reporting — adopsi 5 pola dari **Strix** (`usestrix/strix` v1.5.3)
> **Sumber riset:** `Projects/Strix/Analisis Repository Strix.md` (Obsidian vault) + verifikasi langsung ke kode `usestrix/strix`
> **Lokasi implementasi (rencana):** `dev/main/app/report/sarif.py`, `app/report/cvss.py`, `app/report/coverage.py`, `app/engines/diff_scope.py`, `app/core/scan_modes.py`

---

## 0. Ringkasan Satu Paragraf

Cyense hari ini menghasilkan temuan yang benar tetapi **tidak bisa dikonsumsi mesin lain**: tidak ada SARIF untuk GitHub Code Scanning, tidak ada skor CVSS yang bisa diurutkan lintas-tool, tidak ada jawaban atas pertanyaan auditor *"apa saja yang sudah kalian periksa?"*, dan setiap scan PR selalu memindai seluruh repo meski yang berubah hanya tiga file. Fitur ini mengadopsi **lima pola konkret dari Strix** — `findings.sarif` (SARIF 2.1.0), **CVSS v3.1 8-metrik**, `coverage.json` (*negative space* dengan pemisahan `agent_reported` vs `machine_observed`), **diff-scope** untuk PR, dan **scan mode** `quick|standard|deep` — dan menerapkannya di atas arsitektur Cyense yang sudah ada **tanpa satu pun panggilan LLM**. Semua yang diadopsi dipilih justru karena bagian *deterministik*-nya: rumus CVSS adalah aritmatika, pemetaan CWE→STRIDE adalah tabel, dan diff-scope adalah operasi Git. Bagian Strix yang bergantung pada LLM (dedupe judge), Docker sandbox berisi exploit tooling, dan multi-agent graph **ditolak secara eksplisit** di §2.2 karena bertabrakan dengan keputusan desain `no-LLM` (`instruction/PRD.md:55`, `:82`) dan ground rule read-only.

---

## 1. Latar Belakang & Masalah

### 1.1 Kondisi sebelum fitur ini

Empat kesenjangan nyata, semuanya terverifikasi di kode:

| # | Kesenjangan | Bukti di kode |
|---|-------------|---------------|
| 1 | **Tidak ada SARIF** — temuan tidak bisa masuk tab Security GitHub | `dev/main/app/report/` hanya berisi `json_report.py`, `html_report.py`, `md_report.py` |
| 2 | **Tidak ada CVSS** — `Finding` hanya punya `severity` + `confidence`, tidak ada skor numerik lintas-tool | `dev/main/app/core/models.py:99-109` |
| 3 | **Severity hard-coded per rule** — CY001 selalu `HIGH` apa pun konteksnya | `python_rules.py:147,163,177`, `regex_rules.py:12-41`, `xss_rules.py:18-98` |
| 4 | **Tidak ada catatan cakupan** — laporan 0 temuan tidak bisa dibedakan dari "tidak pernah diperiksa" | tidak ada modul `coverage` di `app/report/` |
| 5 | **Scan PR selalu full-repo** — tidak ada penyempitan berdasarkan file yang berubah | `program_engine.py:60` — `source_dir.rglob("*")` tanpa filter diff |
| 6 | **Tidak ada scan mode** — tidak ada cara meminta scan cepat untuk CI | `GithubScanRequest` (`models_github.py:11-19`) tidak punya field mode |

Konsekuensinya: `cyense scan github ... --fail-on high` (dari `cli-experience.md` §3.7) sudah bisa memerahkan build, tetapi **reviewer PR tidak melihat anotasi inline di GitHub**, dan **auditor tidak menerima bukti cakupan**. Nilai engine tertahan di batas terminal.

### 1.2 Mengapa Strix menjadi rujukan — dan apa yang TIDAK diambil

Strix (`usestrix/strix` v1.5.3, Apache-2.0) adalah *autonomous AI pentesting tool* yang sudah memecahkan tepat lima masalah di atas pada skala produksi. Namun Strix dan Cyense punya filosofi berbeda secara fundamental:

| Dimensi | Strix | Cyense | Keputusan |
|---|---|---|---|
| **Mesin nalar** | LLM multi-provider via LiteLLM | Deterministik (AST, regex, difflib, PII) | ❌ **Tidak diadopsi** — `PRD.md:55` |
| **Eksekusi target** | Menjalankan exploit sungguhan di sandbox Kali | Read-only; kode tidak pernah dieksekusi | ❌ **Tidak diadopsi** — ground rule #4 |
| **Isolasi** | Docker Kali + Caido proxy + `NET_ADMIN` | Container Python slim, non-root (`Dockerfile:18-21`) | ❌ **Tidak diadopsi** |
| **Orkestrasi** | Agent graph dinamis, agen spawn agen | Pipeline tetap 4-agent | ❌ **Tidak diadopsi** |
| **Dedupe** | LLM judge (`dedupe.py:367` `resolve_dedupe_model`) | — | ⚠️ **Diadopsi hanya jalur deterministiknya** (§3.6) |
| **SARIF 2.1.0** | `report/sarif.py` (1185 baris) | — | ✅ **Diadopsi** |
| **CVSS v3.1** | `tools/reporting/tool.py:130` `_calculate_cvss` | — | ✅ **Diadopsi** |
| **Coverage doc** | `report/coverage.py` (443 baris) | — | ✅ **Diadopsi (disederhanakan)** |
| **Diff-scope** | `--scope-mode auto\|diff\|full` (`cli_args.py:196-215`) | — | ✅ **Diadopsi** |
| **Scan mode** | `--scan-mode quick\|standard\|deep` (`cli_args.py:180-193`) | — | ✅ **Diadopsi (dimaknai ulang)** |

> **Keputusan desain inti:** yang diambil dari Strix adalah **format & kontrak data**, bukan mesin nalarnya. SARIF adalah standar OASIS; CVSS v3.1 adalah rumus tertutup; CWE→STRIDE adalah tabel statis. Ketiganya *lebih deterministik* daripada kode Cyense yang sudah ada — mengadopsinya justru **memperkuat** klaim reproducibility di `PRD.md:568`, bukan melemahkannya.

### 1.3 Persona & user story yang dilayani

| Persona (PRD induk §3.1) | Story |
|--------------------------|-------|
| **DevOps** (Rara) | "Saya upload `findings.sarif` ke `github/codeql-action/upload-sarif`; temuan muncul sebagai anotasi inline di PR, bukan hanya teks di log CI." |
| **Developer** (Budi) | "PR saya mengubah 3 file. Saya ingin scan hanya menyentuh 3 file itu dan selesai dalam detik, bukan memindai 2000 file." |
| **Pentester** (Andi) | "Klien menuntut skor CVSS pada setiap temuan agar bisa dimasukkan ke sistem tiket mereka — `HIGH` saja tidak cukup." |
| **Auditor kontrak** | "Laporan 0 temuan tidak berarti apa-apa bagi saya kecuali saya tahu **apa yang diperiksa**. Beri saya daftar rule yang dijalankan dan file yang tersentuh." |
| **Maintainer OSS** | "Saya ingin `quick` mode untuk pre-commit dan `deep` untuk rilis — satu tool, dua tingkat ketelitian." |

---

## 2. Goal & Non-Goal

### 2.1 Goals (MVP)

1. **SARIF 2.1.0** — `app/report/sarif.py` menghasilkan `findings.sarif` yang lolos validasi skema resmi, kompatibel GitHub Code Scanning.
2. **CVSS v3.1 deterministik** — `app/report/cvss.py` memetakan setiap rule (CY001–CY010, XS001–XS008, IDOR-LINK) ke vektor 8-metrik tetap; skor dihitung library `cvss`, bukan ditebak.
3. **CWE per rule** — setiap rule memiliki CWE kanonik; SARIF menuliskannya sebagai `ruleId` dan menurunkan tag STRIDE.
4. **`coverage.json`** — mencatat rule yang dijalankan, file yang dipindai, dan *gap* (rule aktif yang tidak menghasilkan temuan), dengan pemisahan `engine_reported` vs `machine_observed`.
5. **Diff-scope** — `--scope-mode auto|diff|full` + `--diff-base`; mode `diff` membatasi analisis ke file yang berubah.
6. **Scan mode** — `--scan-mode quick|standard|deep` yang memetakan ke kombinasi (rule set × scope × cap file) yang **eksplisit dan terdokumentasi**.
7. **Integrasi CLI** — semua flag di atas tersedia di `cyense scan`, konsisten dengan `cli-experience.md` §3.2.
8. **Field baru pada `Finding`** — `cwe`, `cvss_score`, `cvss_vector` — *opsional* agar backward-compatible.
9. **Determinisme mutlak** — dua scan pada `repo@sha` yang sama menghasilkan `findings.sarif` dan `coverage.json` byte-identik (kecuali timestamp).

### 2.2 Non-Goals (MVP)

- ❌ **LLM untuk apa pun** — termasuk dedupe judge Strix (`dedupe.py:367`). Deduplikasi Cyense **hanya** jalur deterministik (§3.6). Ini menegakkan `PRD.md:82`.
- ❌ **Docker sandbox berisi exploit tooling** (nmap/sqlmap/nuclei/Caido). Cyense tidak pernah menjalankan kode target — ground rule #4.
- ❌ **Multi-agent graph dinamis** (agen spawn agen). Pipeline Cyense tetap 4-agent tetap.
- ❌ **MCP server integration** — menarik, tetapi tidak melayani satu pun user story di §1.3.
- ❌ **PDF report** — `.md` + HTML + SARIF sudah menutup kebutuhan compliance MVP.
- ❌ **CVSS Temporal/Environmental** — hanya Base Score; Temporal butuh data eksploitabilitas yang tidak dimiliki Cyense.
- ❌ **Auto-upload ke GitHub** — Cyense hanya *menulis file*; upload adalah tugas workflow CI pengguna (menjaga read-only terhadap GitHub).
- ❌ **Coverage berbasis klaim agen bebas-teks** — Strix mengizinkan agen menulis narasi cakupan; Cyense hanya mencatat fakta terukur (§3.5).

---

## 3. Spesifikasi Fungsional

### 3.1 CVSS v3.1 — Skor Deterministik per Rule

#### 3.1.1 Prinsip

Strix meminta **agen LLM** mengisi 8 metrik CVSS (`tools/reporting/tool.py:25-34`), lalu memvalidasinya. Cyense tidak punya LLM — maka **setiap rule memiliki vektor tetap** yang ditentukan saat desain rule, bukan saat runtime. Ini justru lebih reproducible: rule yang sama selalu menghasilkan skor yang sama, selamanya.

Metrik dan nilai valid identik dengan Strix (`tool.py:25-34`):

```python
_CVSS_VALID = {
    "attack_vector":        ["N", "A", "L", "P"],
    "attack_complexity":    ["L", "H"],
    "privileges_required":  ["N", "L", "H"],
    "user_interaction":     ["N", "R"],
    "scope":                ["U", "C"],
    "confidentiality":      ["N", "L", "H"],
    "integrity":            ["N", "L", "H"],
    "availability":         ["N", "L", "H"],
}
```

Perhitungan memakai library `cvss` (dependensi yang sama dengan Strix), mengikuti pola `tool.py:130-149`:

```python
def calculate_cvss(breakdown: dict[str, str]) -> tuple[float, str, str]:
    from cvss import CVSS3
    vector = (
        f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
        f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
        f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
        f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
    )
    c = CVSS3(vector)
    score = c.scores()[0]
    base = c.severities()[0].lower()
    return score, ("info" if base == "none" else base), vector
```

#### 3.1.2 Tabel rule → CWE → CVSS (sumber tunggal: `app/report/cvss.py`)

| Rule | CWE | Vektor CVSS 3.1 | Skor | Severity turunan | Severity saat ini |
|------|-----|-----------------|------|------------------|-------------------|
| `CY001` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `CY002` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `CY003` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `CY004` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `CY005` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `CY006` | CWE-22  | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | critical |
| `CY007` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `CY008` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `CY009` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `CY010` | CWE-639 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | medium | high |
| `XS001` | CWE-79 | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | medium | high |
| `XS002` | CWE-79 | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | medium | high |
| `XS003` | CWE-79 | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | medium | high |
| `XS004` | CWE-95 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | critical | critical |
| `XS005` | CWE-79 | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | medium | high |
| `XS006` | CWE-79 | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | medium | high |
| `XS007` | CWE-79 | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | medium | high |
| `XS008` | CWE-79 | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N` | 4.7 | medium | medium |
| `IDOR-LINK` | CWE-639 | *dinamis*, lihat §3.1.4 | 3.1–7.5 | low–high | critical/high/medium |

> **Catatan verifikasi:** seluruh skor pada tabel di atas telah **dihitung dan diverifikasi** terhadap rumus resmi CVSS v3.1 (FIRST.org) saat PRD ini ditulis — 18/18 entri cocok. Test §7.1 mengunci nilai ini terhadap library `cvss`. Bila library menghitung berbeda, **tabel ini yang diperbaiki**, bukan hasil library.

#### 3.1.3 Konflik severity — dan resolusinya

Tabel di atas memunculkan masalah nyata: **CVSS Base Score untuk IDOR statis adalah `medium` (6.5), sedangkan Cyense saat ini melabelinya `high`** (`python_rules.py:147`). CY006 bahkan `CRITICAL` (`:190`) tetapi CVSS-nya 6.5.

Ini bukan bug pada salah satu sisi — keduanya mengukur hal berbeda:

- **CVSS Base** mengukur karakteristik teknis kerentanan *yang sudah terkonfirmasi*.
- **Severity Cyense** adalah *prioritas triase* dari analisis statis, yang belum tentu exploitable.

**Keputusan:** kedua nilai **hidup berdampingan tanpa saling menimpa**.

| Field | Sumber | Dipakai untuk |
|-------|--------|---------------|
| `severity` | tabel rule yang sudah ada | Prioritas triase, `--fail-on`, tampilan CLI, urutan laporan |
| `cvss_score` | dihitung dari vektor | SARIF `security-severity`, integrasi eksternal, tiket klien |

`severity` yang sudah ada **tidak diubah sama sekali** — ini menjaga *acceptance criteria* fitur-fitur sebelumnya (mis. `xss-detection.md` §8) tetap hijau. SARIF menuliskan keduanya: `level` dari `severity`, `security-severity` dari `cvss_score`, dan keduanya diarsipkan di `properties.cyense` agar konsumen bisa memilih.

> **Justifikasi:** Strix mengambil jalan sebaliknya — CVSS **menentukan** severity (`tool.py:148`). Cyense tidak bisa meniru itu karena severity kami sudah menjadi kontrak publik di 4 PRD sebelumnya dan di `GET /rules`. Mengubahnya akan memecah backward-compatibility demi keseragaman kosmetik.

#### 3.1.4 CVSS untuk mode `link`

Mode `link` menghasilkan temuan terverifikasi dinamis, sehingga vektor **boleh** dinaikkan berdasarkan bukti objektif yang sudah dikumpulkan Verifier:

| Kondisi (dari `VerificationEvidence`, `models.py:90-96`) | Penyesuaian |
|---|---|
| `pii_matches` tidak kosong | `C:H` (kebocoran data terkonfirmasi) |
| `control_id_blocked == True` | `PR:L` (kontrol akses ada tetapi bisa dilewati) |
| `control_id_blocked == False` | `PR:N` (tidak ada kontrol sama sekali) |
| `similarity >= threshold` & `retry_consistent` | pertahankan `AC:L` |
| selain itu | `AC:H` |

Aturan ini deterministik: input yang sama → vektor yang sama. Basis vektor:
`AV:N/AC:{L|H}/PR:{N|L}/UI:N/S:U/C:{H|L}/I:N/A:N`.

**Seluruh delapan kombinasi yang mungkin** (terverifikasi terhadap rumus CVSS v3.1):

| PII | Kontrol akses | Konsisten | Vektor | Skor | Severity CVSS |
|-----|---------------|-----------|--------|------|---------------|
| ada | tidak ada | ya | `AC:L/PR:N/C:H` | **7.5** | high |
| ada | ada, dilewati | ya | `AC:L/PR:L/C:H` | **6.5** | medium |
| ada | tidak ada | tidak | `AC:H/PR:N/C:H` | **5.9** | medium |
| ada | ada, dilewati | tidak | `AC:H/PR:L/C:H` | **5.3** | medium |
| tidak | tidak ada | ya | `AC:L/PR:N/C:L` | **5.3** | medium |
| tidak | ada, dilewati | ya | `AC:L/PR:L/C:L` | **4.3** | medium |
| tidak | tidak ada | tidak | `AC:H/PR:N/C:L` | **3.7** | low |
| tidak | ada, dilewati | tidak | `AC:H/PR:L/C:L` | **3.1** | low |

> **Konsekuensi yang harus disadari:** temuan mode `link` yang dilabeli `critical` oleh orchestrator (`orchestrator.py:28-31`) dapat memperoleh `cvss_score` serendah **3.1**. Ini bukan kontradiksi melainkan konsekuensi langsung §3.1.3: `severity` adalah prioritas triase Cyense, `cvss_score` adalah karakteristik teknis standar. Keduanya wajib ditampilkan berdampingan di `.md` dan SARIF, tidak pernah salah satu saja.

### 3.2 SARIF 2.1.0

#### 3.2.1 Kontrak

Modul baru `app/report/sarif.py`, API sejajar `json_report.py:14`:

```python
def build_sarif_report(report: dict[str, Any]) -> dict[str, Any]: ...
def dump_sarif_report(report: dict[str, Any], path: Path) -> Path: ...
```

Mengikuti keputusan desain Strix (`sarif.py:16-47`) yang relevan:

| Aspek | Aturan | Rujukan Strix |
|---|---|---|
| Skema | `https://json.schemastore.org/sarif-2.1.0.json`, versi `2.1.0` | `sarif.py:63-64` |
| `ruleId` | CWE kanonik (`CWE-639`), fallback ke rule id Cyense | `sarif.py:17-20` |
| Level | 5 severity → 3 level SARIF | `sarif.py:81-88` |
| `security-severity` | dari `cvss_score`; fallback tabel label→skor | `sarif.py:90-100` |
| Path | wajib relatif-repo POSIX; path absolut/traversal **ditolak** | `sarif.py:28-30` |
| Lokasi sintetis | temuan tanpa lokasi aman di-anchor ke `SECURITY.md` + flag | `sarif.py:68-76` |
| STRIDE tags | diturunkan dari CWE, ditempel pada rule | `sarif.py:103-110` |
| Provenance | `versionControlProvenance` dari `meta.repo` | `sarif.py:37-39` |

Pemetaan level (identik `sarif.py:81-88`):

```python
_SEVERITY_TO_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}
```

#### 3.2.2 Contoh keluaran

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": {
      "name": "Cyense", "version": "2.0.0",
      "informationUri": "https://github.com/",
      "rules": [{
        "id": "CWE-639",
        "name": "AuthorizationBypassThroughUserControlledKey",
        "shortDescription": { "text": "Unscoped object lookup by request-controlled id" },
        "properties": {
          "security-severity": "6.5",
          "tags": ["security", "external/cwe/cwe-639",
                   "stride:elevation-of-privilege", "cyense:idor"]
        }
      }]
    }},
    "versionControlProvenance": [{
      "repositoryUri": "https://github.com/acme/checkout-service",
      "revisionId": "9f2c1a7b...", "branch": "main"
    }],
    "results": [{
      "ruleId": "CWE-639",
      "level": "error",
      "kind": "fail",
      "message": { "text": "Unscoped .get() by request-controlled id" },
      "locations": [{ "physicalLocation": {
        "artifactLocation": { "uri": "backend/api/invoices.py" },
        "region": { "startLine": 42 }
      }}],
      "partialFingerprints": { "cyenseRuleLocation/v1": "…sha256…" },
      "properties": { "cyense": {
        "rule": "CY004", "severity": "high", "confidence": 0.7,
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "finding_id": "47b7de1d8e3a-CY004"
      }}
    }],
    "invocations": [{ "executionSuccessful": true }]
  }]
}
```

#### 3.2.3 Normalisasi path — masalah nyata yang harus diselesaikan

`Finding.location` saat ini **tidak pernah relatif repo**. Penyebabnya: `python_rules.py:60` menulis `location=f"{path}:{lineno}"` dengan `path` berasal langsung dari `program_engine.py:60` (`source_dir.rglob`).

Bukti dari artefak nyata di `dev/main/reports/`:

```text
# mode=github  (reports/f51ba928c418 — nccgroup/ScoutSuite@master)
reports/f51ba928c418/src/ScoutSuite-master/ScoutSuite/output/data/inc-scoutsuite/scoutsuite.js:137
└──────── prefix sandbox ────────┘└─────────── yang seharusnya dilaporkan ───────────┘

# mode=program
/home/xmitsu/programming/lomba/frontier/cyense/dev/main/app/program/sample/fastapi_routes.py:14
└──────────────────── path absolut mesin developer ────────────────────┘
```

Keduanya melanggar syarat SARIF. Yang kedua lebih buruk: **membocorkan struktur direktori mesin developer** ke artefak yang mungkin dibagikan — masalah privasi, bukan sekadar format.

SARIF **menolak** path semacam ini (`sarif.py:28-30`). Karena itu fitur ini **wajib** menambahkan normalisasi:

```python
def to_repo_relative(location: str, tree_root: str) -> str | None:
    """`/abs/reports/<id>/src/repo-sha/api/x.py:42` → `api/x.py`.
    Kembalikan None bila path tidak berada di bawah tree_root (→ lokasi sintetis)."""
```

`tree_root` sudah tersedia di `FetcherAgent` (`fetcher.py:185`) dan diteruskan ke engine (`github_engine.py:85`). Fitur ini menambahkan `meta.repo.tree_root` ke report agar normalisasi bisa dilakukan di lapisan report tanpa menyentuh rules.

> Catatan: `cli-experience.md` §3.3 sudah **mengasumsikan** `location` berupa path relatif (`backend/api/invoices.py:42`). Normalisasi ini karena itu memperbaiki inkonsistensi yang sudah ada, bukan menambah utang baru.

### 3.3 Diff-Scope untuk PR

#### 3.3.1 Mode

Mengikuti `cli_args.py:196-206`:

| `--scope-mode` | Perilaku |
|---|---|
| `auto` (default) | Aktifkan diff-scope bila terdeteksi konteks CI **dan** base tersedia; selain itu `full` |
| `diff` | Paksa diff-scope; bila base tidak resolvable → **gagal eksplisit**, bukan diam-diam full |
| `full` | Nonaktifkan diff-scope |

`--diff-base` menentukan pembanding (mis. `origin/main`); default = default branch repo.

#### 3.3.2 Cara memperoleh daftar file — tanpa `git clone`

Ini kendala arsitektural yang harus dihormati: `github-repo-audit.md` §3.2 memutuskan Cyense memakai **tarball codeload, bukan git clone**, dan `GithubClient` (`github_client.py:14-18`) membatasi host ke tiga domain GitHub. Tidak ada `.git` di sandbox — jadi `git diff` **tidak mungkin dijalankan**.

Dua jalur, sesuai sumber:

| Mode | Sumber daftar file | Mekanisme |
|---|---|---|
| `program` (lokal) | Working tree yang punya `.git` | `git diff --name-only <base>...HEAD` |
| `github` (tarball) | GitHub Compare API | `GET /repos/{o}/{r}/compare/{base}...{head}` → `files[].filename` |

Endpoint `compare` berada di `api.github.com` yang **sudah ada di allowlist** (`github_client.py:16`) — tidak perlu melonggarkan guard SSRF. Method `compare_refs()` ditambahkan ke `GithubClient` mengikuti pola `resolve_commit_sha()` (`github_client.py:117-131`), termasuk penanganan rate limit yang sudah ada di `:73-76`.

#### 3.3.3 Penerapan filter

`run_program_scan()` (`program_engine.py:45`) menerima parameter opsional baru:

```python
def run_program_scan(
    lang, source_dir, scan_id,
    scan_types=None,
    include_paths: set[str] | None = None,   # BARU — relatif repo
) -> dict[str, Any]: ...
```

Bila `include_paths` diberikan, loop `:60` melewati file yang tidak ada di set tersebut. Perubahan bersifat **aditif**: `None` = perilaku lama persis.

#### 3.3.4 Batas yang harus dijujurkan

Diff-scope **mempersempit cakupan**, artinya bisa melewatkan kerentanan pada file yang tidak berubah tetapi terdampak. Karena itu:

- `coverage.json` **wajib** mencatat `scope_mode`, `diff_base`, dan `files_excluded_by_scope`.
- Laporan `.md` §6 (Metodologi) **wajib** memuat kalimat peringatan bila mode `diff` aktif.
- SARIF `invocations[].properties` mencantumkan `scope_mode` agar konsumen tahu ini scan parsial.

Menyembunyikan fakta ini akan membuat laporan berbohong — persis kekhawatiran yang ditulis Strix di `coverage.py:1-26`.

### 3.4 Scan Mode

Strix memaknai scan mode sebagai *kedalaman usaha agen LLM*. Cyense tidak punya dimensi itu (analisis statis selalu memindai seluruh file yang di-scope). Maka scan mode **dimaknai ulang** menjadi kombinasi eksplisit:

| Mode | `scan_types` | `scope_mode` default | Cap file | Target waktu | Use case |
|------|--------------|---------------------|----------|--------------|----------|
| `quick` | `["idor"]` | `auto` (→ diff di CI) | 500 | < 5 s | Pre-commit, PR check |
| `standard` | `["idor","xss"]` | `auto` | 3000 | < 30 s | Review rutin (default) |
| `deep` | `["idor","xss"]` | `full` | `CYENSE_GITHUB_MAX_FILES` | tanpa target | Audit rilis |

> **Perbedaan default yang disengaja:** Strix default `deep` (`cli_args.py:185`). Cyense default **`standard`** — memindai IDOR+XSS pada scope otomatis. Alasannya: `deep` pada Strix berarti "agen berpikir lebih lama"; pada Cyense berarti "matikan diff-scope", yang di CI justru memperlambat tanpa menambah nilai untuk PR kecil. Menjadikan `deep` default akan menghukum use case paling umum.

Flag eksplisit (`--scan-types`, `--scope-mode`) **selalu menang** atas preset mode.

### 3.5 `coverage.json` — Negative Space

#### 3.5.1 Prinsip yang diadopsi

Strix membuka `coverage.py:1-26` dengan argumen yang tepat: *"daftar temuan menjawab apa yang salah, bukan apa yang diperiksa; auditor yang membaca nol temuan SQL injection tidak bisa membedakan 'sudah diuji 14 endpoint, semua parameterized' dari 'tidak pernah melihat'."*

Strix memisahkan `agent_reported` (klaim agen) dari `machine_observed` (fakta runtime), karena *"klaim cakupan adalah atestasi, jadi mencampur keduanya adalah kegagalan terburuk"* (`coverage.py:19-25`).

**Cyense justru dalam posisi lebih kuat di sini:** tanpa LLM, tidak ada yang bisa berhalusinasi. Seluruh isi `coverage.json` Cyense adalah `machine_observed`. Namun pemisahan tetap dipertahankan secara struktural — untuk kejujuran epistemik dan agar skema kompatibel bila kelak ada sumber non-deterministik.

#### 3.5.2 Skema

```json
{
  "schema_version": 1,
  "scan_id": "47b7de1d8e3a",
  "generated_at": "2026-08-30T18:37:15Z",
  "complete": true,
  "scope": {
    "mode": "diff",
    "diff_base": "origin/main",
    "files_in_scope": 3,
    "files_excluded_by_scope": 211,
    "note": "Scan dibatasi pada file yang berubah; file lain TIDAK diperiksa."
  },
  "machine_observed": {
    "rules_executed": ["CY001","…","XS008"],
    "rules_with_findings": ["CY004","XS002"],
    "files_scanned": 3,
    "files_by_language": { "python": 2, "js": 1 },
    "findings_total": 2,
    "duration_ms": 3410
  },
  "engine_reported": {
    "scan_types": ["idor","xss"],
    "lang": "auto"
  },
  "gaps": [
    { "rule": "XS006", "reason": "no_php_files_in_scope",
      "detail": "Rule aktif tetapi tidak ada file .php dalam scope." },
    { "rule": "CY009", "reason": "no_php_files_in_scope" }
  ]
}
```

#### 3.5.3 Deteksi gap

Deterministik, tanpa pencocokan teks (Strix memakai *phrasing matching* di `coverage.py:77` karena entri cakupannya ditulis LLM — Cyense tidak perlu):

```
Untuk setiap rule R yang aktif pada scan_types:
    bahasa_R  = bahasa target rule R
    file_R    = jumlah file berbahasa itu dalam scope
    jika file_R == 0        → gap(reason="no_<lang>_files_in_scope")
    jika file_R > 0 dan tidak ada temuan → BUKAN gap (diperiksa, bersih)
```

Perbedaan antara "diperiksa dan bersih" vs "tidak pernah diperiksa" inilah seluruh nilai artefak ini.

#### 3.5.4 Flag `complete`

`false` bila salah satu terpenuhi (mengikuti semangat `coverage.py:57-61`):
- cap file tercapai (analisis terpotong),
- scan berstatus `failed`,
- ada file yang gagal dibaca (`program_engine.py:74` `except OSError: continue` — saat ini gagal senyap, fitur ini membuatnya terhitung).

### 3.6 Deduplikasi — Hanya Jalur Deterministik

Strix punya dua jalur (`dedupe.py`): identitas deterministik `(CVE, package, ecosystem)` (`:162-177`) dan **LLM judge** (`:367`). Cyense mengadopsi **hanya yang pertama**, disesuaikan karena Cyense tidak memindai dependensi:

**Kunci identitas Cyense:** `(rule, path_relatif, baris)`

#### 3.6.1 Temuan investigasi: `finding_id` bertabrakan

Pemeriksaan artefak nyata mengungkap masalah yang **lebih mendesak** daripada duplikasi. Pada `reports/47b7de1d8e3a/report.json`:

```text
total findings          : 10
unique (rule, location) : 10   → tidak ada duplikat sejati
CY004 occurrences       : 5    → semuanya di lokasi BERBEDA (sah)

finding_id untuk kelima temuan CY004:
  47b7de1d8e3a-CY004  |  .../sample/fastapi_routes.py:14
  47b7de1d8e3a-CY004  |  .../sample/flask_routes.py:14
  47b7de1d8e3a-CY004  |  .../sample/views.py:16
  47b7de1d8e3a-CY004  |  .../sample/views.py:22
  47b7de1d8e3a-CY004  |  .../sample/views.py:28
```

Kelimanya berbagi **`finding_id` yang sama persis**. Penyebabnya `python_rules.py:51`:

```python
finding_id=f"{scan_id}-{rule}"     # tidak menyertakan lokasi
```

Kontras dengan aturan regex yang sudah benar (`regex_rules.py:63`, `xss_rules.py`):

```python
finding_id=f"{scan_id}-{rule_id}-{line}"   # menyertakan baris
```

Dampaknya nyata dan bukan kosmetik:
- SARIF `partialFingerprints` akan **menggabungkan 5 alert berbeda menjadi 1** di GitHub.
- `cyense fix <scan_id>` tidak bisa menargetkan satu temuan spesifik (`remediations.py` mencari berdasarkan `finding_id`).
- Panel rekomendasi CLI menghitung `occurrences` dengan benar, tetapi `rendered_findings` (`app/cli/models.py`, set `finding_id`) akan **melewatkan 4 dari 5 kartu** karena dianggap sudah dirender.

#### 3.6.2 Perbaikan

Fitur ini memperbaiki `_finding()` di `python_rules.py:50` agar konsisten dengan aturan lain:

```python
finding_id=f"{scan_id}-{rule}-{lineno}"
```

Ini satu-satunya perubahan pada berkas rules yang diizinkan fitur ini, dan **tidak menyentuh logika deteksi maupun severity** — hanya string identitas. Test §7.15 mengunci keunikan.

#### 3.6.3 Deduplikasi

Setelah `finding_id` unik, dedupe menjadi jaring pengaman: temuan dianggap duplikat hanya bila `(rule, path_relatif, baris)` identik. Kunci yang sama menjadi basis `partialFingerprints` SARIF, sehingga GitHub melacak alert lintas-commit tanpa duplikasi.

### 3.7 Perubahan API & CLI

#### 3.7.1 Endpoint

| Method | Path | Perubahan |
|---|---|---|
| GET | `/scans/{id}/report/sarif` | **BARU** — `application/sarif+json` |
| GET | `/scans/{id}/coverage` | **BARU** — `coverage.json` |
| GET | `/rules` | Tambah `cwe`, `cvss_vector`, `cvss_score` per rule |
| POST | `/scans` | Tambah `scan_mode`, `scope_mode`, `diff_base` |
| GET | `/scans/{id}/report` | `findings[]` memuat `cwe`, `cvss_score`, `cvss_vector` |

State machine `QUEUED → RUNNING → COMPLETED | FAILED` **tidak berubah**.

#### 3.7.2 Flag CLI

Menambah ke `cyense scan` (`app/cli/main.py`), konsisten `cli-experience.md` §3.2:

| Flag | Default | Keterangan |
|---|---|---|
| `--scan-mode quick\|standard\|deep` | `standard` | Preset §3.4 |
| `--scope-mode auto\|diff\|full` | `auto` | Scope diff §3.3 |
| `--diff-base <ref>` | default branch | Pembanding diff |
| `--sarif <path>` | `reports/<id>/findings.sarif` | Tujuan SARIF |
| `--no-sarif` | false | Jangan tulis SARIF |
| `--coverage <path>` | `reports/<id>/coverage.json` | Tujuan coverage |

Guard path `--out` (`cli-experience.md` §6.3) berlaku sama untuk `--sarif` dan `--coverage`.

Footer artefak CLI (`cli-experience.md` §3.3 blok 5) bertambah dua baris:

```
   ✔ Laporan Markdown   reports/47b7de1d8e3a/report.md
     SARIF              reports/47b7de1d8e3a/findings.sarif
     Coverage           reports/47b7de1d8e3a/coverage.json
```

Bila `--scope-mode diff` aktif, CLI **wajib** mencetak peringatan agar hasil parsial tidak disalahpahami:

```
  ⚠  Scan dibatasi pada 3 file yang berubah (base: origin/main).
     211 file lain TIDAK diperiksa — lihat coverage.json.
```

#### 3.7.3 Workflow CI referensi

```yaml
- name: Run Cyense
  run: |
    cyense scan github "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
      --ref "$GITHUB_SHA" --i-have-permission \
      --scan-mode quick --scope-mode diff --diff-base "origin/$GITHUB_BASE_REF" \
      --fail-on high
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/*/findings.sarif
```

`continue-on-error` memastikan SARIF tetap terunggah meski exit code 1 — reviewer melihat anotasi justru saat ada temuan.

---

## 4. Model Data (sketsa Pydantic)

```python
# app/core/models.py — perluasan Finding (semua opsional → backward-compatible)

class Finding(BaseModel):
    finding_id: str
    rule: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    title: str
    description: str = ""
    evidence: dict[str, Any] = {}
    verification: VerificationEvidence = VerificationEvidence()
    remediation: str = ""
    location: str | None = None
    # --- BARU ---
    cwe: str | None = None            # "CWE-639"
    cvss_score: float | None = None   # 6.5
    cvss_vector: str | None = None    # "CVSS:3.1/AV:N/..."


# app/report/cvss.py
class CvssProfile(BaseModel):
    """Vektor CVSS tetap untuk satu rule — sumber tunggal §3.1.2."""
    rule: str
    cwe: str
    attack_vector:       Literal["N","A","L","P"]
    attack_complexity:   Literal["L","H"]
    privileges_required: Literal["N","L","H"]
    user_interaction:    Literal["N","R"]
    scope:               Literal["U","C"]
    confidentiality:     Literal["N","L","H"]
    integrity:           Literal["N","L","H"]
    availability:        Literal["N","L","H"]


# app/core/scan_modes.py
class ScanModeProfile(BaseModel):
    name: Literal["quick","standard","deep"]
    scan_types: tuple[str, ...]
    default_scope_mode: Literal["auto","diff","full"]
    max_files: int


# app/engines/diff_scope.py
class DiffScope(BaseModel):
    mode: Literal["auto","diff","full"]
    base: str | None = None
    resolved: bool = False
    include_paths: set[str] = set()
    excluded_count: int = 0
    reason: str = ""           # mis. "ci_detected", "base_unresolvable"


# app/report/coverage.py
class CoverageGap(BaseModel):
    rule: str
    reason: Literal["no_matching_files_in_scope","excluded_by_scan_types",
                    "file_read_error","cap_reached"]
    detail: str = ""
```

`Severity` tetap dari `app/core/models.py:15` — tidak ada enum baru.

---

## 5. Arsitektur & Integrasi dengan Kode yang Ada

### 5.1 Komponen baru

| Komponen | Lokasi | Peran |
|---|---|---|
| CVSS profiles | `app/report/cvss.py` (baru) | Tabel §3.1.2 + `calculate_cvss()` + `enrich_finding()` |
| SARIF builder | `app/report/sarif.py` (baru) | `build_sarif_report()`, `dump_sarif_report()`, normalisasi path |
| Coverage builder | `app/report/coverage.py` (baru) | `build_coverage_document()`, deteksi gap |
| Diff scope | `app/engines/diff_scope.py` (baru) | Resolve base, ambil daftar file (git / Compare API) |
| Scan modes | `app/core/scan_modes.py` (baru) | Preset §3.4 |
| Dedupe | `app/report/dedupe.py` (baru) | Kunci identitas deterministik §3.6 |

### 5.2 Perubahan pada berkas yang ada

| Berkas | Perubahan |
|---|---|
| `app/core/models.py` | +3 field opsional pada `Finding` (`:99-109`) |
| `app/core/models_github.py` | +`scan_mode`, `scope_mode`, `diff_base` pada `GithubScanRequest` (`:11-19`) |
| `app/core/config.py` | +`cyense_scan_mode_default`, `cyense_sarif_enabled`, `cyense_coverage_enabled` (`:14-43`) |
| `app/engines/program_engine.py` | +param `include_paths`; hitung file gagal-baca untuk coverage (`:45`, `:60`, `:74`) |
| `app/engines/github_engine.py` | Panggil diff-scope; sertakan `tree_root` ke `meta.repo` (`:118-131`) |
| `app/utils/github_client.py` | +`compare_refs()` (host tetap dalam allowlist `:14-18`) |
| `app/worker.py` | Tulis `findings.sarif` + `coverage.json` berdampingan `report.json` (`:178-186`) |
| `app/api/reports.py` | +2 endpoint (`:23-31`) |
| `app/api/system.py` | `/rules` sertakan CWE + CVSS (`:15-57`) |
| `app/cli/main.py` | +flag §3.7.2; peringatan diff-scope |
| `app/cli/renderer.py` | Footer +2 baris artefak |
| `app/report/md_report.py` | Kolom CVSS di tabel; catatan scope di §6 (`:196-215`, `_METHODOLOGY`) |
| `app/program/python_rules.py` | **Satu baris**: `finding_id` menyertakan `lineno` (`:51`) — perbaikan tabrakan ID §3.6.2 |
| `pyproject.toml` / `requirements.txt` | +`cvss>=3.2` |

### 5.3 Yang TIDAK berubah

**Logika deteksi dan nilai `severity` seluruh rule** (CY001–CY010, XS001–XS008) tidak berubah sama sekali. Satu-satunya sentuhan pada berkas rules adalah string `finding_id` di `python_rules.py:51` (§3.6.2) — tidak memengaruhi *apa* yang terdeteksi maupun *seberapa parah* penilaiannya, hanya *bagaimana temuan diberi identitas*.

Pipeline 4-agent, `Brain`, `JobStore`, state machine `QUEUED → RUNNING → COMPLETED|FAILED`, `json_report.py`, `html_report.py`, dan seluruh kontrak endpoint lama tetap utuh. Enrichment CVSS terjadi di **lapisan report**, bukan di rules — secara arsitektural fitur ini tidak bisa mengubah hasil deteksi.

### 5.4 Titik integrasi

```
run_program_scan(include_paths?)          ← diff_scope.py
        │  findings[] (severity tetap)
        ▼
cvss.enrich_findings()                    ← +cwe, +cvss_score, +cvss_vector
        │
        ├──► dedupe.deduplicate()         ← kunci deterministik
        │
        ▼
   ReportState (dict)
        ├──► json_report.py    (sudah ada)
        ├──► html_report.py    (sudah ada)
        ├──► md_report.py      (sudah ada, +kolom CVSS)
        ├──► sarif.py          (BARU)
        └──► coverage.py       (BARU)
```

---

## 6. Keamanan, Etika & Robustness (wajib)

### 6.1 Guard SSRF tetap utuh

`compare_refs()` **hanya** memanggil `api.github.com` yang sudah ada di `ALLOWED_HOSTS` (`github_client.py:14-18`). Tidak ada pelonggaran allowlist. Rate limit ditangani dengan pola yang sudah ada (`:73-76`), dan kegagalan `compare` pada mode `auto` **jatuh ke `full`** (aman: memindai lebih banyak), sedangkan pada mode `diff` **gagal eksplisit** (aman: tidak berbohong tentang scope).

### 6.2 Redaksi pada artefak baru

SARIF dan `coverage.json` melewati `app/utils/redact.py` (`redact_headers:23`, `redact_cookies:37`, `redact_url_credentials:41`) sebelum serialisasi — sama seperti JSON/HTML/MD. Khusus SARIF, mengikuti keputusan Strix (`sarif.py:569-577`): **body PoC/evidence mentah tidak dimasukkan**; hanya metadata + lokasi. `github_token` tidak pernah masuk ke `report` (`github_engine.py:61` hanya meneruskan ke fetcher), dan test §7.7 mengunci properti ini.

### 6.3 Path traversal pada penulisan artefak

`--sarif` dan `--coverage` memakai guard yang sama dengan `--out` (`cli-experience.md` §6.3): path di-resolve, wajib di bawah cwd atau `reports_dir`, penulisan atomik (`.tmp` → `os.replace`).

### 6.4 Kejujuran laporan (etika)

Ini risiko etis paling nyata dari fitur ini: **diff-scope membuat scan parsial terlihat seperti scan penuh**. Mitigasi bersifat wajib, bukan opsional:

- `coverage.json` mencatat `files_excluded_by_scope` dan `scope.note`.
- SARIF `invocations[].properties.scope_mode` menandai scan parsial.
- CLI mencetak peringatan (§3.7.2).
- `.md` §6 memuat kalimat batasan.
- `complete: false` bila analisis terpotong.

Prinsip yang dipinjam dari Strix (`coverage.py:19-25`): klaim cakupan palsu **lebih buruk** daripada tidak ada klaim sama sekali.

### 6.5 Batas etis yang tidak dilanggar

Fitur ini **tidak** menambah kapabilitas ofensif apa pun. Tidak ada eksekusi kode target, tidak ada probing baru, tidak ada penulisan ke GitHub. Yang bertambah hanyalah *format keluaran* dan *penyempitan cakupan*. Gate `i_have_permission` (`models_github.py:35-42`) tetap berlaku tanpa perubahan.

---

## 7. Pengujian (tanpa network di CI)

1. **CVSS tabel** — untuk setiap entri §3.1.2, hitung via `CVSS3` dan bandingkan dengan skor+severity yang didokumentasikan. Test ini **menangkap kesalahan tabel**, bukan membenarkannya.
2. **Skema SARIF** — validasi `findings.sarif` terhadap `sarif-2.1.0.json` (skema di-vendor lokal agar hermetik).
3. **Normalisasi path** — absolut sandbox → relatif repo; path di luar `tree_root` → lokasi sintetis + flag; `..` ditolak.
4. **Determinisme** — render dua kali dari fixture yang sama → byte-identik kecuali timestamp (pola sama dengan test `md_report`).
5. **Diff-scope** — `MockTransport` untuk Compare API; assertion: hanya file dalam daftar yang dipindai; `excluded_count` benar.
6. **Diff gagal** — base tidak resolvable: mode `auto` → fallback `full` + alasan tercatat; mode `diff` → FAILED eksplisit.
7. **Redaksi** — scan dengan `--token`; grep `findings.sarif` + `coverage.json` → token tidak muncul.
8. **Coverage gap** — repo tanpa file PHP → `XS006`/`CY009`/`CY010` muncul di `gaps` dengan `reason="no_matching_files_in_scope"`; repo dengan PHP bersih → **tidak** muncul di gaps.
9. **`complete: false`** — cap file tercapai → flag `false`.
10. **Dedupe** — dua temuan `(rule, path, line)` identik → satu; lokasi berbeda → tetap dua.
11. **Backward compatibility** — report lama tanpa `cwe`/`cvss_*` tetap dirender oleh semua writer tanpa error.
12. **Severity tidak berubah** — jalankan `test_program_rules.py` & `test_xss_rules.py` yang ada; seluruhnya harus tetap hijau (membuktikan §3.1.3).
13. **Scan mode** — `quick` → hanya rule IDOR; `deep` → `scope_mode` menjadi `full`.
14. **Guard path** — `--sarif ../../tmp/x.sarif` → exit 3, tidak ada file tertulis.
15. **Keunikan `finding_id`** — scan `app/program/sample/` (yang menghasilkan 5 `CY004` di lokasi berbeda) → kelima `finding_id` **berbeda**; `len({f.finding_id}) == len(findings)` (§3.6.2).
16. **Tidak ada kebocoran path host** — grep `findings.sarif` dan `report.md` untuk `/home/`, `/Users/`, `C:\\` → nol kecocokan (§3.2.3).

Seluruh test hermetik: nol panggilan jaringan.

---

## 8. Kriteria Sukses (Acceptance Criteria)

1. ✅ `findings.sarif` lolos validasi skema SARIF 2.1.0 resmi.
2. ✅ Setiap temuan memiliki `cwe`, `cvss_score`, `cvss_vector` yang konsisten dengan tabel §3.1.2.
3. ✅ Nilai `severity` seluruh temuan **tidak berubah** dibanding sebelum fitur ini (test §7.12 hijau).
4. ✅ `location` di SARIF adalah path relatif repo (`backend/api/x.py`), bukan path sandbox absolut.
5. ✅ `coverage.json` membedakan "diperiksa & bersih" dari "tidak ada file yang cocok".
6. ✅ `--scope-mode diff` pada PR 3-file memindai tepat 3 file; `coverage.json` mencatat `excluded_count`.
7. ✅ Mode `diff` dengan base tidak resolvable → FAILED eksplisit (bukan diam-diam full).
8. ✅ `--scan-mode quick` hanya menjalankan rule IDOR dan lebih cepat dari `standard` pada repo yang sama.
9. ✅ Dua scan `repo@sha` sama → `findings.sarif` byte-identik kecuali timestamp.
10. ✅ `--token` tidak pernah muncul di `findings.sarif` maupun `coverage.json`.
11. ✅ SARIF hasil scan diff-scope menandai `scope_mode` di `invocations`.
12. ✅ CLI mencetak peringatan cakupan parsial saat `--scope-mode diff` aktif.
13. ✅ Report lama (tanpa field CVSS) tetap bisa dirender semua writer.
14. ✅ Tidak ada dependensi LLM yang ditambahkan; `pip list` hanya bertambah `cvss`.
15. ✅ Setiap `finding_id` dalam satu scan bersifat unik (§3.6.2) — 5 temuan `CY004` di lokasi berbeda menghasilkan 5 ID berbeda.
16. ✅ Tidak ada path absolut mesin host (`/home/…`, `/Users/…`) yang muncul di `findings.sarif` maupun `report.md`.

---

## 9. Risiko & Mitigasi

| ID | Risiko | Dampak | Mitigasi |
|----|--------|--------|----------|
| R1 | `location` berisi path absolut host / prefix sandbox (`python_rules.py:60`) — **terkonfirmasi di artefak nyata** | SARIF invalid; alert tidak muncul; struktur direktori developer bocor | Normalisasi §3.2.3 + lokasi sintetis + test §7.3/§7.16 |
| R10 | `finding_id` bertabrakan pada rule AST (`python_rules.py:51`) — **terkonfirmasi: 5 temuan berbagi 1 ID** | SARIF menggabungkan alert berbeda; `cyense fix` salah target; kartu CLI terlewat | Sertakan `lineno` di ID (§3.6.2); test §7.15 |
| R2 | CVSS (`medium`) berkonflik dengan severity (`high`) → membingungkan | Kepercayaan laporan turun | Dua field hidup berdampingan §3.1.3; `.md` menjelaskan perbedaannya |
| R3 | Diff-scope menyembunyikan kerentanan di file tak berubah | Rasa aman palsu | Wajib dicatat di coverage + SARIF + CLI + `.md` (§6.4) |
| R4 | Tidak ada `.git` di sandbox tarball | `git diff` mustahil | GitHub Compare API §3.3.2 (host sudah di allowlist) |
| R5 | Compare API menambah 1 call → rate limit anonim (60/jam) | Scan gagal saat batch | Hanya dipanggil bila diff-scope aktif; fallback `full` pada mode `auto`; pesan token actionable |
| R6 | Tabel CVSS statis mengabaikan konteks | Skor kurang presisi | Diterima secara sadar: determinisme > presisi. Mode `link` menyesuaikan dari bukti objektif (§3.1.4) |
| R7 | Skema SARIF luas → salah implementasi | Alert ditolak GitHub | Validasi skema di test (§7.2); ikuti keputusan desain Strix yang sudah terbukti |
| R8 | Dedupe agresif membuang temuan sah | Kehilangan temuan | Kunci mencakup `line`; hanya identik penuh yang digabung; test §7.10 |
| R9 | Scope creep ke arah fitur LLM Strix | Melanggar `PRD.md:82` | Non-Goals §2.2 eksplisit; review menolak PR yang menambah dep LLM |

---

## 10. Roadmap Implementasi

| Fase | Isi | Estimasi |
|------|-----|----------|
| 1 | `cvss.py` (tabel + kalkulasi) + field `Finding` + test §7.1/§7.12 | 0.5 hari |
| 2 | Normalisasi path + `sarif.py` + endpoint + validasi skema (§7.2/§7.3) | 1 hari |
| 3 | `coverage.py` + deteksi gap + `complete` flag + endpoint (§7.8/§7.9) | 0.5 hari |
| 4 | `diff_scope.py` + `compare_refs()` + `include_paths` (§7.5/§7.6) | 0.75 hari |
| 5 | `scan_modes.py` + flag CLI + peringatan + footer (§7.13/§7.14) | 0.5 hari |
| 6 | `dedupe.py` + integrasi `md_report` + README + eval | 0.5 hari |
| Lanjutan | PDF report, CVSS Temporal, ekspor CSV, GitHub Action siap-pakai | backlog |

Total MVP ≈ **3.75 hari**.

---

## 11. Open Questions

1. Apakah `severity` sebaiknya kelak diturunkan dari CVSS (seperti Strix `tool.py:148`)?
   → **Proposal:** tidak untuk MVP. Itu *breaking change* pada kontrak `GET /rules` dan acceptance criteria 4 PRD sebelumnya. Bila diinginkan, lakukan sebagai PRD tersendiri dengan periode deprecation.
2. Perlukah `coverage.json` mencatat daftar file yang dipindai secara lengkap?
   → **Proposal:** hanya jumlah + pecahan per bahasa. Daftar penuh membocorkan struktur repo privat ke artefak yang mungkin dibagikan, dan membengkak pada monorepo.
3. Haruskah diff-scope menyertakan file yang meng-*import* file berubah (analisis dependensi)?
   → **Proposal:** tidak untuk MVP — butuh import graph lintas-bahasa. Batasnya dijujurkan di coverage.
4. Apakah `--fail-on` sebaiknya bisa memakai ambang CVSS (`--fail-on-cvss 7.0`)?
   → **Proposal:** ya, tetapi fase lanjutan; `--fail-on <severity>` sudah menutup kebutuhan CI dasar.
5. Perlukah endpoint `/scans/{id}/report/sarif` atau cukup file di disk?
   → **Proposal:** keduanya. Endpoint untuk paritas dengan `report/html`; file untuk `upload-sarif` yang membaca dari filesystem.
6. Mode `link` menghasilkan temuan tanpa lokasi file — bagaimana di SARIF?
   → **Proposal:** `logicalLocations` dengan URL endpoint (pola Strix `sarif.py:34-36`), bukan anchor sintetis.

---

## 12. Changelog Fitur

| Versi | Perubahan |
|-------|-----------|
| 1.0 | Draft awal: adopsi 5 pola deterministik dari Strix v1.5.3 — SARIF 2.1.0 (`app/report/sarif.py`), CVSS v3.1 tabel-tetap per rule (`app/report/cvss.py`), `coverage.json` negative-space (`app/report/coverage.py`), diff-scope via GitHub Compare API (`app/engines/diff_scope.py`), scan mode `quick\|standard\|deep` (`app/core/scan_modes.py`), plus dedupe deterministik. Menolak secara eksplisit: LLM dedupe judge, Docker sandbox ofensif, multi-agent graph, MCP. Menetapkan koeksistensi `severity` (triase) dan `cvss_score` (teknis) tanpa mengubah nilai severity yang sudah ada. **Seluruh 18 skor CVSS pada §3.1.2 dan 8 kombinasi §3.1.4 diverifikasi terhadap rumus resmi CVSS v3.1 saat penulisan.** Menemukan dan menspesifikasikan perbaikan 2 bug nyata yang terkonfirmasi di artefak: path absolut host pada `location` (R1) dan tabrakan `finding_id` pada rule AST (R10). |

---

*Addendum ini tunduk pada PRD induk (`instruction/PRD.md`). Aturan konflik: PRD induk menang untuk hal yang tidak diatur di sini (etika, redaction, state machine, gaya commit). Batas arsitektural yang tidak boleh dilanggar: **keputusan no-LLM (`PRD.md:55`, `:82`) bersifat final** — fitur ini mengadopsi format & kontrak data dari Strix, bukan mesin nalar LLM-nya. Aturan deteksi (CY001–CY010, XS001–XS008) dan nilai `severity` yang sudah ada tidak boleh diubah oleh fitur ini; seluruh penambahan terjadi di lapisan report dan scope.*
