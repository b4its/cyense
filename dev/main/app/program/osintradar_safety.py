"""OSINT Radar analysis — security & privacy layer (§3.4) + declarative
workflow contract (§3.3.6).

Reference content, applied verbatim-in-substance from the catalogue analysis:
the document's closing rule — "treat implementasi tidak menyesatkan" — means
a UI that browses an OSINT catalogue must also surface the *normative frame*
the source treats as non-optional: minimisation, proportionality, lawful
basis, abuse-prevention controls, and an absolute child-protection gate.

Cyense's tools catalog is static + client-side (no user accounts, no
connector execution), so §3.4/§3.3.6 cannot be wired as *enforcement*; they
ship as the same kind of curated reference as ``TRAINING``: data for the
"Safety" view and the ``cyense tools safety`` command, so a team building an
OSINT program has the checklist at the point of use instead of buried in the
analysis PDF.

All strings Indonesian, mirroring the analysis document; ``forbidden`` uses
machine codes (subject_is_minor etc.) exactly as the §3.4.3 gate example.
"""

from __future__ import annotations

# §3.4.1 — Penanganan data sensitif
DATA_PRINCIPLES: list[dict[str, str]] = [
    {
        "id": "encryption-baseline",
        "title": "Enkripsi = dasar minimum, bukan pencapaian",
        "body": (
            "In-transit TLS 1.3 dan at-rest AES-256 adalah baseline. Yang "
            "menentukan kepatuhan bukan adanya enkripsi, melainkan minimisasi."
        ),
    },
    {
        "id": "minimisation",
        "title": "Minimisasi data",
        "body": (
            "Kumpulkan hanya field yang menjawab pertanyaan investigasi, dan "
            "hapus sisanya pada tahap normalisasi. Prinsip sumber: 'Collect "
            "the minimum needed to answer your investigative question, and "
            "treat incidental data about third parties as out of bounds.'"
        ),
    },
    {
        "id": "incidental-third-party",
        "title": "Data pihak ketiga insidental",
        "body": (
            "Ketika lookup mengembalikan daftar 'kerabat' atau 'rekan' yang "
            "tidak relevan, jangan simpan. Terapkan filter di pipeline — bukan "
            "mengandalkan analis untuk mengabaikan hasilnya."
        ),
    },
    {
        "id": "secrets",
        "title": "Kredensial & token API",
        "body": (
            "Secret manager (Vault / AWS Secrets Manager) dengan rotasi "
            "terjadwal; kunci tidak masuk kode atau image."
        ),
    },
    {
        "id": "log-redaction",
        "title": "Redaksi log otomatis",
        "body": (
            "Identifier subjek tidak boleh berakhir di sistem observability "
            "yang cakupan aksesnya lebih luas dari data kasusnya."
        ),
    },
]

# §3.4.2 — Kepatuhan regulasi privasi (kebijakan: lokasi SUBJEK & OPERATOR
# menentukan hukum, bukan lokasi server).
REGULATIONS: list[dict[str, str]] = [
    {
        "code": "gdpr",
        "name": "GDPR (UE/EEA)",
        "duties": (
            "Dasar hukum wajib (umumnya legitimate interest + document LIA); "
            "batasan tujuan; minimisasi; hak subjek (akses/hapus/keberatan); "
            "DPIA untuk pemrosesan berisiko tinggi; Pasal 9 = perlindungan "
            "khusus data biometrik, kesehatan, politik, orientasi seksual."
        ),
    },
    {
        "code": "uu-pdp",
        "name": "UU PDP 27/2022 (Indonesia)",
        "duties": (
            "Dasar pemrosesan sah; pemberitahuan; hak subjek data mirip "
            "GDPR; notifikasi kebocoran; pembatasan transfer lintas negara."
        ),
    },
    {
        "code": "ccpa",
        "name": "CCPA/CPRA (California)",
        "duties": (
            "Hak tahu, hapus, dan opt-out penjualan; kewajiban pengungkapan "
            "kategori data yang dikumpulkan."
        ),
    },
    {
        "code": "fcra",
        "name": "FCRA (AS)",
        "duties": (
            "Keputusan kerja/kredit/asuransi/perumahan hanya lewat consumer "
            "reporting agency teregulasi — agregator people search umumnya "
            "BUKAN CRA, sehingga penggunaan demikian melanggar hukum."
        ),
    },
    {
        "code": "bipa",
        "name": "BIPA (Illinois) & UU biometrik",
        "duties": (
            "Persetujuan tertulis sebelum pengumpulan identifier biometrik; "
            "berdampak langsung pada penggunaan pengenalan wajah."
        ),
    },
    {
        "code": "computer-misuse",
        "name": "Computer misuse (global)",
        "duties": (
            "Akses tidak sah, bypass kontrol teknis, dan pemindaian tanpa izin "
            "adalah pidana terlepas dari niat penelitian."
        ),
    },
]

JURISDICTION_RULE = (
    "Tentukan hukum yang berlaku dari lokasi OPERATOR dan lokasi SUBJEK — "
    "bukan lokasi server. Prinsip sumber: 'You are responsible for knowing "
    "the law where you operate and where your subject is located.'"
)

# §3.4.3 — Perlindungan terhadap penyalahgunaan (kontrol organisasional).
ABUSE_CONTROLS: list[dict[str, str]] = [
    {
        "id": "rbac-sod",
        "title": "RBAC + pemisahan tugas",
        "body": (
            "Analis dapat mengumpulkan; hanya supervisor yang dapat mengekspor; "
            "hanya admin yang dapat mengubah retensi."
        ),
    },
    {
        "id": "mandatory-case",
        "title": "Kasus wajib untuk setiap query",
        "body": (
            "Tidak ada pencarian ad hoc tanpa referensi kasus, dasar hukum, dan "
            "tujuan yang tercatat."
        ),
    },
    {
        "id": "audit-log",
        "title": "Log audit append-only",
        "body": (
            "Mencatat siapa mencari apa, kapan, di bawah kasus mana — kontrol "
            "paling efektif melawan penyalahgunaan internal: pengetahuan bahwa "
            "setiap query tercatat mengubah perilaku."
        ),
    },
    {
        "id": "anomaly",
        "title": "Deteksi anomali",
        "body": (
            "Volume tidak wajar, query berulang pada subjek yang sama di luar "
            "kasus aktif, pencarian di luar jam kerja."
        ),
    },
    {
        "id": "hard-gate",
        "title": "Gerbang kebijakan keras",
        "body": (
            "MENOLAK eksekusi, bukan hanya memperingatkan — dan dievaluasi "
            "SEBELUM query dijalankan, bukan sesudahnya."
        ),
    },
    {
        "id": "authorized-assets",
        "title": "Daftar aset terotorisasi (kategori offensif)",
        "body": (
            "Tool offensif (port scanner, exploit DB, kredensial default, ASM, "
            "brute-force direktori) hanya dieksekusi terhadap aset yang terdaftar "
            "dengan bukti otorisasi tertulis; sisanya ditolak secara default."
        ),
    },
]

# Kode gerbang keras persis contoh §3.4.3 — subject_is_minor mutlak tanpa override.
HARD_REFUSALS: list[dict[str, str]] = [
    {
        "code": "subject_is_minor",
        "label": "Perlindungan anak",
        "body": (
            "Penolakan MUTLAK — tanpa pengecualian, tanpa jalur override — untuk "
            "permintaan yang menargetkan anak, kecuali perlindungan anak yang "
            "dijalankan lembaga berwenang. Kombinasi pengenalan wajah + geolokasi "
            "agregat profil sosial = perangkat sangat berbahaya bila diarahkan "
            "ke minor; tidak ada alasan penelitian yang membenarkannya."
        ),
    },
    {
        "code": "no_case_reference",
        "label": "Tanpa referensi kasus",
        "body": "Query ditolak bila tidak terikat kasus dengan dasar hukum + tujuan.",
    },
    {
        "code": "purpose_not_declared",
        "label": "Tanpa deklarasi tujuan",
        "body": "Batasan tujuan harus dinyatakan sebelum pengumpulan.",
    },
    {
        "code": "unauthorized_target_asset",
        "label": "Target offensif tak terotorisasi",
        "body": "Aset tidak ada dalam daftar terotorisasi tertulis → ditolak default.",
    },
]

# §3.3.6 — kontrak orkestrasi deklaratif; blok policy dievaluasi sebelum
# eksekusi. Contoh (adaptasi analyze-an-email dari dokumen) disajikan apa
# adanya untuk tim yang membangun executor — Cyense TIDAK menjalankan konektor.
WORKFLOW_CONTRACT_YAML = """\
workflow: analyze-an-email
input:
  type: email
  validate: [syntax, mx_exists]
steps:
  - id: breach_check
    connector: hibp
    note: "Jalankan lebih dahulu — paling murah dan paling tidak invasif"
    on_success:
      emit: [breach_names, breach_dates]
  - id: reputation
    connector: emailrep
    depends_on: [breach_check]
    emit: [reputation_score]
  - id: domain_pivot
    connector: rdap
    input_from: "{{ input.email | domain_part }}"
    emit: [registrar, nameservers, creation_date]
  - id: mx_dns
    connector: dns
    records: [MX, SPF, DMARC, DKIM]
    emit: [mail_infrastructure]
  - id: archive
    connector: warc
    always_run: true
    note: "Arsipkan setiap halaman hasil sebelum melanjutkan"
policy:                      # gerbang kebijakan dievaluasi SEBELUM eksekusi
  max_total_requests: 40
  require_case_reference: true
  forbid_if: "subject_is_minor"
checkpoints:                 # meniru Reporting Checkpoints platform
  - record_target_value
  - record_source_and_time
  - quote_observed_result
  - assign_confidence
"""

SAFETY: dict[str, object] = {
    "motto": "OSINT is a method, not a license.",
    "aggregation_warning": (
        "'Public availability is not moral license. A person's scattered "
        "public traces, aggregated, can be far more invasive than any single "
        "datum.' — proporsionalitas adalah rujukan normatif seluruh lapisan ini."
    ),
    "data_principles": DATA_PRINCIPLES,
    "regulations": REGULATIONS,
    "jurisdiction_rule": JURISDICTION_RULE,
    "abuse_controls": ABUSE_CONTROLS,
    "hard_refusals": HARD_REFUSALS,
    "workflow_contract": {
        "note": (
            "Saran utama §3.3.6 bila Anda membangun EXECUTOR (Cyense hanya katalog "
            "+ sisi klien): nyatakan workflow secara deklaratif dengan blok policy "
            "yang dievaluasi sebelum eksekusi — blok yang paling sering diabaikan "
            "namun paling penting."
        ),
        "yaml": WORKFLOW_CONTRACT_YAML,
    },
}

__all__ = [
    "ABUSE_CONTROLS",
    "DATA_PRINCIPLES",
    "HARD_REFUSALS",
    "JURISDICTION_RULE",
    "REGULATIONS",
    "SAFETY",
]
