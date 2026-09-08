"""OSINT Radar methodology layer — the platform's own functional features.

Source: independent analysis of osintradar.com (2026-09-08, doc v1.0) covering
``/tools``, ``/categories``, ``/workflows``, ``/free-tools``, ``/about``,
``/responsible-use`` and ``sitemap.xml``.

The analysis' central finding: the 346-entry tool library is a *curated
catalog* (tools execute on third-party sites); the platform's own functional
layer ("Lapis A") is the **pivot map**, the **investigative workflows**, the
**case file**, and **Toolbench**. ``osintradar_tools.py`` mirrors the catalog;
this module mirrors the methodology layer, which is what actually drives an
investigation:

  * ``PIVOT_TYPES``            — the site's verified identifier vocabulary
    (accepted inputs; ``you_have`` in the catalog data already uses these codes)
  * ``CONFIDENCE_SCALE``       — the 4-level analytic confidence standard
    (confirmed / probable / lead / disputed)
  * ``REPORTING_CHECKPOINTS``  — the per-finding recording discipline every
    workflow enforces
  * ``WORKFLOWS``              — the 6 investigative frameworks, with each
    step mapped to catalog tool names (resolved case-insensitively in the UI)
  * ``CATEGORY_NOTES``         — per-OSR-category limitations + the risk
    classes the analysis recommends surfacing next to the most sensitive
    groups (per-tool risk labelling as future work)

Toolbench (7 utilitas lokal) dan Case File diimplementasikan sebagai *fitur UI
klien* (Svelte: ``components/Toolbench.svelte``, ``lib/casefile.js`` —
murni browser, tanpa backend), jadi keduanya tidak butuh modul data Python.
Semua yang ada di sini adalah materi presentasi + referensi — tidak ada engine,
rule, atau state machine scan yang berubah.
"""

from __future__ import annotations

# ruff: noqa: E501 — category limitation notes mirror the source analysis
# verbatim enough to be useful; wrapping long prose strings adds no value.

# ---------------------------------------------------------------------------
# Pivot vocabulary — "saya punya X, apa langkah berikutnya?"
# Codes are exactly the values used in the catalog's ``you_have`` lists.
# ---------------------------------------------------------------------------

PIVOT_TYPES: list[dict[str, str]] = [
    {"code": "name", "label": "Nama"},
    {"code": "company", "label": "Perusahaan"},
    {"code": "username", "label": "Username"},
    {"code": "email", "label": "Email"},
    {"code": "domain", "label": "Domain"},
    {"code": "ip", "label": "IP"},
    {"code": "url", "label": "URL"},
    {"code": "wallet", "label": "Wallet"},
    {"code": "location", "label": "Lokasi"},
    {"code": "image", "label": "Gambar"},
    {"code": "file", "label": "Berkas"},
    {"code": "phone", "label": "Telepon"},
]

# ---------------------------------------------------------------------------
# Analytic confidence — mirrors the platform's "Reporting Checkpoints"
# confidence wording plus the implementation guide's 4-level scale.
# ---------------------------------------------------------------------------

REPORTING_CHECKPOINTS: list[dict[str, str]] = [
    {
        "id": "target_value",
        "label": "Target value",
        "detail": "Catat identifier persis yang dicari — literal, tanpa normalisasi diam-diam.",
    },
    {
        "id": "source_and_time",
        "label": "Source and time",
        "detail": "URL sumber, timestamp koleksi, dan timestamp arsip dicatat terpisah.",
    },
    {
        "id": "observed_result",
        "label": "Observed result",
        "detail": "Kutip hasil mentah sebelum menafsirkannya.",
    },
    {
        "id": "confidence",
        "label": "Confidence",
        "detail": "Beri level keyakinan eksplisit untuk setiap temuan.",
    },
]

CONFIDENCE_SCALE: list[dict[str, str]] = [
    {
        "level": "confirmed",
        "criteria": "≥2 sumber independen berkualitas tinggi + artefak terarsip.",
        "example": "Kepemilikan domain dari RDAP + sertifikat CT yang cocok.",
    },
    {
        "level": "probable",
        "criteria": "1 sumber kuat, atau beberapa sumber lemah yang konsisten.",
        "example": "Handle sama di 4 platform dengan foto profil identik.",
    },
    {
        "level": "lead",
        "criteria": "Satu sinyal lemah, belum terkorroborasi.",
        "example": "Nama muncul di direktori agregator.",
    },
    {
        "level": "disputed",
        "criteria": "Sumber saling bertentangan.",
        "example": "Dua rekaman alamat berbeda pada periode sama.",
    },
]

# ---------------------------------------------------------------------------
# The 6 investigative frameworks ("Start from an investigative question,
# not a tool list"). ``tools`` entries reference catalog names (matched
# case-insensitively by the UI; unmatched names render as plain text).
# ---------------------------------------------------------------------------

WORKFLOWS: list[dict[str, object]] = [
    {
        "slug": "investigate-a-username",
        "question": "Saya punya username — siapa di baliknya?",
        "start_type": "username",
        "summary": (
            "Perluas satu handle menjadi banyak lead, verifikasi setiap "
            "kemunculan, lalu pivot ke identifier baru."
        ),
        "caution": (
            "Treat results as leads, not confirmations — name collisions "
            "are common. Verifikasi manual (foto, bio, pola posting) wajib."
        ),
        "steps": [
            {
                "title": "Enumerate the handle",
                "detail": "Sweep lintas platform sosial, dev, forum, dan paste site.",
                "tools": [
                    "IDCrawl", "Instantusername", "NameCheckr", "NameChk",
                    "Rosint+", "TikTok User Finder", "Tikip", "Whatsmyname",
                    "User Search",
                ],
            },
            {
                "title": "Verify each hit",
                "detail": (
                    "Status HTTP saja menghasilkan false positive; konfirmasi "
                    "dengan pola konten halaman dan konsistensi profil."
                ),
                "tools": ["Namecheckup", "Osint Workbench"],
            },
            {
                "title": "Check breach exposure",
                "detail": "Kebocoran sering menautkan handle ke email.",
                "tools": ["Haveibeenpwned", "Digital Traces"],
            },
            {
                "title": "Pivot to new identifiers",
                "detail": "Dari profil valid → email, domain, lokasi, jaringan sosial.",
                "tools": ["Emailrep", "DeHashed", "Webmii"],
            },
        ],
    },
    {
        "slug": "analyze-an-email",
        "question": "Saya punya alamat email — seberapa kuat signalnya?",
        "start_type": "email",
        "summary": (
            "Mulai dari sumber termurah dan paling tidak invasif (breach "
            "check), baru naik ke reputasi dan pendaftaran sistem."
        ),
        "caution": (
            "Kehadiran di breach ≠ kepemilikan akun. Breach context matters "
            "as much as presence — selalu catat breach spesifiknya."
        ),
        "steps": [
            {
                "title": "Breach check lebih dahulu",
                "detail": (
                    "Jalankan sebelum tool yang lebih invasif — paling murah, "
                    "paling tidak mengganggu."
                ),
                "tools": ["Haveibeenpwned"],
            },
            {
                "title": "Reputasi & keberadaan",
                "detail": "Skor reputasi, association fraud, layanan tertaut.",
                "tools": ["Emailrep", "GHunt"],
            },
            {
                "title": "Perdalam dataset",
                "detail": "DeHashed dsb. untuk data breach yang lebih dalam.",
                "tools": ["DeHashed"],
            },
            {
                "title": "Pivot ke infrastruktur",
                "detail": "Domain bagian → registrasi, MX, SPF/DKIM/DMARC.",
                "tools": ["Easy whois", "Email Tools", "DNSai"],
            },
            {
                "title": "Analisis header (lokal)",
                "detail": (
                    "Raw header RFC 5322 → rantai relay, IP asal, verdict "
                    "autentikasi — tanpa mengirim data ke pihak ketiga."
                ),
                "tools": [],
            },
        ],
    },
    {
        "slug": "research-a-domain",
        "question": "Saya punya domain — bagaimana infrastruktur & riwayatnya?",
        "start_type": "domain",
        "summary": (
            "Registrasi, riwayat DNS, dan enumerasi subdomain lewat jalur "
            "pasif (CT logs) sebelum menyentuh target."
        ),
        "caution": (
            "Kontak WHOIS modern umumnya diredaksi (GDPR) — jangan berharap "
            "nama pemilik. Enumerasi aktif terlihat oleh target; CT pasif."
        ),
        "steps": [
            {
                "title": "Registrasi & kepemilikan",
                "detail": "WHOIS/RDAP: registrar, tanggal, name server, status.",
                "tools": ["Easy whois", "Who Is", "Whoxy", "Domain Tools"],
            },
            {
                "title": "Histori DNS",
                "detail": (
                    "Passive DNS melacak migrasi hosting domain↔IP — arsip "
                    "resolver global, bukan query live."
                ),
                "tools": ["DNS History", "Central Ops", "Security Trails"],
            },
            {
                "title": "Sertifikat & subdomain",
                "detail": "Certificate Transparency tanpa menyentuh target.",
                "tools": [
                    "Certificate Search", "CertObserver CT search",
                    "Cert Graph Crawler", "theHarvester",
                ],
            },
            {
                "title": "Typosquat & klaster",
                "detail": (
                    "Permutasi domain (typo, homoglif, bit-squatting) + "
                    "reverse WHOIS untuk klaster infrastruktur."
                ),
                "tools": ["DNS twister", "Whoisology", "New Domain Hunter"],
            },
        ],
    },
    {
        "slug": "verify-an-image",
        "question": "Gambar ini asli atau daur ulang?",
        "start_type": "image",
        "summary": (
            "Metadata dulu, lalu reverse search lintas waktu, baru analisis "
            "forensik — dan jangan pernah berhenti pada satu sinyal."
        ),
        "caution": (
            "EXIF mudah dipalsukan dan dihapus platform sosial. ELA bukan "
            "bukti manipulasi konklusif. Hasil pengenalan wajah tidak boleh "
            "jadi dasar identifikasi tunggal."
        ),
        "steps": [
            {
                "title": "Metadata & hash",
                "detail": "GPS, model kamera, timestamp, hash file.",
                "tools": ["Exif Viewer", "EXIF.tools"],
            },
            {
                "title": "Reverse search",
                "detail": (
                    "Perceptual hashing menahan crop/kompresi — cari sumber "
                    "asli dan kemunculan termuda."
                ),
                "tools": ["Reverse Image Search", "Reverse Image", "Gif reverse"],
            },
            {
                "title": "Forensik & sintesis",
                "detail": "Error level analysis + deteksi konten AI.",
                "tools": ["Foto Forensics", "AI or Not"],
            },
            {
                "title": "Kandidat lokasi",
                "detail": "Prediksi lokasi bersifat probabilistik — lead, bukan bukti.",
                "tools": ["Photo location", "Whereisthepicture"],
            },
        ],
    },
    {
        "slug": "locate-a-place",
        "question": "Di mana tepatnya tempat ini?",
        "start_type": "location",
        "summary": (
            "Konvergen dari tiga kelas bukti: citra satelit, fitur jalan, dan "
            "sains (matahari, menara) — saling mengkoreksi atau gugur."
        ),
        "caution": (
            "Basis menara & Wi-Fi crowdsourced bias ke wilayah padat; citra "
            "satelit gratis beresolusi terbatas dan tidak real-time."
        ),
        "steps": [
            {
                "title": "Kandidat awal",
                "detail": "Kemiripan visual terhadap citra geolokasi berlabel.",
                "tools": ["Whereisthepicture", "Photo location"],
            },
            {
                "title": "Fitur jalan & panorama",
                "detail": "Street view crowdsourced untuk konfirmasi detail.",
                "tools": ["Mapillary", "Dual Maps"],
            },
            {
                "title": "Citra historis multi-temporal",
                "detail": "Sebelum/sesudah peristiwa untuk tanggal absolut.",
                "tools": ["Image Wayback", "Earth Explorer", "Flash Earth"],
            },
            {
                "title": "Chronolocation",
                "detail": "Arah & panjang bayangan → estimasi waktu penampakan.",
                "tools": ["Sun Calculator", "Geodetic Calculators"],
            },
            {
                "title": "Korelasi sinyal",
                "detail": "Cell-ID/BSSID ke koordinat via basis komunitas.",
                "tools": ["CellMapper 2/4G", "OpenCellID", "Wireless Networks"],
            },
        ],
    },
    {
        "slug": "trace-a-wallet",
        "question": "Ke mana aliran dana wallet ini?",
        "start_type": "wallet",
        "summary": (
            "Ekspansi klaster per hop, label entitas, dan catat setiap asumsi "
            "heuristik — attribution nyata umumnya butuh data non-OSINT."
        ),
        "caution": (
            "Label entitas probabilistik dan usang; CoinJoin/custodial wallet/"
            "batching bursa mematahkan heuristik klaster. Monero menyembunyikan "
            "pengirim, penerima, dan jumlah secara desain."
        ),
        "steps": [
            {
                "title": "Ledger dasar",
                "detail": "Saldo, transaksi, counterparty langsung.",
                "tools": [
                    "Block Explorer", "Blockchain explorer", "Ether Scan",
                    "EtherChain", "Wallet Explorer",
                ],
            },
            {
                "title": "Atribusi entitas",
                "detail": "Label exchange/entitas + wallet clustering.",
                "tools": ["ARKHAM INTEL", "Bitcoin WhosWho", "Bitref"],
            },
            {
                "title": "Monitoring & intel",
                "detail": "Pemantauan saldo via xPub; pencarian klaster terkait.",
                "tools": ["Blockonomics", "IntelX", "Live Coin Watch"],
            },
            {
                "title": "Batasan privasi",
                "detail": "Explorer XMR hanya memberi data blok/hashrate.",
                "tools": ["Monero Blocks", "XMR Chain"],
            },
        ],
    },
]

# ---------------------------------------------------------------------------
# Per-category limitations + risk classes (from the catalogue analysis,
# section B1–B21; implementation guide §3.4 / §4.2 recommends surfacing
# risk explicitly rather than burying it in prose).
# ---------------------------------------------------------------------------

CATEGORY_NOTES: dict[str, dict[str, str]] = {
    "osint-academic": {
        "note": "Nama umum menimbulkan tabrakan masif; catatan genealogis user-submitted dan tidak terautentikasi.",
        "risk": "hukum",
    },
    "osint-archive": {
        "note": "Konten dinamis sering tidak terekam utuh; screenshot tanpa hash+timestamp bernilai pembuktian rendah; memantau individu berkelanjutan bisa melanggar batas responsible use.",
    },
    "osint-breach": {
        "note": "Kehadiran dalam breach tidak membuktikan kepemilikan akun; mengakses akun dengan kredensial bocor adalah tindak pidana di hampir semua yurisdiksi.",
        "risk": "hukum",
    },
    "osint-crypto": {
        "note": "Label entitas probabilistik dan sering usang; heuristik klaster salah pada CoinJoin/custodial/batching bursa; Monero secara desain tidak dapat ditelusuri.",
    },
    "osint-threat": {
        "note": "Memuat tool offensif (pemindai port, basis eksploit, ASM) — sah hanya terhadap aset milik sendiri atau dengan otorisasi tertulis; unggahan ke sandbox publik umumnya dapat diakses publik.",
        "risk": "offensif",
    },
    "osint-darkweb": {
        "note": "Risiko hukum dan keselamatan nyata — wajib VM terisolasi dan pemisahan identitas; indeks .onion sangat usang; direktori dipenuhi phishing dan penipuan.",
        "risk": "operasional",
    },
    "osint-domain": {
        "note": "Kontak WHOIS pasca-2018 mayoritas diredaksi (GDPR + privasi registrar); enumerasi aktif menghasilkan trafik yang terlihat target — pendekatan CT bersifat pasif.",
    },
    "osint-email": {
        "note": "Server catch-all mengembalikan 'valid' untuk alamat apa pun; provider besar mengaburkan respons RCPT TO; verifikasi tidak membuktikan siapa yang mengendalikan mailbox.",
    },
    "osint-geo": {
        "note": "Basis menara/Wi-Fi crowdsourced bias ke wilayah padat kontributor; prediksi lokasi berbasis AI probabilistik dan tidak boleh diperlakukan sebagai bukti.",
    },
    "osint-ip": {
        "note": "Geolokasi tingkat kota sering salah puluhan–ratusan km dan pada CGNAT bisa menunjuk kantor pusat operator; alamat IP mengidentifikasi koneksi, bukan orang.",
    },
    "osint-image": {
        "note": "Pengenalan wajah = kelas fitur paling berisiko di katalog: false positive meyakinkan, tingkat kesalahan berbeda antar kelompok demografis, tunduk UU biometrik (GDPR Pasal 9, BIPA). Jangan jadikan dasar identifikasi tunggal.",
        "risk": "biometrik",
    },
    "osint-search": {
        "note": "Mesin pencari membatasi automasi agresif (CAPTCHA); hasil personal dan berubah — arsipkan bersama timestamp; dorking ke data sensitif pihak lain berpotensi melanggar hukum.",
        "risk": "hukum",
    },
    "osint-people": {
        "note": "Kategori potensi penyalahgunaan tertinggi — tidak boleh untuk melacak/memantau/memprofilkan individu atas alasan pribadi (stalking, pidana di sebagian besar wilayah); data agregator usang dan bercampur antar-orang bernama sama; cakupan kuat di AS, lemah di banyak negara.",
        "risk": "privasi tinggi",
    },
    "osint-privacy": {
        "note": "Kategori yang melindungi penyelidik, bukan menargetkan subjek; VPN gratis punya model bisnis meragukan; satu login ke akun pribadi dari infrastruktur investigasi menggagalkan seluruh rantai OPSEC.",
    },
    "osint-records": {
        "note": "Ketersediaan rekaman sangat bervariasi antar-yurisdiksi; sebagian entri sudah mati meski masih terdaftar; memakai agregator untuk keputusan kerja/kredit melanggar FCRA di AS.",
        "risk": "hukum",
    },
    "osint-social": {
        "note": "Kategori paling cepat rusak — banyak tool bergantung API yang ditutup; prioritaskan API resmi dan arsip pihak ketiga; pola waktu posting mengungkap zona waktu dan rutinitas subjek.",
        "risk": "ToS",
    },
    "osint-synthetic": {
        "note": "Kata kuncinya 'authorized' — identitas sintetis untuk menipu individu atau membuka rekening adalah penipuan; artefak chat sintetis hanya layak dipakai untuk mengenali (bukan memproduksi) disinformasi.",
        "risk": "penipuan",
    },
    "osint-training": {
        "note": "Fondasi metodologi tetapi baru 2 entri — kesenjangan paling jelas dalam katalog; materi pelatihan cepat usang mengikuti perubahan platform.",
    },
    "osint-transport": {
        "note": "AIS dan ADS-B tidak terenkripsi/terautentikasi sehingga dapat dipalsukan (spoofing terdokumentasi luas); ketiadaan sinyal bukan berarti ketiadaan kapal; data infrastruktur kritis sensitif.",
    },
    "osint-username": {
        "note": "Hasil adalah lead, bukan konfirmasi — tabrakan nama lazim; deteksi berbasis kode status menghasilkan false positive pada halaman generik dan false negative di balik login/anti-bot.",
    },
    "osint-web": {
        "note": "Brute-force direktori hanya boleh pada aset terotorisasi; membuka URL mencurigakan langsung berisiko — gunakan sandbox/layanan analisis; scraping tunduk ToS dan robots.txt.",
        "risk": "offensif",
    },
}

__all__ = [
    "CATEGORY_NOTES",
    "CONFIDENCE_SCALE",
    "PIVOT_TYPES",
    "REPORTING_CHECKPOINTS",
    "WORKFLOWS",
]
