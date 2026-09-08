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
  * ``WORKFLOWS``              — the 6 original investigative frameworks from
    OSINT Radar + 4 Cyense extensions (flagged ``extension: True``) filling the
    categories §4.2 flags as lacking an alur; each step maps to catalog tool
    names (resolved case-insensitively in the UI)
  * ``CATEGORY_NOTES``         — per-OSR-category limitations + the risk
    classes the analysis recommends surfacing next to the most sensitive groups
  * ``TOOL_RISK`` / ``TOOL_RISK_WHY`` — per-tool risk class for the specific
    tools the analysis singles out (§B5/B11/B13/B14), with rationale
  * ``JURISDICTION``           — region-coverage hints (§B13: aggregator
    coverage is US-centric; RIRs; UK/CA portals)

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
            "Label entitas probabilistik dan sering usang; CoinJoin/custodial wallet/"
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
                "tools": ["ARKHAM INTEL", "Bitcoin WhosWho", "BitRef"],
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
    # ── Fase 4: perluasan cakupan workflow (§4.2 — dari 6 untuk mengisi 4
    # kategori yang disebut dokumen tidak punya alur: threat intelligence,
    # dark web, transport tracking, verifikasi rekaman publik) ──
    {
        "slug": "triage-a-threat-alert",
        "extension": True,
        "question": "Alert menyebut IP/domain/hash — nyata atau derau?",
        "start_type": "ip",
        "summary": (
            "Pisahkan pemindai internet oportunistik dari ancaman tertarget, "
            "perkaya indikator multi-sumber, lalu petakan ke taktik ATT&CK."
        ),
        "caution": (
            "Unggahan sampel ke sandbox publik umumnya dapat diakses publik — "
            "jangan pernah unggah dokumen sensitif; verdict agregat engine memuat "
            "false positive. Kategori ini offensif-adjacent: hanya aset terotorisasi."
        ),
        "steps": [
            {
                "title": "Reputasi indikator",
                "detail": "Laporan komunitas + blocklist + skor reputasi.",
                "tools": ["VirusTotal", "Abuse IP DB", "Pulsedive", "Spamhaus", "Phishtank"],
            },
            {
                "title": "Konteks jaringan",
                "detail": "Pemindaian internet-wide pasif, ASN/RIR, klasifikasi sumber scan.",
                "tools": ["Shodan", "Censys Search", "Greynoise", "RIPE", "ARIN"],
            },
            {
                "title": "Perilaku sampel",
                "detail": "Sandbox dinamis + basis kerentanan + basis intel malware.",
                "tools": ["Hybrid analysis", "Exploit DB", "Vulnerability DB", "OSV Database", "Malpedia Library"],
            },
            {
                "title": "Korelasi & pemetaan",
                "detail": "IOC sharing (STIX/TAXII) + honeypot + pemetaan teknik adversary.",
                "tools": ["MISP Project", "Honey DB", "Ransomware finder", "Mitre Attack"],
            },
            {
                "title": "Arsipkan bukti triase",
                "detail": "Snapshot halaman verdict + timestamp terpisah.",
                "tools": ["Hunchly", "Webpage Saver", "ArchiveBox"],
            },
        ],
    },
    {
        "slug": "investigate-a-darkweb-service",
        "extension": True,
        "question": "Layanan .onion ini — aktif, dan apa hubungannya dengan clearnet?",
        "start_type": "url",
        "summary": (
            "Temukan layanan tersembunyi, periksa kebocoran konfigurasi operator "
            "yang menautkannya ke clearnet, dan verifikasi status relay."
        ),
        "caution": (
            "Wajib VM terisolasi + pemisahan identitas (OPSEC); konten ilegal dapat "
            "termuat tanpa disengaja — sebagian materi ilegal untuk sekadar diunduh. "
            "Indeks .onion sangat usang; direktori penuh phishing."
        ),
        "steps": [
            {
                "title": "Temukan & indeks",
                "detail": "Mesin pencari & direktori onion (dengan skeptisisme).",
                "tools": ["Ahmia", "Onion Search Engine", "BlackWeb", "Thehiddenwiki", "Onion Links"],
            },
            {
                "title": "Pemeriksaan kerentanan konfigurasi",
                "detail": "Kebocoran klasik: server-status, EXIF gambar, sertifikat, reused Bitcoin address.",
                "tools": ["Onion Inspector", "Onion Scan", "Onion Scan Tool", "Dark Web Tools"],
            },
            {
                "title": "Riwayat relay",
                "detail": "Apakah IP ini exit/relay Tor pada tanggal peristiwa — memisahkan derau dari pemilik IP.",
                "tools": ["Tor IP Relay", "Tor Project"],
            },
            {
                "title": "Korelasi clearnet",
                "detail": "Tautkan indikator yang bocor ke domain/IP/identitas clearnet.",
                "tools": ["Certificate Search", "Shodan", "IntelX"],
            },
        ],
    },
    {
        "slug": "track-a-vessel-or-flight",
        "extension": True,
        "question": "Benarkah kapal/pesawat ini berada di lokasi & waktu yang diklaim?",
        "start_type": "location",
        "summary": (
            "Verifikasi pergerakan lintas udara/laut dari siaran ADS-B/AIS dan "
            "koridas darat — dengan kesadaran penuh kedua protokol dapat dipalsukan."
        ),
        "caution": (
            "AIS & ADS-B tidak terenkripsi dan tidak terautentikasi — spoofing "
            "terdokumentasi luas (penghindaran sanksi); ketiadaan sinyal ≠ tidak ada "
            "kapal; sebagian penerbangan disensor platform; data infrastruktur "
            "kritis sensitif di tangan yang salah."
        ),
        "steps": [
            {
                "title": "Posisi & rute langsung",
                "detail": "Agregasi siaran ADS-B/AIS dari feeder sukarelawan.",
                "tools": ["Flight Radar", "Flight Aware", "Marine Traffic", "Vessel Finder", "Vessel Tracker"],
            },
            {
                "title": "Riwayat pergerakan",
                "detail": "Port call, lintasan lama, jadwal satelit.",
                "tools": ["Live Train Tracker", "Open Railway Map", "Satellite Tracking", "Military Tracking"],
            },
            {
                "title": "Koridor & infrastruktur",
                "detail": "Kabel, jaringan listrik/telekom — konteks geografis.",
                "tools": ["Submarine Cable Map", "Open Infrastructure"],
            },
            {
                "title": "Korroborasi independen",
                "detail": "Citra satelit bertanggal untuk konfirmasi sebelum/sesudah.",
                "tools": ["Image Wayback", "Earth Explorer"],
            },
        ],
    },
    {
        "slug": "verify-a-public-record",
        "extension": True,
        "question": "Klaim ini harus dipegang oleh rekaman resmi — ada tidaknya?",
        "start_type": "name",
        "summary": (
            "Telusuri rekaman pengadilan/properti/perusahaan lewat portal resmi "
            "dan agregator — verifikasi ke sumber asal, catat yurisdiksi."
        ),
        "caution": (
            "Ketersediaan rekaman sangat bervariasi antar-yurisdiksi; agregator "
            "bukan consumer reporting agency — memakai hasilnya untuk keputusan "
            "kerja/kredit melanggar FCRA di AS; sebagian entri direktori sudah mati."
        ),
        "steps": [
            {
                "title": "Kandidat dari agregator",
                "detail": "Reverse lookup nama/perusahaan/telepon sebagai penunjuk arah.",
                "tools": ["Background Checks", "Global Business Directory", "Numlookup", "FamilyTreeNow"],
            },
            {
                "title": "Portal resmi",
                "detail": "Pivot dari kandidat ke direktori situs pemerintah & arsip nasional.",
                "tools": ["Usa Official", "National Archives UK", "UK People Search"],
            },
            {
                "title": "Konteks lokasi & lingkungan",
                "detail": "Rekaman geografis/non-kriminal sebagai korroborasi.",
                "tools": ["Environmental Info", "Snoop Station"],
            },
            {
                "title": "Arsipkan & tandai sumber",
                "detail": "Screenshot + hash hanya sebagai pendukung; kutipan dokumen resmi yang mengendalikan.",
                "tools": ["Webpage Saver", "SingleFile", "Webrecorder"],
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
        "note": "Fondasi metodologi — lihat resources di bawah; materi cepat usang mengikuti perubahan platform.",
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

# ---------------------------------------------------------------------------
# Per-tool risk labels (§4.2: "Tandai kelas risiko per tool" + "Catatan
# cakupan yurisdiksi"). Only tools the analysis singles out get an explicit,
# human-written label; everything else inherits the category-level note and
# carries no per-tool flag. These are *display data for the UI*, consumed by
# the tool drawer — never by a detection engine.
# ---------------------------------------------------------------------------

# risk class: biometrik | privasi-tinggi | offensif | darkweb | ToS | mati
TOOL_RISK: dict[str, str] = {
    "Face Recognition": "biometrik",
    "Face Search": "biometrik",
    "Facecheck": "biometrik",
    "Photofeeder": "biometrik",
    "StalkFace": "privasi-tinggi",
    "Spokeo": "privasi-tinggi",
    "Intelius": "privasi-tinggi",
    "Radaris": "privasi-tinggi",
    "Truecaller": "privasi-tinggi",
    "Whitepages": "privasi-tinggi",
    "US People Search": "privasi-tinggi",
    "Thatsthem": "privasi-tinggi",
    "People Data Labs": "privasi-tinggi",
    "Zaba Search": "privasi-tinggi",
    "Gobuster": "offensif",
    "theHarvester": "offensif",
    "Exploit DB": "offensif",
    "Default Passwords": "offensif",
    "Sn1per": "offensif",
    "Amass": "offensif",
    "Tor Bot": "darkweb",
    "Onion Scan": "darkweb",
    "Onion Scan Tool": "darkweb",
    "Dark Web Tools": "darkweb",
    "Instagram Osint Tool": "ToS",
    "Twitter/X Scraping": "ToS",
    "InstaLooter": "mati",
    "Opengrey": "mati",
}

# One-line explanations shown with the badge (verbatim rationale from the
# analysis' kategori limitations §B1–B21 and responsible-use framing).
TOOL_RISK_WHY: dict[str, str] = {
    "biometrik": "Kelas paling berisiko di katalog: false positive meyakinkan, bias demografis, tunduk GDPR Art.9/BIPA — jangan jadikan dasar identifikasi tunggal.",
    "privasi-tinggi": "Agregator orang — tidak boleh untuk melacak/memantau individu atas alasan pribadi (stalking, pidana di banyak yurisdiksi); keputusan kerja/kredit diatur FCRA.",
    "offensif": "Hanya sah terhadap aset milik sendiri atau dengan otorisasi tertulis; pemindaian tanpa izin adalah computer-misuse.",
    "darkweb": "Wajib VM terisolasi + pemisahan identitas; risiko konten ilegal & indeks .onion usang.",
    "ToS": "Bergantung pada scraping/endpoint internal — melanggar ToS platform & rentan perubahan API.",
    "mati": "Diuji defunct/tidak aktif tetapi masih tercantum — ilustrasi pentingnya tanggal verifikasi.",
}

# Jurisdiction/coverage hints per the §B9/B13/B15 note that people & registries
# coverage is region-bound (US/UK/CA/RIR).
JURISDICTION: dict[str, str] = {
    "US People Search": "cakupan: AS",
    "UK People Search": "cakupan: Inggris (192.com)",
    "Canada People Search": "cakupan: Kanada (Canada411)",
    "Whitepages": "cakupan: AS",
    "White Pages": "cakupan: AS",
    "Spokeo": "cakupan: AS",
    "Intelius": "cakupan: AS",
    "Radaris": "cakupan: AS",
    "Thatsthem": "cakupan: AS",
    "Skipease": "cakupan: AS",
    "Zaba Search": "cakupan: AS",
    "Background Checks": "cakupan: AS (FCRA berlaku)",
    "Truecaller": "cakupan terkuat: Brasil/Serbia/AS",
    "National Archives UK": "cakupan: Inggris Raya",
    "APNIC": "cakupan: Asia-Pasifik",
    "RIPE": "cakupan: Eropa/Timur Tengah/Afrika",
    "ARIN": "cakupan: Amerika Utara",
}

# ---------------------------------------------------------------------------
# Training & Reference gap (§4.2 — "Tinggi": expand from 2 to 20+ entries).
# Rather than invent catalogue tools with unverified external URLs (which would
# rot, the very disease this catalogue fights), we close the gap with an
# in-house, deterministic methodology library distilled from the analysis
# itself. These are reference/principles resources, not executable tools — the
# "Training & Reference OSINT" the taxonomy describes.
# ---------------------------------------------------------------------------

TRAINING: list[dict[str, str]] = [
    {
        "id": "responsible-use",
        "title": "Prinsip Responsible Use",
        "body": (
            "'Public availability is not moral license.' Kumpulkan minimum yang "
            "dibutuhkan untuk menjawab pertanyaan investigasi; data pihak ketiga "
            "insidental berada di luar batas. Pisahkan infrastruktur investigasi "
            "dari akun pribadi. OSINT adalah metode, bukan lisensi — legalitas, "
            "proporsionalitas, dan verifikasi sebelum menyimpulkan adalah bagian "
            "dari pekerjaan."
        ),
    },
    {
        "id": "proportionality",
        "title": "Prinsip Proporsionalitas",
        "body": (
            "Intrusivitas pengumpulan harus sepadan dengan keseriusan yang "
            "diinvestigasi. Pertanyaan 'apakah pengumpulan ini perlu dan sepadan?' "
            "diajukan sebelum setiap langkah, bukan sesudahnya. Kategori paling "
            "berisiko (People OSINT, biometrik, offensif) memerlukan pembenaran "
            "yang lebih tinggi."
        ),
    },
    {
        "id": "validation",
        "title": "Validasi Input & SSRF Defense",
        "body": (
            "Klasifikasi & tolak input sebelum memanggil API mana pun: IP privat/"
            "loopback/link-local ditolak (cegah SSRF); email, domain, username "
            "dinormalisasi. Ini menghemat kuota dan menghindari permintaan yang "
            "tidak sah terhadap target internal."
        ),
    },
    {
        "id": "entity-resolution",
        "title": "Entity Resolution & Name Collision",
        "body": (
            "Gabungkan rekaman ke entitas yang sama dengan pencocokan berbobot — "
            "kecocokan tepat pada identifier kuat (email, hash) berbobot tinggi; "
            "fuzzy nama berbobot rendah. Jangan auto-merge di atas ambang tanpa "
            "jejak audit; tabrakan nama adalah penyebab kesalahan investigasi "
            "paling umum."
        ),
    },
    {
        "id": "chain-of-custody",
        "title": "Chain of Custody",
        "body": (
            "Simpan artefak mentah + hash SHA-256 sebelum parsing; pisahkan raw "
            "(bukti, immutable) dari parsed (analisis). Arsipkan halaman bersama "
            "timestamp sebelum dikutip; screenshot tanpa hash+timestamp bernilai "
            "pembuktian rendah. Report: target value, source & time, kutip hasil, "
            "level keyakinan."
        ),
    },
    {
        "id": "confidence-scale",
        "title": "Menilai Keyakinan",
        "body": (
            "confirmed: ≥2 sumber independen berkualitas tinggi + artefak. "
            "probable: 1 sumber kuat / beberapa lemah konsisten. lead: satu sinyal "
            "lemah. disputed: sumber bertentangan. Sebut 'confirmed' yang salah "
            "sering adalah liabilitas hukum."
        ),
    },
    {
        "id": "attack-surface-consent",
        "title": "Aset Terotorisasi",
        "body": (
            "Kategori offensif (port scanner, basis eksploit, kredensial default, "
            "ASM toolkit) sah hanya terhadap aset milik sendiri atau dengan "
            "otorisasi tertulis. Memindai sistem pihak lain tanpa izin adalah "
            "pelanggaran computer-misuse di hampir semua yurisdiksi."
        ),
    },
    {
        "id": "biometric-warning",
        "title": "Perhatian Biometrik & Media",
        "body": (
            "Pengenalan wajah menghasilkan false positive meyakinkan, bias antar "
            "kelompok demografis, dan tunduk UU biometrik (GDPR Pasal 9, BIPA). "
            "Jangan jadikan satu-satunya dasar identifikasi. EXIF mudah dipalsukan; "
            "ELA bukan bukti konklusif; deteksi AI salah di dua arah."
        ),
    },
    {
        "id": "offline-toolbench",
        "title": "Minimisasi via Tool Lokal",
        "body": (
            "Menganalisis header email / EXIF gambar di browser berarti data "
            "investigasi tidak pernah meninggalkan mesin — properti privasi yang "
            "sulit ditandingi layanan server. Nama ini juga kebal link-rot."
        ),
    },
    {
        "id": "pivot-discipline",
        "title": "Disiplin Pivot",
        "body": (
            "Pivot map adalah lead, bukan konfirmasi. Satu identifier lemah bisa "
            "berkembang: username → accounts → email → breach → domain → infra. "
            "Namun tiap hop perlu diverifikasi (foto, bio, pola) — tabrakan nama "
            "lazim dan verifikasi tidak membuktikan kontrol."
        ),
    },
]

__all__ = [
    "CATEGORY_NOTES",
    "CONFIDENCE_SCALE",
    "PIVOT_TYPES",
    "REPORTING_CHECKPOINTS",
    "TRAINING",
    "WORKFLOWS",
]
