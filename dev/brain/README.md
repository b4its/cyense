# 🧠 Brain — knowledge base & memory (PRD v2.0 §1.2, §5.2)

Brain adalah *shared memory* antar-agent Cyense. Data ini di-mount ke
`/app/brain` pada service API dan dibaca/ditulis oleh agent saat scan berjalan.

## Kontrak data (`knowledge.json`)

```json
{
  "version": 1,
  "frameworks": {
    "<framework-name>": {
      "hints": ["substring pembeda di header/body response"],
      "id_pattern": "numeric | uuid | unknown",
      "strategy": "heuristik probing untuk framework tsb"
    }
  },
  "memory": {
    "<host>": {
      "valid_ids": ["...id yang pernah terbukti valid..."],
      "<key>": "observasi lain"
    }
  }
}
```

## Siapa menulis apa

| Agent | Aksi |
|-------|------|
| Recon | baca `frameworks` → pilih strategi probing |
| Prober | baca `memory[host].valid_ids` → tambah kandidat; tulis id valid baru |
| Verifier | (tidak menulis; verifikasi objektif per-scan) |

## Prinsip

- Memory antar-scan mempercepat scan berikutnya pada target yang sama.
- Ukuran memory dibatasi (maks 200 id valid per host) agar tetap ringan.
- File ini aman di-commit: tidak pernah berisi kredensial (semua redacted).
