// Minimal client-side EXIF reader for JPEG (APP1 "Exif" segment). Parses
// IFD0 + Exif-sub-IFD + GPS-sub-IFD with DataView — no dependencies, nothing
// leaves the browser (Toolbench promise: no accounts, no uploads, no logging).

const TAGS_IFD0 = {
  270: 'Make', 271: 'Model', 274: 'Orientation', 282: 'XResolution',
  283: 'YResolution', 296: 'ResolutionUnit', 305: 'Software',
  306: 'DateTime', 315: 'Artist', 256: 'ImageWidth', 257: 'ImageLength',
  34665: '_ExifIFD', 34853: '_GPSIFD',
}
const TAGS_EXIF = {
  36864: 'ExifVersion', 36867: 'DateTimeOriginal', 36868: 'DateTimeDigitized',
  37380: 'ExposureBias', 37381: 'MaxApertureValue', 37383: 'MeteringMode',
  37384: 'LightSource', 37385: 'Flash', 37386: 'FocalLength',
  40962: 'PixelXDimension', 40963: 'PixelYDimension', 41729: 'ExifImageWidth',
  41730: 'ExifImageHeight', 42033: 'LensMake', 42034: 'LensModel',
}
const TAGS_GPS = {
  0: 'GPSVersionID', 1: 'GPSLatitudeRef', 2: 'GPSLatitude',
  3: 'GPSLongitudeRef', 4: 'GPSLongitude', 5: 'GPSAltitudeRef',
  6: 'GPSAltitude', 7: 'GPSTimeStamp', 29: 'GPSDateStamp',
}

export async function readExif(file) {
  const buf = await file.arrayBuffer()
  const out = {
    name: file.name, size: file.size, type: file.type || '',
    format: 'other', exif: {}, gps: {}, warnings: [],
  }
  out.sha256 = await sha256(buf)

  const dv = new DataView(buf)
  if (file.type === 'image/png' || (dv.getUint8(0) === 0x89 && dv.getUint8(1) === 0x50)) {
    out.format = 'png'
    parsePngText(buf, out)
    out.warnings.push('Pembaca minimal ini hanya mengekstrak tEXt PNG; EXIF penuh perlu exiftool lokal.')
    return out
  }
  if (!(dv.getUint8(0) === 0xff && dv.getUint8(1) === 0xd8)) {
    out.warnings.push('Bukan JPEG/PNG — hanya hash SHA-256 + info dasar.')
    return out
  }
  out.format = 'jpeg'

  let off = 2
  while (off + 4 < dv.byteLength) {
    if (dv.getUint8(off) !== 0xff) { off++; continue }
    const marker = dv.getUint8(off + 1)
    const segLen = dv.getUint16(off + 2)
    if (marker === 0xe1) {
      const seg = new Uint8Array(buf, off + 4, Math.max(0, segLen - 2))
      if (String.fromCharCode(...seg.subarray(0, 4)) === 'Exif') {
        parseTiff(new Uint8Array(seg.subarray(6, seg.byteLength)), out)
        break
      }
      out.warnings.push('APP1 ada tetapi blok XMP (bukan Exif TIFF).')
    }
    if (marker === 0xda) break // Start-Of-Scan: header berhenti di sini
    off += segLen + 2
  }
  finalizeGps(out)
  if (!Object.keys(out.exif).length && !Object.keys(out.gps).length) {
    out.warnings.push('Tidak ada tag EXIF — kemungkinan besar metadata dihapus platform sosial.')
  }
  return out
}

function parsePngText(buf, out) {
  const dec = new TextDecoder()
  let off = 8
  while (off + 8 <= buf.byteLength) {
    const len = new DataView(buf, off, 4).getUint32(0)
    const type = dec.decode(new Uint8Array(buf, off + 4, 4))
    if (type === 'tEXt' || type === 'iTXt') {
      const data = new Uint8Array(buf, off + 8, Math.min(len, 4096))
      const nul = data.indexOf(0)
      if (nul > 0) {
      const key = dec.decode(data.subarray(0, nul))
        const val = dec.decode(data.subarray(nul + 1)).replace(/\0+$/, '')
        if (val.length < 500) out.exif[`PNG·${key}`] = val
      }
    }
    if (type === 'IEND') break
    off += 12 + len
  }
}

function parseTiff(tiff, out) {
  if (tiff.byteLength < 8) { out.warnings.push('Blok Exif terlalu pendek'); return }
  const dv = new DataView(tiff.buffer, tiff.byteOffset, tiff.byteLength)
  const little = dv.getUint16(0) === 0x4949 // II
  if (dv.getUint16(2, little) !== 0x002a) { out.warnings.push('Tiff magic salah'); return }
  const get16 = (o) => dv.getUint16(o, little)
  const get32 = (o) => dv.getUint32(o, little)

  function readIfd(off) {
    const n = get16(off)
    const entries = []
    for (let i = 0; i < n; i++) {
      const e = off + 2 + i * 12
      if (e + 12 > dv.byteLength) break
      entries.push({
        tag: get16(e), type: get16(e + 2), count: get32(e + 4), valOff: e + 8,
      })
    }
    return entries
  }

  function value(t, count, valOff) {
    let off = valOff
    const size = sizeOfType(t) * count
    if (size > 4) off = get32(valOff)
    if (off + Math.min(size, 1024) > dv.byteLength) return null
    switch (t) {
      case 1: case 7: return undefined // raw bytes — skipped
      case 2: return new TextDecoder().decode(
        new Uint8Array(dv.buffer, dv.byteOffset + off, Math.min(size, 512))).replace(/\0.*$/, '')
      case 3: return get16(off)
      case 4: return get32(off)
      case 5: { const r = []; for (let i = 0; i < count; i++) {
        const num = get32(off + i * 8), den = get32(off + i * 8 + 4)
        r.push(den ? num / den : 0) } return r }
      case 9: { const r = []; for (let i = 0; i < count; i++) {
        const v = get32(off + i * 4); r.push(v > 0x7fffffff ? v - 0x100000000 : v) } return r }
      case 10: { const r = []; for (let i = 0; i < count; i++) {
        const num = get32(off + i * 8), den = get32(off + i * 8 + 4)
        const sr = dv.getInt32(off + i * 8, little)
        const sv = sr > 0x7fffffff ? sr - 0x100000000 : sr
        r.push(den ? sv / den : 0) } return r }
      default: return undefined
    }
  }

  function apply(entries, tmap, dict) {
    for (const en of entries) {
      const name = tmap[en.tag]
      if (!name || name.startsWith('_')) continue
      const v = value(en.type, en.count, en.valOff)
      if (v !== undefined && v !== null && v !== '') dict[name] = v
    }
  }

  const ifd0 = readIfd(get32(4))
  for (const en of ifd0) {
    const name = TAGS_IFD0[en.tag]
    if (!name) continue
    if (name === '_ExifIFD' || name === '_GPSIFD') {
      const sub = readIfd(get32(en.valOff))
      apply(sub, name === '_ExifIFD' ? TAGS_EXIF : TAGS_GPS,
        name === '_ExifIFD' ? out.exif : out.gps)
    } else {
      const v = value(en.type, en.count, en.valOff)
      if (v !== undefined && v !== null && v !== '') out.exif[name] = v
    }
  }
  out._gpsRaw = out.gps.GPSLatitude && Array.isArray(out.gps.GPSLatitude)
    ? { lat: out.gps.GPSLatitude, latRef: out.gps.GPSLatitudeRef,
        lon: out.gps.GPSLongitude, lonRef: out.gps.GPSLongitudeRef } : null
}

function finalizeGps(out) {
  const raw = out._gpsRaw
  if (!raw) return
  const lat = dms(raw.lat, raw.latRef)
  const lon = dms(raw.lon, raw.lonRef)
  if (lat !== null && lon !== null) {
    out.gps.Coordinates = `${lat.toFixed(6)}, ${lon.toFixed(6)}`
  }
}
function dms(triple, ref) {
  if (!Array.isArray(triple) || triple.length < 3) return null
  const deg = triple[0] + triple[1] / 60 + triple[2] / 3600
  return /[SsWw]/.test(ref || '') ? -deg : deg
}

function sizeOfType(t) {
  return [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 8][t] || 1
}

export async function sha256(buf) {
  if (!globalThis.crypto?.subtle) return null // non-secure context
  const h = await crypto.subtle.digest('SHA-256', buf)
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('')
}
