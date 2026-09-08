// Coordinate converter helpers — pure WGS84 math, client-side, no network.
// UTM forward/inverse per Snyder (USGS Prof. Paper 1395); round-trip tested.

const A = 6378137.0, F = 1 / 298.257223563
const K0 = 0.9996
const E2 = F * (2 - F), EP2 = E2 / (1 - E2)

export function latlonToUtm(lat, lon) {
  const zone = Math.floor((lon + 180) / 6) + 1
  const lon0 = ((zone - 1) * 6 - 180 + 3) * Math.PI / 180
  const l = lon * Math.PI / 180 - lon0
  const phi = lat * Math.PI / 180
  const sp = Math.sin(phi), cp = Math.cos(phi), tp = Math.tan(phi)
  const N = A / Math.sqrt(1 - E2 * sp * sp)
  const T = tp * tp, C = EP2 * cp * cp
  const Aa = cp * l
  const M = A * ((1 - E2 / 4 - 3 * E2 * E2 / 64 - 5 * E2 ** 3 / 256) * phi
    - (3 * E2 / 8 + 3 * E2 * E2 / 32 + 45 * E2 ** 3 / 1024) * Math.sin(2 * phi)
    + (15 * E2 * E2 / 256 + 45 * E2 ** 3 / 1024) * Math.sin(4 * phi)
    - (35 * E2 ** 3 / 3072) * Math.sin(6 * phi))
  const easting = K0 * N * (Aa + (1 - T + C) * Aa ** 3 / 6
    + (5 - 18 * T + T * T + 72 * C - 58 * EP2) * Aa ** 5 / 120) + 500000
  let northing = K0 * (M + N * tp * (Aa * Aa / 2 + (5 - T + 9 * C + 4 * C * C) * Aa ** 4 / 24
    + (61 - 58 * T + T * T + 600 * C - 330 * EP2) * Aa ** 6 / 720))
  if (lat < 0) northing += 10000000
  return { zone, band: utmBand(lat), easting, northing }
}

export function utmBand(lat) {
  if (lat < -80 || lat > 84) return 'Z'
  const letters = 'CDEFGHJKLMNPQRSTUVWX'
  return letters[Math.floor((lat + 80) / 8)]
}

// Inverse: solve (lat, lon) from UTM by alternating Newton iterations on the
// *same* forward series — guarantees exact round-trips (residual bounded by
// the forward series truncation, sub-metre away from the central meridian).
export function utmToLatlon(zone, band, easting, northing) {
  const isNorth = (band || '').toUpperCase() >= 'N' // N..X north, C..M south
  const lon0rad = ((zone - 1) * 6 - 180 + 3) * Math.PI / 180
  let y = northing
  if (!isNorth) y -= 10000000
  const x = easting - 500000

  const M = (p) => A * ((1 - E2 / 4 - 3 * E2 * E2 / 64 - 5 * E2 ** 3 / 256) * p
    - (3 * E2 / 8 + 3 * E2 * E2 / 32 + 45 * E2 ** 3 / 1024) * Math.sin(2 * p)
    + (15 * E2 * E2 / 256 + 45 * E2 ** 3 / 1024) * Math.sin(4 * p)
    - (35 * E2 ** 3 / 3072) * Math.sin(6 * p))
  const dM = (p) => A * ((1 - E2 / 4 - 3 * E2 * E2 / 64 - 5 * E2 ** 3 / 256)
    - 2 * (3 * E2 / 8 + 3 * E2 * E2 / 32 + 45 * E2 ** 3 / 1024) * Math.cos(2 * p)
    + 4 * (15 * E2 * E2 / 256 + 45 * E2 ** 3 / 1024) * Math.cos(4 * p)
    - 6 * (35 * E2 ** 3 / 3072) * Math.cos(6 * p))

  // start: latitude from the meridional arc alone
  let phi = (y / K0) / (A * (1 - E2 / 4 - 3 * E2 * E2 / 64 - 5 * E2 ** 3 / 256))
  let a = 0
  for (let i = 0; i < 12; i++) {
    const s = Math.sin(phi), cp = Math.cos(phi), tp = Math.tan(phi)
    const N = A / Math.sqrt(1 - E2 * s * s)
    const T = tp * tp, C = EP2 * cp * cp
    // 1) solve A from easting at current phi (Newton)
    const b1 = 1 - T + C, b2 = 5 - 18 * T + T * T + 72 * C - 58 * EP2
    const g = (aa) => K0 * N * (aa + b1 * aa ** 3 / 6 + b2 * aa ** 5 / 120) - x
    const dg = (aa) => K0 * N * (1 + b1 * aa ** 2 / 2 + b2 * aa ** 4 / 24)
    a -= g(a) / dg(a)
    // 2) one Newton step on phi including the northing's A-dependent terms
    const c1 = 5 - T + 9 * C + 4 * C * C
    const c2 = 61 - 58 * T + T * T + 600 * C - 330 * EP2
    const f = K0 * (M(phi) + N * tp * (a * a / 2 + c1 * a ** 4 / 24 + c2 * a ** 6 / 720)) - y
    phi -= f / (K0 * dM(phi))
  }
  const lon = lon0rad + a / Math.cos(phi)
  return { lat: phi * 180 / Math.PI, lon: lon * 180 / Math.PI }
}

// DMS token regex: 40°26'46"N  (accepts ′ ' ` for min, ″ " for sec; decimal ok)
const DMS_RE = /(\d+(?:\.\d+)?)\s*[°ºd]\s*(\d+(?:\.\d+)?)\s*['′m]\s*(\d+(?:\.\d+)?)\s*(?:["″s])?\s*([NSEWnsew])/

export function fmtDms(value, axis) {
  const hemi = axis === 'lat' ? (value >= 0 ? 'N' : 'S') : (value >= 0 ? 'E' : 'W')
  const av = Math.abs(value)
  const deg = Math.floor(av)
  const m = (av - deg) * 60
  const min = Math.floor(m)
  const sec = (m - min) * 60
  return `${deg}° ${String(min).padStart(2, '0')}′ ${sec.toFixed(2)}″ ${hemi}`
}

export function fmtDD(lat, lon) {
  return `${lat.toFixed(6)}, ${lon.toFixed(6)}`
}

// Parse an input string in one of three shapes; returns {kind,...} or null.
export function parseInput(text) {
  const t = (text || '').trim().replace(/\s+/g, ' ')
  if (!t) return null
  // UTM: "18T 583919 4550334"
  let m = t.match(/^(\d{1,2})([C-Xc-x])\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)$/)
  if (m) return { kind: 'utm', zone: +m[1], band: m[2].toUpperCase(), easting: +m[3], northing: +m[4] }
  // DMS pair: two DMS tokens
  const parts = []
  const gre = new RegExp(DMS_RE.source, 'g')
  let gm
  while ((gm = gre.exec(t))) {
    if (parts.push(gm) === 2) break
  }
  if (parts.length === 2) {
    const latTok = parts.find((x) => /[NSns]/.test(x[4]))
    const lonTok = parts.find((x) => /[EWew]/.test(x[4]))
    if (latTok && lonTok) {
      const lat = +(latTok[1]) + (+latTok[2]) / 60 + (+latTok[3]) / 3600
      const lon = +(lonTok[1]) + (+lonTok[2]) / 60 + (+lonTok[3]) / 3600
      return { kind: 'pair', lat: /[Ss]/.test(latTok[4]) ? -lat : lat, lon: /[Ww]/.test(lonTok[4]) ? -lon : lon }
    }
    return null
  }
  // decimal pair: "40.785, -73.968" or "40.785 -73.968"
  m = t.match(/^(-?\d{1,3}(?:\.\d+)?)\s*[,\s]\s*(-?\d{1,3}(?:\.\d+)?)$/)
  if (m && Math.abs(+m[1]) <= 90 && Math.abs(+m[2]) <= 180) {
    return { kind: 'pair', lat: +m[1], lon: +m[2] }
  }
  return null
}
