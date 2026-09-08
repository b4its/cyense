// Chronolocation math for the Toolbench — solar position (Ed Williams / NOAA
// spreadsheet formulation) + elevation solver. Pure client-side, deterministic,
// no network. This powers §B9's "chronolocation" technique: from a known-ish
// location + a date, estimate the *time* a photo was taken from shadow
// direction/length — or the reverse — with honest error margins.
//
// Accuracy: ±~0.1° for azimuth/elevation on 1990–2050, plenty for
// chronolocation's real-world error bars (which the analysis notes must be
// reported as probable/lead, never confirmed).

const RAD = Math.PI / 180
const J2000 = 2451545

function julianDay(utcMs) {
  return utcMs / 86400000 + 2440587.5
}

/** Sun azimuth (deg from North, CW) + elevation (deg) at lat/lon and UTC time. */
export function sunPosition(lat, lon, utcDate) {
  const jd = julianDay(utcDate.getTime())
  const jc = (jd - J2000) / 36525
  const ml = 357.52911 + jc * (35999.05029 - 0.0001537 * jc) // mean anomaly deg
  const mt = 280.46646 + jc * (36000.76983 + jc * 0.0003032) // mean longitude deg
  const mml = ((mt % 360) + 360) % 360
  const e = 0.016708634 - jc * (0.000042037 + 0.0000001267 * jc)
  const sing = Math.sin(ml * RAD)
  const c = sing * (1.914602 - jc * (0.004817 + 0.000014 * jc))
    + Math.sin(2 * ml * RAD) * (0.019993 - 0.000101 * jc)
    + Math.sin(3 * ml * RAD) * 0.000289
  const trueLong = mml + c
  const omega = 125.04 - 1934.136 * jc
  const lambda = trueLong - 0.00569 - 0.00478 * Math.sin(omega * RAD)
  const eps0 = 23 + (26 + (21.448 - jc * (46.815 + jc * (0.00059 - jc * 0.001813))) / 60) / 60
  const eps = eps0 + 0.00256 * Math.cos(omega * RAD)
  const sinDec = Math.sin(eps * RAD) * Math.sin(lambda * RAD)
  const dec = Math.asin(sinDec) / RAD
  const y = Math.tan((eps / 2) * RAD) ** 2
  const eqTime = 4 * (
    y * Math.sin(2 * mml * RAD)
    - 2 * e * sing
    + 4 * e * y * sing * Math.cos(2 * mml * RAD)
    - 0.5 * y * y * Math.sin(4 * mml * RAD)
    - 1.25 * e * e * Math.sin(2 * ml * RAD)
  ) / RAD // (…) is in radians → degrees → minutes (×4)
  // true solar time (minutes)
  const utcMin = utcDate.getUTCHours() * 60 + utcDate.getUTCMinutes() + utcDate.getUTCSeconds() / 60
  const tst = ((utcMin + eqTime + 4 * lon) % 1440 + 1440) % 1440
  const H = tst / 4 - 180
  const h = H * RAD
  const sl = Math.sin(lat * RAD)
  const cl = Math.cos(lat * RAD)
  const sd = Math.sin(dec * RAD)
  const cd = Math.cos(dec * RAD)
  const cosZ = sl * sd + cl * cd * Math.cos(h)
  const z = Math.acos(Math.max(-1, Math.min(1, cosZ))) / RAD
  const el = 90 - z
  // azimuth from North, clockwise (Williams/NOAA):
  const aa = (sl * Math.cos(z * RAD) - sd) / ((cl * Math.sin(z * RAD)) || 1e-9)
  const base = Math.acos(Math.max(-1, Math.min(1, aa))) / RAD
  let az
  if (H > 0) az = (base + 180) % 360
  else az = (540 - base) % 360
  return { azimuth: az, elevation: el, declination: dec, equationOfTime: eqTime }
}

/** elevation ⇒ shadow length per metre of vertical object (tan). */
export function shadowPerMetre(elevationDeg) {
  if (elevationDeg <= 0.05) return Infinity
  return 1 / Math.tan(elevationDeg * RAD)
}

/** Observed height/shadow ⇒ elevation of the light source. */
export function elevationFromShadow(heightM, shadowM) {
  if (!(shadowM > 0) || !(heightM > 0)) return null
  return Math.atan(heightM / shadowM) / RAD
}

/**
 * UTC instants on utcDay (Date at 00:00) when the sun's elevation equals
 * `target` (scan 96 steps of 15 min + bisection). Returns [] if none — e.g.
 * polar night for negative targets.
 */
export function findTimesForElevation(lat, lon, utcDay, target) {
  const out = []
  const t0 = Date.parse(utcDay.toISOString().slice(0, 10) + 'T00:00:00Z')
  const step = 15 * 60000
  let prevEl = sunPosition(lat, lon, new Date(t0)).elevation - target
  for (let i = 1; i <= 96; i++) {
    const ts = t0 + i * step
    const el = sunPosition(lat, lon, new Date(ts)).elevation - target
    if ((prevEl < 0 && el >= 0) || (prevEl >= 0 && el < 0)) {
      let lo = ts - step, hi = ts
      for (let k = 0; k < 40; k++) {
        const mid = (lo + hi) / 2
        const dm = sunPosition(lat, lon, new Date(mid)).elevation - target
        if ((prevEl < 0) === (dm < 0)) lo = mid
        else hi = mid
      }
      out.push(new Date((lo + hi) / 2))
    }
    prevEl = el
  }
  return out
}
