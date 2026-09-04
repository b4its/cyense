// Fast search helpers — single-pass, no N+1.
//
// For pages that render many rows/grid cells we build a lightweight *search
// index* once per dataset (one pass, fields normalized to lowercase) and then
// filter by scanning the index linearly. This avoids re-normalizing every
// cell on each keystroke and avoids nested N+1 lookups.

/**
 * Build a search index for a list of rows.
 *
 * @param {Array} rows              raw items
 * @param {Function|string[]} pick  field name(s) or a function returning the
 *                                  searchable string for a row
 * @returns {{rows: Array, keys: string[]}} same-length arrays (rows[i] ↔ keys[i])
 */
export function buildIndex(rows, pick) {
  if (!Array.isArray(rows)) return { rows: [], keys: [] }
  const keys = new Array(rows.length)
  const pickFn =
    typeof pick === 'function'
      ? pick
      : (r) => (Array.isArray(pick) ? pick.map((k) => r?.[k]).join(' ') : String(r?.[pick] ?? ''))

  for (let i = 0; i < rows.length; i++) {
    const v = pickFn(rows[i])
    keys[i] = (v == null ? '' : String(v)).toLowerCase()
  }
  return { rows, keys }
}

/**
 * Filter an index by a search string (substring, case-insensitive).
 * Fast: one pass over `keys`, no allocation beyond the result list.
 *
 * @param {{rows: Array, keys: string[]}} index
 * @param {string} q
 * @returns {Array} matching rows in original order
 */
export function searchIndex(index, q) {
  const needle = (q || '').trim().toLowerCase()
  if (!needle) return index.rows
  const { rows, keys } = index
  const out = []
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].includes(needle)) out.push(rows[i])
  }
  return out
}

/**
 * Debounce a function (leading edge optional).
 * @param {Function} fn
 * @param {number} wait ms
 */
export function debounce(fn, wait = 150) {
  let t = null
  return (...args) => {
    if (t) clearTimeout(t)
    t = setTimeout(() => {
      t = null
      fn(...args)
    }, wait)
  }
}