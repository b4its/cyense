// Soft celebration chime via WebAudio (no asset files needed).
let ctx = null
export function playChime() {
  try {
    ctx = ctx || new (window.AudioContext || window.webkitAudioContext)()
    if (ctx.state === 'suspended') ctx.resume()
    const now = ctx.currentTime
    const notes = [523.25, 659.25, 783.99] // C5 E5 G5 — major triad
    notes.forEach((freq, i) => {
      const osc = ctx.createOscillator()
      const gain = ctx.createGain()
      osc.type = 'sine'
      osc.frequency.value = freq
      gain.gain.setValueAtTime(0, now + i * 0.08)
      gain.gain.linearRampToValueAtTime(0.12, now + i * 0.08 + 0.02)
      gain.gain.exponentialRampToValueAtTime(0.0001, now + i * 0.08 + 0.9)
      osc.connect(gain).connect(ctx.destination)
      osc.start(now + i * 0.08)
      osc.stop(now + i * 0.08 + 1)
    })
  } catch { /* audio unavailable — ignore */ }
}
