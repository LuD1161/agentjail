// Single source of truth for the composition timeline (30fps). Both the visual
// Stage and the audio SoundLayer import these so sound lands on the exact frames
// the visuals animate.

export const FPS = 30;
export const CPS = 24; // characters/second — must match the Typewriter default

// Per-line local start frames within a beat (frame 0 = beat start).
// Order: user, assistant, tool, blocked, recover.
export const LINE_STARTS = [0, 78, 132, 188, 232];
export const DENY_LOCAL = LINE_STARTS[3]; // the blocked line lands here

export const BEAT1_FROM = 120; // intro: 0..120
export const BEAT2_FROM = 470; // beat 1: 120..470
export const OUTRO_FROM = 850; // beat 2: 470..850
export const TOTAL = 1080;     // outro: 850..1080

// Global frame at which each beat's DENY stamp + red log row land.
export const DENY1_FRAME = BEAT1_FROM + DENY_LOCAL; // 308
export const DENY2_FRAME = BEAT2_FROM + DENY_LOCAL; // 658

// Frames a line of `len` characters takes to type at the Typewriter's speed.
export const typingFrames = (len: number) => Math.ceil((len / CPS) * FPS);
