import React from 'react';
import {AbsoluteFill, Audio, Sequence, staticFile, interpolate} from 'remotion';
import {beat1, beat2} from './script';
import type {TranscriptLine} from './script';
import {
  BEAT1_FROM, BEAT2_FROM, OUTRO_FROM, LINE_STARTS,
  DENY1_FRAME, DENY2_FRAME, TOTAL, typingFrames,
} from './timing';

// Remotion's <Audio> has a strict prop type that mismatches the installed React
// types; alias it to the props we actually pass. Runtime behavior is unchanged.
const Sfx = Audio as unknown as React.FC<{
  src: string;
  volume?: number | ((f: number) => number);
  loop?: boolean;
}>;

const clamp = {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'} as const;

const lineLen = (line: TranscriptLine): number => {
  if (line.kind === 'user' || line.kind === 'assistant') return line.text.length;
  if (line.kind === 'tool') return line.command.length;
  return 0; // 'blocked' lines aren't typed
};

// One typing-sound window per text line in each beat, matching exactly when
// that line is being typed on screen.
const typingWindows = (): {from: number; dur: number}[] => {
  const out: {from: number; dur: number}[] = [];
  ([[BEAT1_FROM, beat1], [BEAT2_FROM, beat2]] as const).forEach(([beatFrom, beat]) => {
    beat.forEach((line, i) => {
      const len = lineLen(line);
      if (len > 0) out.push({from: beatFrom + LINE_STARTS[i], dur: typingFrames(len)});
    });
  });
  return out;
};

// Music-bed volume: a quiet background that fades at the loop seam and ducks
// briefly under each DENY so the punch stays clean. `f` is the composition
// frame (the bed runs the full length, unlooped).
const duckUnder = (f: number, center: number) =>
  interpolate(f, [center - 5, center, center + 12, center + 22], [1, 0.4, 0.4, 1], clamp);

const bedVolume = (f: number): number => {
  const fade = interpolate(f, [0, 18, TOTAL - 30, TOTAL - 1], [0, 1, 1, 0], clamp);
  const duck = Math.min(duckUnder(f, DENY1_FRAME), duckUnder(f, DENY2_FRAME));
  return 0.2 * fade * duck;
};

// Audio track, layered over the silent Stage. `pack` selects the SFX folder
// under public/sfx/<pack>/. With `bed`, a full-length music track replaces the
// ambient pad and the key clicks are boosted to cut through it.
export const SoundLayer: React.FC<{pack: string; bed?: boolean}> = ({pack, bed}) => {
  const sfx = (name: string) => staticFile(`sfx/${pack}/${name}.wav`);
  const keysVol = bed ? 1.4 : 0.28; // clicks are ~24dB quieter than the bed
  return (
    <AbsoluteFill>
      {/* bed (music) or ambient pad */}
      {bed ? (
        <Sfx src={sfx('bed')} volume={bedVolume} />
      ) : (
        <Sfx src={sfx('pad')} loop volume={0.1} />
      )}

      {/* intro power-on swell as the wordmark springs in */}
      <Sequence from={4}>
        <Sfx src={sfx('intro')} volume={0.5} />
      </Sequence>

      {/* key clicks only while each line is typing */}
      {typingWindows().map((w, i) => (
        <Sequence key={i} from={w.from} durationInFrames={w.dur}>
          <Sfx src={sfx('keys')} loop volume={keysVol} />
        </Sequence>
      ))}

      {/* the deny thunk — synced to each DENY stamp + red log row */}
      <Sequence from={DENY1_FRAME}>
        <Sfx src={sfx('deny')} volume={0.95} />
      </Sequence>
      <Sequence from={DENY2_FRAME}>
        <Sfx src={sfx('deny')} volume={0.95} />
      </Sequence>

      {/* outro resolve chime + install-box accent */}
      <Sequence from={OUTRO_FROM}>
        <Sfx src={sfx('outro')} volume={0.7} />
      </Sequence>
      <Sequence from={OUTRO_FROM + 90}>
        <Sfx src={sfx('blip')} volume={0.6} />
      </Sequence>
    </AbsoluteFill>
  );
};
