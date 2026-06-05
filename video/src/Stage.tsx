import React from 'react';
import {AbsoluteFill, Sequence, useCurrentFrame, interpolate} from 'remotion';
import {theme} from './theme';
import {ClaudeCodePane} from './components/ClaudeCodePane';
import {LogsPane} from './components/LogsPane';
import {InstallCard} from './components/InstallCard';
import type {TranscriptLine, LogRow} from './script';
import {
  beat1, beat2, seedRows, denyRow1, denyRow2, montageIcons, installCmd, tagline,
} from './script';

// Per-line local start frames within a beat sequence (frame 0 = sequence start).
// Order matches the transcript: user, assistant, tool, blocked, recover.
const LINE_STARTS = [0, 35, 70, 110, 140];
const DENY_LOCAL = LINE_STARTS[3]; // the blocked line — deny stamp + log row land here

const BEAT1_FROM = 30;
const BEAT_LEN = 180;
const BEAT2_FROM = BEAT1_FROM + BEAT_LEN; // 210
const MONTAGE_FROM = BEAT2_FROM + BEAT_LEN; // 390
const TOTAL = 600;

// One beat: Claude Code pane on the left, synced logs pane on the right.
// `priorDeny` rows are already-present (static) DENY rows from earlier beats;
// `newDeny` slides in at DENY_LOCAL, in lockstep with the inline stamp.
const Beat: React.FC<{
  lines: TranscriptLine[];
  priorDeny: LogRow[];
  newDeny: LogRow;
}> = ({lines, priorDeny, newDeny}) => {
  const rows = [
    ...seedRows.map((row) => ({row, appearFrame: -100})),
    ...priorDeny.map((row) => ({row, appearFrame: -100})),
    {row: newDeny, appearFrame: DENY_LOCAL},
  ];
  return (
    <AbsoluteFill style={{flexDirection: 'row'}}>
      <ClaudeCodePane cwd="~/acme-api" lines={lines} startFrames={LINE_STARTS} />
      <LogsPane rows={rows} allow={4} ask={0} />
    </AbsoluteFill>
  );
};

export const Stage: React.FC = () => {
  const frame = useCurrentFrame();

  // Loop seam: fade up over the first 12 frames, fade down over the last 18,
  // so frame 0 and frame TOTAL-1 are both near-black and the loop is invisible.
  const seam = interpolate(
    frame, [0, 12, TOTAL - 18, TOTAL - 1], [0, 1, 1, 0],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );

  // Crossfade the two-pane beats out and the montage in around MONTAGE_FROM.
  const panesOpacity = interpolate(
    frame, [MONTAGE_FROM - 15, MONTAGE_FROM], [1, 0],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  const montageOpacity = interpolate(
    frame, [MONTAGE_FROM - 8, MONTAGE_FROM + 6], [0, 1],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );

  // Outer layer stays a solid dark fill at all times; the seam fade is applied
  // only to the content above it, so the loop boundary fades to theme.bg (dark)
  // rather than revealing the white page behind and flashing.
  return (
    <AbsoluteFill style={{background: theme.bg}}>
      <AbsoluteFill style={{opacity: seam}}>
        <AbsoluteFill style={{opacity: panesOpacity}}>
          <Sequence from={BEAT1_FROM} durationInFrames={BEAT_LEN}>
            <Beat lines={beat1} priorDeny={[]} newDeny={denyRow1} />
          </Sequence>
          <Sequence from={BEAT2_FROM} durationInFrames={BEAT_LEN}>
            <Beat lines={beat2} priorDeny={[denyRow1]} newDeny={denyRow2} />
          </Sequence>
        </AbsoluteFill>
        <AbsoluteFill style={{opacity: montageOpacity}}>
          <Sequence from={MONTAGE_FROM}>
            <InstallCard
              slugs={montageIcons}
              tagline={tagline}
              installCmd={installCmd}
              startFrame={0}
            />
          </Sequence>
        </AbsoluteFill>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
