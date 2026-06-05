import React from 'react';
import {AbsoluteFill, Sequence, useCurrentFrame, interpolate} from 'remotion';
import {theme} from './theme';
import {ClaudeCodePane} from './components/ClaudeCodePane';
import {LogsPane} from './components/LogsPane';
import {IntroCard} from './components/IntroCard';
import {InstallCard} from './components/InstallCard';
import type {TranscriptLine, LogRow} from './script';
import {
  beat1, beat2, seedRows, denyRow1, denyRow2, montageIcons, installCmd,
} from './script';

// Per-line local start frames within a beat (frame 0 = beat start). Spaced so
// each line finishes typing — at the Typewriter's slow default speed — before
// the next begins, and so the final line lingers before the beat ends.
// Order: user, assistant, tool, blocked, recover.
const LINE_STARTS = [0, 78, 132, 188, 232];
const DENY_LOCAL = LINE_STARTS[3]; // the blocked line — deny stamp + log row land here

// Timeline (30fps). Each section holds well past its last animation so nothing
// reads as rushed; transitions are gentle crossfades.
const BEAT1_FROM = 120;                 // intro: 0..120 (~4s)
const BEAT2_FROM = 470;                 // beat 1: 120..470 (~11.7s, incl. hold)
const OUTRO_FROM = 850;                 // beat 2: 470..850 (~12.7s, incl. ~2s hold)
const TOTAL = 1080;                     // outro: 850..1080 (~7.7s)

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

  // Loop seam: fade up over the first 14 frames, fade down over the last 20, so
  // frame 0 and frame TOTAL-1 are both theme.bg and the loop is invisible.
  const seam = interpolate(
    frame, [0, 14, TOTAL - 20, TOTAL - 1], [0, 1, 1, 0],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );

  // Intro fades out into beat 1; beats hold full, then fade out into the outro.
  const introOpacity = interpolate(
    frame, [BEAT1_FROM - 16, BEAT1_FROM], [1, 0],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  const panesOpacity = interpolate(
    frame, [BEAT1_FROM - 12, BEAT1_FROM, OUTRO_FROM - 18, OUTRO_FROM], [0, 1, 1, 0],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  const outroOpacity = interpolate(
    frame, [OUTRO_FROM - 10, OUTRO_FROM + 8], [0, 1],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );

  // Outer layer stays a solid dark fill at all times; the seam fade is applied
  // only to the content above it, so the loop boundary fades to theme.bg (dark)
  // rather than revealing the white page behind and flashing.
  return (
    <AbsoluteFill style={{background: theme.bg}}>
      <AbsoluteFill style={{opacity: seam}}>
        <AbsoluteFill style={{opacity: introOpacity}}>
          <Sequence from={0} durationInFrames={BEAT1_FROM}>
            <IntroCard startFrame={0} />
          </Sequence>
        </AbsoluteFill>
        <AbsoluteFill style={{opacity: panesOpacity}}>
          <Sequence from={BEAT1_FROM} durationInFrames={BEAT2_FROM - BEAT1_FROM}>
            <Beat lines={beat1} priorDeny={[]} newDeny={denyRow1} />
          </Sequence>
          <Sequence from={BEAT2_FROM} durationInFrames={OUTRO_FROM - BEAT2_FROM}>
            <Beat lines={beat2} priorDeny={[denyRow1]} newDeny={denyRow2} />
          </Sequence>
        </AbsoluteFill>
        <AbsoluteFill style={{opacity: outroOpacity}}>
          <Sequence from={OUTRO_FROM}>
            <InstallCard slugs={montageIcons} installCmd={installCmd} startFrame={0} />
          </Sequence>
        </AbsoluteFill>
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
