import React from 'react';
import {useCurrentFrame, useVideoConfig} from 'remotion';

export function revealedChars(
  frame: number, startFrame: number, cps: number, fps: number, len: number,
): number {
  if (frame < startFrame) return 0;
  const elapsed = (frame - startFrame) / fps;
  return Math.min(len, Math.floor(elapsed * cps));
}

export const Typewriter: React.FC<{
  text: string;
  startFrame: number;
  cps?: number;
  cursor?: boolean;
  style?: React.CSSProperties;
}> = ({text, startFrame, cps = 24, cursor = true, style}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const n = revealedChars(frame, startFrame, cps, fps, text.length);
  const done = n >= text.length;
  const showCursor = cursor && frame >= startFrame && frame % 30 < 15;
  return (
    <span style={style}>
      {text.slice(0, n)}
      {showCursor && !done ? '█' : ''}
    </span>
  );
};
