import React from 'react';
import {useCurrentFrame, useVideoConfig, spring, interpolate} from 'remotion';
import {theme} from '../theme';

// Opening title: AGENTJAIL in caps with the product subtitle, centered.
export const IntroCard: React.FC<{startFrame: number}> = ({startFrame}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const s = spring({frame: frame - startFrame, fps, config: {damping: 20}});
  const titleY = interpolate(s, [0, 1], [28, 0]);
  const titleOpacity = interpolate(
    frame, [startFrame, startFrame + 18], [0, 1],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  const subOpacity = interpolate(
    frame, [startFrame + 22, startFrame + 44], [0, 1],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  return (
    <div style={{
      flex: 1, background: theme.bg, fontFamily: theme.mono,
      display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center', gap: 32,
    }}>
      <div style={{
        fontSize: 132, fontWeight: 700, letterSpacing: 14, color: theme.text,
        transform: `translateY(${titleY}px)`, opacity: titleOpacity,
      }}>
        AGENTJAIL
      </div>
      <div style={{fontSize: 40, color: theme.dim, opacity: subOpacity}}>
        Policy guardrails for coding agents
      </div>
    </div>
  );
};
