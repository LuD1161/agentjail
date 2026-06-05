import React from 'react';
import {useCurrentFrame, useVideoConfig, spring, interpolate, Img, staticFile} from 'remotion';
import {theme} from '../theme';

// Remotion's <Img> has a strict prop type that mismatches the installed React
// types; alias it to the props we actually pass. Runtime behavior (waiting for
// the image to load before capturing the frame) is unchanged.
const Logo = Img as unknown as React.FC<{src: string; style?: React.CSSProperties}>;

// Opening title: the agentjail wordmark (same pixel logo as the README) with
// the product subtitle, centered.
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
      alignItems: 'center', justifyContent: 'center', gap: 40,
    }}>
      <Logo
        src={staticFile('agentjail-logo.svg')}
        style={{width: 760, transform: `translateY(${titleY}px)`, opacity: titleOpacity}}
      />
      <div style={{fontSize: 40, color: theme.dim, opacity: subOpacity}}>
        Policy guardrails for coding agents
      </div>
    </div>
  );
};
