import React from 'react';
import {useCurrentFrame, useVideoConfig, spring, interpolate, Img, staticFile} from 'remotion';
import {theme} from '../theme';
import {LogoMontage} from './LogoMontage';

// Remotion's <Img> has a strict prop type that mismatches the installed React
// types; alias it to the props we actually pass. Runtime behavior (waiting for
// the image to load before capturing the frame) is unchanged.
const Logo = Img as unknown as React.FC<{src: string; style?: React.CSSProperties}>;

// Closing card: the big agentjail wordmark (same pixel logo as the README),
// "Write a policy for anything." below it, then the governable-tool logos and
// the install one-liner.
export const InstallCard: React.FC<{
  slugs: string[];
  installCmd: string;
  startFrame: number;
}> = ({slugs, installCmd, startFrame}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const wordmark = spring({frame: frame - startFrame, fps, config: {damping: 20}});
  const wordmarkY = interpolate(wordmark, [0, 1], [26, 0]);
  const wordmarkOpacity = interpolate(
    frame, [startFrame, startFrame + 16], [0, 1],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  const subOpacity = interpolate(
    frame, [startFrame + 18, startFrame + 36], [0, 1],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  const ctaOpacity = interpolate(
    frame, [startFrame + 78, startFrame + 96], [0, 1],
    {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'},
  );
  return (
    <div style={{
      flex: 1, background: theme.bg, fontFamily: theme.mono, color: theme.text,
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 40,
    }}>
      <Logo
        src={staticFile('agentjail-logo.svg')}
        style={{width: 680, transform: `translateY(${wordmarkY}px)`, opacity: wordmarkOpacity}}
      />
      <div style={{fontSize: 46, fontWeight: 700, opacity: subOpacity}}>
        Guardrails for your whole stack.
      </div>
      <LogoMontage slugs={slugs} startFrame={startFrame + 26} />
      <div style={{
        opacity: ctaOpacity, fontSize: 28, color: theme.text, background: '#2a231e',
        border: `1.5px solid #57493d`, borderRadius: 8, padding: '16px 26px',
      }}>
        {installCmd}
      </div>
    </div>
  );
};
