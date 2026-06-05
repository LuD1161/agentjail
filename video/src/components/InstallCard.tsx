import React from 'react';
import {useCurrentFrame, interpolate} from 'remotion';
import {theme} from '../theme';
import {LogoMontage} from './LogoMontage';

export const InstallCard: React.FC<{
  slugs: string[];
  tagline: string;
  installCmd: string;
  startFrame: number;
}> = ({slugs, tagline, installCmd, startFrame}) => {
  const frame = useCurrentFrame();
  const headlineOpacity = interpolate(frame, [startFrame, startFrame + 12], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const ctaOpacity = interpolate(frame, [startFrame + 50, startFrame + 65], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  return (
    <div style={{
      flex: 1, background: theme.bg, fontFamily: theme.mono, color: theme.text,
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 36,
    }}>
      <div style={{fontSize: 52, fontWeight: 700, opacity: headlineOpacity}}>
        Write a policy for anything.
      </div>
      <LogoMontage slugs={slugs} startFrame={startFrame + 10} />
      <div style={{opacity: ctaOpacity, textAlign: 'center', display: 'flex', flexDirection: 'column', gap: 14}}>
        <div style={{fontSize: 34}}>
          <span style={{color: theme.accent, fontWeight: 700}}>agentjail</span>
          <span style={{color: theme.dim}}>{' — ' + tagline}</span>
        </div>
        <div style={{
          fontSize: 28, color: theme.text, background: theme.panel,
          border: `1px solid ${theme.border}`, borderRadius: 6, padding: '12px 20px',
        }}>
          {installCmd}
        </div>
      </div>
    </div>
  );
};
