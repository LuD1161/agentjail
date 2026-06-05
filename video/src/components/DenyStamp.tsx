import React from 'react';
import {useCurrentFrame, useVideoConfig, spring, interpolate} from 'remotion';
import {theme} from '../theme';

export const DenyStamp: React.FC<{rule: string; enterFrame: number}> = ({rule, enterFrame}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const s = spring({frame: frame - enterFrame, fps, config: {damping: 12, mass: 0.7}});
  const scale = interpolate(s, [0, 1], [1.25, 1]);
  const opacity = interpolate(frame, [enterFrame, enterFrame + 4], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  if (frame < enterFrame) return null;
  return (
    <div style={{
      transform: `scale(${scale})`, transformOrigin: 'left center', opacity,
      display: 'inline-flex', alignItems: 'center', gap: 12,
      color: theme.red, fontWeight: 700,
    }}>
      <span>{'✗ Blocked by agentjail'}</span>
      <span style={{
        background: 'rgba(224,86,79,0.15)', border: `1px solid ${theme.red}`,
        borderRadius: 4, padding: '2px 8px', fontSize: 22,
      }}>
        {'DENY · ' + rule}
      </span>
    </div>
  );
};
