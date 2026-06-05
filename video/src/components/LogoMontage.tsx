import React from 'react';
import * as icons from 'simple-icons';
import {useCurrentFrame, useVideoConfig, spring, interpolate} from 'remotion';
import {theme} from '../theme';

const slugToKey = (slug: string) => 'si' + slug.charAt(0).toUpperCase() + slug.slice(1);

const Logo: React.FC<{slug: string; index: number; startFrame: number}> = ({slug, index, startFrame}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const appear = startFrame + index * 4;
  const s = spring({frame: frame - appear, fps, config: {damping: 14}});
  const y = interpolate(s, [0, 1], [30, 0]);
  const opacity = interpolate(s, [0, 1], [0, 1]);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const icon = (icons as any)[slugToKey(slug)];
  if (!icon) return null;
  return (
    <svg viewBox="0 0 24 24" width={92} height={92}
      style={{transform: `translateY(${y}px)`, opacity, margin: 18}}>
      <path d={icon.path} fill={theme.text} />
    </svg>
  );
};

export const LogoMontage: React.FC<{slugs: string[]; startFrame: number}> = ({slugs, startFrame}) => {
  return (
    <div style={{
      display: 'flex', flexWrap: 'wrap', justifyContent: 'center',
      alignItems: 'center', maxWidth: 980,
    }}>
      {slugs.map((slug, i) => (
        <Logo key={slug} slug={slug} index={i} startFrame={startFrame} />
      ))}
    </div>
  );
};
