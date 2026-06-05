import React from 'react';
import {useCurrentFrame, spring, useVideoConfig, interpolate} from 'remotion';
import {theme} from '../theme';
import type {LogRow} from '../script';

const actionColor = (a: LogRow['action']) =>
  a === 'ALLOW' ? theme.green : a === 'DENY' ? theme.red : theme.yellow;
const actionGlyph = (a: LogRow['action']) =>
  a === 'ALLOW' ? '✓' : a === 'DENY' ? '✗' : '?';

const Row: React.FC<{row: LogRow; appearFrame: number}> = ({row, appearFrame}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const s = spring({frame: frame - appearFrame, fps, config: {damping: 16}});
  const x = interpolate(s, [0, 1], [40, 0]);
  const opacity = interpolate(frame, [appearFrame, appearFrame + 6], [0, 1], {
    extrapolateLeft: 'clamp', extrapolateRight: 'clamp',
  });
  const isDeny = row.action === 'DENY';
  return (
    <div style={{
      transform: `translateX(${x}px)`, opacity, marginBottom: 10,
      padding: isDeny ? '8px 10px' : '2px 10px',
      background: isDeny ? 'rgba(224,86,79,0.12)' : 'transparent',
      borderLeft: isDeny ? `3px solid ${theme.red}` : '3px solid transparent',
      borderRadius: 4,
    }}>
      <div style={{display: 'flex', gap: 16}}>
        <span style={{color: theme.dim}}>{row.time}</span>
        <span style={{color: actionColor(row.action), fontWeight: 700}}>
          {actionGlyph(row.action)} {row.action}
        </span>
        <span style={{color: theme.text}}>{row.tool}</span>
      </div>
      {isDeny && (
        <div style={{color: theme.dim, marginTop: 4}}>
          {row.impact}
          {row.cmd && <div style={{color: theme.text}}>{'↳ ' + row.cmd}</div>}
        </div>
      )}
    </div>
  );
};

export const LogsPane: React.FC<{
  rows: {row: LogRow; appearFrame: number}[];
  allow: number; deny: number; ask: number;
}> = ({rows, allow, deny, ask}) => {
  return (
    <div style={{
      flex: 1, background: theme.panel, borderLeft: `1px solid ${theme.border}`,
      fontFamily: theme.mono, fontSize: 26, color: theme.text,
      padding: 28, display: 'flex', flexDirection: 'column',
    }}>
      <div style={{color: theme.accent, fontWeight: 700, marginBottom: 18}}>
        agentjail logs {'▸'} watching
      </div>
      <div style={{flex: 1}}>
        {rows.map((r, i) => <Row key={i} row={r.row} appearFrame={r.appearFrame} />)}
      </div>
      <div style={{color: theme.dim, marginTop: 12}}>
        <span style={{color: theme.green}}>{'🟢 ' + allow}</span>{'   '}
        <span style={{color: theme.red}}>{'🔴 ' + deny}</span>{'   '}
        <span style={{color: theme.yellow}}>{'🟡 ' + ask}</span>
      </div>
    </div>
  );
};
