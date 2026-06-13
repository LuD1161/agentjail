import React from 'react';
import {AbsoluteFill} from 'remotion';

// A macOS desktop: brand-tinted wallpaper, soft top-left light, and a slim menu bar.
export const MacDesktop: React.FC = () => (
  <AbsoluteFill>
    <AbsoluteFill
      style={{
        background:
          'linear-gradient(150deg, #18122e 0%, #34203f 32%, #6e3556 60%, #c96f4a 100%)',
      }}
    />
    <AbsoluteFill
      style={{
        background:
          'radial-gradient(1200px 720px at 22% 10%, rgba(255,255,255,0.16), rgba(255,255,255,0) 60%)',
      }}
    />
    <div
      style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 30,
        background: 'rgba(18,14,20,0.42)', backdropFilter: 'blur(10px)',
        display: 'flex', alignItems: 'center', gap: 22, padding: '0 18px',
        fontFamily: '"JetBrains Mono", sans-serif', fontSize: 15,
        color: 'rgba(255,255,255,0.92)',
      }}
    >
      <span style={{fontWeight: 700}}>Terminal</span>
      <span style={{opacity: 0.78}}>Shell</span>
      <span style={{opacity: 0.78}}>Edit</span>
      <span style={{opacity: 0.78}}>View</span>
      <span style={{opacity: 0.78}}>Window</span>
      <span style={{opacity: 0.78}}>Help</span>
      <span style={{marginLeft: 'auto', opacity: 0.9}}>Thu 9:41 AM</span>
    </div>
  </AbsoluteFill>
);

// A macOS Terminal window (traffic lights + centered title) wrapping its children.
export const TerminalWindow: React.FC<{title?: string; children: React.ReactNode}> = ({
  title = 'agentjail — claude — 132×34',
  children,
}) => (
  <AbsoluteFill style={{alignItems: 'center', justifyContent: 'center'}}>
    <div
      style={{
        width: 1680, height: 884, marginTop: 22, borderRadius: 14, overflow: 'hidden',
        boxShadow: '0 30px 90px rgba(0,0,0,0.6)', border: '1px solid rgba(255,255,255,0.08)',
        display: 'flex', flexDirection: 'column',
      }}
    >
      <div
        style={{
          height: 42, flexShrink: 0, background: '#2c2622', position: 'relative',
          display: 'flex', alignItems: 'center', padding: '0 16px',
          borderBottom: '1px solid rgba(0,0,0,0.3)',
        }}
      >
        <div style={{display: 'flex', gap: 9}}>
          <span style={{width: 14, height: 14, borderRadius: '50%', background: '#ff5f57'}} />
          <span style={{width: 14, height: 14, borderRadius: '50%', background: '#febc2e'}} />
          <span style={{width: 14, height: 14, borderRadius: '50%', background: '#28c840'}} />
        </div>
        <div
          style={{
            position: 'absolute', left: 0, right: 0, textAlign: 'center', pointerEvents: 'none',
            fontFamily: '"JetBrains Mono", monospace', fontSize: 18, color: '#b8a89c',
          }}
        >
          {title}
        </div>
      </div>
      <div style={{flex: 1, minHeight: 0, display: 'flex', flexDirection: 'row'}}>
        {children}
      </div>
    </div>
  </AbsoluteFill>
);
