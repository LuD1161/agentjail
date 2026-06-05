import React from 'react';
import {theme} from '../theme';
import {Typewriter} from './Typewriter';
import {DenyStamp} from './DenyStamp';
import type {TranscriptLine} from '../script';

export const ClaudeCodePane: React.FC<{
  cwd: string;
  lines: TranscriptLine[];
  startFrames: number[];
}> = ({cwd, lines, startFrames}) => {
  return (
    <div style={{
      flex: 1.62, background: theme.bg, fontFamily: theme.mono, fontSize: 30,
      color: theme.text, padding: 32, display: 'flex', flexDirection: 'column', gap: 18,
    }}>
      <div style={{color: theme.dim, fontSize: 24}}>
        {'◤ Claude Code — ' + cwd}
      </div>
      {lines.map((line, i) => {
        const start = startFrames[i] ?? 0;
        if (line.kind === 'user') {
          return (
            <div key={i} style={{color: theme.accent}}>
              <span style={{color: theme.dim}}>{'› '}</span>
              <Typewriter text={line.text} startFrame={start} cursor={false} />
            </div>
          );
        }
        if (line.kind === 'assistant') {
          return (
            <div key={i}>
              <span style={{color: theme.accent}}>{'● '}</span>
              <Typewriter text={line.text} startFrame={start} cursor={false} />
            </div>
          );
        }
        if (line.kind === 'tool') {
          return (
            <div key={i} style={{color: theme.dim, paddingLeft: 24}}>
              {'⏺ Bash('}
              <span style={{color: theme.text}}>
                <Typewriter text={line.command} startFrame={start} />
              </span>
              {')'}
            </div>
          );
        }
        return (
          <div key={i} style={{paddingLeft: 48}}>
            <DenyStamp rule={line.rule} enterFrame={start} />
          </div>
        );
      })}
    </div>
  );
};
