import React from 'react';
import {Composition} from 'remotion';
import {Stage} from './Stage';

export const Root: React.FC = () => {
  return (
    <Composition
      id="Hero"
      component={Stage}
      durationInFrames={1080}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
