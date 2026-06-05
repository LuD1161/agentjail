import React from 'react';
import {Composition} from 'remotion';

const Placeholder: React.FC = () => (
  <div style={{flex: 1, background: '#1a1714'}} />
);

export const Root: React.FC = () => {
  return (
    <Composition
      id="Hero"
      component={Placeholder}
      durationInFrames={600}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
