import React from 'react';
import {AbsoluteFill, Composition} from 'remotion';
import {Stage} from './Stage';
import {SoundLayer} from './SoundLayer';

// Same visuals as Hero, with an audio track layered on top. One composition per
// SFX pack (under public/sfx/<pack>/) so each renders without needing CLI props.
const HeroSoundSynth: React.FC = () => (
  <AbsoluteFill>
    <Stage />
    <SoundLayer pack="synth" />
  </AbsoluteFill>
);

const HeroSoundLicensed: React.FC = () => (
  <AbsoluteFill>
    <Stage />
    <SoundLayer pack="licensed" />
  </AbsoluteFill>
);

const HeroSoundElevenLabs: React.FC = () => (
  <AbsoluteFill>
    <Stage />
    <SoundLayer pack="elevenlabs" />
  </AbsoluteFill>
);

// ElevenLabs SFX + a full-length music bed (ducked under the DENY hits).
const HeroSoundMusic: React.FC = () => (
  <AbsoluteFill>
    <Stage />
    <SoundLayer pack="elevenlabs" bed />
  </AbsoluteFill>
);

const common = {durationInFrames: 1080, fps: 30, width: 1920, height: 1080} as const;

export const Root: React.FC = () => {
  return (
    <>
      <Composition id="Hero" component={Stage} {...common} />
      <Composition id="HeroSoundSynth" component={HeroSoundSynth} {...common} />
      <Composition id="HeroSoundLicensed" component={HeroSoundLicensed} {...common} />
      <Composition id="HeroSoundElevenLabs" component={HeroSoundElevenLabs} {...common} />
      <Composition id="HeroSoundMusic" component={HeroSoundMusic} {...common} />
    </>
  );
};
