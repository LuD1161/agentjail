import {loadFont} from '@remotion/google-fonts/JetBrainsMono';

const {fontFamily} = loadFont();

export const theme = {
  bg: '#1a1714',      // warm dark
  panel: '#221d19',   // pane surface
  border: '#3a322c',
  text: '#e8e0d8',
  dim: '#9b8f84',
  accent: '#c96f4a',  // terracotta (install-UI accent)
  green: '#5fb37a',   // ✓ ALLOW
  red: '#e0564f',     // ✗ DENY
  yellow: '#d9a441',  // ASK
  mono: fontFamily,
  fontSizeBase: 30,
} as const;
