import {Config} from '@remotion/cli/config';

Config.setVideoImageFormat('jpeg');
Config.setOverwriteOutput(true);

// On machines where Remotion can't auto-locate a working Chrome/Chromium
// (e.g. a broken `chromium` shim on PATH), point it at an explicit binary via
// REMOTION_BROWSER_EXECUTABLE. Left unset, Remotion uses its normal detection.
const browserExecutable = process.env.REMOTION_BROWSER_EXECUTABLE;
if (browserExecutable) {
  Config.setBrowserExecutable(browserExecutable);
}
