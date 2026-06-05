import {revealedChars} from './Typewriter';

const cases: [number, number, number, number, number, number][] = [
  [0, 0, 30, 30, 10, 0],
  [30, 0, 30, 30, 10, 10],
  [15, 0, 30, 30, 100, 15],
  [5, 10, 30, 30, 10, 0],
];
for (const [f, s, c, fp, l, e] of cases) {
  const got = revealedChars(f, s, c, fp, l);
  if (got !== e) {
    console.error(`FAIL revealedChars(${f},${s},${c},${fp},${l}) = ${got}, want ${e}`);
    process.exit(1);
  }
}
console.log('PASS Typewriter.revealedChars');
