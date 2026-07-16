// npm-licenses.mjs — emit the THIRD_PARTY_LICENSES section for the npm tree.
//
// The Vite/React frontend is compiled into static/dist/ and embedded in the
// agentjail binary, so its runtime dependencies are *distributed* and carry the
// same attribution obligations as the Go modules. `go list` cannot see them.
//
// Mirrors gen-third-party-licenses.sh's Go half: no network, no extra deps —
// walk the installed tree, reproduce each package's license text verbatim.
//
// Only the production dependency closure is emitted. devDependencies (vite,
// typescript, oxlint) build the bundle but are never shipped inside it, so they
// carry no distribution obligation.
//
// Usage: node scripts/npm-licenses.mjs <frontend-dir>

import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'

const frontend = resolve(process.argv[2])
const root = join(frontend, 'node_modules')

if (!existsSync(root)) {
  console.error(`npm-licenses: ${root} missing — run \`bun install\` first`)
  process.exit(1)
}

const readJSON = (p) => JSON.parse(readFileSync(p, 'utf8'))

// Resolve like Node does: nearest nested node_modules first, then walk up to the
// hoisted root. Package managers hoist most deps but nest on version conflicts.
function resolvePkg(name, fromDir) {
  let dir = fromDir
  for (;;) {
    const candidate = join(dir, 'node_modules', name, 'package.json')
    if (existsSync(candidate)) return candidate
    const parent = dirname(dir)
    if (parent === dir || dir.length < frontend.length) return null
    dir = parent
  }
}

const LICENSE_RE = /^(LICEN[CS]E|COPYING|NOTICE)/i

function licenseTexts(pkgDir) {
  const out = []
  for (const f of readdirSync(pkgDir, { withFileTypes: true })
    .filter((e) => e.isFile() && LICENSE_RE.test(e.name))
    .map((e) => e.name)
    .sort()) {
    out.push({ name: f, text: readFileSync(join(pkgDir, f), 'utf8') })
  }
  return out
}

// SPDX id from package.json, tolerating the legacy {type,url} / array shapes.
function spdx(pkg) {
  const l = pkg.license ?? pkg.licenses
  if (!l) return ''
  if (typeof l === 'string') return l
  if (Array.isArray(l)) return l.map((e) => e.type ?? e).join(' OR ')
  return l.type ?? ''
}

const collected = new Map()
const seen = new Set()
const queue = Object.keys(readJSON(join(frontend, 'package.json')).dependencies ?? {})
  .map((name) => ({ name, from: frontend }))

while (queue.length > 0) {
  const { name, from } = queue.shift()
  const manifest = resolvePkg(name, from)
  if (manifest === null) continue // optional/peer dep not installed
  const pkgDir = dirname(manifest)
  if (seen.has(pkgDir)) continue
  seen.add(pkgDir)

  const pkg = readJSON(manifest)
  const key = `${pkg.name}@${pkg.version}`
  if (!collected.has(key)) {
    collected.set(key, { name: pkg.name, version: pkg.version, spdx: spdx(pkg), files: licenseTexts(pkgDir) })
  }
  for (const dep of Object.keys(pkg.dependencies ?? {})) queue.push({ name: dep, from: pkgDir })
}

const pkgs = [...collected.values()].sort((a, b) =>
  a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name),
)

const lines = []
lines.push('npm packages:')
for (const p of pkgs) lines.push(`  - ${p.name} ${p.version}${p.spdx ? ` (${p.spdx})` : ''}`)
lines.push('')

for (const p of pkgs) {
  lines.push('')
  lines.push('='.repeat(80))
  lines.push(`${p.name} ${p.version}${p.spdx ? ` (${p.spdx})` : ''}`)
  lines.push('='.repeat(80))
  lines.push('')
  if (p.files.length === 0) {
    lines.push(`(no license file published in the package — SPDX id "${p.spdx || 'UNKNOWN'}" declared in package.json; review manually)`)
    continue
  }
  for (const f of p.files) {
    lines.push(`----- ${f.name} -----`)
    lines.push(f.text.replace(/\s+$/, ''))
    lines.push('')
  }
}

process.stdout.write(lines.join('\n') + '\n')
