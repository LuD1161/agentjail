/**
 * Cloudflare Worker: agentjail releases analytics proxy
 *
 * Routes:
 *   GET /v1/latest?v=X&os=Y&arch=Z  — fetch GitHub latest release, return JSON (edge-cached 5m)
 *   GET /download/{version}/{filename} — validate + 302 redirect to GitHub releases
 *   GET /health                       — liveness check
 *   *                                 — 404
 *
 * Every request logs a datapoint to Workers Analytics Engine (best-effort).
 */

const GITHUB_REPO = "LuD1161/agentjail";
const GITHUB_API_BASE = "https://api.github.com";
const GITHUB_RELEASES_BASE = `https://github.com/${GITHUB_REPO}/releases/download`;
const WORKER_BASE = "https://releases.agentjail.io";

const VERSION_RE = /^v\d+\.\d+\.\d+$/;
const FILENAME_RE =
  /^(agentjail-v\d+\.\d+\.\d+-\w+-\w+\.tar\.gz|SHA256SUMS(\.minisig)?)$/;

// OS/arch extracted from tarball filename, e.g. agentjail-v0.6.0-darwin-arm64.tar.gz
const ASSET_RE = /^agentjail-(v\d+\.\d+\.\d+)-(\w+)-(\w+)\.tar\.gz$/;

/**
 * Write a single analytics datapoint to Workers Analytics Engine.
 * Fire-and-forget — never throws.
 */
function recordAnalytics(env, request, { pathname, installedVersion, os, arch }) {
  try {
    if (!env.ANALYTICS) return;
    const country = (request.cf && request.cf.country) || "unknown";
    env.ANALYTICS.writeDataPoint({
      blobs: [pathname, installedVersion || "", os || "", arch || "", country],
      doubles: [],
      indexes: [pathname],
    });
  } catch (_) {
    // best-effort, never fail the request
  }
}

/**
 * Fetch the SHA256SUMS file from the release and parse it into a map of
 * filename → hex digest.
 */
async function fetchChecksums(version) {
  const url = `${GITHUB_RELEASES_BASE}/${version}/SHA256SUMS`;
  const resp = await fetch(url, {
    headers: { "User-Agent": "agentjail-releases-worker/1" },
  });
  if (!resp.ok) return {};
  const text = await resp.text();
  const map = {};
  for (const line of text.split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts.length === 2) {
      const [hash, name] = parts;
      map[name] = hash;
    }
  }
  return map;
}

/**
 * Handle GET /v1/latest
 * Query params: v (installed version), os, arch (for analytics only)
 */
async function handleLatest(request, env) {
  const cacheKey = new Request("https://cache.internal/v1/latest", { method: "GET" });
  const cache = caches.default;

  // Serve from edge cache if available
  let cached = await cache.match(cacheKey);
  if (cached) {
    return cached;
  }

  const apiURL = `${GITHUB_API_BASE}/repos/${GITHUB_REPO}/releases/latest`;
  const ghResp = await fetch(apiURL, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "agentjail-releases-worker/1",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!ghResp.ok) {
    return new Response(
      JSON.stringify({ error: "upstream error", status: ghResp.status }),
      { status: 502, headers: { "Content-Type": "application/json" } }
    );
  }

  const release = await ghResp.json();
  const version = release.tag_name;
  const published_at = release.published_at;

  // Fetch checksums
  const checksums = await fetchChecksums(version);

  // Build assets list from release assets
  const assets = [];
  for (const asset of release.assets || []) {
    const m = ASSET_RE.exec(asset.name);
    if (!m) continue;
    const [, , assetOs, assetArch] = m;
    assets.push({
      os: assetOs,
      arch: assetArch,
      url: `${WORKER_BASE}/download/${version}/${asset.name}`,
      sha256: checksums[asset.name] || null,
      sig_url: `${WORKER_BASE}/download/${version}/SHA256SUMS.minisig`,
      sums_url: `${WORKER_BASE}/download/${version}/SHA256SUMS`,
    });
  }

  const body = JSON.stringify({ version, published_at, assets });
  const response = new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=300", // 5 minutes
    },
  });

  // Store in edge cache
  await cache.put(cacheKey, response.clone());

  return response;
}

/**
 * Handle GET /download/{version}/{filename}
 * Validates inputs, then 302 redirects to GitHub releases.
 */
function handleDownload(request, version, filename) {
  if (!VERSION_RE.test(version)) {
    return new Response(
      JSON.stringify({ error: "invalid version format" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
  if (!FILENAME_RE.test(filename)) {
    return new Response(
      JSON.stringify({ error: "invalid filename" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const method = request.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    return new Response(
      JSON.stringify({ error: "method not allowed" }),
      {
        status: 405,
        headers: {
          "Content-Type": "application/json",
          Allow: "GET, HEAD",
        },
      }
    );
  }

  const target = `${GITHUB_RELEASES_BASE}/${version}/${filename}`;
  return Response.redirect(target, 302);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Parse analytics params
    const qv = url.searchParams.get("v");
    const qos = url.searchParams.get("os");
    const qarch = url.searchParams.get("arch");
    const installedVersion =
      request.headers.get("X-Agentjail-Version") || qv || "";

    // Record analytics for every request (best-effort)
    recordAnalytics(env, request, {
      pathname,
      installedVersion,
      os: qos,
      arch: qarch,
    });

    // Route: / — redirect browsers to the latest GitHub release page
    if (pathname === "/" || pathname === "") {
      return Response.redirect(
        `https://github.com/${GITHUB_REPO}/releases/latest`,
        302
      );
    }

    // Route: /health
    if (pathname === "/health") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Route: /v1/latest
    if (pathname === "/v1/latest") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response(JSON.stringify({ error: "method not allowed" }), {
          status: 405,
          headers: { "Content-Type": "application/json", Allow: "GET, HEAD" },
        });
      }
      return handleLatest(request, env);
    }

    // Route: /download/{version}/{filename}
    const downloadMatch = pathname.match(/^\/download\/([^/]+)\/([^/]+)$/);
    if (downloadMatch) {
      const [, version, filename] = downloadMatch;
      return handleDownload(request, version, filename);
    }

    // Fallback: 404
    return new Response(JSON.stringify({ error: "not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  },
};
