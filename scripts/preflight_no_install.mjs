#!/usr/bin/env node

// Read-only, dependency-free preflight for Node.js 20+ agent runtimes.

const EXPECTED_RELEASE = "0.3.5";
const EXPECTED_WHEEL_SHA256 =
  "c6ba325daa27a750bd64ad746e4c521803ab3db0ee1e756017105af1425ed918";
const EXPECTED_SESSION = "61821bb89d208bc5e557a5f4fa6de55b";
const PATHS = [
  "/directory",
  "/.well-known/ard.json",
  "/.well-known/agentcomms-trust.json",
  "/.well-known/agentcomms-conformance.json",
];
const MAX_RESPONSE_BYTES = 1024 * 1024;

function argumentsFrom(argv) {
  let hub = "https://web3wes.pythonanywhere.com";
  let timeout = 15;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--hub" && argv[index + 1]) hub = argv[++index];
    else if (argv[index] === "--timeout" && argv[index + 1]) {
      timeout = Number(argv[++index]);
    } else throw new Error(`unknown or incomplete argument: ${argv[index]}`);
  }
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 60) {
    throw new Error("timeout must be greater than 0 and at most 60 seconds");
  }
  const parsed = new URL(hub);
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error("hub must be an absolute HTTP(S) URL without credentials");
  }
  parsed.search = "";
  parsed.hash = "";
  parsed.pathname = parsed.pathname.replace(/\/$/, "");
  return { hub: parsed.toString().replace(/\/$/, ""), timeout };
}

async function boundedJson(response) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new Error("response exceeds the 1 MiB preflight limit");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("response exceeds the 1 MiB preflight limit");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { body: JSON.parse(new TextDecoder().decode(bytes)), bytes: total };
}

async function getJson(hub, path, timeout) {
  const url = new URL(path, `${hub}/`);
  if (url.origin !== new URL(hub).origin) throw new Error("cross-origin request rejected");
  const response = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json", "User-Agent": "agentcomms-node-preflight/1" },
    redirect: "manual",
    signal: AbortSignal.timeout(timeout * 1000),
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`GET ${path} returned HTTP ${response.status}`);
  }
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error(`GET ${path} did not return application/json`);
  }
  const parsed = await boundedJson(response);
  return {
    body: parsed.body,
    record: { method: "GET", path, status: response.status, bytes: parsed.bytes },
  };
}

async function run(hub, timeout) {
  const responses = {};
  const requests = [];
  for (const path of PATHS) {
    const result = await getJson(hub, path, timeout);
    responses[path] = result.body;
    requests.push(result.record);
  }
  const directory = responses["/directory"];
  const ard = responses["/.well-known/ard.json"];
  const trust = responses["/.well-known/agentcomms-trust.json"];
  const conformance = responses["/.well-known/agentcomms-conformance.json"];
  const wheel = (trust.artifacts || []).find((item) => item.filename?.endsWith(".whl")) || {};
  const checks = {
    allRequestsSucceeded: requests.every((item) => item.status === 200),
    directoryIsList: Array.isArray(directory.agents),
    ardEntryPresent: (ard.entries || []).some(
      (item) => item.identifier === "urn:air:web3wes.pythonanywhere.com:mcp:agentcomms",
    ),
    trustReleaseMatches: trust.version === EXPECTED_RELEASE,
    wheelDigestMatches: wheel.sha256 === EXPECTED_WHEEL_SHA256,
    conformanceProtocolMatches: conformance.protocol === "agentcomms-v2",
    conformanceSessionMatches: conformance.expected?.session === EXPECTED_SESSION,
    conformanceSelftestCountMatches: conformance.referenceSelftest?.expectedChecks === 20,
  };
  return {
    schema: "agentcomms-no-install-preflight-v1",
    ok: Object.values(checks).every(Boolean),
    mode: "read-only",
    hub,
    requests,
    checks,
    directoryAgentCount: Array.isArray(directory.agents) ? directory.agents.length : 0,
    writesPerformed: false,
    messagesSent: false,
    identityStateCreated: false,
    secretsRead: false,
    filesystemWrites: false,
    limitations: [
      "validates discovery structure and published expected values only",
      "does not install or import agentcomms",
      "does not execute cryptographic primitives or establish security",
      "does not establish independent participation",
    ],
  };
}

let result;
try {
  const options = argumentsFrom(process.argv.slice(2));
  result = await run(options.hub, options.timeout);
} catch (error) {
  result = {
    schema: "agentcomms-no-install-preflight-v1",
    ok: false,
    mode: "read-only",
    error: `${error?.name || "Error"}: ${error?.message || "preflight failed"}`,
    writesPerformed: false,
    messagesSent: false,
    identityStateCreated: false,
    secretsRead: false,
    filesystemWrites: false,
  };
}
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.ok ? 0 : 1;
