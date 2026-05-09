#!/usr/bin/env node
/**
 * Smoke test for deny-sh-mcp.
 *
 * Spawns the MCP server, sends MCP `initialize` + `tools/list` requests via stdio
 * JSON-RPC, asserts the server responds with the expected tools.
 *
 * Does NOT make any actual API calls (no DENY_API_KEY required, no network).
 */
const { spawn } = require('child_process');
const path = require('path');

const SERVER = path.join(__dirname, 'deny-mcp-server.cjs');
const TIMEOUT_MS = 5000;

const child = spawn('node', [SERVER], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, DENY_API_KEY: 'dk_smoke_dummy_key_not_used' },
});

let stdout = '';
let stderr = '';
let received = [];
let buf = '';

child.stdout.on('data', (chunk) => {
  stdout += chunk;
  buf += chunk.toString('utf8');
  let nl;
  while ((nl = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (line) {
      try { received.push(JSON.parse(line)); } catch {}
    }
  }
});
child.stderr.on('data', (chunk) => { stderr += chunk; });

function send(msg) {
  child.stdin.write(JSON.stringify(msg) + '\n');
}

const timer = setTimeout(() => {
  console.error('TIMEOUT after', TIMEOUT_MS, 'ms');
  console.error('stderr:', stderr);
  console.error('received:', JSON.stringify(received, null, 2));
  child.kill();
  process.exit(1);
}, TIMEOUT_MS);

(async () => {
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '0.0.0' } } });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });

  await new Promise((r) => setTimeout(r, 1000));

  clearTimeout(timer);

  const initResp = received.find((m) => m.id === 1);
  const toolsResp = received.find((m) => m.id === 2);

  let pass = true;

  if (!initResp || initResp.error) {
    console.error('FAIL: initialize:', JSON.stringify(initResp));
    pass = false;
  } else {
    console.log('OK   initialize: protocolVersion=' + (initResp.result?.protocolVersion || 'missing'));
  }

  if (!toolsResp || toolsResp.error) {
    console.error('FAIL: tools/list:', JSON.stringify(toolsResp));
    pass = false;
  } else {
    const tools = (toolsResp.result?.tools || []).map((t) => t.name).sort();
    const expected = ['deny_create_decoy', 'deny_decrypt', 'deny_encrypt', 'deny_local_create_decoy', 'deny_local_decrypt', 'deny_local_encrypt', 'deny_local_shamir_split', 'deny_usage', 'deny_vault_get', 'deny_vault_list', 'deny_vault_store'];
    console.log('OK   tools/list: ' + tools.length + ' tools — ' + tools.join(', '));
    const missing = expected.filter((e) => !tools.includes(e));
    if (missing.length) {
      console.error('FAIL: missing tools: ' + missing.join(', '));
      pass = false;
    }
  }

  child.kill();
  process.exit(pass ? 0 : 1);
})();
