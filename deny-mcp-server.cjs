#!/usr/bin/env node
/**
 * deny.sh MCP Server
 * 
 * Model Context Protocol server for AI agents.
 * Provides deniable encryption as tools that any MCP-compatible agent can call.
 * 
 * Tools (API-mode, requires DENY_API_KEY):
 *   deny_encrypt          - Encrypt text via the deny.sh API
 *   deny_decrypt          - Decrypt with control data + passwords
 *   deny_create_decoy     - Create new control data for a different plaintext (same ciphertext)
 *   deny_vault_store      - Store encrypted data in the deny.sh vault
 *   deny_vault_list       - List vault items
 *   deny_vault_get        - Retrieve a vault item by id
 *   deny_usage            - Check current API usage and plan limits
 *
 * Tools (local-mode, no API call, fully offline):
 *   deny_local_encrypt        - Encrypt locally using the same algorithm as the API
 *   deny_local_decrypt        - Decrypt locally
 *   deny_local_create_decoy   - Create decoy control data locally
 *   deny_local_shamir_split   - Split a secret into M-of-N Shamir shares locally
 *
 * Setup:
 *   1. Get an API key at https://deny.sh/register (only needed for API-mode tools)
 *   2. Set DENY_API_KEY environment variable
 *   3. Add to your agent's MCP config
 *
 * MCP Config (claude_desktop_config.json / openclaw.json):
 *   {
 *     "mcpServers": {
 *       "deny": {
 *         "command": "npx",
 *         "args": ["deny-sh-mcp"],
 *         "env": { "DENY_API_KEY": "dk_your_key" }
 *       }
 *     }
 *   }
 */

const API_BASE = process.env.DENY_API_URL || 'https://deny.sh/api';
const API_KEY = process.env.DENY_API_KEY || '';

if (!API_KEY) {
  process.stderr.write('DENY_API_KEY not set. Get one at https://deny.sh/register\n');
}

// ─── MCP Protocol (stdio JSON-RPC) ───

const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

async function api(method, path, body) {
  const url = API_BASE + path;
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + API_KEY,
    },
  };
  if (body) opts.body = JSON.stringify(body);
  
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `API error ${res.status}`);
  return data;
}

// ─── Local crypto (no API needed) ───
const crypto = require('crypto');

// P0-8 (ii): MUST match src/core.ts:deriveKey() byte-for-byte, otherwise
// MCP-encrypted ciphertexts cannot be decrypted by the SDK / API and
// vice-versa. The old form `scrypt(Buffer.from(pw1+pw2), salt, ...)` had a
// length-ambiguity bug: scryptDerive('foo','bar') == scryptDerive('foob','ar').
// core.ts hashes each password to 32 bytes via SHA-256 first, then
// concatenates, eliminating the ambiguity.
function scryptDerive(pw1, pw2, salt) {
  const pw1Hash = crypto.createHash('sha256').update(pw1, 'utf8').digest();
  const pw2Hash = crypto.createHash('sha256').update(pw2, 'utf8').digest();
  const combined = Buffer.concat([pw1Hash, pw2Hash]);
  return crypto.scryptSync(combined, salt, 32, { N: 16384, r: 8, p: 1 });
}

function localEncrypt(plaintext, pw1, pw2) {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const key = scryptDerive(pw1, pw2, salt);

  const ptBuf = Buffer.from(plaintext);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(ptBuf.length);
  const payload = Buffer.concat([lenBuf, ptBuf]);

  const controlData = crypto.randomBytes(payload.length);
  const xored = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) xored[i] = payload[i] ^ controlData[i];

  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  const encrypted = Buffer.concat([cipher.update(xored), cipher.final()]);

  const ciphertext = Buffer.concat([salt, iv, encrypted]);
  return { ciphertext: ciphertext.toString('hex'), controlData: controlData.toString('hex') };
}

function localDecrypt(ciphertextHex, pw1, pw2, controlDataHex) {
  const ct = Buffer.from(ciphertextHex, 'hex');
  const ctrl = Buffer.from(controlDataHex, 'hex');

  const salt = ct.subarray(0, 32);
  const iv = ct.subarray(32, 48);
  const encrypted = ct.subarray(48);

  const key = scryptDerive(pw1, pw2, salt);
  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  const xored = Buffer.concat([decipher.update(encrypted), decipher.final()]);

  const payload = Buffer.alloc(xored.length);
  for (let i = 0; i < xored.length; i++) payload[i] = xored[i] ^ ctrl[i];

  const len = payload.readUInt32LE(0);
  return payload.subarray(4, 4 + len).toString();
}

function localDeny(ciphertextHex, pw1, pw2, fakePlaintext) {
  const ct = Buffer.from(ciphertextHex, 'hex');
  const salt = ct.subarray(0, 32);
  const iv = ct.subarray(32, 48);
  const encrypted = ct.subarray(48);

  const key = scryptDerive(pw1, pw2, salt);
  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  const xored = Buffer.concat([decipher.update(encrypted), decipher.final()]);

  const fakeBuf = Buffer.from(fakePlaintext);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(fakeBuf.length);
  const fakePayload = Buffer.concat([lenBuf, fakeBuf]);

  // Pad to match xored length
  const padded = Buffer.alloc(xored.length);
  fakePayload.copy(padded);
  if (fakePayload.length < xored.length) {
    crypto.randomBytes(xored.length - fakePayload.length).copy(padded, fakePayload.length);
  }

  const fakeCtrl = Buffer.alloc(xored.length);
  for (let i = 0; i < xored.length; i++) fakeCtrl[i] = xored[i] ^ padded[i];

  return fakeCtrl.toString('hex');
}

function localShamirSplit(secret, threshold, shares) {
  // GF(256) Shamir's Secret Sharing
  const secretBuf = Buffer.from(secret);
  const allShares = [];

  for (let s = 1; s <= shares; s++) {
    const shareBuf = Buffer.alloc(secretBuf.length);
    for (let i = 0; i < secretBuf.length; i++) {
      // Generate random polynomial coefficients
      const coeffs = [secretBuf[i]];
      for (let c = 1; c < threshold; c++) coeffs.push(crypto.randomBytes(1)[0]);
      // Evaluate at point s
      let val = 0;
      for (let c = 0; c < coeffs.length; c++) {
        val ^= gfMul(coeffs[c], gfPow(s, c));
      }
      shareBuf[i] = val;
    }
    allShares.push({ index: s, data: shareBuf.toString('hex') });
  }
  return allShares;
}

// GF(256) arithmetic
function gfMul(a, b) {
  let r = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) r ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return r;
}

function gfPow(base, exp) {
  let r = 1;
  for (let i = 0; i < exp; i++) r = gfMul(r, base);
  return r;
}

const TOOLS = [
  {
    name: 'deny_encrypt',
    description: 'Encrypt text with deniable encryption. Returns ciphertext and control data. The same ciphertext can later decrypt to different content using different control data.',
    inputSchema: {
      type: 'object',
      properties: {
        plaintext: { type: 'string', description: 'The text to encrypt' },
        password1: { type: 'string', description: 'Primary password' },
        password2: { type: 'string', description: 'Secondary password (both needed to decrypt)' },
      },
      required: ['plaintext', 'password1', 'password2'],
    },
  },
  {
    name: 'deny_decrypt',
    description: 'Decrypt ciphertext using control data and passwords. Returns the plaintext.',
    inputSchema: {
      type: 'object',
      properties: {
        ciphertext: { type: 'string', description: 'Hex-encoded ciphertext' },
        controlData: { type: 'string', description: 'Hex-encoded control data' },
        password1: { type: 'string', description: 'Primary password' },
        password2: { type: 'string', description: 'Secondary password' },
      },
      required: ['ciphertext', 'controlData', 'password1', 'password2'],
    },
  },
  {
    name: 'deny_create_decoy',
    description: 'Create deniable decoy control data. The same ciphertext will decrypt to this fake message using the new control data. The original decryption still works with the original control data.',
    inputSchema: {
      type: 'object',
      properties: {
        ciphertext: { type: 'string', description: 'Hex-encoded ciphertext' },
        password1: { type: 'string', description: 'Primary password' },
        password2: { type: 'string', description: 'Secondary password' },
        fakeMessage: { type: 'string', description: 'The decoy plaintext' },
      },
      required: ['ciphertext', 'password1', 'password2', 'fakeMessage'],
    },
  },
  {
    name: 'deny_vault_store',
    description: 'Store encrypted data in the deny.sh vault. Data should be pre-encrypted.',
    inputSchema: {
      type: 'object',
      properties: {
        label: { type: 'string', description: 'Label for the vault item' },
        encryptedData: { type: 'string', description: 'Hex-encoded encrypted data' },
        iv: { type: 'string', description: 'Hex-encoded IV' },
        salt: { type: 'string', description: 'Hex-encoded salt' },
      },
      required: ['label', 'encryptedData', 'iv', 'salt'],
    },
  },
  {
    name: 'deny_vault_list',
    description: 'List all items in the deny.sh vault.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'deny_vault_get',
    description: 'Retrieve an item from the deny.sh vault by ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Vault item ID' },
      },
      required: ['id'],
    },
  },
  {
    name: 'deny_usage',
    description: 'Check current API usage and plan limits.',
    inputSchema: { type: 'object', properties: {} },
  },
  // ─── Local tools (no API key needed, runs on agent's machine) ───
  {
    name: 'deny_local_encrypt',
    description: 'Encrypt text locally using deny.sh algorithm. No API call, no server, runs entirely on your machine. Same algorithm as the API (AES-256-CTR + scrypt + XOR composition).',
    inputSchema: {
      type: 'object',
      properties: {
        plaintext: { type: 'string', description: 'Text to encrypt' },
        password1: { type: 'string', description: 'Primary password' },
        password2: { type: 'string', description: 'Secondary password' },
      },
      required: ['plaintext', 'password1', 'password2'],
    },
  },
  {
    name: 'deny_local_decrypt',
    description: 'Decrypt locally. No API call needed.',
    inputSchema: {
      type: 'object',
      properties: {
        ciphertext: { type: 'string', description: 'Hex ciphertext' },
        controlData: { type: 'string', description: 'Hex control data' },
        password1: { type: 'string', description: 'Primary password' },
        password2: { type: 'string', description: 'Secondary password' },
      },
      required: ['ciphertext', 'controlData', 'password1', 'password2'],
    },
  },
  {
    name: 'deny_local_create_decoy',
    description: 'Create decoy control data locally. Same ciphertext, different plaintext. No API call.',
    inputSchema: {
      type: 'object',
      properties: {
        ciphertext: { type: 'string', description: 'Hex ciphertext' },
        password1: { type: 'string', description: 'Primary password' },
        password2: { type: 'string', description: 'Secondary password' },
        fakePlaintext: { type: 'string', description: 'Decoy message' },
      },
      required: ['ciphertext', 'password1', 'password2', 'fakePlaintext'],
    },
  },
  {
    name: 'deny_local_shamir_split',
    description: 'Split a secret into M-of-N shares using Shamir Secret Sharing. Runs locally.',
    inputSchema: {
      type: 'object',
      properties: {
        secret: { type: 'string', description: 'The secret to split' },
        threshold: { type: 'number', description: 'Minimum shares needed to reconstruct (M)' },
        shares: { type: 'number', description: 'Total shares to generate (N)' },
      },
      required: ['secret', 'threshold', 'shares'],
    },
  },
];

async function handleToolCall(name, args) {
  switch (name) {
    case 'deny_encrypt':
      // P0-8 (i): server expects `message`, not `plaintext`. The old MCP
      // call shape sent `plaintext`, which the server discarded — every
      // deny_encrypt invocation came back as a 400 'Required: message...'
      // error. Fixed by aligning the body shape with server/index.ts.
      return await api('POST', '/encrypt', {
        message: args.plaintext,
        password1: args.password1,
        password2: args.password2,
      });

    case 'deny_decrypt':
      // server accepts {ciphertext, controlData} OR {ciphertextHex, controlDataHex}
      // (see /api/decrypt body parse). Send the canonical *Hex shape since
      // the audit normalised the SKILL.md docs to that form.
      return await api('POST', '/decrypt', {
        ciphertextHex: args.ciphertext,
        controlDataHex: args.controlData,
        password1: args.password1,
        password2: args.password2,
      });

    case 'deny_create_decoy':
      // server's /api/deny accepts ciphertext OR ciphertextHex — keep the
      // hex variant for consistency with the SKILL.md docs.
      return await api('POST', '/deny', {
        ciphertextHex: args.ciphertext,
        password1: args.password1,
        password2: args.password2,
        fakeMessage: args.fakeMessage,
      });

    case 'deny_vault_store':
      return await api('POST', '/vault/store', {
        label: args.label,
        encryptedData: args.encryptedData,
        iv: args.iv,
        salt: args.salt,
      });

    case 'deny_vault_list':
      return await api('GET', '/vault/list');

    case 'deny_vault_get':
      return await api('GET', '/vault/' + args.id);

    case 'deny_usage':
      return await api('GET', '/usage');

    // Local tools (no API key needed)
    case 'deny_local_encrypt':
      return localEncrypt(args.plaintext, args.password1, args.password2);

    case 'deny_local_decrypt':
      return { plaintext: localDecrypt(args.ciphertext, args.password1, args.password2, args.controlData) };

    case 'deny_local_create_decoy':
      return { controlData: localDeny(args.ciphertext, args.password1, args.password2, args.fakePlaintext) };

    case 'deny_local_shamir_split':
      return { shares: localShamirSplit(args.secret, args.threshold, args.shares) };

    default:
      throw new Error('Unknown tool: ' + name);
  }
}

// ─── JSON-RPC Handler ───

async function handleMessage(msg) {
  const { id, method, params } = msg;

  switch (method) {
    case 'initialize':
      send({
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: {
            name: 'deny-sh',
            version: '1.0.0',
          },
        },
      });
      break;

    case 'tools/list':
      send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
      break;

    case 'tools/call': {
      const { name, arguments: args } = params;
      try {
        const result = await handleToolCall(name, args || {});
        send({
          jsonrpc: '2.0', id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          },
        });
      } catch (e) {
        send({
          jsonrpc: '2.0', id,
          result: {
            content: [{ type: 'text', text: 'Error: ' + e.message }],
            isError: true,
          },
        });
      }
      break;
    }

    case 'notifications/initialized':
      // Client acknowledged init
      break;

    default:
      send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + method } });
  }
}

rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    handleMessage(msg).catch(e => {
      send({ jsonrpc: '2.0', id: msg.id, error: { code: -32603, message: e.message } });
    });
  } catch (e) {
    // Invalid JSON, ignore
  }
});

process.stderr.write('deny.sh MCP server started\n');
