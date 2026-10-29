import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocket as NodeWebSocket } from 'ws';
import { createServer } from '../server/app.js';
import { ChatClient } from '../src/protocol/client.js';

export const PASSWORDS = {
  alice: 'violet-harbor-sunrise-71',
  bob: 'granite-meadow-lantern-38',
  carol: 'copper-willow-thunder-55',
  mallory: 'shadow-orchid-compass-90',
};

const silentLog = { log() {}, error() {} };
const liveClients = new Set();

export async function startServer({ dataDir, ...options } = {}) {
  const dir = dataDir ?? mkdtempSync(join(tmpdir(), 'qsc-test-'));
  const logLines = [];
  const log = { log: (...args) => logLines.push(args.join(' ')), error: (...args) => logLines.push(args.join(' ')) };
  const server = await createServer({ dataDir: dir, log: options.quiet ? silentLog : log, ...options });
  const port = await server.listen(0);
  return {
    server,
    dataDir: dir,
    base: `http://127.0.0.1:${port}`,
    logLines,
    async close({ keepData = false } = {}) {
      for (const client of liveClients) client.disconnect();
      liveClients.clear();
      await server.close();
      if (!keepData && !dataDir) rmSync(dir, { recursive: true, force: true });
    },
  };
}

class MemoryStorage {
  #map = new Map();
  get length() { return this.#map.size; }
  key(index) { return [...this.#map.keys()][index] ?? null; }
  getItem(key) { return this.#map.has(key) ? this.#map.get(key) : null; }
  setItem(key, value) { this.#map.set(key, String(value)); }
  removeItem(key) { this.#map.delete(key); }
}

// A ChatClient wired for Node: cookie jar, `ws` sockets carrying the cookie, and a recorder of every
// byte the client sends or receives, so tests can assert on actual network payloads.
export function makeClient(base, { storage = new MemoryStorage() } = {}) {
  const jar = { cookie: null };
  const network = [];
  const fetchImpl = async (url, init = {}) => {
    const headers = { ...(init.headers ?? {}) };
    if (jar.cookie) headers.cookie = jar.cookie;
    const response = await fetch(url, { ...init, headers });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) jar.cookie = setCookie.split(';')[0];
    const text = await response.text();
    network.push({ direction: 'http', method: init.method ?? 'GET', url, request: init.body ?? '', response: text, status: response.status });
    return new Response(text, { status: response.status, headers: response.headers });
  };
  const createWebSocket = (url) => {
    const socket = new NodeWebSocket(url, { headers: jar.cookie ? { cookie: jar.cookie } : {} });
    const send = socket.send.bind(socket);
    socket.send = (data) => { network.push({ direction: 'ws-out', data: String(data) }); send(data); };
    socket.on('message', (data) => network.push({ direction: 'ws-in', data: data.toString() }));
    return socket;
  };
  const client = new ChatClient({ baseUrl: base, fetch: fetchImpl, createWebSocket, storage });
  liveClients.add(client);
  client.network = network;
  client.jar = jar;
  client.storage = storage;
  return client;
}

// Packets this client handed to the relay, in order.
export function sentPackets(client) {
  return client.network
    .filter((entry) => entry.direction === 'ws-out')
    .map((entry) => JSON.parse(entry.data))
    .filter((frame) => frame.type === 'send')
    .map((frame) => frame.packet);
}

export function networkText(client) {
  return client.network.map((entry) => `${entry.request ?? ''}\n${entry.response ?? ''}\n${entry.data ?? ''}`).join('\n');
}

export async function waitFor(predicate, { timeout = 15000, interval = 25, message = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const value = await predicate();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${message}`);
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
}

export function nextEvent(client, event, { timeout = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { off(); reject(new Error(`Timed out waiting for ${event}`)); }, timeout);
    const off = client.on(event, (data) => { clearTimeout(timer); off(); resolve(data); });
  });
}

export async function connected(client) {
  client.connect();
  await waitFor(() => client.connected, { message: 'websocket connection' });
}

// Registers two (or more) users and connects them.
export async function setupUsers(base, names = ['alice', 'bob']) {
  const clients = {};
  for (const name of names) {
    clients[name] = makeClient(base);
    await clients[name].register(name, PASSWORDS[name]);
    await connected(clients[name]);
  }
  return clients;
}

// Sends and waits until the recipient has processed (authenticated + decrypted) the message.
export async function deliver(from, to, text) {
  const received = nextEvent(to, 'message');
  await from.sendText(to.username, text);
  const event = await received;
  await to.idle();
  return event;
}

export function queueFor(server, username) {
  return server.store.queue.filter((item) => item.to === username);
}

// ----- Malicious-server helpers ------------------------------------------------------------------
// The tests below model an attacker who controls the relay and its database: it can read, drop,
// modify, reorder, replay and inject queued packets, and rewrite the public key directory.

// Has `from` send a message while `to` is offline, then removes the packet from the queue before
// delivery and returns it (as a malicious relay would see it).
export async function interceptNext(env, from, to, text) {
  to.disconnect();
  const before = new Set(env.server.store.queue.map((item) => item.qid));
  await from.sendText(to.username, text);
  const item = await waitFor(() => env.server.store.queue.find((entry) => !before.has(entry.qid) && entry.to === to.username), { message: 'queued packet' });
  env.server.store.queue = env.server.store.queue.filter((entry) => entry.qid !== item.qid);
  return structuredClone(item.packet);
}

// Injects packets into `client`'s queue and waits for the client to accept or reject each one.
export async function injectAndProcess(env, client, packets) {
  const outcomes = [];
  const offMessage = client.on('message', (event) => outcomes.push({ kind: 'message', text: event.message.text, from: event.message.from }));
  const offRejected = client.on('rejected', (event) => outcomes.push({ kind: 'rejected', code: event.code }));
  try {
    await waitFor(() => !env.server.store.queue.some((item) => item.to === client.username), { message: 'drained queue before injection' });
    for (const packet of packets) env.server.store.queue.push({ qid: crypto.randomUUID(), to: client.username, packet, at: Date.now() });
    if (client.connected) client.requestSync(); else client.connect();
    await waitFor(() => outcomes.length >= packets.length, { message: `${packets.length} processed packets` });
    await client.idle();
    return outcomes;
  } finally {
    offMessage();
    offRejected();
  }
}
