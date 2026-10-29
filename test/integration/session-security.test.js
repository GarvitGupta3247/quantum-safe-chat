// F4 regression: forward secrecy and (classical) post-compromise security of the PQXDH + Double
// Ratchet sessions, demonstrated with real envelopes and real device-state snapshots.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAccountVault, encryptEnvelope, openEnvelope } from '../../src/protocol/envelope.js';
import { deliver, injectAndProcess, interceptNext, setupUsers, startServer } from '../helpers.js';

function withoutReplayCache(vault) {
  return { ...vault, seen: {} };
}

test('F4 forward secrecy: compromising a device after delivery does not decrypt captured earlier traffic', async () => {
  const env = await startServer();
  try {
    const { alice, bob } = await setupUsers(env.base);
    // A passive network/relay attacker records every packet.
    const captured = [];
    for (const text of ['first flight 1', 'first flight 2']) {
      const packet = await interceptNext(env, alice, bob, text);
      captured.push(packet);
      await injectAndProcess(env, bob, [structuredClone(packet)]);
    }
    await deliver(bob, alice, 'reply');
    const later = await interceptNext(env, alice, bob, 'second chain');
    captured.push(later);
    await injectAndProcess(env, bob, [structuredClone(later)]);

    // Full compromise of bob's device NOW: identity keys, prekeys, ratchet state (replay cache removed
    // so that only cryptography, not bookkeeping, stands in the way).
    const stolen = withoutReplayCache(bob.snapshotForTesting());
    for (const packet of captured) {
      await assert.rejects(openEnvelope(stolen, structuredClone(packet)), (error) => ['replay', 'stale_prekey', 'decrypt_failed'].includes(error.code),
        `captured message ${packet.h.n} must stay confidential`);
    }
    // Even recomputing PQXDH from scratch fails: the one-time prekey was deleted after first use.
    const noSessions = { ...stolen, sessions: {} };
    await assert.rejects(openEnvelope(noSessions, structuredClone(captured[0])), (error) => error.code === 'stale_prekey');
    // Long-term identity keys alone are useless for decryption (they only sign / authenticate).
  } finally {
    await env.close();
  }
});

test('F4 post-compromise security (classical): a stolen state snapshot stops working once a post-compromise ratchet key is used and answered', async () => {
  let { vault: alice } = createAccountVault('alice');
  let { vault: bob, upload } = createAccountVault('bob');
  const prekeys = { identity: upload.identity, spk: upload.spk, pq: upload.pqopks[0], opk: upload.opks[0] };
  const send = async (from, peer, text, pk) => encryptEnvelope(from, { peer, text, prekeys: pk });

  let r = await send(alice, 'bob', 'hello', prekeys); alice = r.vault;
  let o = await openEnvelope(bob, r.packet); bob = o.vault;
  r = await send(bob, 'alice', 'hi'); bob = r.vault;
  o = await openEnvelope(alice, r.packet); alice = o.vault;

  // Attacker steals alice's complete state, then only observes traffic passively.
  let attacker = withoutReplayCache(structuredClone(alice));

  r = await send(bob, 'alice', 'b1 (same chain as before compromise)'); bob = r.vault;
  const b1 = r.packet;
  o = await openEnvelope(alice, b1); alice = o.vault;
  const attackerB1 = await openEnvelope(attacker, structuredClone(b1));
  assert.equal(attackerB1.message.text, 'b1 (same chain as before compromise)', 'compromise is real: current chain readable');
  attacker = withoutReplayCache(attackerB1.vault);

  // a2 still uses alice's ratchet key A1, generated BEFORE the compromise, so bob's answer b2 is
  // still readable by the attacker. This is expected Double Ratchet behaviour, not a bug.
  r = await send(alice, 'bob', 'a2 (ratchet key from before compromise)'); alice = r.vault;
  o = await openEnvelope(bob, r.packet); bob = o.vault;
  r = await send(bob, 'alice', 'b2 (not yet healed)'); bob = r.vault;
  const b2 = r.packet;
  o = await openEnvelope(alice, b2); alice = o.vault; // alice now generates a fresh key A2
  const attackerB2 = await openEnvelope(attacker, structuredClone(b2));
  assert.equal(attackerB2.message.text, 'b2 (not yet healed)');
  attacker = withoutReplayCache(attackerB2.vault);

  // Healing: alice sends with A2 (generated after the compromise, unknown to the attacker), bob replies.
  r = await send(alice, 'bob', 'a3 (fresh post-compromise key)'); alice = r.vault;
  o = await openEnvelope(bob, r.packet); bob = o.vault;
  r = await send(bob, 'alice', 'b3 (after healing)'); bob = r.vault;
  const b3 = r.packet;
  o = await openEnvelope(alice, b3); alice = o.vault;
  assert.equal(o.message.text, 'b3 (after healing)');

  // The attacker's copy of the state can no longer derive the keys (X25519 secret it never saw).
  await assert.rejects(openEnvelope(attacker, structuredClone(b3)), (error) => error.code === 'decrypt_failed');
});

test('LIMITATION (documented): first-flight messages without a one-time prekey are exposed by a later compromise before signed-prekey rotation', async () => {
  let { vault: alice } = createAccountVault('alice');
  const { vault: bob, upload } = createAccountVault('bob');
  // Server ran out of one-time prekeys: last-resort ML-KEM prekey and no X25519 one-time prekey.
  const prekeys = { identity: upload.identity, spk: upload.spk, pq: upload.pqspk, opk: null };
  const r = await encryptEnvelope(alice, { peer: 'bob', text: 'first flight, no OPK', prekeys });
  alice = r.vault;
  const delivered = await openEnvelope(bob, r.packet);
  // Bob's device is later compromised while the signed prekeys are still retained.
  const stolen = { ...withoutReplayCache(delivered.vault), sessions: {} };
  const exposed = await openEnvelope(stolen, structuredClone(r.packet));
  assert.equal(exposed.message.text, 'first flight, no OPK');
  // This mirrors the PQXDH specification's own caveat; mitigation is OPK replenishment + SPK rotation.
});
