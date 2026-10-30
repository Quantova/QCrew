// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function issueLicence(key, subject) {
  return Q.issue({ key, licenceKind: 'atpl', licenceNumber: 'UK FCL 123456', subject: Q.keyId(subject), issuerLabel: 'Civil Aviation Authority' });
}

test('an issued licence is a well formed signed record of the authority', () => {
  const authority = freshKey();
  const holder = freshKey();
  const lic = issueLicence(authority, holder);
  assert.strictEqual(lic.format, 'qcrew/1');
  assert.strictEqual(lic.type, 'issue');
  assert.strictEqual(lic.algorithm, 'ML-DSA-65');
  assert.strictEqual(lic.signer.id, Q.keyId(authority));
  assert.strictEqual(lic.statement.issuerKeyId, Q.keyId(authority));
  assert.strictEqual(lic.statement.subjectKeyId, Q.keyId(holder));
  assert.match(lic.statement.crewId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(lic.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(lic.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the rating, medical and check records chain to the same credential', () => {
  const authority = freshKey();
  const holder = freshKey();
  const examiner = freshKey();
  const doctor = freshKey();
  const lic = issueLicence(authority, holder);
  const rated = Q.rating({ key: examiner, issue: lic, rating: 'B738 type rating' });
  const med = Q.medical({ key: doctor, record: lic, medicalClass: 'class1' });
  const chk = Q.check({ key: examiner, record: med, checkKind: 'proficiency', result: 'pass' });
  assert.strictEqual(rated.statement.crewId, lic.statement.crewId);
  assert.strictEqual(rated.statement.issueRef, Q.recordRef(lic));
  assert.strictEqual(med.statement.priorRef, Q.recordRef(lic));
  assert.strictEqual(chk.statement.priorRef, Q.recordRef(med));
  assert.strictEqual(chk.statement.result, 'pass');
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const holder = freshKey();
  const base = { key, licenceKind: 'atpl', licenceNumber: 'L1', subject: Q.keyId(holder) };
  assert.throws(() => Q.issue(Object.assign({}, base, { licenceKind: 'wizard' })), /licenceKind must be one of/);
  assert.throws(() => Q.issue(Object.assign({}, base, { licenceNumber: '' })), /licenceNumber is 1 to/);
  assert.throws(() => Q.issue(Object.assign({}, base, { subject: 'nothex' })), /subject is a/);
  assert.throws(() => Q.issue(Object.assign({}, base, { unknownField: 1 })), /is not an option of issue/);
  const lic = issueLicence(key, holder);
  assert.throws(() => Q.medical({ key, record: lic, medicalClass: 'class9' }), /medicalClass must be one of/);
  assert.throws(() => Q.check({ key, record: lic, checkKind: 'proficiency', result: 'maybe' }), /result must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  const holder = freshKey();
  assert.throws(() => issueLicence(new Uint8Array(16), holder), /32 byte Uint8Array seed/);
  assert.throws(() => issueLicence(new Uint8Array(32), holder), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const lic = issueLicence(authority, holder);
  const ok = await Q.verify(lic, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'issue');
  assert.strictEqual(ok.crewId, lic.statement.crewId);
  const wrongType = await Q.verify(lic, { type: 'rating', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(lic, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const lic = issueLicence(authority, holder);
  const forged = JSON.parse(JSON.stringify(lic));
  forged.statement.licenceKind = 'ppl';
  const r = await Q.verify(forged, { type: 'issue', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a record to the record before it', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const doctor = freshKey();
  const lic = issueLicence(authority, holder);
  const med = Q.medical({ key: doctor, record: lic, medicalClass: 'class1' });
  const good = await Q.verify(med, { type: 'medical', network: 'testnet', requireAnchor: false, strict: false, prior: lic });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherLic = issueLicence(authority, holder);
  const bad = await Q.verify(med, { type: 'medical', network: 'testnet', requireAnchor: false, strict: false, prior: otherLic });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('crewRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.crewRef(secret, 'UK FCL 123456');
  const b = Q.crewRef(secret, 'UK FCL 123456');
  const c = Q.crewRef(secret, 'UK FCL 123457');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the aircrew line', () => {
  assert.strictEqual(Q.KIND, 1405);
  assert.strictEqual(Q.FORMAT, 'qcrew/1');
  assert.deepStrictEqual([...Q.TYPES], ['issue', 'rating', 'medical', 'check', 'revoke']);
  assert.deepStrictEqual([...Q.LICENCES], ['atpl', 'cpl', 'ppl', 'mpl', 'cabin', 'dispatcher', 'maintenance']);
  assert.deepStrictEqual([...Q.RESULTS], ['pass', 'fail', 'partial']);
});
