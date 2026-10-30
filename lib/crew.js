// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  if (value === undefined || value === null) return Object.create(null);
  if (typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) F.reject('the options are a plain object');
  return Object.assign(Object.create(null), value);
}

function requireSeed(key) {
  if (!((ArrayBuffer.isView(key) && key instanceof Uint8Array) && key.length === 32 && key.buffer instanceof ArrayBuffer)) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  if (new Set(key).size < 13) F.reject('a signing key made of too few different byte values is refused, draw one with generateKey');
  return key;
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

const HIDDEN = 'SecretKey [hidden]';

class SecretKey extends Uint8Array {
  static get [Symbol.species]() {
    return Uint8Array;
  }

  toJSON() {
    return HIDDEN;
  }

  toString() {
    return HIDDEN;
  }

  toLocaleString() {
    return HIDDEN;
  }

  [require('util').inspect.custom]() {
    return HIDDEN;
  }
}

function generateKey() {
  const seed = new SecretKey(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qcrew-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function keyIdOf(party, what) {
  if (typeof party === 'string' && /^[0-9a-f]{64}$/.test(party)) return party;
  if ((ArrayBuffer.isView(party) && party instanceof Uint8Array)) return F.keyIdOf(party);
  if (party && typeof party === 'object' && party.format === 'qcrew-key/1' && typeof party.publicKey === 'string') {
    const raw = Buffer.from(party.publicKey, 'base64');
    if (raw.toString('base64') !== party.publicKey) F.reject('the ' + what + ' public key is not canonical base64');
    const id = F.keyIdOf(raw);
    if (party.id !== id) F.reject('the ' + what + ' key description names an id that does not match its public key');
    return id;
  }
  F.reject(what + ' is a qcrew-key/1 description, a public key or a 64 character key id');
}

function crewRef(secret, reference) {
  return F.crewRefOf(secret, reference);
}

function nowIso() {
  return new Date().toISOString();
}

function seal(type, key, statement) {
  const pk = publicKey(key);
  const id = F.keyIdOf(pk);
  let plain;
  try {
    plain = F.plainCopy(statement);
  } catch (e) {
    F.reject('the statement is not plain data');
  }
  const problem = F.statementProblem(type, plain);
  if (problem) F.reject(problem);
  const message = F.payload(type, plain);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id, publicKey: Buffer.from(pk).toString('base64') },
    statement: JSON.parse(JSON.stringify(plain)),
    signature: Buffer.from(signature).toString('base64'),
  };
}

function badCrew(message) {
  const e = new Error(message);
  e.code = 'QCREW_INVALID_CREDENTIAL';
  throw e;
}

function verifiedPrior(envelope, what) {
  const p = F.parse(envelope);
  if (p.signerId !== F.keyIdOf(p.publicKey)) badCrew('the ' + what + ' names a signer id that does not match its public key');
  if (!native.verify(p.publicKey, F.encoded(p), p.signature)) badCrew('the ' + what + ' signature does not verify');
  return p;
}

function issue(options) {
  if (!options || typeof options !== 'object') F.reject('issue needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.licenceKind === undefined) F.reject('licenceKind is required, one of ' + F.LICENCES.join(', '));
  if (options.licenceNumber === undefined) F.reject('licenceNumber is required, the number of the licence');
  if (options.subject === undefined) F.reject('subject is required, the key of the crew member the licence is for');
  return seal('issue', options.key, {
    crewId: randomHex(16),
    licenceKind: options.licenceKind,
    licenceNumber: options.licenceNumber,
    subjectKeyId: keyIdOf(options.subject, 'subject'),
    issuerKeyId: keyId(options.key),
    issuerLabel: options.issuerLabel === undefined ? '' : options.issuerLabel,
    issuedAt: options.issuedAt === undefined ? nowIso() : options.issuedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function rating(options) {
  if (!options || typeof options !== 'object') F.reject('rating needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.issue === undefined) F.reject('the issue envelope the rating extends is required');
  if (options.rating === undefined) F.reject('rating is required, the rating or endorsement added to the licence');
  const r = verifiedPrior(options.issue, 'issue');
  if (r.type !== 'issue') badCrew('the referenced envelope is not an issue');
  return seal('rating', options.key, {
    crewId: r.statement.crewId,
    issueRef: F.refOf(r),
    rating: options.rating,
    ratingId: randomHex(16),
    examinerKeyId: keyId(options.key),
    examinerLabel: options.examinerLabel === undefined ? '' : options.examinerLabel,
    ratedAt: options.ratedAt === undefined ? nowIso() : options.ratedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function medical(options) {
  if (!options || typeof options !== 'object') F.reject('medical needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior credential envelope this medical follows is required');
  if (options.medicalClass === undefined) F.reject('medicalClass is required, one of ' + F.MEDICAL_CLASSES.join(', '));
  const prior = verifiedPrior(options.record, 'record');
  return seal('medical', options.key, {
    crewId: prior.statement.crewId,
    priorRef: F.refOf(prior),
    medicalClass: options.medicalClass,
    examinerKeyId: keyId(options.key),
    examinerLabel: options.examinerLabel === undefined ? '' : options.examinerLabel,
    assessedAt: options.assessedAt === undefined ? nowIso() : options.assessedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function check(options) {
  if (!options || typeof options !== 'object') F.reject('check needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior credential envelope this check follows is required');
  if (options.checkKind === undefined) F.reject('checkKind is required, one of ' + F.CHECK_KINDS.join(', '));
  if (options.result === undefined) F.reject('result is required, one of ' + F.RESULTS.join(', '));
  const prior = verifiedPrior(options.record, 'record');
  return seal('check', options.key, {
    crewId: prior.statement.crewId,
    priorRef: F.refOf(prior),
    checkKind: options.checkKind,
    result: options.result,
    examinerKeyId: keyId(options.key),
    examinerLabel: options.examinerLabel === undefined ? '' : options.examinerLabel,
    checkedAt: options.checkedAt === undefined ? nowIso() : options.checkedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function revoke(options) {
  if (!options || typeof options !== 'object') F.reject('revoke needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior credential envelope this revoke follows is required');
  if (options.status === undefined) F.reject('status is required, one of ' + F.STATUSES.join(', '));
  if (options.reason === undefined) F.reject('reason is required, why the licence changes status');
  const prior = verifiedPrior(options.record, 'record');
  return seal('revoke', options.key, {
    crewId: prior.statement.crewId,
    priorRef: F.refOf(prior),
    status: options.status,
    reason: options.reason,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    revokedAt: options.revokedAt === undefined ? nowIso() : options.revokedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

const ENDPOINT_OPTIONS = ['network', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'clockSlackMs'];

function strictOf(opts) {
  if (opts.strict === undefined) return true;
  if (typeof opts.strict !== 'boolean') F.reject('strict is true or false');
  return opts.strict;
}

function endpointOptions(opts) {
  const out = Object.create(null);
  for (const k of ENDPOINT_OPTIONS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

async function chainClock(opts, strict) {
  if (strict !== false && strictOf(opts) && opts.trustSingleEndpoint === true) {
    F.reject('strict mode takes the time of the chain only from at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to rely on one endpoint');
  }
  try {
    return await qstamp.chainTime(endpointOptions(opts));
  } catch (e) {
    const err = new Error('the chain time could not be established, so no decision was made, ' + ((e && e.message) || 'unknown error'));
    err.code = 'QCREW_NO_CHAIN_TIME';
    throw err;
  }
}

function anchorBatch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('anchor needs at least one envelope');
  const parsed = list.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) F.reject('an envelope is already anchored');
    if (p.signerId !== F.keyIdOf(p.publicKey)) F.reject('an envelope names a signer id that does not match its public key');
    if (!native.verify(p.publicKey, F.encoded(p), p.signature)) F.reject('an envelope carries a signature that does not verify');
    return p;
  });
  return { list, parsed };
}

function attach(list, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== list.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return list.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  options = own(options);
  const { list, parsed } = anchorBatch(envelopes);
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  const stampOptions = Object.assign(own(options), { records, kind: F.KIND });
  delete stampOptions.strict;
  return attach(list, await qstamp.stamp(stampOptions));
}

async function complete(envelopes, pending, options) {
  const opts = own(options);
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { list, parsed } = anchorBatch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(F.KIND)) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  const completeOptions = own(opts);
  delete completeOptions.strict;
  return attach(list, await qstamp.complete(p, completeOptions));
}

const OPTIONS_OF = {
  issue: ['key', 'licenceKind', 'licenceNumber', 'subject', 'issuerLabel', 'issuedAt', 'note'],
  rating: ['key', 'issue', 'rating', 'examinerLabel', 'ratedAt', 'note'],
  medical: ['key', 'record', 'medicalClass', 'examinerLabel', 'assessedAt', 'note'],
  check: ['key', 'record', 'checkKind', 'result', 'examinerLabel', 'checkedAt', 'note'],
  revoke: ['key', 'record', 'status', 'reason', 'authorityLabel', 'revokedAt', 'note'],
  anchor: ['allowLoopback', 'client', 'clients', 'clockSlackMs', 'endpointAllowList', 'index', 'maxFee', 'meter', 'network', 'onPending', 'rpc', 'seed', 'signal', 'strict', 'timeoutMs', 'trustCustomEndpoints', 'trustSingleEndpoint'],
};

function onlyKnown(name, options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) return;
  const unknown = Object.keys(options).find((k) => !OPTIONS_OF[name].includes(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of ' + name + ', so nothing was signed');
}

function strict(name, fn, at, isAsync) {
  return function strictly(...args) {
    try {
      onlyKnown(name, args[at]);
    } catch (e) {
      if (isAsync) return Promise.reject(e);
      throw e;
    }
    return fn.apply(this, args);
  };
}

module.exports = {
  own, generateKey, publicKey, keyId, describeKey, crewRef, verifiedPrior, anchor, complete, chainClock, endpointOptions, strictOf,
};
Object.assign(module.exports, {
  issue: strict('issue', issue, 0, false),
  rating: strict('rating', rating, 0, false),
  medical: strict('medical', medical, 0, false),
  check: strict('check', check, 0, false),
  revoke: strict('revoke', revoke, 0, false),
});
