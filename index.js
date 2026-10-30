// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const B = require('./lib/crew');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: B.generateKey,
  publicKey: B.publicKey,
  keyId: B.keyId,
  describeKey: B.describeKey,
  crewRef: B.crewRef,
  issue: B.issue,
  rating: B.rating,
  medical: B.medical,
  check: B.check,
  revoke: B.revoke,
  anchor: B.anchor,
  complete: B.complete,
  verify,
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  recordRef: (envelope) => F.refOf(F.parse(envelope)),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  LICENCES: F.LICENCES,
  MEDICAL_CLASSES: F.MEDICAL_CLASSES,
  CHECK_KINDS: F.CHECK_KINDS,
  RESULTS: F.RESULTS,
  STATUSES: F.STATUSES,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
