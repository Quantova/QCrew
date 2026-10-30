# QCrew

QCrew is a live production post quantum licensing and certification record tool for aircrew on the Quantova network. It proves the issue, rating, medical certificate, proficiency check and revocation of a crew licence, and it lets any third party confirm that history without trusting the party that created it.

QCrew proves records without disclosing them. Crew identities and personal details stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no personal detail is ever published.

## What it records

Each record is a signed envelope of one of five types.

1. issue, an authority issues a licence of a stated kind to the crew member it names by key.
2. rating, an examiner adds a rating or endorsement to the licence.
3. medical, a medical examiner records a medical certificate of a stated class.
4. check, an examiner records a proficiency, line or skill check and its result.
5. revoke, an authority changes the status of the licence to suspended, revoked or expired.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a licence forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qcrew
```

## Use

```js
const qcrew = require('@quantovainc/qcrew');

const authority = qcrew.generateKey();
const holder = qcrew.generateKey();
const licence = qcrew.issue({
  key: authority,
  licenceKind: 'atpl',
  licenceNumber: 'UK FCL 123456',
  subject: qcrew.keyId(holder),
  issuerLabel: 'Civil Aviation Authority',
});

const anchored = await qcrew.anchor(licence, { seed, index: 0, network: 'testnet' });
const result = await qcrew.verify(anchored[0], { type: 'issue', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural or legal person. The signer and the subject are chain addresses, and linking an address to a person is a separate attestation.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
