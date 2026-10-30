// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type LicenceKind = 'atpl' | 'cpl' | 'ppl' | 'mpl' | 'cabin' | 'dispatcher' | 'maintenance';
export type MedicalClass = 'class1' | 'class2' | 'class3' | 'lapl';
export type CheckKind = 'proficiency' | 'line' | 'skill';
export type Result = 'pass' | 'fail' | 'partial';
export type Status = 'suspended' | 'revoked' | 'expired';
export type RecordType = 'issue' | 'rating' | 'medical' | 'check' | 'revoke';

export interface KeyDescription {
  format: 'qcrew-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qcrew/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface IssueOptions {
  key: Uint8Array;
  licenceKind: LicenceKind;
  licenceNumber: string;
  subject: Party;
  issuerLabel?: string;
  issuedAt?: string;
  note?: string;
}

export interface RatingOptions {
  key: Uint8Array;
  issue: Envelope;
  rating: string;
  examinerLabel?: string;
  ratedAt?: string;
  note?: string;
}

export interface MedicalOptions {
  key: Uint8Array;
  record: Envelope;
  medicalClass: MedicalClass;
  examinerLabel?: string;
  assessedAt?: string;
  note?: string;
}

export interface CheckOptions {
  key: Uint8Array;
  record: Envelope;
  checkKind: CheckKind;
  result: Result;
  examinerLabel?: string;
  checkedAt?: string;
  note?: string;
}

export interface RevokeOptions {
  key: Uint8Array;
  record: Envelope;
  status: Status;
  reason: string;
  authorityLabel?: string;
  revokedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  crewId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  crewId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function crewRef(secret: Uint8Array, reference: string): string;
export function issue(options: IssueOptions): Envelope;
export function rating(options: RatingOptions): Envelope;
export function medical(options: MedicalOptions): Envelope;
export function check(options: CheckOptions): Envelope;
export function revoke(options: RevokeOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qcrew/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1405;
export const TYPES: readonly RecordType[];
export const LICENCES: readonly LicenceKind[];
export const MEDICAL_CLASSES: readonly MedicalClass[];
export const CHECK_KINDS: readonly CheckKind[];
export const RESULTS: readonly Result[];
export const STATUSES: readonly Status[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
