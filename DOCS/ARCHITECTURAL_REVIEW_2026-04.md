# geekLock — Architectural Review

**Date:** 2026-04-21
**Reviewer disposition:** Tired. Unimpressed by the README. Has seen this movie before.
**Scope:** `Cargo.toml`, `src/main.rs`, `src/crypto.rs`, `src/static/*`, all docs. v0.1.0.

**TL;DR:** The crypto primitive is fine. The *sidecar* is a liability. In its current form the threat model described in the README is literally inverted — the sidecar makes it *easier*, not harder, to steal plaintext from a compromised web tier. Three of the findings below each individually block adoption. None of them are hard to fix.

---

## What's actually good

Credit where due — this review is meant to land the project, not kill it:

- AEAD choice is right. AES-256-GCM, unique 96-bit nonces per encrypt, no nonce reuse.
- `spawn_blocking` around the crypto — correct; don't stall the tokio scheduler on CPU work.
- `DefaultBodyLimit::max(10MB)` — good, explicit, not infinity.
- Graceful shutdown wired to SIGTERM + SIGINT.
- Envelope pattern is implemented as a clean primitive: unique DEK per record, KEK wraps DEK, round-trip tested, wrong-KEK rejection tested.
- 336 LOC total. Small surface area. Easy to audit. This is an asset — don't ruin it.

---

## 🚨 Blockers (do not ship to prod)

### B1. There is no authentication. At all. — `main.rs:93-101`

`POST /decrypt` accepts any envelope from any caller on `0.0.0.0:9090` and returns plaintext. No shared secret, no mTLS, no HMAC, no caller identity, nothing. The README's threat model — *"if Node is cracked, attacker gets only ciphertext, not DEKs"* — is **wrong**. If Node is cracked:

1. Attacker already has the envelopes (they're in the DB that Node is talking to).
2. Attacker calls `http://geeklock:9090/decrypt` with those envelopes.
3. geekLock returns plaintext. Done.

The Rust process holding the KEK does not help you when it will decrypt anything anyone asks it to. Right now geekLock is *an oracle*, not a *boundary*. `INTEGRATION_GUIDE.md` hand-waves this as "run on the same private network" — on docker-compose that means any container on the host network can reach it. That's not a mitigation, that's a prayer.

**Fix:** Shared-secret HMAC on every request, or mTLS, or (cheapest) bind to a UNIX socket that only the app containers can mount. Bind to `127.0.0.1` by default; `0.0.0.0` is never a safe default for a thing that holds keys.

### B2. The master key is never zeroized. — `main.rs:21, 154, 180`

`AppState.master_key: [u8; 32]` is a plain `Copy` byte array. Every `let master_key = state.master_key;` inside a handler **bit-copies the KEK onto the stack of a blocking-pool worker thread** — dozens per second under load. Those stack copies never run through `Zeroize`. The `SecretKey` wrapper in `crypto.rs:9` is theater; the thing it supposedly protects (the KEK) is duplicated freely outside it.

The entire marketing premise ("keys wiped from RAM the moment memory is freed, mitigating Cold Boot attacks") is fiction for the only key that matters.

**Fix:** Wrap the KEK in `Arc<Zeroizing<[u8; 32]>>`, never the bare array. Clone the Arc into the closure (cheap), not the bytes. Make it `!Copy`.

### B3. The envelope has no version byte and no KEK ID. — `crypto.rs:13-19`

```rust
pub struct Envelope { encrypted_data, encrypted_dek, data_nonce, dek_nonce }
```

No `version: u8`. No `kek_id: u8`. No algorithm tag. You are one day away from production and you have no way to:

- Rotate the master key without a flag-day migration that requires reading every ciphertext in the system.
- Introduce a second algorithm (or fix a bug in the current one) without breaking every envelope ever written.
- Tell a v1 envelope from a v2 envelope.

Every compliance regime named in `THE_PLAN.md` (HIPAA, PCI-DSS) requires a documented key rotation procedure. You do not currently have one that is mechanically possible. Add the version byte **before** you write the first production envelope, not after.

**Fix:**
```rust
pub struct Envelope {
    version: u8,                // 1
    kek_id: u8,                 // KEK generation
    alg: u8,                    // 1 = AES-256-GCM
    data_nonce: [u8; 12],
    dek_nonce: [u8; 12],
    encrypted_dek: [u8; 48],    // 32 + 16 tag
    encrypted_data: Vec<u8>,
}
```

Fixed-size arrays also mean bincode enforces length; see S3.

---

## 🔴 Serious (fix before any app depends on this)

### S1. No associated data (AAD). — `crypto.rs:38-39, 88`

AES-GCM supports AAD — bind ciphertext to a context like `user_id=X,field=ssn`. Without it, an attacker (or app bug, or NoSQL injection) who can *write* to Mongo can copy user A's `ssnEnvelope` onto user B's document. Decryption succeeds. Authenticity has been preserved for the bytes, but not for their meaning. This is a well-known GCM footgun with a one-line fix:
```rust
cipher.encrypt(nonce, Payload { msg: plaintext, aad: context })
```
Require callers to pass an `aad` field (e.g., `{user_id}:{field_name}`) and bind it. Non-optional. Reject requests without one.

### S2. Decryption failures return HTTP 401. — `main.rs:188`

AEAD auth failure is not "unauthorized." It's "the ciphertext is wrong or tampered with." Worse, returning **401 specifically on the AEAD error** and **400 on bincode/base64 errors** gives an attacker a clean oracle to distinguish "valid envelope format, wrong key" from "garbage input." Return `422 Unprocessable Entity` (or `400`) uniformly on any decrypt failure, log the specific reason server-side. Do not let HTTP status codes leak cryptographic internals.

### S3. Nonces typed as `Vec<u8>`. — `crypto.rs:17-18, 36, 67, 85`

`data_nonce: Vec<u8>` + `Nonce::from_slice(&self.data_nonce)`. `from_slice` in `aes-gcm` panics on wrong length. A corrupt envelope with a zero-length or 1000-byte nonce field panics the blocking worker. `spawn_blocking` catches it as `JoinError` → 500, so it's a DoS by malformed payload rather than memory corruption, but it's sloppy. Type them `[u8; 12]`. Let bincode enforce length at deserialize time.

### S4. No concurrency cap or rate limit.

Every handler spawns an unbounded blocking task. Tokio's default blocking pool is 512 threads, each with a stack. A trivial loop of `/decrypt` calls from anywhere on the network (see B1) will exhaust the pool and RAM. Add a semaphore-based cap (`tower::limit::ConcurrencyLimit`) and per-IP rate limiting (`tower_governor` or similar). Both are middleware — minutes of work.

### S5. Plaintext is assumed UTF-8. — `main.rs:190`

```rust
let data = String::from_utf8(plaintext).map_err(client_error)?;
```

This means geekLock cannot round-trip arbitrary bytes. Encrypt-side accepts only `data: String` too (`main.rs:48-51`). Every non-UTF-8 payload — encrypted files, binary blobs, serialized protobuf — is rejected with a 400, and worse, the sales pitch of "encrypt any sensitive data" is a lie. Make the wire format base64-in / base64-out, or add `/encrypt-bytes` + `/decrypt-bytes`. This is a design decision, not a bug — decide now or you'll be breaking compat for it later.

### S6. No `/health` with real liveness. — `main.rs:137-146`

`/stats` always returns `"status": "Healthy"`. Always. No dependency check, no round-trip test, no read of the KEK. Orchestrators polling this get "service responding" conflated with "service healthy." Add `/health` that does a synthetic encrypt→decrypt cycle with a fixed test vector and returns non-200 on mismatch. This is how you catch "KEK loaded from the wrong secret" before users do.

### S7. Dashboard served by the crypto process from a relative path. — `main.rs:96`

`ServeDir::new("src/static")` is relative to CWD. Run the binary from anywhere other than the repo root and the dashboard silently 404s. If you want a dashboard, `include_dir!` the assets at compile time. Better: don't serve a dashboard from the crypto process at all — observability belongs out of band (Prometheus `/metrics` endpoint, external Grafana). The dashboard also ships with zero auth, so it's telling attackers your throughput.

### S8. No audit log.

`THE_PLAN.md` name-drops HIPAA's "Access Control" safeguards. Where is the per-operation audit trail? TraceLayer logs HTTP spans — that is not an audit log. You need: timestamp, caller identity (requires B1 first), operation, envelope ID or field ID, success/failure. Append-only, ideally to a separate sink the web tier can't tamper with. Without this, the compliance claims in the docs are aspirational at best and actively misleading at worst.

---

## 🟡 Design debt (2026-you will hate 2026-you-before-this-was-fixed)

- **No batch endpoints.** `DOCS/SUITE_TODO.md` already flagged this in the GeekSuite repo. A notegeek list render with 50 notes × 2 fields = 100 sequential HTTP round-trips. Apps will cache decrypted data in Node to paper over it. That caching defeats the entire premise. `POST /encrypt-batch` and `POST /decrypt-batch` accepting arrays are table stakes.
- **KEK comes from a hex env var.** Fine for dev; document that explicitly. For prod, the path forward is a mounted secrets file (short term) and a KMS-backed KEK (long term). Docs say "FIPS-compliant (logical)" — auditors read "logical" as "aspirational." Soften the language or commit to the work.
- **No KEK rotation tool.** Once B3 lands, you need a companion binary that re-wraps every DEK under a new KEK. Not runtime code, but it has to exist before the first rotation request arrives in a 3am page.
- **`bincode` 1.x is EOL-adjacent.** Pin the on-wire format behind the version byte so the binary codec can change without breaking ciphertext. Today a bincode 2.x upgrade would silently corrupt the world.
- **No `Dockerfile`.** Advertised as a sidecar. Where's the image? And if one is written, run as non-root UID (the default is uid 0 → container escape = host root).
- **Edition 2024.** Fine, but pin the toolchain (`rust-toolchain.toml`) so CI doesn't regress on a stale rustup.

---

## 🟢 Nits

- `README.md` says *"listens on `127.0.0.1:9090` by default"* — code binds `0.0.0.0`. The docs are lying about the security posture. Fix one or the other.
- `GETTING_STARTED.md` Step 2 hands users `000102...1f` as a sample key with no warning that this is a known test vector. Add `openssl rand -hex 32` and a "committing this key ends your career" line.
- `INTEGRATION_GUIDE.md` Node example has no retry, no circuit breaker, no timeout. Users will copy it verbatim.
- `crypto.rs` has three good unit tests. `main.rs` has zero. `axum::Router` is trivially testable via `tower::ServiceExt::oneshot` — the entire HTTP layer is currently unverified.
- `generate_dek()` returns a plain `[u8; 32]` — the stack slot holding it in the caller is never zeroized. Minor, but the project's marketing is entirely about zeroization.
- Graceful shutdown has no drain timeout. A stuck blocking task = compose hangs until SIGKILL.

---

## Prioritized roadmap

One sprint to make this adoptable:

1. **Week 1:** B1 (auth) + B2 (KEK zeroization) + B3 (envelope versioning). These three together close the embarrassing gap between the README's threat model and reality. Until these ship, the TODO entry blocking rollout should read *"geekLock is not yet a security improvement over cryptoVault."*
2. **Week 2:** S1 (AAD), S3 (typed nonces), S6 (real health), S8 (audit log). Now it's something an auditor won't laugh at.
3. **Week 3:** Batch endpoints + Dockerfile + KEK rotation tool + rate limiting. Now it's actually deployable to the suite.

Then and only then does GeekSuite's `SUITE_TODO.md` "rollout order" become a real sequence instead of a wish list.

---

## Closing

The 336-line surface is a feature, not an apology. Don't let it grow until the three blockers are fixed. Every line added before then is one more line auditing a system that, today, trades a real threat (compromised Node reads plaintext from Mongo) for an indistinguishable one (compromised Node reads plaintext from the oracle it's authorized to talk to). Fix the oracle problem first. The rest is polish.
