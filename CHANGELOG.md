## 0.1.0

* Binary handshake (lazynton >= 0.3): 32 raw key bytes up, 52 raw bytes down.
  `HandshakeFormat.auto` falls back to the old JSON handshake when the server
  rejects it, so one build talks to both server versions.
* Sessions renew just before the server's `expiresIn` instead of waiting for a
  401 round trip.
* `SessionCipher`: the wire codec on its own, usable outside the client. Keys
  are decoded once per session; encrypt allocates only the wire buffer and
  decrypt allocates nothing, both working in place.
* Hex is gone from the hot path, and JSON is converted straight to and from
  UTF-8 bytes — 1.6x–5.4x faster per request depending on payload size
  (`benchmark/wire_benchmark.dart`).
* Payloads at or above `isolateThreshold` (64 KB by default) are encrypted and
  decrypted on a background isolate.
* `postBytes` for payloads that are already encoded; `post` takes per-request
  `headers` and a `cancelToken`.
* Failed authentication throws `LazyntonDecryptException`, and a malformed
  handshake response throws `LazyntonProtocolException`.

## 0.0.1

* `LazyntonClient`: E2EE client for lazynton servers — rhttp transport, X25519
  handshake with 401 re-handshake retry, XChaCha20-Poly1305 binary bodies,
  optional pre-shared key mode.
