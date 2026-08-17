# lazynton

E2EE HTTP client for [lazynton](https://github.com/prongbang/lazynton-rs)
(axum) servers. [rhttp](https://pub.dev/packages/rhttp) transport, X25519
handshake, XChaCha20-Poly1305 binary bodies.

- **Binary wire format**: `application/octet-stream` body = raw
  `nonce(24) || ciphertext || tag(16)` — raw bytes end to end, no hex on the
  hot path
- **Binary handshake**: `POST /handshake` sends 32 raw key bytes and reads 52
  back (lazynton >= 0.3); falls back to the older JSON handshake automatically
- **Per-session keys**, addressed by the `X-Session-Id` header, renewed just
  before the server's `expiresIn`; auto re-handshake + one retry on 401
- **Pre-shared key mode**: pass `sharedKey` to skip the handshake
  (server fallback-key mode)

## Usage

```dart
import 'package:lazynton/lazynton.dart';

await Rhttp.init(); // once at app startup

final client = await LazyntonClient.create(baseUrl: 'https://api.example.com');

// Handshakes lazily on first call; encrypts request, decrypts response.
final data = await client.post('/data', {'msg': 'hi'});
```

Pre-shared key (no handshake):

```dart
final client = await LazyntonClient.create(
  baseUrl: 'https://api.example.com',
  sharedKey: 'edf9d004edae8335f095bb8e01975c42cf693ea60322b75cb7c6667dc836fd7e',
);
```

Already-encoded payloads (protobuf, msgpack, a file) skip the JSON layer:

```dart
final Uint8List? reply = await client.postBytes('/upload', bytes);
```

Non-2xx responses throw `RhttpStatusCodeException` (server errors pass through
unencrypted); a body that fails authentication throws
`LazyntonDecryptException`. Tune the transport with
`settings: ClientSettings(...)`.

## Server compatibility

| server | handshake |
|--------|-----------|
| lazynton >= 0.3 | binary — 32 bytes up, `sessionId(16) \|\| serverPublicKey(32) \|\| expiresIn(u32 be)` down |
| lazynton < 0.3 | JSON — `{"clientPublicKey"}` → `{"sessionId", "serverPublicKey", "expiresIn"}`, all hex |

`HandshakeFormat.auto` (the default) tries binary and latches onto JSON if the
server rejects it, so one build talks to both. Pin it with
`handshakeFormat: HandshakeFormat.binary` once every server is on 0.3.

## Performance

The AEAD is the floor; everything this package does around it is about not
paying anything else. Bodies are raw bytes on the wire, so a request costs one
allocation (the wire buffer) and a response costs none — the ciphertext is
decrypted in place inside the buffer rhttp already returned. The session key is
decoded from hex once per handshake, not once per call, and JSON is converted
straight to and from UTF-8 bytes without an intermediate string.

`flutter test benchmark/wire_benchmark.dart` on an Apple M-series, JSON object
to wire and back, ns/op. The absolute numbers are JIT — release AOT is several
times faster — but the ratio against the pre-0.1.0 hex path holds:

| payload | encrypt via hex | binary | decrypt via hex | binary |
|---------|----------------:|-------:|----------------:|-------:|
| 128 B   |  72444 |  **13445** (5.4x) |  45430 |  **9768** (4.7x) |
| 1 KB    |  77389 |  **30595** (2.5x) |  76609 | **27165** (2.8x) |
| 16 KB   | 717005 | **411703** (1.7x) | 688505 | **372460** (1.8x) |
| 64 KB   | 2653925 | **1631695** (1.6x) | 2698275 | **1513300** (1.8x) |

The cipher itself is pure Dart: `cryptography_flutter` has no accelerated
XChaCha20, and only the Dart implementation exposes the in-place buffer path
above. That makes large bodies a frame-budget question, so payloads at or above
`isolateThreshold` (64 KB by default, matching the server's own default body
cap) are encrypted and decrypted on a background isolate instead of the calling
one. Pass `isolateThreshold: null` to keep everything inline, or lower it if
your server accepts bigger bodies and you see jank.

Encrypting outside the client — a cached payload, a background upload — uses
the same codec directly:

```dart
final cipher = SessionCipher.fromHex(keyHex)!;
final wire = cipher.encrypt(utf8.encode('...'));
final plain = cipher.decrypt(wire); // consumes `wire`
```
