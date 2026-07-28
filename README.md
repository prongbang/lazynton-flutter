# lazynton

E2EE HTTP client for [lazynton](https://github.com/prongbang/lazynton-rs)
(axum) servers. [rhttp](https://pub.dev/packages/rhttp) transport, X25519
handshake, XChaCha20-Poly1305 binary bodies via
[lazyxchacha](https://pub.dev/packages/lazyxchacha).

- **Binary wire format**: `application/octet-stream` body = raw
  `nonce(24) || ciphertext || tag(16)`
- **Per-session keys**: X25519 handshake (`POST /handshake`), session addressed
  by the `X-Session-Id` header; auto re-handshake + one retry on 401
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

Non-2xx responses throw `RhttpStatusCodeException` (server errors pass through
unencrypted). Tune the transport with `settings: ClientSettings(...)`.
