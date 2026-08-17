/// E2EE HTTP client for [lazynton](https://github.com/prongbang/lazynton-rs)
/// servers, built on [rhttp](https://pub.dev/packages/rhttp).
///
/// Wire format: `application/octet-stream` body =
/// `nonce(24) || ciphertext || tag(16)` (XChaCha20-Poly1305), raw bytes end to
/// end — no hex on the hot path. Keys are agreed per session with a binary
/// X25519 handshake and addressed by the `X-Session-Id` header, or a
/// pre-shared key is used directly (server fallback-key mode).
///
/// ```dart
/// await Rhttp.init();
/// final client = await LazyntonClient.create(baseUrl: 'https://api.example.com');
/// final data = await client.post('/data', {'msg': 'hi'});
/// ```
library;

export 'package:rhttp/rhttp.dart';

export 'src/client.dart'
    show HandshakeFormat, LazyntonClient, LazyntonProtocolException;
export 'src/session_cipher.dart' show LazyntonDecryptException, SessionCipher;
