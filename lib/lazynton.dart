/// E2EE HTTP client for [lazynton](https://github.com/prongbang/lazynton-rs)
/// servers, built on [rhttp](https://pub.dev/packages/rhttp).
///
/// Wire format: `application/octet-stream` body = `nonce(24) || ciphertext`
/// (XChaCha20-Poly1305 via lazyxchacha). Keys are agreed per session with an
/// X25519 handshake and addressed by the `X-Session-Id` header, or a
/// pre-shared key is used directly (server fallback-key mode).
///
/// ```dart
/// await Rhttp.init();
/// final client = await LazyntonClient.create(baseUrl: 'https://api.example.com');
/// final data = await client.post('/data', {'msg': 'hi'});
/// ```
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart' show hex;
import 'package:lazyxchacha/keypair.dart';
import 'package:lazyxchacha/lazyxchacha.dart';
import 'package:rhttp/rhttp.dart';

export 'package:rhttp/rhttp.dart';

class LazyntonClient {
  final RhttpClient _http;
  final LazyXChaCha _crypto = LazyXChaCha.instance;
  final String _handshakePath;
  final String? _presharedKey;

  String? _sessionId;
  String? _sessionKey;
  Future<void>? _handshaking;

  LazyntonClient._(this._http, this._handshakePath, this._presharedKey);

  /// [sharedKey]: optional hex 32-byte pre-shared key. When set, no handshake
  /// is performed and no `X-Session-Id` header is sent.
  ///
  /// Call `await Rhttp.init()` once before creating a client.
  /// `throwOnStatusCode` is forced on: non-2xx responses always throw
  /// [RhttpStatusCodeException] (server errors pass through unencrypted).
  static Future<LazyntonClient> create({
    required String baseUrl,
    String handshakePath = '/handshake',
    String? sharedKey,
    ClientSettings? settings,
  }) async {
    final http = await RhttpClient.create(
      settings: (settings ?? const ClientSettings())
          .copyWith(baseUrl: baseUrl, throwOnStatusCode: true),
    );
    return LazyntonClient._(http, handshakePath, sharedKey);
  }

  void dispose() => _http.dispose();

  /// X25519 key agreement with the server. [post] calls this lazily; call it
  /// directly only to warm up or force a fresh session.
  Future<void> handshake() async {
    final kp = await KeyPair.newKeyPair();
    final res = await _http.requestText(
      method: HttpMethod.post,
      url: _handshakePath,
      body: HttpBody.json({'clientPublicKey': kp.pk}),
    );
    final json = jsonDecode(res.body) as Map<String, dynamic>;
    _sessionKey = await kp.sharedKey(json['serverPublicKey'] as String);
    _sessionId = json['sessionId'] as String;
  }

  /// POSTs [json] encrypted to [path] and returns the decrypted JSON response
  /// (`null` for an empty body). On 401 (expired/unknown session) it
  /// re-handshakes and retries once.
  Future<dynamic> post(String path, Object? json) async {
    final preshared = _presharedKey;
    if (preshared != null) return _send(path, json, preshared, null);

    await _ensureSession();
    try {
      return await _send(path, json, _sessionKey!, _sessionId!);
    } on RhttpStatusCodeException catch (e) {
      if (e.statusCode != 401) rethrow;
      _sessionKey = null;
      await _ensureSession();
      return await _send(path, json, _sessionKey!, _sessionId!);
    }
  }

  Future<void> _ensureSession() async {
    if (_sessionKey != null) return;
    try {
      await (_handshaking ??= handshake());
    } finally {
      _handshaking = null;
    }
  }

  Future<dynamic> _send(
      String path, Object? json, String key, String? sessionId) async {
    final wireHex = await _crypto.encrypt(jsonEncode(json), key);
    final res = await _http.requestBytes(
      method: HttpMethod.post,
      url: path,
      headers: HttpHeaders.rawMap({
        'Content-Type': 'application/octet-stream',
        'X-Session-Id': ?sessionId,
      }),
      body: HttpBody.bytes(Uint8List.fromList(hex.decode(wireHex))),
    );
    if (res.body.isEmpty) return null;
    final plaintext = await _crypto.decrypt(hex.encode(res.body), key);
    return jsonDecode(plaintext);
  }
}
