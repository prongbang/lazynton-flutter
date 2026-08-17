import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart' show hex;
import 'package:lazyxchacha/keypair.dart';
import 'package:rhttp/rhttp.dart';

import 'session_cipher.dart';

/// Which wire format the client uses for `POST /handshake`.
enum HandshakeFormat {
  /// Binary first, falling back to [json] once and for good if the server
  /// rejects it — lazynton 0.3 speaks binary, older builds only JSON.
  auto,

  /// Binary: 32 raw key bytes up, 52 raw bytes down. lazynton >= 0.3.
  binary,

  /// The pre-0.3 JSON format, every field hex-encoded.
  json,
}

/// Thrown when a server answers with something that is not the documented
/// lazynton wire format.
class LazyntonProtocolException implements Exception {
  final String message;

  const LazyntonProtocolException(this.message);

  @override
  String toString() => 'LazyntonProtocolException: $message';
}

/// Session id, raw on the wire, hex in the `X-Session-Id` header.
const int _sessionIdLength = 16;

/// X25519 public key.
const int _publicKeyLength = 32;

/// `session_id(16) || server_public_key(32) || expires_in_secs(u32 be)`.
const int _handshakeResponseLength = _sessionIdLength + _publicKeyLength + 4;

/// Splits a binary handshake response, hex-encoding the two fields the rest of
/// the client carries as hex. Not exported: public only so the byte offsets
/// can be tested without a server.
({String sessionId, String serverPublicKeyHex, int expiresInSeconds})
parseBinaryHandshake(Uint8List body) {
  if (body.length != _handshakeResponseLength) {
    throw LazyntonProtocolException(
      'handshake response must be $_handshakeResponseLength bytes, '
      'got ${body.length}',
    );
  }
  return (
    sessionId: hex.encode(Uint8List.sublistView(body, 0, _sessionIdLength)),
    serverPublicKeyHex: hex.encode(
      Uint8List.sublistView(
        body,
        _sessionIdLength,
        _sessionIdLength + _publicKeyLength,
      ),
    ),
    expiresInSeconds: ByteData.sublistView(
      body,
      _handshakeResponseLength - 4,
    ).getUint32(0, Endian.big),
  );
}

/// E2EE client for a [lazynton](https://github.com/prongbang/lazynton-rs)
/// server: rhttp transport, X25519 session keys, XChaCha20-Poly1305 binary
/// bodies.
///
/// ```dart
/// await Rhttp.init();
/// final client = await LazyntonClient.create(baseUrl: 'https://api.example.com');
/// final data = await client.post('/data', {'msg': 'hi'});
/// ```
class LazyntonClient {
  /// How early a session is replaced, so a request never races the server's
  /// expiry and pays a 401 round trip. Capped at a tenth of the TTL so short
  /// sessions do not renew on every call.
  static const Duration _maxRenewalSkew = Duration(seconds: 30);

  /// JSON straight to UTF-8 bytes, and UTF-8 bytes straight to JSON: neither
  /// direction materialises the intermediate string.
  static final JsonUtf8Encoder _jsonToUtf8 = JsonUtf8Encoder();
  static final Converter<List<int>, Object?> _utf8ToJson = const Utf8Decoder()
      .fuse(const JsonDecoder());

  final RhttpClient _http;
  final String _handshakePath;
  final SessionCipher? _preshared;
  final int? _isolateThreshold;

  HandshakeFormat _handshakeFormat;
  SessionCipher? _session;
  String? _sessionId;
  DateTime? _renewAt;
  Future<void>? _handshaking;

  LazyntonClient._(
    this._http,
    this._handshakePath,
    this._preshared,
    this._handshakeFormat,
    this._isolateThreshold,
  );

  /// [sharedKey]: optional hex 32-byte pre-shared key. When set, no handshake
  /// is performed and no `X-Session-Id` header is sent.
  ///
  /// [isolateThreshold]: payloads at least this large are encrypted and
  /// decrypted on a background isolate instead of the calling one, trading
  /// ~1 ms of spawn cost for a frame that does not jank. `null` disables it;
  /// the default sits at the server's own default body cap, so it only kicks
  /// in for servers configured to accept more.
  ///
  /// Call `await Rhttp.init()` once before creating a client.
  /// `throwOnStatusCode` is forced on: non-2xx responses always throw
  /// [RhttpStatusCodeException] (server errors pass through unencrypted).
  static Future<LazyntonClient> create({
    required String baseUrl,
    String handshakePath = '/handshake',
    String? sharedKey,
    HandshakeFormat handshakeFormat = HandshakeFormat.auto,
    int? isolateThreshold = 64 * 1024,
    ClientSettings? settings,
  }) async {
    SessionCipher? preshared;
    if (sharedKey != null) {
      preshared = SessionCipher.fromHex(sharedKey);
      if (preshared == null) {
        throw ArgumentError.value(
          sharedKey,
          'sharedKey',
          'must be 32 bytes of hex (64 chars)',
        );
      }
    }
    final http = await RhttpClient.create(
      settings: (settings ?? const ClientSettings()).copyWith(
        baseUrl: baseUrl,
        throwOnStatusCode: true,
      ),
    );
    return LazyntonClient._(
      http,
      handshakePath,
      preshared,
      handshakeFormat,
      isolateThreshold,
    );
  }

  void dispose() => _http.dispose();

  /// Hex session id sent as `X-Session-Id`, or `null` before the first
  /// handshake and in pre-shared key mode.
  String? get sessionId => _sessionId;

  /// Whether a session key is held and not yet due for renewal.
  bool get hasSession => _session != null && !_isDueForRenewal;

  /// X25519 key agreement with the server. [post] calls this lazily; call it
  /// directly only to warm up a session or to force a fresh one.
  Future<void> handshake() async {
    if (_handshakeFormat == HandshakeFormat.json) return _handshakeJson();
    try {
      await _handshakeBinary();
    } on RhttpStatusCodeException catch (e) {
      // 400/404/415 from a pre-0.3 server that only parses the JSON body.
      if (_handshakeFormat != HandshakeFormat.auto ||
          !const [400, 404, 415].contains(e.statusCode)) {
        rethrow;
      }
      _handshakeFormat = HandshakeFormat.json;
      await _handshakeJson();
    } on LazyntonProtocolException {
      if (_handshakeFormat != HandshakeFormat.auto) rethrow;
      _handshakeFormat = HandshakeFormat.json;
      await _handshakeJson();
    }
  }

  /// POSTs [json] encrypted to [path] and returns the decrypted JSON response
  /// (`null` for an empty body). Handshakes on demand, renews the session
  /// before it expires, and on a 401 re-handshakes and retries once.
  ///
  /// [headers] are merged into the request; [cancelToken] cancels it.
  Future<dynamic> post(
    String path,
    Object? json, {
    Map<String, String>? headers,
    CancelToken? cancelToken,
  }) async {
    final response = await postBytes(
      path,
      _jsonToUtf8.convert(json),
      headers: headers,
      cancelToken: cancelToken,
    );
    if (response == null || response.isEmpty) return null;
    return _utf8ToJson.convert(response);
  }

  /// [post] without the JSON layer: encrypts [body] as-is and returns the
  /// decrypted response bytes (`null` for an empty body). Use it for payloads
  /// that are already encoded — protobuf, msgpack, a file.
  Future<Uint8List?> postBytes(
    String path,
    List<int> body, {
    Map<String, String>? headers,
    CancelToken? cancelToken,
  }) async {
    final preshared = _preshared;
    if (preshared != null) {
      return _send(path, body, preshared, null, headers, cancelToken);
    }

    await _ensureSession();
    try {
      return await _send(
        path,
        body,
        _session!,
        _sessionId!,
        headers,
        cancelToken,
      );
    } on RhttpStatusCodeException catch (e) {
      // The server dropped the session (restart, eviction, TTL race).
      if (e.statusCode != 401) rethrow;
      _session = null;
      await _ensureSession();
      return await _send(
        path,
        body,
        _session!,
        _sessionId!,
        headers,
        cancelToken,
      );
    }
  }

  bool get _isDueForRenewal {
    final renewAt = _renewAt;
    return renewAt != null && !DateTime.now().isBefore(renewAt);
  }

  /// One handshake at a time: concurrent callers share the in-flight future
  /// instead of each burning a session slot on the server.
  Future<void> _ensureSession() {
    if (_session != null && !_isDueForRenewal) return Future.value();
    return _handshaking ??= handshake().whenComplete(() => _handshaking = null);
  }

  Future<Uint8List?> _send(
    String path,
    List<int> plaintext,
    SessionCipher cipher,
    String? sessionId,
    Map<String, String>? extraHeaders,
    CancelToken? cancelToken,
  ) async {
    final wire = await cipher.encryptAsync(
      plaintext,
      isolateThreshold: _isolateThreshold,
    );
    final res = await _http.requestBytes(
      method: HttpMethod.post,
      url: path,
      headers: HttpHeaders.rawMap({
        'Content-Type': 'application/octet-stream',
        'X-Session-Id': ?sessionId,
        ...?extraHeaders,
      }),
      body: HttpBody.bytes(wire),
      cancelToken: cancelToken,
    );
    final body = res.body;
    if (body.isEmpty) return null;
    return cipher.decryptAsync(body, isolateThreshold: _isolateThreshold);
  }

  /// `client_public_key(32)` up,
  /// `session_id(16) || server_public_key(32) || expires_in(u32 be)` down.
  Future<void> _handshakeBinary() async {
    final keyPair = await KeyPair.newKeyPair();
    final res = await _http.requestBytes(
      method: HttpMethod.post,
      url: _handshakePath,
      headers: HttpHeaders.rawMap(const {
        'Content-Type': 'application/octet-stream',
      }),
      body: HttpBody.bytes(Uint8List.fromList(hex.decode(keyPair.pk))),
    );

    final handshake = parseBinaryHandshake(res.body);
    await _adoptSession(
      keyPair,
      serverPublicKeyHex: handshake.serverPublicKeyHex,
      sessionId: handshake.sessionId,
      expiresInSeconds: handshake.expiresInSeconds,
    );
  }

  /// The pre-0.3 format: hex in, hex out.
  Future<void> _handshakeJson() async {
    final keyPair = await KeyPair.newKeyPair();
    final res = await _http.requestText(
      method: HttpMethod.post,
      url: _handshakePath,
      body: HttpBody.json({'clientPublicKey': keyPair.pk}),
    );
    final json = jsonDecode(res.body);
    if (json is! Map<String, dynamic> ||
        json['serverPublicKey'] is! String ||
        json['sessionId'] is! String) {
      throw const LazyntonProtocolException(
        'handshake response is not {sessionId, serverPublicKey, expiresIn}',
      );
    }
    await _adoptSession(
      keyPair,
      serverPublicKeyHex: json['serverPublicKey'] as String,
      sessionId: json['sessionId'] as String,
      expiresInSeconds: (json['expiresIn'] as num?)?.toInt() ?? 0,
    );
  }

  Future<void> _adoptSession(
    KeyPair keyPair, {
    required String serverPublicKeyHex,
    required String sessionId,
    required int expiresInSeconds,
  }) async {
    const malformed = LazyntonProtocolException(
      'server returned a malformed public key',
    );
    final SessionCipher? cipher;
    try {
      cipher = SessionCipher.fromHex(
        await keyPair.sharedKey(serverPublicKeyHex),
      );
    } on FormatException {
      throw malformed;
    } on ArgumentError {
      throw malformed;
    }
    if (cipher == null) throw malformed;
    _session = cipher;
    _sessionId = sessionId;
    if (expiresInSeconds > 0) {
      final ttl = Duration(seconds: expiresInSeconds);
      final skew = ttl ~/ 10 < _maxRenewalSkew ? ttl ~/ 10 : _maxRenewalSkew;
      _renewAt = DateTime.now().add(ttl - skew);
    } else {
      // No TTL reported: hold the session until the server 401s.
      _renewAt = null;
    }
  }
}
