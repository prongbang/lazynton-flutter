import 'dart:typed_data';

import 'package:convert/convert.dart' show hex;
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter/foundation.dart' show compute;

/// Thrown when a body cannot be decrypted: wrong key, wrong session, a
/// truncated body, or tampering in transit.
class LazyntonDecryptException implements Exception {
  final String message;

  const LazyntonDecryptException(this.message);

  @override
  String toString() => 'LazyntonDecryptException: $message';
}

/// XChaCha20-Poly1305 codec for the lazynton wire format —
/// `nonce(24) || ciphertext || tag(16)`, the Dart counterpart of
/// `lazynton::SessionCipher`.
///
/// Build one per session and reuse it: the key is decoded once, and both
/// directions run in place, so an encrypt costs a single allocation (the wire
/// buffer) and a decrypt costs none.
class SessionCipher {
  /// XChaCha20-Poly1305 nonce, prefixed to every body.
  static const int nonceLength = 24;

  /// Poly1305 authentication tag, appended to every body.
  static const int tagLength = 16;

  /// Shared key: 32 bytes, 64 hex characters.
  static const int keyLength = 32;

  /// Bytes the wire format adds to a payload.
  static const int overhead = nonceLength + tagLength;

  // Pure Dart on purpose: cryptography_flutter has no accelerated XChaCha20,
  // and only the Dart implementation exposes the in-place `possibleBuffer`
  // path this class is built on.
  static const _cipher = DartXchacha20.poly1305Aead();

  final Uint8List _keyBytes;
  final SecretKeyData _key;

  /// [key] must be exactly [keyLength] bytes.
  SessionCipher(List<int> key)
    // Copied so the key owns a zero-offset buffer: the Poly1305 sink views
    // key bytes through `.buffer`, which ignores a view's own offset.
    : this._(_checkedLength(Uint8List.fromList(key)));

  SessionCipher._(Uint8List keyBytes)
    : _keyBytes = keyBytes,
      _key = SecretKeyData(keyBytes);

  static Uint8List _checkedLength(Uint8List key) {
    if (key.length != keyLength) {
      throw ArgumentError.value(key.length, 'key', 'must be $keyLength bytes');
    }
    return key;
  }

  /// `null` unless [keyHex] is exactly 32 bytes of hex, mirroring
  /// `SessionCipher::from_hex` on the server.
  static SessionCipher? fromHex(String keyHex) {
    if (keyHex.length != keyLength * 2) return null;
    try {
      return SessionCipher._(Uint8List.fromList(hex.decode(keyHex)));
    } on FormatException {
      return null;
    }
  }

  /// `nonce(24) || ciphertext || tag(16)`. [plaintext] is not modified.
  Uint8List encrypt(List<int> plaintext) {
    final length = plaintext.length;
    final wire = Uint8List(overhead + length);
    final nonce = _cipher.newNonce();
    wire.setRange(0, nonceLength, nonce);

    // Encrypt straight into the middle of the wire buffer: `encryptSync` may
    // reuse `region` only when it is the very same object it is handed.
    final region = Uint8List.view(wire.buffer, nonceLength, length);
    region.setRange(0, length, plaintext);
    final box = _cipher.encryptSync(
      region,
      secretKey: _key,
      nonce: nonce,
      possibleBuffer: region,
    );
    final cipherText = box.cipherText;
    if (!identical(cipherText, region)) {
      region.setRange(0, length, cipherText);
    }
    wire.setRange(nonceLength + length, wire.length, box.mac.bytes);
    return wire;
  }

  /// Decrypts a [encrypt]-shaped body. [wire] is overwritten with the
  /// plaintext, which is returned as a view into it — treat [wire] as consumed.
  ///
  /// Throws [LazyntonDecryptException] on a wrong key or a tampered body.
  Uint8List decrypt(Uint8List wire) {
    if (wire.length < overhead) {
      throw LazyntonDecryptException(
        'body is ${wire.length} bytes, shorter than the $overhead-byte frame',
      );
    }
    final length = wire.length - overhead;
    final buffer = wire.buffer;
    final start = wire.offsetInBytes;
    final box = SecretBox(
      Uint8List.view(buffer, start + nonceLength, length),
      nonce: Uint8List.view(buffer, start, nonceLength),
      mac: Mac(Uint8List.view(buffer, start + nonceLength + length, tagLength)),
    );
    try {
      final plaintext = _cipher.decryptSync(
        box,
        secretKey: _key,
        possibleBuffer: box.cipherText as Uint8List,
      );
      return plaintext is Uint8List ? plaintext : Uint8List.fromList(plaintext);
    } on SecretBoxAuthenticationError {
      throw const LazyntonDecryptException(
        'authentication failed: wrong key, wrong session, or tampered body',
      );
    }
  }

  /// [encrypt], moved to a background isolate once [plaintext] reaches
  /// [isolateThreshold] bytes. `null` keeps everything on the calling isolate.
  ///
  /// Spawning costs a millisecond or so, so the threshold should sit where the
  /// cipher itself would otherwise blow a frame budget, not lower.
  Future<Uint8List> encryptAsync(List<int> plaintext, {int? isolateThreshold}) {
    if (isolateThreshold == null || plaintext.length < isolateThreshold) {
      return Future.value(encrypt(plaintext));
    }
    return compute(_encryptOnIsolate, (_keyBytes, _bytes(plaintext)));
  }

  /// [decrypt], moved to a background isolate once [wire] reaches
  /// [isolateThreshold] bytes. See [encryptAsync].
  Future<Uint8List> decryptAsync(Uint8List wire, {int? isolateThreshold}) {
    if (isolateThreshold == null || wire.length < isolateThreshold) {
      return Future.value(decrypt(wire));
    }
    return compute(_decryptOnIsolate, (_keyBytes, wire));
  }

  static Uint8List _bytes(List<int> list) =>
      list is Uint8List ? list : Uint8List.fromList(list);
}

Uint8List _encryptOnIsolate((Uint8List, Uint8List) args) =>
    SessionCipher(args.$1).encrypt(args.$2);

Uint8List _decryptOnIsolate((Uint8List, Uint8List) args) =>
    SessionCipher(args.$1).decrypt(args.$2);
