import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart' show hex;
import 'package:flutter_test/flutter_test.dart';
import 'package:lazynton/lazynton.dart';
// Not part of the public API: reached directly so the handshake byte offsets
// can be checked without a server.
import 'package:lazynton/src/client.dart' show parseBinaryHandshake;
import 'package:lazyxchacha/keypair.dart';
import 'package:lazyxchacha/lazyxchacha.dart';

// Shared key + ciphertext taken verbatim from lazyxchacha-rs tests: proves the
// Dart side decrypts exactly what the Rust server encrypts.
const key = 'edf9d004edae8335f095bb8e01975c42cf693ea60322b75cb7c6667dc836fd7e';
const rustCiphertextHex =
    '58b99ca42eaed1949d3d707208b39fc9bd8d8b35d44066c072c4ce44cd004971'
    'a66389adbfcb3b59903bc22dd825cf7267c63efda6c86bdb0f62571858ac914a'
    'f67d7cf92e84738996441afcb141a9f621e795e2d2446e1b75d26ee61187c168'
    '0af84b5625c3bc9199f69abfb940dbf90970fd1b53bf51d86524249e3af9132b'
    '8fdb09f0cd3303f2e9eeeae8e3333104ebb4463aa7';
const rustPlaintext =
    '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.'
    'rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}';

Uint8List bytes(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  final cipher = SessionCipher.fromHex(key)!;

  group('SessionCipher', () {
    test('decrypts a body produced by lazynton-rs', () {
      final wire = Uint8List.fromList(hex.decode(rustCiphertextHex));
      expect(utf8.decode(cipher.decrypt(wire)), rustPlaintext);
    });

    test('produces a body lazyxchacha (and so the server) accepts', () async {
      const msg = '{"msg":"hi"}';
      final wire = cipher.encrypt(bytes(msg));
      expect(wire.length, SessionCipher.overhead + msg.length);
      expect(await LazyXChaCha.instance.decrypt(hex.encode(wire), key), msg);
    });

    test('round-trips, leaving the caller plaintext untouched', () {
      final plaintext = bytes('{"msg":"hi"}');
      final snapshot = Uint8List.fromList(plaintext);
      final wire = cipher.encrypt(plaintext);
      expect(plaintext, snapshot);
      expect(cipher.decrypt(wire), snapshot);
    });

    test('round-trips an empty body and non-UTF-8 bytes', () {
      expect(cipher.decrypt(cipher.encrypt(Uint8List(0))), isEmpty);
      final blob = Uint8List.fromList([0xff, 0xfe, 0x00, 0x80]);
      expect(cipher.decrypt(cipher.encrypt(blob)), blob);
    });

    test('nonce is fresh per call', () {
      final plaintext = bytes('same payload');
      final a = cipher.encrypt(plaintext);
      final b = cipher.encrypt(plaintext);
      expect(
        a.sublist(0, SessionCipher.nonceLength),
        isNot(b.sublist(0, SessionCipher.nonceLength)),
      );
    });

    test('rejects a tampered body, a wrong key, and a short body', () {
      final wire = cipher.encrypt(bytes('{"msg":"hi"}'));
      final tampered = Uint8List.fromList(wire)
        ..[SessionCipher.nonceLength] ^= 0x01;
      expect(
        () => cipher.decrypt(tampered),
        throwsA(isA<LazyntonDecryptException>()),
      );

      final other = SessionCipher.fromHex('ab' * 32)!;
      expect(
        () => other.decrypt(Uint8List.fromList(wire)),
        throwsA(isA<LazyntonDecryptException>()),
      );

      expect(
        () => cipher.decrypt(Uint8List(SessionCipher.overhead - 1)),
        throwsA(isA<LazyntonDecryptException>()),
      );
    });

    test('fromHex refuses anything that is not 32 bytes of hex', () {
      expect(SessionCipher.fromHex(''), isNull);
      expect(SessionCipher.fromHex(key.substring(0, 62)), isNull);
      expect(SessionCipher.fromHex('z' * 64), isNull);
      expect(SessionCipher.fromHex(key), isNotNull);
      expect(() => SessionCipher(Uint8List(31)), throwsArgumentError);
    });

    test('offloads to an isolate above the threshold', () async {
      final plaintext = bytes('{"msg":"offloaded"}');
      final wire = await cipher.encryptAsync(plaintext, isolateThreshold: 0);
      expect(await cipher.decryptAsync(wire, isolateThreshold: 0), plaintext);
    });
  });

  group('binary handshake', () {
    // Built exactly as lazynton::handshake writes it.
    final sessionId = List.generate(16, (i) => i);
    final serverPublicKey = List.generate(32, (i) => 0xa0 + i);
    final body = Uint8List.fromList([
      ...sessionId,
      ...serverPublicKey,
      0x00, 0x00, 0x0e, 0x10, // expiresIn = 3600, u32 big-endian
    ]);

    test('splits sessionId(16) || serverPublicKey(32) || expiresIn(u32)', () {
      final parsed = parseBinaryHandshake(body);
      expect(parsed.sessionId, hex.encode(sessionId));
      expect(parsed.serverPublicKeyHex, hex.encode(serverPublicKey));
      expect(parsed.expiresInSeconds, 3600);
    });

    test('reads a body that arrives as a view into a larger buffer', () {
      final padded = Uint8List(8 + body.length + 8)
        ..setRange(8, 8 + body.length, body);
      final view = Uint8List.sublistView(padded, 8, 8 + body.length);
      expect(parseBinaryHandshake(view), parseBinaryHandshake(body));
    });

    test('expiresIn is unsigned', () {
      final forever = Uint8List.fromList(body)
        ..setRange(48, 52, [0xff, 0xff, 0xff, 0xff]);
      expect(parseBinaryHandshake(forever).expiresInSeconds, 0xffffffff);
    });

    test('rejects a response that is not 52 bytes', () {
      for (final length in [0, 51, 53]) {
        expect(
          () => parseBinaryHandshake(Uint8List(length)),
          throwsA(isA<LazyntonProtocolException>()),
        );
      }
    });
  });

  test('X25519 agreement: both sides derive the same shared key', () async {
    final client = await KeyPair.newKeyPair();
    final server = await KeyPair.newKeyPair();
    expect(
      await client.sharedKey(server.pk),
      await server.sharedKey(client.pk),
    );
    expect(client.pk.length, 64);
  });
}
