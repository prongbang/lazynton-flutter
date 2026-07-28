import 'package:convert/convert.dart' show hex;
import 'package:flutter_test/flutter_test.dart';
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

void main() {
  test('decrypts ciphertext produced by lazyxchacha-rs', () async {
    expect(await LazyXChaCha.instance.decrypt(rustCiphertextHex, key),
        rustPlaintext);
  });

  test('binary wire roundtrip: nonce(24) || ciphertext || tag(16)', () async {
    const msg = '{"msg":"hi"}';
    final wire = hex.decode(await LazyXChaCha.instance.encrypt(msg, key));
    expect(wire.length, 24 + msg.length + 16);
    expect(await LazyXChaCha.instance.decrypt(hex.encode(wire), key), msg);
  });

  test('X25519 agreement: both sides derive the same shared key', () async {
    final client = await KeyPair.newKeyPair();
    final server = await KeyPair.newKeyPair();
    expect(await client.sharedKey(server.pk), await server.sharedKey(client.pk));
    expect(client.pk.length, 64);
  });
}
