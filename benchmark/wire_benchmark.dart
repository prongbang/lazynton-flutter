// Measures the client's request path — JSON object in, wire bytes out, and
// back — against the hex-based path this package used before 0.1.0.
//
//   flutter test benchmark/wire_benchmark.dart
//
// Run it in release-ish conditions for numbers you can quote; under the plain
// test runner (JIT) the ratio is meaningful but the absolute figures are not.

// The table is the whole output of this file.
// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart' show hex;
import 'package:flutter_test/flutter_test.dart';
import 'package:lazynton/lazynton.dart';
import 'package:lazyxchacha/lazyxchacha.dart';

const key = 'edf9d004edae8335f095bb8e01975c42cf693ea60322b75cb7c6667dc836fd7e';

final cipher = SessionCipher.fromHex(key)!;
final jsonToUtf8 = JsonUtf8Encoder();
final utf8ToJson = const Utf8Decoder().fuse(const JsonDecoder());

/// A JSON object whose encoding is about [size] bytes.
Object payload(int size) => {'msg': 'x' * (size - 11)};

Uint8List binaryEncode(Object? json) =>
    cipher.encrypt(jsonToUtf8.convert(json));

Object? binaryDecode(Uint8List wire) =>
    utf8ToJson.convert(cipher.decrypt(wire));

Future<Uint8List> hexEncode(Object? json) async => Uint8List.fromList(
  hex.decode(await LazyXChaCha.instance.encrypt(jsonEncode(json), key)),
);

Future<Object?> hexDecode(Uint8List wire) async =>
    jsonDecode(await LazyXChaCha.instance.decrypt(hex.encode(wire), key));

/// Nanoseconds per call, after a warm-up of the same shape.
Future<double> timeIt(int rounds, Future<void> Function(int) body) async {
  // Warm-up draws from the tail of the buffer pool so the measured rounds
  // still get untouched wires.
  for (var i = 0; i < 20; i++) {
    await body(rounds + i);
  }
  final watch = Stopwatch()..start();
  for (var i = 0; i < rounds; i++) {
    await body(i);
  }
  watch.stop();
  return watch.elapsedMicroseconds * 1000 / rounds;
}

String row(String label, double hexNs, double binaryNs) =>
    '| ${label.padLeft(7)} | ${hexNs.round().toString().padLeft(9)} | '
    '${binaryNs.round().toString().padLeft(9)} | '
    '${(hexNs / binaryNs).toStringAsFixed(1)}x |';

void main() {
  test(
    'wire codec: hex path vs binary path',
    () async {
      const sizes = {128: 2000, 1024: 2000, 16 * 1024: 400, 64 * 1024: 200};
      final encrypt = <String>[];
      final decrypt = <String>[];

      for (final entry in sizes.entries) {
        final size = entry.key;
        final rounds = entry.value;
        final label = size < 1024 ? '$size B' : '${size ~/ 1024} KB';
        final object = payload(size);

        encrypt.add(
          row(
            label,
            await timeIt(rounds, (_) async => hexEncode(object)),
            await timeIt(rounds, (_) async => binaryEncode(object)),
          ),
        );

        // Decryption consumes its buffer, so every round gets its own copy;
        // the copies are made up front, outside the measured region.
        List<Uint8List> wires() => List.generate(
          rounds + 20,
          (_) => Uint8List.fromList(binaryEncode(object)),
        );
        final forHex = wires();
        final forBinary = wires();
        decrypt.add(
          row(
            label,
            await timeIt(rounds, (i) async => hexDecode(forHex[i])),
            await timeIt(rounds, (i) async => binaryDecode(forBinary[i])),
          ),
        );
      }

      print('\nJSON object -> wire (ns/op)');
      print('| payload |  hex path | binary path | speedup |');
      print('|--------:|----------:|------------:|--------:|');
      encrypt.forEach(print);
      print('\nwire -> JSON object (ns/op)');
      print('| payload |  hex path | binary path | speedup |');
      print('|--------:|----------:|------------:|--------:|');
      decrypt.forEach(print);
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );
}
