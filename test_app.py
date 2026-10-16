"""실행: python -B -m unittest -v

고정 키/nonce는 공개 표준 벡터 검증에만 사용한다. 앱은 OS 난수를 사용한다.
독립 교차 검증(선택): python -m pip install pycryptodome==3.23.0
아래 통과 결과는 실험으로 확인한 사실이며 전체 보안성의 증명이 아니다.

벡터 출처(확인 2026-10-16):
NIST, Block Cipher Modes of Operation-GCM Mode for Authentication and
Confidentiality, GCM-AES256 Example #1, #2, pp. 21-23:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
A. Langley, M. Hamburg, S. Turner, Elliptic Curves for Security,
RFC 7748 §6.1 (2016): https://www.rfc-editor.org/rfc/rfc7748.txt
H. Krawczyk, P. Eronen, HMAC-based Extract-and-Expand Key Derivation Function
(HKDF), RFC 5869 A.1 (2010): https://www.rfc-editor.org/rfc/rfc5869.txt
"""

import base64
import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import app


class CryptoTests(unittest.TestCase):
    def test_nist_aes256_gcm_vectors(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308" * 2)
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aes = AESGCM(key)
        self.assertEqual(aes.encrypt(nonce, b"", None).hex(),
                         "fd2caa16a5832e76aa132c1453eeda7e")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
        expected = bytes.fromhex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
            "b094dac5d93471bdec1a502270e3cc6c")
        self.assertEqual(aes.encrypt(nonce, plaintext, None), expected)
        self.assertEqual(aes.decrypt(nonce, expected, None), plaintext)

    def test_rfc7748_x25519_vector(self):
        alice = X25519PrivateKey.from_private_bytes(bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        bob = X25519PrivateKey.from_private_bytes(bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        self.assertEqual(alice.public_key().public_bytes_raw().hex(),
                         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        expected = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        self.assertEqual(alice.exchange(bob.public_key()), expected)
        self.assertEqual(bob.exchange(alice.public_key()), expected)

    def test_rfc5869_hkdf_vector(self):
        actual = HKDF(algorithm=hashes.SHA256(), length=42,
                      salt=bytes(range(13)), info=bytes(range(240, 250))).derive(b"\x0b" * 22)
        self.assertEqual(actual.hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")

    def test_round_trip_and_tamper_for_boundary_inputs(self):
        for message in ["", "hello", "한글 🔐\n줄바꿈\x00", "a" * 4096,
                        "가" * 1365 + "a", "<script>alert(1)</script>"]:
            with self.subTest(length=len(message)):
                result = app.run_demo(message)
                self.assertEqual(result["recovered"], message)
                self.assertTrue(result["keys_match"])
                self.assertTrue(result["round_trip"])
                self.assertTrue(result["tamper_rejected"])
                self.assertEqual(len(base64.b64decode(result["nonce"])), 12)
                self.assertEqual(len(base64.b64decode(result["tag"])), 16)
                self.assertEqual(len(base64.b64decode(result["ciphertext"])), len(message.encode()))

    def test_invalid_inputs(self):
        for message in [None, 7, [], {}, "a" * 4097, "가" * 1366, "\ud800"]:
            with self.subTest(type=type(message).__name__):
                with self.assertRaises(ValueError):
                    app.run_demo(message)

    def test_fresh_keys_and_nonce(self):
        first, second = app.run_demo("repeat"), app.run_demo("repeat")
        for field in ["alice_public", "bob_public", "nonce", "salt", "ciphertext"]:
            self.assertNotEqual(first[field], second[field])

    def test_wrong_key_nonce_aad_and_tag_are_rejected(self):
        key = AESGCM.generate_key(bit_length=256)
        nonce = bytes(range(12))
        sealed = AESGCM(key).encrypt(nonce, b"message", app.AAD)
        bad_key = bytes([key[0] ^ 1]) + key[1:]
        bad_tag = sealed[:-1] + bytes([sealed[-1] ^ 1])
        for k, n, ciphertext, aad in [
            (bad_key, nonce, sealed, app.AAD),
            (key, b"x" * 12, sealed, app.AAD),
            (key, nonce, sealed, b"changed"),
            (key, nonce, bad_tag, app.AAD),
            (key, nonce, sealed[:-1], app.AAD),
        ]:
            with self.assertRaises(InvalidTag):
                AESGCM(k).decrypt(n, ciphertext, aad)

    def test_all_zero_peer_key_rejected(self):
        with self.assertRaises(ValueError):
            X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(bytes(32)))

    def test_pycryptodome_independent_decryption(self):
        try:
            from Crypto.Cipher import AES
        except ImportError:
            self.skipTest("독립 검증은 선택 의존성 pycryptodome이 필요합니다.")
        session = app.exchange_keys()
        with patch.object(app, "exchange_keys", return_value=session):
            result = app.run_demo("독립 구현 교차 검증 🔐")
        cipher = AES.new(session[1], AES.MODE_GCM, nonce=base64.b64decode(result["nonce"]))
        cipher.update(app.AAD)
        plaintext = cipher.decrypt_and_verify(base64.b64decode(result["ciphertext"]),
                                              base64.b64decode(result["tag"]))
        self.assertEqual(plaintext.decode(), result["recovered"])


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, body, **headers):
        request = Request(self.url + "/api/demo", data=body,
                          headers={"Content-Type": "application/json", **headers})
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def test_api_success(self):
        status, result = self.request(json.dumps({"message": "API 한글"}).encode())
        self.assertEqual(status, 200)
        self.assertEqual(result["recovered"], "API 한글")

    def test_api_invalid_json_and_oversized_input(self):
        for body in [b"bad json", b"[]", b"{}", b'{"message":123}',
                     b'{"message":"\\ud800"}',
                     json.dumps({"message": "a" * 4097}).encode(), b"x" * 32769]:
            with self.subTest(size=len(body)):
                status, result = self.request(body)
                self.assertEqual(status, 400)
                self.assertIn("error", result)

    def test_foreign_origin_rejected(self):
        status, _ = self.request(b'{"message":"hello"}', Origin="https://example.com")
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
