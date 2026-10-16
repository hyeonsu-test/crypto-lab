"""해커톤: AES 암·복호화와 키 교환을 관찰하는 로컬 교육용 프로그램.

설치: python -m pip install -r requirements.txt
실행: python app.py (가상환경 설정은 README.md 참고)
접속: http://127.0.0.1:8765    검증: python -m unittest -v
검증 환경: Windows / Python 3.10.11 / cryptography 45.0.7.

목표: X25519 양측 키 일치, UTF-8 평문 복원, 변조 시 InvalidTag 확인.
순서: X25519 -> HKDF-SHA256(32 bytes) -> AES-256-GCM -> 인증 후 복호화.
매 실행 새 개인키·salt(16 bytes)·nonce(12 bytes)를 OS 난수로 생성한다.
GCM 태그는 16 bytes이며, 바이트열 표시는 Base64이다. 별도 정수 직렬화는 없다.
상대 공개키가 진짜라는 가정하에, 암호문을 바꾸는 공격자를 실험한다.
Alice/Bob은 한 프로세스에서 모사한다. 상대 인증·실제 네트워크 키 교환·
키 보관·부채널 방어는 범위 밖이며, 테스트 통과는 전체 보안 증명이 아니다.
실제 비밀/운영 데이터에는 사용하지 않는다. 키를 파일이나 응답에 저장하지 않는다.

구현 참고(확인 2026-10-16, pyca 공식 문서 50.0.2):
https://cryptography.io/en/50.0.2/hazmat/primitives/aead/
https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/x25519/
"""

import argparse
import base64
import hmac
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MAX_MESSAGE_BYTES = 4096
AAD = b"P.code_crypto | AES-GCM demo | v1"
INFO = b"P.code_crypto | X25519 to AES-256-GCM | v1"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    """ECDH 공유 비밀을 바로 쓰지 않고 HKDF로 256-bit AES 키를 유도한다."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO
    ).derive(shared_secret)


def exchange_keys() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Alice와 Bob이 서로의 공개키로 독립적으로 같은 AES 키를 만든다."""
    alice = X25519PrivateKey.generate()
    bob = X25519PrivateKey.generate()
    salt = secrets.token_bytes(16)  # 양측이 공유하는 공개 값; 비밀키가 아니다.
    alice_key = derive_key(alice.exchange(bob.public_key()), salt)
    bob_key = derive_key(bob.exchange(alice.public_key()), salt)
    return (
        alice_key, bob_key,
        alice.public_key().public_bytes_raw(),
        bob.public_key().public_bytes_raw(), salt,
    )


def run_demo(message: str) -> dict:
    if not isinstance(message, str):
        raise ValueError("평문은 문자열이어야 합니다.")
    try:
        plaintext = message.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("유효한 UTF-8 문자열을 입력해 주세요.") from exc
    if len(plaintext) > MAX_MESSAGE_BYTES:
        raise ValueError("평문은 UTF-8 기준 4,096바이트 이하여야 합니다.")

    alice_key, bob_key, alice_public, bob_public, salt = exchange_keys()
    keys_match = hmac.compare_digest(alice_key, bob_key)
    if not keys_match:
        raise RuntimeError("양측의 키가 일치하지 않습니다.")

    # 매 실행 새 키로 단 한 번 암호화하므로 동일 키/nonce 쌍을 재사용하지 않는다.
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(alice_key).encrypt(nonce, plaintext, AAD)
    # encrypt 반환 형식: ciphertext || tag(16 bytes).
    recovered = AESGCM(bob_key).decrypt(nonce, sealed, AAD)

    # 같은 키/nonce/AAD를 유지하고 첫 바이트의 최하위 비트만 바꾼다.
    altered = bytes([sealed[0] ^ 1]) + sealed[1:]
    tamper_rejected = False
    try:
        AESGCM(bob_key).decrypt(nonce, altered, AAD)
    except InvalidTag:
        tamper_rejected = True

    return {
        "alice_public": b64(alice_public), "bob_public": b64(bob_public),
        "keys_match": keys_match, "salt": b64(salt), "nonce": b64(nonce),
        "ciphertext": b64(sealed[:-16]), "tag": b64(sealed[-16:]),
        "plaintext_bytes": len(plaintext), "ciphertext_bytes": len(sealed) - 16,
        "recovered": recovered.decode("utf-8"), "round_trip": recovered == plaintext,
        "tamper_rejected": tamper_rejected,
        "tamper_target": "암호문" if plaintext else "인증 태그",
        "tamper_byte_before": f"{sealed[0]:02x}",
        "tamper_byte_after": f"{altered[0]:02x}",
    }


class Handler(BaseHTTPRequestHandler):
    """정적 화면 하나와 데모 API 하나만 제공하는 로컬 서버."""

    def log_message(self, fmt, *args):
        pass  # 입력 평문이나 실행 결과를 로그에 남기지 않는다.

    def reply(self, status: int, data: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def json_reply(self, status: int, data: dict):
        self.reply(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def local_request(self) -> bool:
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        origin = self.headers.get("Origin")
        return (self.headers.get("Host") in hosts and
                (origin is None or origin in {f"http://{host}" for host in hosts}))

    def do_GET(self):
        if not self.local_request():
            self.json_reply(403, {"error": "로컬 접속만 허용합니다."})
        elif self.path == "/":
            self.reply(200, Path(__file__).with_name("index.html").read_bytes(),
                       "text/html; charset=utf-8")
        elif self.path == "/favicon.ico":
            self.reply(204, b"", "image/x-icon")
        else:
            self.json_reply(404, {"error": "없는 경로입니다."})

    def do_POST(self):
        if not self.local_request():
            self.json_reply(403, {"error": "로컬 접속만 허용합니다."})
            return
        if self.path != "/api/demo":
            self.json_reply(404, {"error": "없는 경로입니다."})
            return
        try:
            if self.headers.get_content_type() != "application/json":
                raise ValueError("JSON 입력이 필요합니다.")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 32768:
                raise ValueError("요청 크기가 허용 범위를 벗어났습니다.")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or "message" not in payload:
                raise ValueError("message 필드가 필요합니다.")
            result = run_demo(payload["message"])
        except (ValueError, UnicodeError) as exc:
            self.json_reply(400, {"error": str(exc)})
            return
        self.json_reply(200, result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="로컬 AES 암·복호화 실습")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Crypto Lab: http://127.0.0.1:{server.server_address[1]}", flush=True)
    print("Stop: Ctrl+C", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
