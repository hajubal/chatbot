from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64


class SignUtil:
    def __init__(self, private_key_der_str=None, public_key_der_str=None):
        """초기화: 문자열 키를 사용해 설정하거나 새 키 생성"""
        if private_key_der_str:
            self.private_key = self._load_private_key_from_string(private_key_der_str)
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        self.public_key = self.private_key.public_key() if not public_key_der_str else self._load_public_key_from_string(public_key_der_str)

    @staticmethod
    def _load_private_key_from_string(private_key_der_str: str, password=None):
        """문자열에서 개인 키 로드"""
        return serialization.load_der_private_key(
            base64.b64decode(private_key_der_str),
            password=password.encode() if password else None,
            backend=default_backend(),
        )

    @staticmethod
    def _load_public_key_from_string(public_key_der_str: str):
        """문자열에서 공개 키 로드"""
        return serialization.load_der_public_key(
            base64.b64decode(public_key_der_str),
            backend=default_backend(),
        )

    def export_private_key(self, password=None) -> str:
        """개인 키를 PEM 문자열로 내보내기"""
        encryption = (
            serialization.BestAvailableEncryption(password.encode())
            if password else serialization.NoEncryption()
        )

        key_data = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        return base64.b64encode(key_data).decode()

    def export_public_key(self) -> str:
        """공개 키를 PEM 문자열로 내보내기"""
        key_data = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return base64.b64encode(key_data).decode()

    def sign(self, message: str) -> str:
        """전자서명 생성"""
        signature = self.private_key.sign(
            bytes(message, 'utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode()

    def verify(self, message: str, signature: str) -> bool:
        """전자서명 검증"""
        try:
            self.public_key.verify(
                signature,
                bytes(message, 'utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


# 테스트 코드
if __name__ == "__main__":
    # 1. 키 생성
    util = SignUtil()
    private_key_der = util.export_private_key()
    public_key_der = util.export_public_key()

    print("Generated Private Key PEM:")
    print(private_key_der)
    print("Generated Public Key PEM:")
    print(public_key_der)

    # 2. 문자열로 키 설정
    util_from_strings = SignUtil(private_key_der, public_key_der)

    # 3. 전자서명 테스트
    message = "This is a test message."
    signature = util_from_strings.sign(message)
    print(f"Signature: {signature}")

    is_valid = util_from_strings.verify(message, signature)
    print(f"Is signature valid? {is_valid}")
