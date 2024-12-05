import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


class CryptoUtil:
    def __init__(self, key):
        # 16, 24, 32 바이트 길이의 키 지원
        self.key = key.encode('utf-8').ljust(32, b'\0')[:32]

    def encrypt(self, plain_text):
        # 16바이트 IV 생성
        iv = os.urandom(16)

        # AES CBC 모드 암호기 생성
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # UTF-8로 명시적 인코딩 및 패딩
        plain_bytes = plain_text.encode('utf-8')
        cipher_text = cipher.encrypt(pad(plain_bytes, AES.block_size))

        # IV + 암호문을 base64로 인코딩
        return base64.b64encode(iv + cipher_text).decode('utf-8')

    def decrypt(self, cipher_text):
        try:
            # base64 디코딩
            decoded = base64.b64decode(cipher_text.encode('utf-8'))

            # IV 추출 (첫 16바이트)
            iv = decoded[:16]

            # 암호문 추출 (16바이트 이후)
            encrypted = decoded[16:]

            # AES CBC 모드 복호기 생성
            cipher = AES.new(self.key, AES.MODE_CBC, iv)

            # 복호화 및 패딩 제거
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

            # UTF-8로 명시적 디코딩
            return decrypted.decode('utf-8')

        except Exception as e:
            print(f"복호화 오류: {e}")
            return None


# 사용 예시
def main():
    secret_key = "my_very_secret_key_32_bytes_long"

    # 암호화
    aes_cipher = CryptoUtil(secret_key)
    original_text = "Hello, World! 안녕하세요."
    encrypted_text = aes_cipher.encrypt(original_text)
    print("Encrypted:", encrypted_text)

    # 복호화
    decrypted_text = aes_cipher.decrypt(encrypted_text)
    print("Decrypted:", decrypted_text)


if __name__ == "__main__":
    main()
