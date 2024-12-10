# Streamlit 채팅 애플리케이션
import streamlit as st
import requests
import json
import logging
import time

from dataclasses import asdict
from util.CryptoUtil import CryptoUtil
from util.SignUtil import SignUtil
from dto.MessageDto import MessageDto

logging.basicConfig(level=logging.ERROR)

log = logging.getLogger()
log.setLevel(logging.INFO)

timeLog = logging.getLogger("timeLogger")
timeLog.setLevel(logging.INFO)


class OllamaEncryptChatApp:
    def __init__(self):
        self.GATEWAY_API_URL = "http://localhost:8080/api/chat"
        self.crypto = CryptoUtil("my_very_secret_key_32_bytes_long")
        self.sign = SignUtil("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCqKmoRL9s5MbsxQ+Q1tI1t4OeghVIN8tsYV4TpZ2HQ+3XClSUxqX34GHZ1uJHU00Z2MIipM2m3nl2r3fwynhPZt3i0xUrZLl/1VdUjSWBkk2WZbFZxA27RWuLRk8LNRGPDmUzbIRTqXys+SYeirWVMuF6S+IJMAU0qz5qCBlXnBzphgCNzYvY2O/zb2v+VmUJFIWsirIIjQcILgEFPuZncTaUta7ZlqcrwkFyVfwTeVMpp4eLQHr55GS22w/eRORnyxPQQgAT2tM5PhOVUvqaltmN8pxNCzMnfwUjGBX+4LLPYgmM0O5phTLOQW21epBzsdaNNBnSqGJQVRcN2u/lNAgMBAAECggEAJ9tN4y8sn6GamRAwFnUvEC62yhYYEUzSDQpIxxuQIXEYlMY2w0JSD0d5jZq4y5rd3OaCx/DTIO8+vPf+b4OvnhXXd63jWWm/j5j2VnDEG2Kb0Dr8JzXY4b/yMwjzPn13iZOxWP0PZ1L5r7nsw0luWfEwM6fx6uf+IVoldDGUMsuQfQFR4sWbqGJvwUD6CjMgAiNnQefNpi7npxK9pt3X47LmXlx1DaQokW5qqV8EBvpIoGAob+M+HnHYdpUgZ+B5VjKVyk+GfvmeAVJ+pOl9lS75KmmPp2RBSj8D8uDwMXKMINgAEN3n4iSFknggjNZZ31feLusbNtQFzjaKwWBdQQKBgQDHdPR1OBkkJRn0m2Jztky6zDRfs8D4s5N/HtJbAzg0hlv8ABWBzE8qcOpRXkt4zGyXAcqlohgIHtvgrU18Zyfxk5resHYaC76DS27Yk449Cwm3s27SRA7RBo3ajmrc1mEZMpQZEjOJAM46c31dponm+MNQDpqhLN6U/vsv+0zXwQKBgQDaZ7su8wNvdnmQjDTukLeW6k/Yu8N/fzCNEEl5SUQXFMf4g8gyJ3hIsP8x1uqcYnP2eT4lXjqUFgFMNm+KFhPBe5ReKi2va/VwS3gM0qok39R4Ou4H2eyk/bPKxxjWBDE76BEFfulqQv9rBDcSXgSG3eIFjE62ueYLioJg85IkjQKBgANtSP3ylsv+LzH6sXhXe34CICw8xGYBf9lBSE/0ADU20cHEppnyTrHl+sCnJBjROlRl3Xt3C36oORLlJ12p0A/gf1qwIXdVGFLdKuxhrKHz3JjhZlgKf06sFCfbJo7gyA5MxiqgG26RKvnqHg9L2zays3hep915DeH1d49de/aBAoGAJy8hKCU1YpQQ71wYSwzvw0W6mZnmU0OQhF59sCLy8mkqD24lRspKDFClGF4ErZYEVB4ghjfHrrXb+b5yeIXJeZcgYVyT4bsux7zihvpsyDzYM9Huzr3MdTWHQkRCMnOCGcti8md4nTXz+VFCSCtSCJhaasBnhuUHXt600YwhlikCgYBfPGWq+gibeWeHlew6yJxep5RE38zKV5y9QOBc14efpxZSKLwuYwaGUfwVUbH0FKSB7K0iRnij8qec/D8Ou0zBjdBoj62TgNLMdu4RW+3Nc7OM8VDSq53z0ogHrxpBP1k0o+vPs6V7NYIqTZQB4VXb8wHQ/cO0j/39LuNXkcGyxA=="
                             , "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqipqES/bOTG7MUPkNbSNbeDnoIVSDfLbGFeE6Wdh0Pt1wpUlMal9+Bh2dbiR1NNGdjCIqTNpt55dq938Mp4T2bd4tMVK2S5f9VXVI0lgZJNlmWxWcQNu0Vri0ZPCzURjw5lM2yEU6l8rPkmHoq1lTLhekviCTAFNKs+aggZV5wc6YYAjc2L2Njv829r/lZlCRSFrIqyCI0HCC4BBT7mZ3E2lLWu2ZanK8JBclX8E3lTKaeHi0B6+eRkttsP3kTkZ8sT0EIAE9rTOT4TlVL6mpbZjfKcTQszJ38FIxgV/uCyz2IJjNDuaYUyzkFttXqQc7HWjTQZ0qhiUFUXDdrv5TQIDAQAB")
        self.isEncrypted = True

        # 세션 상태 초기화
        if "messages" not in st.session_state:
            st.session_state.messages = []

    def display_messages(self):
        # 기존 메시지 표시
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

    def process_chat(self, prompt):
        # 사용자 메시지 추가
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # 페이로드 준비 및 암호화
        # payload = {
        #     "userMessage": prompt,
        #     "conversationHistory": [
        #         f"{msg['role']}: {msg['content']}" for msg in st.session_state.messages[:-1]
        #     ]
        # }

        log.info(f"st.session_state.messages: {st.session_state.messages}")

        payload = {
            "model": "llama3.1",
            "messages": st.session_state.messages,
            "stream": True
        }

        original_str = json.dumps(payload)

        log.info(f"Request original_str: {original_str}")

        # 암호화
        encrypted_payload = self.crypto.encrypt(original_str)
        # encrypted_payload = payload

        # 서명
        signature = self.sign.sign(encrypted_payload)

        log.info(f"signature: {signature}")

        request_message_dto = MessageDto(True, True, encrypted_payload, signature)

        log.info(f"request_message_dto: {request_message_dto}")

        request_message = json.dumps(asdict(request_message_dto))

        log.info(f"request_message: {request_message}")

        # Spring Gateway API 호출
        with st.chat_message("assistant"):
            response_placeholder = st.empty()
            full_response = ""

            try:
                # 암호화된 데이터 전송
                response = requests.post(
                    f"{self.GATEWAY_API_URL}",
                    data=request_message,
                    stream=True
                )

                for line in response.iter_lines():
                    if line:
                        # JSON 디코딩
                        decode_data = line.decode('utf-8')

                        log.info(f"response data: {decode_data}")

                        json_data = json.loads(decode_data)

                        response_message_dto = MessageDto(**json_data)

                        # 서명 검증
                        if response_message_dto.encrypted:
                            if self.sign.verify(response_message_dto.message, response_message_dto.signature):
                                raise ValueError('서명 검증 오류')

                        # 복호화
                        if response_message_dto.encrypted:
                            start = time.time_ns()

                            decrypted_response = self.crypto.decrypt(response_message_dto.message)

                            timeLog.info(f"Decrypted time(ms): {(time.time_ns() - start) / 1000000}, content length: {len(decode_data)}")
                        else:
                            decrypted_response = response_message_dto.message

                        json_data = json.loads(decrypted_response)

                        log.debug(f"Response data: {json_data}")

                        if json_data.get('done', True):
                            break

                        if 'message' in json_data:
                            chunk = json_data['message']
                            full_response += chunk['content']
                            response_placeholder.markdown(full_response + "▌")

                # 최종 응답 표시
                response_placeholder.markdown(full_response)

            except Exception as e:
                logging.error(e)
                st.error(f"API 호출 중 오류 발생: {e}")

        # 어시스턴트 메시지 추가
        st.session_state.messages.append({"role": "assistant", "content": full_response})

    def run(self):
        st.title("💬 암호화된 Ollama 채팅")

        # 기존 메시지 표시
        self.display_messages()

        # 채팅 입력
        if prompt := st.chat_input("메시지를 입력하세요"):
            self.process_chat(prompt)


# 애플리케이션 실행
if __name__ == "__main__":
    app = OllamaEncryptChatApp()
    app.run()
