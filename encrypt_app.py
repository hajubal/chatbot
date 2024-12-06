# Streamlit 채팅 애플리케이션
import streamlit as st
import requests
import json
import logging
import time

from util.CryptoUtil import CryptoUtil

logging.basicConfig(level=logging.DEBUG)


class OllamaEncryptChatApp:
    def __init__(self):
        self.GATEWAY_API_URL = "http://localhost:8080/api/chat"
        self.crypto = CryptoUtil("my_very_secret_key_32_bytes_long")
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

        logging.info(st.session_state.messages)

        payload = {
            "model": "llama3.1",
            "messages": st.session_state.messages,
            "stream": True
        }

        # encrypted_payload = self.crypto.encrypt(payload)
        encrypted_payload = payload

        # Spring Gateway API 호출
        with st.chat_message("assistant"):
            response_placeholder = st.empty()
            full_response = ""

            try:
                # 암호화된 데이터 전송
                response = requests.post(
                    f"{self.GATEWAY_API_URL}",
                    json=encrypted_payload,
                    stream=True
                )

                for line in response.iter_lines():
                    if line:
                        # JSON 디코딩
                        decode_data = line.decode('utf-8')

                        logging.info(f"decode_data: {decode_data}")

                        if self.isEncrypted:

                            start = time.time()

                            decrypted_response = self.crypto.decrypt(decode_data)

                            end = time.time()

                            logging.debug(f"Decrypted time(ms): {(end - start) / 1000}")
                        else:
                            decrypted_response = decode_data

                        json_data = json.loads(decrypted_response)

                        logging.debug(f"Response data: {json_data}")

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
