import streamlit as st
import requests
import json
import traceback
import logging

logging.basicConfig(level=logging.DEBUG)

# Show title and description.
st.title("💬 Chatbot with Ollama Llama3")

# Ollama 서버 설정
OLLAMA_API_URL = "http://localhost:11434/api/chat"

# 세션 상태 초기화
if "messages" not in st.session_state:
    st.session_state.messages = []

# 기존 메시지 표시
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# 채팅 입력 처리
if prompt := st.chat_input("메시지를 입력하세요"):
    # 사용자 메시지 추가
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    logging.info(st.session_state.messages)

    # Ollama API 호출을 위한 페이로드 준비
    payload = {
        "model": "llama3.1",
        "messages": st.session_state.messages,
        "stream": True
    }

    # Ollama API 호출
    with st.chat_message("assistant"):
        # 스트리밍 응답 처리
        response_placeholder = st.empty()
        full_response = ""

        try:
            response = requests.post(
                OLLAMA_API_URL,
                json=payload,
                stream=True
            )

            for line in response.iter_lines():
                if line:
                    # JSON 디코딩
                    decode_data = line.decode('utf-8')

                    json_data = json.loads(decode_data)

                    logging.debug(json_data)

                    if json_data.get('done', True):
                        break

                    if 'message' in json_data:
                        chunk = json_data['message']
                        full_response += chunk['content']
                        response_placeholder.markdown(full_response + "▌")

            # 최종 응답 표시
            response_placeholder.markdown(full_response)

        except Exception as e:
            logging.error(traceback.format_exc())
            st.error(f"API 호출 중 오류 발생: {e}")

    # 어시스턴트 메시지 추가
    st.session_state.messages.append({"role": "assistant", "content": full_response})