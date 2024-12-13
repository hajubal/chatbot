import requests
import json
import logging
import time

from dataclasses import asdict
from util.CryptoUtil import CryptoUtil
from util.SignUtil import SignUtil
from dto.MessageDto import MessageDto

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger()
timeLog = logging.getLogger("timeLogger")


class OllamaEncryptChatApp:
    def __init__(self):
        self.GATEWAY_API_URL = "http://localhost:8070/api/chat"
        self.crypto = CryptoUtil("my_very_secret_key_32_bytes_long")
        self.sign = SignUtil(
            "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"
        )
        self.messages = []

    def send_message(self, prompt):
        """
        Send a message to the server and print the response
        """
        # Add user message to conversation history
        self.messages.append({"role": "user", "content": prompt})

        # Prepare payload
        payload = {
            "model": "llama3.1",
            "messages": self.messages,
            "stream": True
        }

        original_str = json.dumps(payload)
        log.info(f"Request original_str: {original_str}")

        # Encrypt payload
        encrypted_payload = self.crypto.encrypt(original_str)

        # Sign the encrypted payload
        signature = self.sign.sign(encrypted_payload)

        # Prepare message DTO
        request_message_dto = MessageDto(True, True, encrypted_payload, signature)
        request_message = json.dumps(asdict(request_message_dto))

        # Full response storage
        full_response = ""

        try:
            # Send request to server
            response = requests.post(
                f"{self.GATEWAY_API_URL}",
                data=request_message,
                stream=True
            )

            print('Streaming', end='')

            # Process streaming response
            for line in response.iter_lines():
                if line:
                    # Decode and parse response
                    decode_data = line.decode('utf-8')

                    json_data = json.loads(decode_data)
                    response_message_dto = MessageDto(**json_data)

                    # Verify signature
                    if response_message_dto.encrypted:
                        if self.sign.verify(response_message_dto.message, response_message_dto.signature):
                            raise ValueError('Signature verification error')

                    # Decrypt response
                    if response_message_dto.encrypted:
                        start = time.time_ns()
                        decrypted_response = self.crypto.decrypt(response_message_dto.message)
                    else:
                        decrypted_response = response_message_dto.message

                    json_data = json.loads(decrypted_response)

                    # Check if streaming is complete
                    if json_data.get('done', True):
                        print('\nResponse done.')
                        break

                    print('.', end='')

            # Add assistant message to conversation history
            self.messages.append({"role": "assistant", "content": full_response})

        except Exception as e:
            log.error(f"Error during API call: {e}")

    def run(self):
        """
        Run the console-based chat application
        """
        print("Sending message.")

        # while True:
        #     try:
        #         user_input = input("You: ")
        #
        #         if user_input.lower() == 'quit':
        #             break
        #
        #         self.send_message(user_input)
        #
        #     except KeyboardInterrupt:
        #         print("\nChat ended.")
        #         break

        # self.send_message 함수를 10번 실행
        for i in range(100):
            print(f"Sending message {i}")
            self.send_message("나에게 새로운 농담을 해줘.")

def main():
    app = OllamaEncryptChatApp()
    app.run()


if __name__ == "__main__":
    main()
