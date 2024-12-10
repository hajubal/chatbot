from dataclasses import dataclass
import json

@dataclass
class MessageDto:
    encrypted: bool
    signed: bool
    message: str
    signature: str

    def to_json(self):
        return json.dumps(self.__dict__)[1]

