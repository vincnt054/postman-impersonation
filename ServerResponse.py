from enum import Enum

class ServerResponse(Enum):
    s220 = ["220", "Service ready"]
    s221 = ["221", "Service closing transmission channel"]
    s235 = ["235", "Authentication successful"]
    s250 = ["250", "Requested mail action okay completed"]
    s334 = ["334", "Server BASE64-encoded challenge"]
    s354 = ["354", "Start mail input end <CRLF>.<CRLF>"]
    s421 = ["421", "Service not available, closing transmission channel"]

    e500 = ["500", "Syntax error, command unrecognized"]
    e501 = ["501", "Syntax error in parameters or arguments"]
    e503 = ["503", "Bad sequence of commands"]
    e504 = ["504", "Unrecognized authentication type"]
    e535 = ["535", "Authentication credentials invalid"]

    def __str__(self):
        return self._value_[0] + " " + self._value_[1]
