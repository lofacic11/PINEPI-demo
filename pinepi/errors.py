from __future__ import annotations


class PinePiError(Exception):
    def __init__(self, code: str, message: str, status: int = 400, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}

    def as_dict(self) -> dict:
        result = {"code": self.code, "message": self.message}
        if self.details:
            result["details"] = self.details
        return result


def require(condition: bool, code: str, message: str, status: int = 400) -> None:
    if not condition:
        raise PinePiError(code, message, status)
