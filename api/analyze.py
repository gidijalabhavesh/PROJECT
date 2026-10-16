import json
from http.server import BaseHTTPRequestHandler

from pydantic import BaseModel, Field, ValidationError

from tools import analyze_message


class AnalysisRequest(BaseModel):
    content: str = Field(min_length=1, max_length=10000)
    sender: str = Field(default="Unknown", max_length=200)


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            request = AnalysisRequest.model_validate_json(body)
            content = request.content.strip()
            if not content:
                self._respond(422, {"detail": "Message content cannot be blank."})
                return
            result = analyze_message(content, request.sender.strip() or "Unknown")
            self._respond(200, result.model_dump(mode="json"))
        except ValidationError as error:
            self._respond(422, {"detail": error.errors(include_url=False)})
        except (ValueError, json.JSONDecodeError):
            self._respond(400, {"detail": "Request body must be valid JSON."})

    def do_GET(self) -> None:
        self._respond(200, {"status": "ok"})

    def _respond(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
