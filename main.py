from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from model import ScamAnalysisResult
from tools import analyze_message


BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="BankScam Sentinel", version="1.0.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class AnalysisRequest(BaseModel):
	content: str = Field(min_length=1, max_length=10000)
	sender: str = Field(default="Unknown", max_length=200)


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
	return FileResponse(BASE_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, Literal["ok"]]:
	return {"status": "ok"}


@app.post("/api/analyze", response_model=ScamAnalysisResult)
def analyze(request: AnalysisRequest) -> ScamAnalysisResult:
	content = request.content.strip()
	if not content:
		raise HTTPException(status_code=422, detail="Message content cannot be blank.")
	return analyze_message(content, request.sender.strip() or "Unknown")
