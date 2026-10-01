from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from analyzer import (
    extract_urls, extract_emails, extract_phone_numbers,
    find_indicators, resolve_overlaps, classify_archetype,
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_methods=["*"],
    allow_headers=["*"],
)

class MessageInput(BaseModel):
    text: str = Field(min_length=1, max_length=5000)

@app.get("/")
def read_root():
    return {"status": "ok"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/analyze/message")
def analyze_message(input: MessageInput):
    text = input.text
    found = find_indicators(text)
    return {
        "text": text,
        "urls": extract_urls(text),
        "emails": extract_emails(text),
        "phones": extract_phone_numbers(text),
        "annotations": resolve_overlaps(found),
        "archetype": classify_archetype(found),
    }