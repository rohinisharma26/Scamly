from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from analyzer import (
    extract_emails, extract_phone_numbers,
    find_indicators, resolve_overlaps, classify_archetype,
)
from links import extract_links, analyze_links
from virustotal import check_url
from playbooks import get_playbook

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_methods=["*"],
    allow_headers=["*"],
)

class MessageInput(BaseModel):
    text: str = Field(min_length=1, max_length=5000)

class LinkInput(BaseModel):
    url: str = Field(min_length=3, max_length=2000)

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
    archetype = classify_archetype(found)
    return {
        "text": text,
        "urls": extract_links(text),
        "emails": extract_emails(text),
        "phones": extract_phone_numbers(text),
        "links": analyze_links(text),
        "annotations": resolve_overlaps(found),
        "archetype": archetype,
        "playbook": get_playbook(archetype["name"]) if archetype else None,
    }

@app.post("/api/check-link")
def check_link(input: LinkInput):
    return check_url(input.url)