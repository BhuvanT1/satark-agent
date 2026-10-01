---
title: Satark
emoji: 🛡️
colorFrom: blue
colorTo: yellow
sdk: docker
app_port: 7860
pinned: false
short_description: Cyber-fraud first-responder agent for India
---

# Satark — cyber-fraud first responder

Paste a suspicious SMS / WhatsApp / call, or describe a fraud. Satark investigates, scores the risk, plans the golden-hour response and drafts the complaint pack.

- `POST /run` — aiKart-style form answers → `{format, response}`
- `POST /api/analyze` — full structured result
- `/docs` — interactive API docs

Set the Space variable `SATARK_MODE=server` (and optionally the secret `GEMINI_API_KEY`).
