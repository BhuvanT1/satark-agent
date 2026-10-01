# Satark — cyber-fraud first-responder agent
# One image, two modes:
#   default CMD  -> aiKart "Try Me Now" runner (reads /aikart/input.json, writes /aikart/output.json)
#   server mode  -> docker run -p 7860:7860 IMAGE python server.py   (HTTP API + demo UI)
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SATARK_OUTPUT_FORMAT=html \
    SATARK_TIME_BUDGET=150 \
    PORT=7860

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY satark ./satark
COPY web ./web
COPY run.py server.py ./

# Optional LLM upgrade. The agent works fully offline without it.
# For the aiKart sandbox (which has no secret injection), you may bake a
# DEDICATED, NO-BILLING, restricted key at build time:
#   docker build --build-arg GEMINI_API_KEY=xxxx -t you/satark-agent:1.0.0 .
# Prefer SATARK_REMOTE_URL (a hosted Satark API that keeps the key server-side).
ARG GEMINI_API_KEY=""
ARG GEMINI_MODEL=""
ARG SATARK_REMOTE_URL=""
ENV GEMINI_API_KEY=${GEMINI_API_KEY} \
    GEMINI_MODEL=${GEMINI_MODEL} \
    SATARK_REMOTE_URL=${SATARK_REMOTE_URL}

# Runs as root on purpose: aiKart mounts /aikart at run time and the runner
# must be able to write /aikart/output.json whatever the mount's ownership.
RUN mkdir -p /aikart
EXPOSE 7860
CMD ["python", "run.py"]
