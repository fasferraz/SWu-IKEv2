# syntax=docker/dockerfile:1
FROM python:3.14-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git swig libpcsclite-dev 

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} + \
    && rm -rf /opt/venv/lib/python*/site-packages/pip/_vendor/__pycache__

FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcsclite1 iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1

WORKDIR /app
COPY swu_emulator.py .

ENTRYPOINT ["python3", "swu_emulator.py"]
CMD ["-h"]
