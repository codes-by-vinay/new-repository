FROM node:24.18.0-slim AS frontend
WORKDIR /frontend
COPY FictionFlix-Codex-Setup-FIXED/package.json FictionFlix-Codex-Setup-FIXED/package-lock.json ./
RUN npm ci
COPY FictionFlix-Codex-Setup-FIXED/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
COPY templates/ ./templates/
COPY img/ ./img/
COPY --from=frontend /frontend/dist/ ./FictionFlix-Codex-Setup-FIXED/dist/
EXPOSE 10000
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT:-10000} --workers 2 --threads 4 --timeout 120"]
