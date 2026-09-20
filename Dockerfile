# 1. Base Image: Official Python 3.14 slim image (supports linux/arm64 for Apple Silicon and linux/amd64)
FROM python:3.14-slim

# 2. Environment variables for optimized container logging and execution
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# 3. Set container working directory
WORKDIR /app

# 4. Copy project specification first to leverage Docker layer caching
COPY pyproject.toml .

# 5. Copy application source code and data directory
# Note: Preserves the directory hierarchy so relative paths (e.g. data/controls) resolve correctly
COPY src/ ./src/

# 6. Install the project in editable mode so source files reside in /app/src,
# preserving relative path resolution (e.g. repository.py -> /app/data) without modifying Python code
RUN pip install --no-cache-dir -e .

# 7. Security: Create and switch to non-root user (Principle of Least Privilege)
# 업로드 저장소(data/evidence_uploads)는 컨테이너 로컬 — 인스턴스 교체 시 소실(ephemeral)
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/data/evidence_uploads && \
    chown -R appuser:appuser /app
USER appuser

# 8. Cloud Run은 PORT env로 리슨 포트를 주입한다 (기본 8080)
EXPOSE 8080

# 9. v2 인증심사 콘솔 실행 — $PORT를 셸에서 확장하기 위해 sh -c 사용
CMD ["sh", "-c", "exec secgrc web-cert --host 0.0.0.0 --port ${PORT:-8080}"]
