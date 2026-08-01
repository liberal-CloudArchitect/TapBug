FROM python:3.11-slim@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5
WORKDIR /app
COPY app.py /app/app.py
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["python", "/app/app.py"]
