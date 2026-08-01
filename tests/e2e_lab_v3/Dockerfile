FROM python:3.12-alpine@sha256:9ba6d8cbebf0fb6546ae71f2a1c14f6ffd2fdab83af7fa5669734ef30ad48844

WORKDIR /app
COPY app.py /app/app.py

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "/app/app.py"]
