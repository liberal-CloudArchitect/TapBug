# This non-runnable digest is intentional: production builds must override the
# argument with a reviewed immutable image reference.
ARG PYTHON_BASE_IMAGE=python:3.11-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
FROM ${PYTHON_BASE_IMAGE}

WORKDIR /opt/hermes
COPY containers/role-runtime/runtime.py /opt/hermes/runtime.py
COPY prompts /opt/hermes/prompts

# Runtime network isolation is owned by RunnerHost (`docker run --network none`).
# The image contains no credentials, package manager invocation, or target tools.
USER 65532:65532
ENTRYPOINT ["python", "/opt/hermes/runtime.py"]
