# syntax=docker/dockerfile:1
# Override with a verified digest after the destination platform acceptance.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= http_proxy= https_proxy= all_proxy= \
    NO_PROXY=* no_proxy=*
WORKDIR /opt/fxfetch
COPY deploy/docker/requirements-runtime.lock /opt/fxfetch/requirements-runtime.lock
# No source-build fallback for native dependencies; missing platform wheels fail the build.
RUN python -m pip install --no-cache-dir --only-binary=:all: -r requirements-runtime.lock
COPY pyproject.toml /opt/fxfetch/pyproject.toml
COPY src /opt/fxfetch/src
# Package metadata is unnecessary at runtime; importing src also includes bundled templates/assets.
ENV PYTHONPATH=/opt/fxfetch/src
COPY deploy/docker/entrypoint.py /opt/fxfetch/container_entrypoint.py
RUN groupadd --gid 10001 fxfetch && useradd --uid 10001 --gid 10001 --no-create-home fxfetch \
    && mkdir -p /var/lib/fxfetch && chown 10001:10001 /var/lib/fxfetch \
    && chmod 700 /var/lib/fxfetch
USER 10001:10001
ENTRYPOINT ["python", "/opt/fxfetch/container_entrypoint.py"]
CMD ["serve"]

# Optional build-capable target: SDK is pre-provisioned and mounted read-only separately.
# This target installs JDK only, never downloads Chrome, Android images or SDK packages.
FROM runtime AS builder
USER root
RUN apt-get update && apt-get install --no-install-recommends -y openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s "$(dirname "$(dirname "$(readlink -f /usr/bin/javac)")")" /opt/java
ENV JAVA_HOME=/opt/java
USER 10001:10001
