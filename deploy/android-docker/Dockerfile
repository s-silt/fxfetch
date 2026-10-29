# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= http_proxy= https_proxy= all_proxy= \
    NO_PROXY=* no_proxy=*
# Official Debian signed repositories only. A failed download is not retried.
# Operators may select an official HTTPS mirror for this build only.
ARG DEBIAN_MIRROR=deb.debian.org
RUN case "$DEBIAN_MIRROR" in deb.debian.org|mirrors.ustc.edu.cn) ;; *) exit 2 ;; esac \
    && sed -i "s|http://deb.debian.org|https://${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Retries "0";\nAcquire::EnableSrvRecords "false";\nAcquire::ForceIPv4 "true";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\nAcquire::http::Proxy "false";\nAcquire::https::Proxy "false";\nAPT::Update::Error-Mode "any";\n' > /etc/apt/apt.conf.d/99fxfetch-direct \
    && apt-get update \
    && apt-get install --no-install-recommends -y qemu-system-x86 qemu-utils ovmf openssh-client \
    && dpkg-query -W > /usr/local/share/fxfetch-packages.tsv \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/android-docker/kvm_probe.py /opt/fxfetch/kvm_probe.py
COPY deploy/android-docker/entrypoint.py /opt/fxfetch/entrypoint.py
ENTRYPOINT ["python", "/opt/fxfetch/entrypoint.py"]
