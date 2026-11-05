# syntax=docker/dockerfile:1
# Base image pinned by digest; Dependabot (docker) moves the pin.
FROM python:3.15-slim@sha256:8c13a3f37a6a5b71498228e902c4b9f51c1f7900d49fabf71f9a650c6120e0d0 AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.15-slim@sha256:8c13a3f37a6a5b71498228e902c4b9f51c1f7900d49fabf71f9a650c6120e0d0
# softhsm2 gives a PKCS#11 token for labs and CI; production mounts the
# vendor PKCS#11 library (Luna, nShield, CloudHSM) instead.
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /var/lib/certadillo certadillo \
 && mkdir -p /var/lib/certadillo && chown certadillo /var/lib/certadillo
# Dependencies come only from the hash-pinned lock (requirements/image.txt,
# regenerated with pip-compile --generate-hashes); pip refuses anything whose
# hash does not match. The application wheel itself is installed without
# resolving dependencies, so nothing unpinned can slip in.
COPY requirements/image.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir --no-deps /tmp/*.whl && rm /tmp/*.whl && pip check
USER 10001
ENV CERTADILLO_DATA_DIR=/var/lib/certadillo \
    PYTHONUNBUFFERED=1
EXPOSE 8080
# start-interval: check every 2s while starting, so a proxy that waits for "healthy"
# (Traefik skips starting containers) sends traffic within seconds of a restart
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --start-interval=2s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"
ENTRYPOINT ["certadillo"]
CMD ["serve", "--port", "8080"]
