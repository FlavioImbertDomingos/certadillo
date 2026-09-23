# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
# softhsm2 gives a PKCS#11 token for labs and CI; production mounts the
# vendor PKCS#11 library (Luna, nShield, CloudHSM) instead.
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /var/lib/certadillo certadillo \
 && mkdir -p /var/lib/certadillo && chown certadillo /var/lib/certadillo
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir "$(ls /tmp/*.whl)[postgres,hsm]" && rm /tmp/*.whl
USER 10001
ENV CERTADILLO_DATA_DIR=/var/lib/certadillo \
    PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"
ENTRYPOINT ["certadillo"]
CMD ["serve", "--port", "8080"]
