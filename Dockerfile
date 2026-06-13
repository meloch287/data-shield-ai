# Образ для CLI/сервисов Data Shield AI. Ноль зависимостей -> образ крошечный.
FROM python:3.12-slim AS build
WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim
LABEL org.opencontainers.image.title="Data Shield AI" \
      org.opencontainers.image.description="Local PII/secret redaction before text reaches an external AI" \
      org.opencontainers.image.source="https://github.com/meloch287/data-shield-ai" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl
# Непривилегированный пользователь.
RUN useradd --create-home --uid 10001 datashield
USER datashield
ENTRYPOINT ["datashield"]
CMD ["--help"]
