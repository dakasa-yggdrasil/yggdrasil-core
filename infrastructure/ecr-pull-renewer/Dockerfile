# Root supplies a reviewed public Python 3.12 base by immutable sha256 digest.
ARG PYTHON_BASE_IMAGE
FROM ${PYTHON_BASE_IMAGE}
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN python3 -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /app/requirements.lock
COPY pure_refresh.py refresh_once.py /app/
RUN chmod 0555 /app /app/pure_refresh.py /app/refresh_once.py
ENTRYPOINT ["python3", "-I", "-B", "/app/refresh_once.py"]
CMD ["--admission", "/etc/dakasa-ecr/admission.json"]
