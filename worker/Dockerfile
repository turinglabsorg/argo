FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5 AS node
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY worker/requirements.txt /opt/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /opt/requirements.txt
COPY src/argo/data/agent/ /opt/argo/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["python", "-I", "/opt/argo/worker.py"]
