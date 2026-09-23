# Adds an audited project's declared Python dependencies to the pinned worker image.
# Built by scripts/install_project_worker.py: the build needs the network, the run never does.
ARG BASE
FROM ${BASE}
USER 0:0
COPY requirements.txt /opt/project-requirements.txt
RUN pip install --no-cache-dir -r /opt/project-requirements.txt
USER 65532:65532
