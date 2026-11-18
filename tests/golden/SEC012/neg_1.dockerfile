FROM python:3.12-slim
USER appuser
RUN pip install .
