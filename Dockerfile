FROM python:3.10-slim

WORKDIR /sinker
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . .
ENTRYPOINT ["python3", "sinker/core.py"]
