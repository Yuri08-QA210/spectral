FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLAG="QA{r3d4ct3d}"
ENV FLAG_OFFSET="131072"
ENV MAX_KEYSTREAM_START="8000"
ENV MAX_KEYSTREAM_LENGTH="2000"
ENV PORT="10000"

EXPOSE 10000

CMD ["python", "server.py"]
