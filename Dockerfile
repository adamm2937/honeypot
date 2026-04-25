FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p exports
EXPOSE 5001 2222 8080 21 23 3306 5432 6379 5900 8888
CMD ["python", "main.py"]
