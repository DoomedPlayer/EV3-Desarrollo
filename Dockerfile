FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Inicializa la base de datos SQLite al construir la imagen
RUN python init_db.py

EXPOSE 5000

CMD ["python", "app.py"]
