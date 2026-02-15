# Используем официальный легкий образ Python
FROM python:3.11-slim

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Запрещаем Python создавать .pyc файлы и буферизировать вывод (для логов)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Копируем файл зависимостей и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь код проекта в контейнер
COPY . .

# Команда запуска. Убедитесь, что ваш файл запуска называется main.py, а объект FastAPI — app
CMD ["python", "main.py"]