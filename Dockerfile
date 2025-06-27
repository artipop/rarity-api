# Используем официальный образ Python
FROM python:3.13.2-slim-bullseye AS prod

# Устанавливаем необходимые зависимости
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем Poetry через pip
RUN pip install poetry

# Создаем директории для проекта
WORKDIR /app/rarityapi

# Копируем pyproject.toml и poetry.lock
COPY pyproject.toml poetry.lock /app/rarityapi/

# Настраиваем Poetry
RUN poetry config virtualenvs.create false

# Устанавливаем зависимости
RUN poetry install --no-root

# Очищаем кэш
RUN apt-get purge -y && rm -rf /var/lib/apt/lists/*
# ENV PYTHONPATH="${PYTHONPATH}:/app/rarityapi/src"
# Копируем приложение
COPY . /app/rarityapi/