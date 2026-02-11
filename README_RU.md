# Documents Exp API

> [English version | Английская версия](README.md)

![Python](https://img.shields.io/badge/Python-3.14-blue)
![Framework](https://img.shields.io/badge/Framework-FastAPI-009688)
![Database](https://img.shields.io/badge/Database-PostgreSQL-336791)
![Cache](https://img.shields.io/badge/Cache-Redis-DC382D)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)

Backend API для поиска, хранения и управления технической документацией предприятия. Разработан для работы с иерархическими структурами данных (Отделы -> Категории -> Документы -> Страницы) с безопасным контролем доступа.

---

## 📌 Обзор

**Documents Exp API** служит основой для системы управления документацией. API предоставляет надежный интерфейс для:

- **Гостей**: Просмотр и поиск документации.
- **Пользователей**: Создание, обновление и удаление контента.

Система обеспечивает целостность данных с помощью PostgreSQL и высокую производительность благодаря Redis для ограничения частоты запросов (Rate Limiting) и кэширования.

---

## 🎯 Ключевые возможности

### ✅ Иерархическая структура данных

- **Группы (Отделы)**: Организационные единицы верхнего уровня.
- **Категории**: Подразделы внутри групп.
- **Документы**: Технические документы с уникальными шифрами.
- **Страницы**: Содержимое отдельных страниц внутри документов.

### ✅ Безопасность и Авторизация

- **JWT Аутентификация**: Безопасный доступ и ротация refresh токенов.
- **Верификация Email**: Регистрация и сброс пароля через email (Resend).
- **Rate Limiting**: Защита от спама и перегрузки с использованием Redis.
- **Политика паролей**: Строгая валидация сложности паролей.

### ✅ Поисковый движок

- Функционал поиска по документам и страницам внутри категорий.
- Оптимизированные запросы для быстрого получения результатов.

### ✅ Производительность

- **Асинхронная БД**: Полностью асинхронный SQLAlchemy 2.0 + Asyncpg.
- **Массовые операции**: Оптимизированное каскадное удаление для предотвращения проблемы N+1 запросов.

---

## 🛠 Стек технологий

- **Язык:** Python 3.14
- **Фреймворк:** FastAPI
- **База данных:** PostgreSQL (Asyncpg + SQLAlchemy 2.0)
- **Миграции:** Alembic
- **Кэширование и лимиты:** Redis
- **Контейнеризация:** Docker & Docker Compose
- **Email сервис:** Resend

---

## 🔧 Установка и запуск

### Требования

- Docker & Docker Compose

### 1. Клонирование репозитория

```bash
git clone <repository-url>
cd Documents-Exp-API
```

### 2. Настройка окружения

Создайте файл `.env` в корневой директории. Используйте пример ниже:

```ini
# Сервер
SERVER_HOST=0.0.0.0
SERVER_PORT=8000

# База данных
DB_USER=postgres
DB_PASS=postgres
DB_NAME=documents_db
DATABASE_URL=postgresql+asyncpg://${DB_USER}:${DB_PASS}@db:5432/${DB_NAME}

# Redis
REDIS_URL=redis://redis:6379

# Безопасность (Сгенерируйте надежные ключи!)
SECRET_KEY=your_super_secret_key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=10080

# Email (Resend)
RESEND_API_KEY=re_123...
EMAIL_SENDER=onboarding@resend.dev
EMAIL_VERIFICATION_CODE_EXPIRE_MINUTES=10
RESET_TOKEN_EXPIRE_MINUTES=30

# Опционально: Ограничение регистрации по доменам
ALLOWED_EMAIL_DOMAINS=["gmail.com", "your-company.com"]
```

### 3. Запуск в Docker

```bash
docker-compose up -d --build
```

### 4. Применение миграций

Инициализация схемы базы данных:

```bash
docker-compose exec api alembic upgrade head
```

API будет доступно по адресу `http://localhost:8000`.

---

## 📂 Структура проекта

```
Documents-Exp-API/
│
├─ alembic/             # Миграции базы данных
├─ core/                # Конфигурация и настройки
├─ db/                  # Подключение к БД и сессии
├─ models/              # SQLAlchemy ORM модели
├─ repositories/        # DAL (Слой доступа к данным)
├─ routers/             # API Эндпоинты
├─ schemas/             # Pydantic схемы валидации
├─ services/            # Бизнес-логика
├─ utils/               # Утилиты (Auth, Security, Validators)
│
├─ main.py              # Точка входа приложения
├─ docker-compose.yml   # Конфигурация Docker сервисов
└─ Dockerfile           # Сборка контейнера API
```

---

## 👤 Автор

**Pavel (PN Tech)**
