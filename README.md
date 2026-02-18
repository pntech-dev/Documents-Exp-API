# Documents Exp API

> [Russian version | Русская версия](README_RU.md)

![Python](https://img.shields.io/badge/Python-3.14-blue)
![Framework](https://img.shields.io/badge/Framework-FastAPI-009688)
![Database](https://img.shields.io/badge/Database-PostgreSQL-336791)
![Cache](https://img.shields.io/badge/Cache-Redis-DC382D)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)
![License](https://img.shields.io/badge/License-MIT-green)

Backend API for searching, storing, and managing enterprise technical documentation. Designed to handle hierarchical data structures (Departments -> Categories -> Documents -> Pages) with secure access control.

---

## 📌 Overview

**Documents Exp API** serves as the backbone for a documentation management system. It provides a robust interface for:

- **Guests**: Viewing and searching documentation.
- **Users**: Creating, updating, and deleting documentation content.

The system ensures data integrity using PostgreSQL and high performance using Redis for rate limiting and caching capabilities.

---

## 💡 What's New (v1.1.0) - Tags & Filters

- **Tag Search**: The API now supports searching documents by tags.
- **Advanced Search Filters**:
    - `exact_match`: Toggle between exact phrase matching and word-based partial matching.
    - `include_pages`: Option to include or exclude document pages from search results.
    - `search_fields`: Specify which fields to search in (e.g., `name`, `code`).
- **Optimization**: Performance improvements for search queries and database interactions.

---

## 🎯 Key Features

### ✅ Hierarchical Data Structure

- **Groups (Departments)**: Top-level organization units.
- **Categories**: Subdivisions within groups.
- **Documents**: Technical documents with unique codes.
- **Pages**: Individual pages content within documents.

### ✅ Security & Auth

- **JWT Authentication**: Secure access and refresh token rotation.
- **Email Verification**: Sign-up and password reset flows via email (Resend).
- **Rate Limiting**: Protection against abuse using Redis.
- **Password Policy**: Strict validation rules.

### ✅ Search Engine

- Search functionality across documents and pages within categories.
- Optimized queries for quick retrieval.

### ✅ Performance

- **Async Database**: Fully asynchronous SQLAlchemy 2.0 + Asyncpg.
- **Bulk Operations**: Optimized bulk deletes to prevent N+1 query issues.

---

## 🛠 Tech Stack

- **Language:** Python 3.14
- **Framework:** FastAPI
- **Database:** PostgreSQL (Asyncpg + SQLAlchemy 2.0)
- **Migrations:** Alembic
- **Caching & Limiting:** Redis
- **Containerization:** Docker & Docker Compose
- **Email Service:** Resend

---

## 🔧 Installation & Setup

### Prerequisites

- Docker & Docker Compose

### 1. Clone the repository

```bash
git clone <repository-url>
cd Documents-Exp-API
```

### 2. Configure Environment

Create a `.env` file in the root directory. You can use the example below:

```ini
# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8000

# Database
DB_USER=postgres
DB_PASS=postgres
DB_NAME=documents_db
DATABASE_URL=postgresql+asyncpg://${DB_USER}:${DB_PASS}@db:5432/${DB_NAME}

# Redis
REDIS_URL=redis://redis:6379

# Security (Generate strong keys!)
SECRET_KEY=your_super_secret_key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=10080

# Email (Resend)
RESEND_API_KEY=re_123...
EMAIL_SENDER=onboarding@resend.dev
EMAIL_VERIFICATION_CODE_EXPIRE_MINUTES=10
RESET_TOKEN_EXPIRE_MINUTES=30

# Optional: Restrict registration to specific domains
ALLOWED_EMAIL_DOMAINS=["gmail.com", "your-company.com"]
```

### 3. Run with Docker

```bash
docker-compose up -d --build
```

### 4. Apply Migrations

Initialize the database schema:

```bash
docker-compose exec api alembic upgrade head
```

The API will be available at `http://localhost:8000`.

---

## 📂 Project Structure

```
Documents-Exp-API/
│
├─ alembic/             # Database migrations
├─ core/                # Configuration & settings
├─ db/                  # Database connection & session
├─ models/              # SQLAlchemy ORM models
├─ repositories/        # DAL (Data Access Layer)
├─ routers/             # API Endpoints
├─ schemas/             # Pydantic data validation
├─ services/            # Business logic
├─ utils/               # Helpers (Auth, Security, Validators)
│
├─ main.py              # Application entry point
├─ docker-compose.yml   # Docker services config
└─ Dockerfile           # API container build
```

---

## 👤 Author

**Pavel (PN Tech)**
