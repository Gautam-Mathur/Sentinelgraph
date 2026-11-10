SHELL := /usr/bin/env bash
.PHONY: help up down logs migrate seed test test-unit test-int test-sec test-perf test-e2e lint typecheck dev-api dev-worker dev-ui openapi

help:
	@echo "SentinelGraph targets:"
	@echo "  up          Start full stack with Docker Compose"
	@echo "  down        Stop Docker Compose stack"
	@echo "  migrate     Run Alembic migrations"
	@echo "  seed        Seed synthetic demo tenant & secondary isolation tenant"
	@echo "  test        Run backend unit, integration, and security tests"
	@echo "  test-e2e    Run Playwright browser E2E suite"
	@echo "  lint        Run Python & frontend linting"
	@echo "  typecheck   Run mypy & TypeScript checks"
	@echo "  openapi     Export OpenAPI v1 schema to docs/openapi.json"

up:
	docker compose up --build -d

down:
	docker compose down -v

logs:
	docker compose logs -f

migrate:
	cd backend && alembic upgrade head

seed:
	cd backend && python3 -m app.seed

test:
	pytest tests/unit tests/integration

test-unit:
	pytest tests/unit

test-int:
	pytest tests/integration

test-perf:
	pytest tests/performance -m performance

test-e2e:
	pytest tests/e2e -m e2e

lint:
	cd frontend && npm run lint

typecheck:
	cd frontend && npm run typecheck

dev-api:
	cd backend && uvicorn app.main:app --reload --port 8000

dev-worker:
	cd backend && python3 -m app.workers.run_worker

dev-ui:
	cd frontend && npm run dev

openapi:
	cd backend && python3 -c "import json; from app.main import app; print(json.dumps(app.openapi(), indent=2))" > ../docs/openapi.json
