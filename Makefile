.PHONY: help build up down restart logs ps test clean

# Load environment variables from .env file
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

help:
	@echo "RAXE API Server - Make Commands"
	@echo "================================"
	@echo "build      - Build Docker image"
	@echo "up         - Start services in background"
	@echo "down       - Stop and remove containers"
	@echo "restart    - Restart services"
	@echo "logs       - View logs (follow mode)"
	@echo "ps         - Show running containers"
	@echo "test       - Run API tests"
	@echo "shell      - Open shell in container"
	@echo "clean      - Remove containers, volumes, and images"
	@echo "health     - Check service health"
	@echo "stats      - Show RAXE stats"

build:
	docker compose build

up:
	docker compose up -d
	@echo "✅ Services started!"
	@echo "API: http://localhost:$${PORT:-8000}"
	@echo "Health: http://localhost:$${PORT:-8000}/health"

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

ps:
	docker compose ps

test:
	@echo "Running API tests..."
	python test_api.py

shell:
	docker compose exec raxe-api bash

clean:
	docker compose down -v --rmi local
	@echo "✅ Cleanup complete!"

health:
	@curl -s http://localhost:$${PORT:-8000}/health | python -m json.tool || echo "Service not available"

stats:
	@curl -s http://localhost:$${PORT:-8000}/stats -H "Authorization: Bearer $${API_KEY}" | python -m json.tool || echo "Service not available or API_KEY not set"

