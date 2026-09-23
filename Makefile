.PHONY: dev test lint run demo up down interop

dev:            ## install in editable mode with test and HSM extras
	pip install -e ".[dev,hsm]"

test:           ## unit + integration tests (SoftHSM2 test runs when installed)
	pytest

lint:
	ruff check .

run:            ## local server on :8080 with throwaway keys
	CERTADILLO_BOOTSTRAP_ADMIN_KEY=admin-key CERTADILLO_BOOTSTRAP_APPROVER_KEY=approver-key certadillo serve

demo:           ## seed a running server with a demo estate
	python scripts/demo_seed.py --server http://localhost:8080 --admin-key admin-key --approver-key approver-key

up:             ## full stack: postgres, prometheus, alertmanager, grafana
	docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build

down:
	docker compose -f deploy/docker-compose.yml --env-file deploy/.env down

interop:        ## real certbot against a real server (needs root for :80)
	bash scripts/interop-certbot.sh
