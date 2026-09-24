.PHONY: dev test lint run demo up down interop interop-scep

dev:            ## install in editable mode with test and HSM extras
	pip install -e ".[dev,hsm]"

test:           ## unit + integration tests (SoftHSM2 test runs when installed)
	pytest

lint:
	ruff check .

DEV_KEYS := .certadillo/dev-keys.env

$(DEV_KEYS):
	@mkdir -p .certadillo && umask 077 && printf 'ADMIN_KEY=%s\nAPPROVER_KEY=%s\n' "$$(openssl rand -hex 24)" "$$(openssl rand -hex 24)" > $@
	@echo "random dev keys written to $@"

run: $(DEV_KEYS)  ## local server on :8080 with random dev keys (see .certadillo/dev-keys.env)
	@. ./$(DEV_KEYS) && echo "admin key: $$ADMIN_KEY" && CERTADILLO_BOOTSTRAP_ADMIN_KEY=$$ADMIN_KEY CERTADILLO_BOOTSTRAP_APPROVER_KEY=$$APPROVER_KEY certadillo serve

demo: $(DEV_KEYS)  ## seed a running server with a demo estate
	@. ./$(DEV_KEYS) && python scripts/demo_seed.py --server http://localhost:8080 --admin-key "$$ADMIN_KEY" --approver-key "$$APPROVER_KEY"

up:             ## full stack: postgres, prometheus, alertmanager, grafana
	docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build

down:
	docker compose -f deploy/docker-compose.yml --env-file deploy/.env down

interop:        ## real certbot against a real server (needs root for :80)
	bash scripts/interop-certbot.sh

interop-scep:   ## real SCEP client (micromdm scepclient) against a real server
	bash scripts/interop-scep.sh
