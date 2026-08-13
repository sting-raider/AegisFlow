PYTHON ?= python
UV ?= uv
COMPOSE = docker compose -f compose.yml -f compose.demo.yml
LIVE_COMPOSE = docker compose -f compose.yml -f compose.live.yml
SURICATA_COMPOSE = docker compose -f compose.suricata.yml
OIDC_COMPOSE = docker compose -f compose.yml -f compose.oidc.yml
SUSTAINED_DURATION ?= 600
SUSTAINED_RATE ?= 50
SUSTAINED_OUTPUT ?= sustained-compose-local.json
OIDC_OUTPUT ?= docs/acceptance/oidc-local.json
RESTORE_OUTPUT ?= docs/acceptance/restore-local.json
KUBERNETES_OUTPUT ?= docs/acceptance/kubernetes-local.json
SECURITY_OUTPUT ?= docs/acceptance/security-local.json

.PHONY: install lint typecheck test frozen-evidence-check research-evidence-check train-smoke demo demo-stop replay \
	live live-stop suricata-replay benchmark benchmark-sustained multiworker-acceptance restore-acceptance kubernetes-acceptance security-acceptance production-check oidc-prepare oidc-acceptance oidc-stop \
	retention-cleanup reset

install:
	$(UV) sync --extra dev
	npm --prefix apps/dashboard install

lint:
	$(UV) run ruff check .
	npm --prefix apps/dashboard run lint

typecheck:
	$(UV) run mypy packages services apps/api training scripts
	npm --prefix apps/dashboard run build

test:
	$(UV) run pytest
	npm --prefix apps/dashboard test

frozen-evidence-check:
	$(UV) run python -m scripts.verify_frozen_evidence

research-evidence-check:
	$(UV) run python -m scripts.verify_research_experiments

train-smoke:
	$(UV) run python -m training.cli.train_smoke

demo: train-smoke
	$(COMPOSE) up --build -d postgres redis api detector dashboard
	$(COMPOSE) run --rm sensor
	@echo AegisFlow dashboard: http://127.0.0.1:5173
	@echo AegisFlow API docs:  http://127.0.0.1:8000/docs
	@echo Stop with: make demo-stop

demo-stop:
	$(COMPOSE) down

replay:
ifndef PCAP
	$(error PCAP=/path/to/file.pcap is required)
endif
	$(UV) run python -m scripts.replay_demo --pcap "$(PCAP)"

live:
ifndef INTERFACE
	$(error INTERFACE=eth0 is required)
endif
	@echo PRIVACY WARNING: Capture only an explicitly authorized local Linux interface.
	INTERFACE="$(INTERFACE)" $(LIVE_COMPOSE) --profile live up --build

live-stop:
	$(LIVE_COMPOSE) --profile live down

suricata-replay:
ifndef PCAP
	$(error PCAP=/path/to/file.pcap is required)
endif
	SURICATA_PCAP="$(PCAP)" $(SURICATA_COMPOSE) --profile suricata run --rm suricata-replay

benchmark:
	$(UV) run python -m scripts.benchmark

benchmark-sustained:
	$(COMPOSE) up -d --build postgres redis api detector
	$(COMPOSE) run --rm --no-deps \
		--volume "$(CURDIR)/docs/benchmarks:/app/docs/benchmarks" api \
		python -m scripts.benchmark_sustained \
		--duration-seconds "$(SUSTAINED_DURATION)" \
		--target-rate "$(SUSTAINED_RATE)" \
		--output "/app/docs/benchmarks/$(SUSTAINED_OUTPUT)"

multiworker-acceptance:
	$(COMPOSE) up -d --build postgres redis api detector
	$(UV) run python -m scripts.accept_multiworker

restore-acceptance:
	$(UV) run python -m scripts.accept_restore --output "$(RESTORE_OUTPUT)"

kubernetes-acceptance:
	$(UV) run python -m scripts.accept_kubernetes --output "$(KUBERNETES_OUTPUT)"

security-acceptance:
	$(UV) run python -m scripts.accept_security --output "$(SECURITY_OUTPUT)"

production-check:
	$(UV) run python -m scripts.production_check

oidc-prepare:
	$(UV) run --extra dev python -m scripts.prepare_oidc_acceptance

oidc-acceptance: oidc-prepare
	$(OIDC_COMPOSE) up -d --build postgres redis dex api detector
	$(OIDC_COMPOSE) run --rm sensor
	$(UV) run python -m scripts.accept_oidc --output "$(OIDC_OUTPUT)"

oidc-stop:
	$(OIDC_COMPOSE) down

retention-cleanup:
	$(UV) run python -m scripts.retention_cleanup

reset:
	$(COMPOSE) down -v
	$(UV) run python -m scripts.reset_demo
