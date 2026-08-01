PYTHON ?= python
UV ?= uv
COMPOSE = docker compose -f compose.yml -f compose.demo.yml
LIVE_COMPOSE = docker compose -f compose.yml -f compose.live.yml
SURICATA_COMPOSE = docker compose -f compose.suricata.yml

.PHONY: install lint typecheck test train-smoke demo demo-stop replay live live-stop \
	suricata-replay benchmark retention-cleanup reset

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

retention-cleanup:
	$(UV) run python -m scripts.retention_cleanup

reset:
	$(COMPOSE) down -v
	$(UV) run python -m scripts.reset_demo
