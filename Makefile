# Top-level convenience targets (problem-statement section 36).
#
# The application stack (Postgres/NATS/OPA/Batfish/backend/frontend/...)
# runs fully with `make up` alone — Fabric is optional and off by default
# (FABRIC_ENABLED=false), because standing up a Fabric network requires
# cloning+building hyperledger/fabric-samples on first run (`make fabric-up`)
# which is slow and needs internet access to github.com. `make demo` brings
# up everything, Fabric included, for the full section-39 demo scenario.

.PHONY: up down reset demo \
        fabric-up fabric-down fabric-deploy fabric-reset fabric-health \
        logs ps

up:
	docker compose up --build -d

down:
	docker compose down

reset:
	docker compose down -v

# --- Fabric network (separate lifecycle from the app stack; section 15) --
fabric-up:
	bash fabric/scripts/up.sh

fabric-down:
	bash fabric/scripts/down.sh

fabric-deploy:
	bash fabric/scripts/deploy-chaincode.sh

fabric-reset:
	bash fabric/scripts/reset.sh

fabric-health:
	bash fabric/scripts/health.sh

# --- Full demo: app stack + Fabric network + chaincode + gateway, then
# flips FABRIC_ENABLED on for the backend so evidence actually anchors
# (section 39's demo scenario needs a real Fabric TX to show).
demo: fabric-up fabric-deploy
	FABRIC_ENABLED=true docker compose --profile fabric up --build -d fabric-gateway backend
	docker compose up --build -d
	@echo ""
	@echo "== Demo stack is up =="
	@echo "Frontend:  http://localhost:5173"
	@echo "Backend:   http://localhost:8000"
	@echo "Grafana:   http://localhost:3001"
	@echo "Upload sample_configs/cisco_iosxe_core_sw01.cfg via the Ingestion page,"
	@echo "then open the scan's Evidence tab to anchor + verify on Fabric."

logs:
	docker compose logs -f --tail=200

ps:
	docker compose ps
