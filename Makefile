PLUGIN_NAME := vault-plugin-secrets-temporalcloud
PLUGIN_DIR  := ./bin
MOUNT       := temporalcloud

.PHONY: build test test-live sweep dev fmt lint clean

## build: compile the plugin and print the SHA256 Vault needs for registration
build:
	@mkdir -p $(PLUGIN_DIR)
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)
	@echo "SHA256: $$(shasum -a 256 $(PLUGIN_DIR)/$(PLUGIN_NAME) | cut -d' ' -f1)"

## test: fast tests only — no credentials, no network
test:
	go test ./... -count=1

## test-live: tests against a real Temporal Cloud account
test-live:
	@test -n "$$TEMPORAL_CLOUD_API_KEY" || \
		(echo "TEMPORAL_CLOUD_API_KEY is not set. See README 'Running live tests'."; exit 1)
	@test -n "$$TEMPORAL_CLOUD_ADMIN_SA_ID" || \
		(echo "TEMPORAL_CLOUD_ADMIN_SA_ID is not set. See README 'Running live tests'."; exit 1)
	go test ./... -tags=acceptance -count=1 -v -timeout 20m

## sweep: delete leftover vault-acctest- resources from failed live tests
sweep:
	go run ./cmd/sweep

## dev: build the plugin and run Vault in dev mode with it mounted
dev:
	@./scripts/dev.sh

fmt:
	gofmt -w .

lint:
	golangci-lint run

clean:
	rm -rf $(PLUGIN_DIR)
