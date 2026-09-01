PLUGIN_NAME := vault-plugin-secrets-temporalcloud
PLUGIN_DIR  := ./bin
MOUNT       := temporalcloud

.PHONY: build test test-live sweep dev snapshot release-check release fmt lint clean

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
		(echo "TEMPORAL_CLOUD_API_KEY is not set. See README 'Running tests'."; exit 1)
	go test ./... -tags=acceptance -count=1 -v -timeout 20m

## sweep: delete leftover vault-acctest- resources from failed live tests
sweep:
	go run ./cmd/sweep

## dev: build the plugin and run Vault in dev mode with it mounted
dev:
	@./scripts/dev.sh

## release-check: validate the GoReleaser config without building
release-check:
	goreleaser check

## snapshot: build release artifacts locally into dist/, publishing nothing
snapshot:
	goreleaser release --snapshot --clean

## release: build and publish a GitHub release for the current tag.
## Tag first (git tag -a vX.Y.Z -m ... && git push origin vX.Y.Z) — GoReleaser
## refuses to run on an untagged or dirty tree, which is the behaviour you want.
release:
	@test -n "$$GITHUB_TOKEN" || \
		(echo "GITHUB_TOKEN is not set. Try: export GITHUB_TOKEN=\$$(gh auth token)"; exit 1)
	goreleaser release --clean

fmt:
	gofmt -w .

lint:
	golangci-lint run

clean:
	rm -rf $(PLUGIN_DIR) dist
