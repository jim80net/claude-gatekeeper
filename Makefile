BINARY     := claude-gatekeeper
INSTALL_DIR := $(HOME)/.claude/hooks
CONFIG_SRC := gatekeeper.toml
CONFIG_DST := $(HOME)/.claude/gatekeeper.toml
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -s -w -X main.version=$(VERSION)

.PHONY: build test lint install uninstall clean plugin-test init-config download

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/claude-gatekeeper

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

init-config:
	@mkdir -p $(HOME)/.claude
	@if [ ! -f $(CONFIG_DST) ]; then \
		cp $(CONFIG_SRC) $(CONFIG_DST); \
		echo "Installed default config: $(CONFIG_DST)"; \
	else \
		echo "Config already exists: $(CONFIG_DST) (skipped)"; \
	fi

install: build init-config
	mkdir -p $(INSTALL_DIR)
	cp bin/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	$(INSTALL_DIR)/$(BINARY) setup --binary $(INSTALL_DIR)/$(BINARY)
	@echo ""
	@echo "To migrate existing permissions:"
	@echo "  $(INSTALL_DIR)/$(BINARY) migrate"
	@echo ""
	@echo "For debug mode, edit ~/.claude/settings.json and append --debug to the command."

uninstall:
	$(INSTALL_DIR)/$(BINARY) uninstall || true
	rm -f $(INSTALL_DIR)/$(BINARY)
	@echo "Uninstall complete."

plugin-test: build
	@echo "Run Claude Code with this plugin:"
	@echo "  claude --plugin-dir $(CURDIR)"
	@echo ""
	@echo "First install the default config (if not already present):"
	@echo "  make init-config"

download:
	./bin/install.sh

clean:
	rm -f bin/claude-gatekeeper bin/claude-gatekeeper.exe
