BINARY     := claude-gatekeeper
INSTALL_DIR := $(HOME)/.claude/hooks
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -s -w -X main.version=$(VERSION)

.PHONY: build test lint install uninstall clean plugin-test

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/claude-gatekeeper

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

install: build
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

clean:
	rm -rf bin/
