BINARY     := claude-gatekeeper
INSTALL_DIR := $(HOME)/.claude/hooks
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -s -w -X main.version=$(VERSION)

.PHONY: build test lint install uninstall clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/claude-gatekeeper

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

install: build
	mkdir -p $(INSTALL_DIR)
	cp bin/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo ""
	@echo "Installed $(BINARY) to $(INSTALL_DIR)/$(BINARY)"
	@echo ""
	@echo "Add the following to ~/.claude/settings.json (or .claude/settings.json):"
	@echo ""
	@echo '  "hooks": {'
	@echo '    "PreToolUse": ['
	@echo '      {'
	@echo '        "matcher": "",'
	@echo '        "hooks": ['
	@echo '          {'
	@echo '            "type": "command",'
	@echo '            "command": "$(INSTALL_DIR)/$(BINARY)",'
	@echo '            "timeout": 10'
	@echo '          }'
	@echo '        ]'
	@echo '      }'
	@echo '    ]'
	@echo '  }'
	@echo ""
	@echo "To migrate existing permissions:"
	@echo "  $(INSTALL_DIR)/$(BINARY) migrate"
	@echo ""
	@echo "For debug mode, change the command to:"
	@echo "  $(INSTALL_DIR)/$(BINARY) --debug"

uninstall:
	rm -f $(INSTALL_DIR)/$(BINARY)
	@echo "Removed $(INSTALL_DIR)/$(BINARY)"
	@echo "Remember to remove the hooks config from settings.json."

clean:
	rm -rf bin/
