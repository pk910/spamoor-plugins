# Builds distributable archives for every plugin in this repository.
#
# A plugin is a top-level directory containing plugin.go. `make plugins` writes
# dist/<plugin>.tar.gz with a generated plugin.yaml at the archive root, which is the
# format `spamoor --plugin <file>` and the daemon's plugin API load.

PLUGINS   := $(patsubst %/plugin.go,%,$(wildcard */plugin.go))
DIST      := dist
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
BUILDTIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

.PHONY: all plugins validate test vet clean $(PLUGINS)

all: plugins

plugins: $(PLUGINS)

$(PLUGINS):
	@mkdir -p $(DIST)
	@echo "Building plugin: $@ ($(VERSION))"
	@printf 'name: %s\nbuild_time: "%s"\ngit_version: "%s"\n' "$@" "$(BUILDTIME)" "$(VERSION)" > $@/plugin.yaml
	@tar -czf $(DIST)/$@.tar.gz --exclude='*_test.go' --exclude='testdata' -C $@ .
	@rm -f $@/plugin.yaml
	@echo "  -> $(DIST)/$@.tar.gz"

# Loads every plugin through spamoor's Yaegi interpreter and checks its descriptors.
# Needs spamoor-utils (go install github.com/ethpandaops/spamoor/cmd/spamoor-utils@latest).
validate:
	@for p in $(PLUGINS); do spamoor-utils validate-plugin ./$$p || exit 1; done

# Native checks of the pure-Go parts (signature scheme, encoders).
test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(DIST)
