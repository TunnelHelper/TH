APP := th
DAEMON := thd
BIN_DIR := ./bin

PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
SYSTEMDUNITDIR ?= $(PREFIX)/lib/systemd/system
SYSUSERSDIR ?= $(PREFIX)/lib/sysusers.d
TMPFILESDIR ?= $(PREFIX)/lib/tmpfiles.d

.PHONY: help build run test test-integration vet fmt tidy clean package \
	build-linux build-linux-amd64 build-linux-arm64 build-linux-armv7 \
	install uninstall

help:
	@echo "Targets:"
	@echo "  make build              Build client and daemon into ./bin"
	@echo "  make build-linux        Cross-build both binaries for Linux"
	@echo "  make run                Run the local client"
	@echo "  make test               Run unit tests"
	@echo "  make test-integration   Run network-namespace tests"
	@echo "  make vet                Run go vet"
	@echo "  make fmt                Format Go sources"
	@echo "  make tidy               Normalize Go modules"
	@echo "  make install            Install binaries and service assets"
	@echo "  make uninstall          Remove installed program files only"
	@echo "  make package            Build snapshot deb/rpm packages with GoReleaser"
	@echo "  make clean              Remove ./bin"

build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -o $(BIN_DIR)/$(APP) ./cmd/$(APP)
	go build -trimpath -o $(BIN_DIR)/$(DAEMON) ./cmd/$(DAEMON)

run:
	go run ./cmd/$(APP)

test:
	go test ./...

test-integration:
	go test -tags=integration ./internal/backend/linux -v

vet:
	go vet ./...

fmt:
	go fmt ./...

tidy:
	go mod tidy

build-linux-amd64:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(BIN_DIR)/$(APP)_linux_amd64 ./cmd/$(APP)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(BIN_DIR)/$(DAEMON)_linux_amd64 ./cmd/$(DAEMON)

build-linux-arm64:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o $(BIN_DIR)/$(APP)_linux_arm64 ./cmd/$(APP)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o $(BIN_DIR)/$(DAEMON)_linux_arm64 ./cmd/$(DAEMON)

build-linux-armv7:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -o $(BIN_DIR)/$(APP)_linux_armv7 ./cmd/$(APP)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -o $(BIN_DIR)/$(DAEMON)_linux_armv7 ./cmd/$(DAEMON)

build-linux: build-linux-amd64 build-linux-arm64 build-linux-armv7

package:
	goreleaser release --snapshot --clean

install: build
	install -Dm0755 $(BIN_DIR)/$(APP) $(DESTDIR)$(BINDIR)/$(APP)
	install -Dm0755 $(BIN_DIR)/$(DAEMON) $(DESTDIR)$(SBINDIR)/$(DAEMON)
	install -Dm0644 packaging/systemd/$(DAEMON).service $(DESTDIR)$(SYSTEMDUNITDIR)/$(DAEMON).service
	install -Dm0644 packaging/sysusers.d/$(APP).conf $(DESTDIR)$(SYSUSERSDIR)/$(APP).conf
	install -Dm0644 packaging/tmpfiles.d/$(APP).conf $(DESTDIR)$(TMPFILESDIR)/$(APP).conf
	install -d -m0755 $(DESTDIR)$(SYSCONFDIR)/$(APP)
	@if [ ! -e $(DESTDIR)$(SYSCONFDIR)/$(APP)/$(DAEMON).json ]; then \
		install -m0644 packaging/$(DAEMON).json $(DESTDIR)$(SYSCONFDIR)/$(APP)/$(DAEMON).json; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(APP)
	rm -f $(DESTDIR)$(SBINDIR)/$(DAEMON)
	rm -f $(DESTDIR)$(SYSTEMDUNITDIR)/$(DAEMON).service
	rm -f $(DESTDIR)$(SYSUSERSDIR)/$(APP).conf
	rm -f $(DESTDIR)$(TMPFILESDIR)/$(APP).conf
	@echo "Preserved $(SYSCONFDIR)/$(APP) and daemon state."

clean:
	rm -rf $(BIN_DIR)
