BIN     := wsst
GOOS    ?= linux
GOARCH  ?= amd64
LDFLAGS := -s -w

.PHONY: build clean install

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -ldflags "$(LDFLAGS)" -o $(BIN) .

# Cross-compile for ARM64 (e.g. Ampere VPS)
build-arm64:
	$(MAKE) build GOARCH=arm64

clean:
	rm -f $(BIN)

install:
	install -m 755 $(BIN) /usr/local/bin/$(BIN)
