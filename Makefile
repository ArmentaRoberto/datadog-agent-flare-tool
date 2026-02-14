BINARY = flare-tool
GOFLAGS = -modfile=flare-tool.go.mod
GOTOOLCHAIN = local
GOWORK = off

export GOFLAGS GOTOOLCHAIN GOWORK

.PHONY: build test clean

build:
	go build -o $(BINARY) ./cmd/flare-tool/

test:
	go test -count=1 -v ./pkg/analyzer/... ./pkg/extractor/... ./pkg/report/... ./pkg/types/...

clean:
	rm -f $(BINARY)
