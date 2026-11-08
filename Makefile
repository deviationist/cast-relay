VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
ARCHES  := arm64 amd64
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test build clean

test:
	go vet ./...
	go test ./...

build: $(ARCHES:%=dist/cast-relay-linux-%)

dist/cast-relay-linux-%: $(wildcard *.go) go.mod go.sum
	GOOS=linux GOARCH=$* CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ .

# A single-platform image tar in the classic `docker save` layout, importable with RouterOS
# `/container add file=…` or `docker load`. No provenance attestations:
# RouterOS expects a plain image with uncompressed layers in the classic
# layout; it fails with "could not load next layer" on the OCI layout.
image-%: dist/cast-relay-linux-%
	docker buildx build --platform linux/$* --provenance=false --sbom=false \
		-t cast-relay:$(VERSION) \
		--output type=docker,dest=dist/oci-$(VERSION)-$*.tar,compression=uncompressed,force-compression=true .
	python3 -I tools/legacy-tar.py dist/oci-$(VERSION)-$*.tar dist/cast-relay-$(VERSION)-$*.tar
	@rm -f dist/oci-$(VERSION)-$*.tar
	@ls -l dist/cast-relay-$(VERSION)-$*.tar

clean:
	rm -rf dist
