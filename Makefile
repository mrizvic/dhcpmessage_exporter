GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test ./...
GOGET=$(GOCMD) get -u -v

# Detect the os so that we can build proper statically linked binary
OS := $(shell uname -s | awk '{print tolower($$0)}')

# Get a short hash of the git had for building images.
TAG = $$(git rev-parse --short HEAD)

# Name of actual binary to create
BINARY = dhcpmessage_exporter

# GOARCH tells go build which arch. to use while building a statically linked executable
GOARCH = amd64

bin:
	env CGO_ENABLED=1 GOOS=$(OS) GOARCH=$(GOARCH) go build -o ${BINARY}-$(OS)-${GOARCH} . ;
	strip ${BINARY}-$(OS)-${GOARCH}
	@echo "sudo setcap cap_net_raw,cap_net_admin=eip ${BINARY}-$(OS)-${GOARCH}"

deps:
	$(GOGET) github.com/google/gopacket
	$(GOGET) github.com/prometheus/client_golang 

clean:
	$(GOCLEAN)
	rm -f ${BINARY}-$(OS)-${GOARCH}

push:
	curl -T ${BINARY}-$(OS)-${GOARCH} https://xfer.ts.si; echo ""

