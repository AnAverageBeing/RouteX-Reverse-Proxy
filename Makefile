.PHONY: build run lint test clean

APP_NAME := routex
CMD_DIR := ./cmd/routex
BUILD_DIR := ./bin

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) $(CMD_DIR)

run: build
	$(BUILD_DIR)/$(APP_NAME) -config configs/global.yaml -proxies configs/proxies

lint:
	golangci-lint run ./...

test:
	go test -race -cover -coverprofile=coverage.txt ./...

clean:
	rm -rf $(BUILD_DIR)
	rm -f *.db *.log coverage.txt
