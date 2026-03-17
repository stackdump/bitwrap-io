.PHONY: build run test clean

PORT ?= 8088

build:
	go build -o bitwrap ./cmd/bitwrap

run: build
	./bitwrap -port $(PORT)

test:
	go test ./...

clean:
	rm -f bitwrap
