BIN := sxel

.PHONY: build vet test race fmt check clean

build:
	go build -o $(BIN) ./cmd/sxel

vet:
	go vet ./...

test:
	go test ./... -timeout 300s

race:
	go test ./... -race -timeout 600s

fmt:
	gofmt -l .
	gofmt -w .

check: fmt vet test

clean:
	rm -f $(BIN)
