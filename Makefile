.PHONY: setup format check

setup:
	go mod download

format:
	gofmt -w .

check:
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then printf '%s\n' "Run make format:" "$$unformatted"; exit 1; fi
	go vet ./...
	go test -race ./...
