test:
	@go test -v -race -count=1 ./...

bench-test:
	@go test -v -race -count=1 -bench=. -benchmem ./...