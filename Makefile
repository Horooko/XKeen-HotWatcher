.PHONY: test build vet clean

test:
	go test -race -cover ./...
vet:
	go vet ./...
build:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/hotwatcher-linux-arm64 ./cmd/hotwatcher
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/hotwatcher-linux-amd64 ./cmd/hotwatcher
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/hotwatcher-updater-linux-arm64 ./cmd/hotwatcher-updater
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/hotwatcher-updater-linux-amd64 ./cmd/hotwatcher-updater
	cd dist && sha256sum hotwatcher-linux-* hotwatcher-updater-linux-* > SHA256SUMS
clean:
	rm -f dist/hotwatcher-linux-arm64 dist/hotwatcher-linux-amd64 dist/hotwatcher-updater-linux-arm64 dist/hotwatcher-updater-linux-amd64 dist/SHA256SUMS
