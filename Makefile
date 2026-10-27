.PHONY: build web test clean serve

build: web
	mkdir -p bin
	go build -trimpath -o bin/tokhive-verify ./cmd/tokhive-verify

web:
	GOOS=js GOARCH=wasm go build -trimpath -ldflags='-s -w' -o web/static/verifier.wasm ./cmd/wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/static/wasm_exec.js
	@if [ -f "$$(go env GOROOT)/LICENSE" ]; then cp "$$(go env GOROOT)/LICENSE" web/static/wasm_exec.LICENSE; else cp "$$(go env GOROOT)/../LICENSE" web/static/wasm_exec.LICENSE; fi

test:
	go test -race ./...
	go vet ./...

serve: build
	./bin/tokhive-verify serve

clean:
	rm -f bin/tokhive-verify web/static/verifier.wasm web/static/wasm_exec.js web/static/wasm_exec.LICENSE
