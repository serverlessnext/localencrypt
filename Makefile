
.PHONY: tests

build:
	wasm-pack build --target web -d example/pkg

tests:
	wasm-pack test --headless --firefox

run:
	@# install simple-http-server with `cargo install simple-http-server`
	simple-http-server example/ -i

