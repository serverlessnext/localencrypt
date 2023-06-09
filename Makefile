
.PHONY: tests build run run_js

build:
	wasm-pack build --target web -d examples/pkg

tests:
	wasm-pack test --headless --firefox

run: build
	cd examples && python3 server.py

run_js: build
	@# similar to examples, but using nodejs instead to run the server
	@# ensure express is installed: npm install express
	cd examples && node server.js

