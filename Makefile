
.PHONY: tests build run run_js

export SUPPRESS_STACK_TRACE=true

ifeq ($(filter $(SCOPE) scope,$(SCOPE)),)
	SCOPE := $(scope)
endif


build:
	wasm-pack build --target web -d examples/pkg

tests:
	@# run all tests: make tests
	@# run a specific test: make tests SCOPE=localencrypt::utils
	@if [ "$(SUPPRESS_STACK_TRACE)" = "true" ]; then \
	    wasm-pack test --headless --firefox . -- $(SCOPE) 2>&1 | \
		awk '/^[ ]*Stack:/ || \
		    /JS exception that was thrown:/ \
		    { suppress=1; next } \
		/^[^ ]/ { suppress=0 } \
		suppress==0 { print }'; \
	else \
	    wasm-pack test --headless --firefox . -- $(SCOPE); \
	fi


run: build
	cd examples && python3 server.py

run_js: build
	@# similar to examples, but using nodejs instead to run the server
	@# ensure express is installed: npm install express
	cd examples && node server.js

