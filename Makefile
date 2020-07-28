# =================================================================
#
# Work of the U.S. Department of Defense, Defense Digital Service.
# Released as open source under the MIT License.  See LICENSE file.
#
# =================================================================

.PHONY: help
help:  ## Print the help documentation
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#
# Go building, formatting, testing, and installing
#

fmt:  ## Format Go source code
	go fmt $$(go list ./... )

.PHONY: imports
imports: bin/goimports ## Update imports in Go source code
	# If missing, install goimports with: go get golang.org/x/tools/cmd/goimports
	bin/goimports -w -local github.com/deptofdefense/iceberg,github.com/deptofdefense $$(find . -iname '*.go')

vet: ## Vet Go source code
	go vet $$(go list ./...)

tidy: ## Tidy Go source code
	go mod tidy

.PHONY: test_go
test_go: bin/errcheck bin/ineffassign bin/staticcheck bin/shadow ## Run Go tests
	bash scripts/test.sh

.PHONY: test_cli
test_cli: bin/iceberg temp/ca.crt temp/server.crt ## Run CLI tests
	bash scripts/test-cli.sh

install:  ## Install iceberg CLI on current platform
	go install github.com/deptofdefense/iceberg/cmd/iceberg

#
# Command line Programs
#

bin/errcheck:
	go build -o bin/errcheck github.com/kisielk/errcheck

bin/goimports:
	go build -o bin/goimports golang.org/x/tools/cmd/goimports

bin/gox:
	go build -o bin/gox github.com/mitchellh/gox

bin/ineffassign:
	go build -o bin/ineffassign github.com/gordonklaus/ineffassign

bin/staticcheck:
	go build -o bin/staticcheck honnef.co/go/tools/cmd/staticcheck

bin/shadow:
	go build -o bin/shadow golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow

bin/iceberg: ## Build iceberg CLI for Darwin / amd64
	go build -o bin/iceberg github.com/deptofdefense/iceberg/cmd/iceberg

bin/iceberg_linux_amd64: bin/gox ## Build iceberg CLI for Darwin / amd64
	scripts/build-release linux amd64

.PHONY: build
build: bin/iceberg

.PHONY: build_release
build_release: bin/gox
	scripts/build-release

#
# Docker
#

docker_build: bin/iceberg_linux_amd64 ## Build docker server image
	docker build -f Dockerfile --tag iceberg:latest .

docker_serve_example: temp/ca.crt temp/server.crt ## Serve using docker server image
	docker run -it --rm -p 8080:8080 -v $(PWD):/iceberg iceberg:latest serve \
	--addr :8080 \
	--server-cert /iceberg/temp/server.crt \
	--server-key /iceberg/temp/server.key \
	--client-ca /iceberg/temp/ca.crt \
	--client-ca-format pem \
	--root /iceberg/examples/public \
	--template /iceberg/examples/conf/template.html \
	--access-policy /iceberg/examples/conf/example.json

#
# Certificate Targets
#

temp/ca.crt:
	mkdir -p temp
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/C=US/O=Atlantis/OU=Atlantis Digital Service/CN=icebergca" -keyout temp/ca.key -out temp/ca.crt

temp/server.crt:
	mkdir -p temp
	openssl req -x509 -nodes -days 365 -newkey rsa:2048  -subj "/C=US/O=Atlantis/OU=Atlantis Digital Service/CN=iceberglocal" -keyout temp/server.key -out temp/server.crt

temp/client.crt: temp/ca.crt
	mkdir -p temp
	openssl genrsa -out temp/client.key 2048
	openssl req -new -key temp/client.key -subj "/C=US/O=Atlantis/OU=Atlantis Digital Service/CN=username" -out temp/client.csr
	openssl x509 -req -in temp/client.csr -CA temp/ca.crt -CAkey temp/ca.key -CAcreateserial -out temp/client.crt

temp/client.p12: temp/client.crt
	mkdir -p temp
	openssl pkcs12 -export -out temp/client.p12 -inkey temp/client.key -in temp/client.crt -certfile temp/ca.crt -passout pass:

## Clean

clean:  ## Clean artifacts
	rm -fr bin
