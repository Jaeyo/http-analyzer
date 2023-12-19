NAME=http-analyzer

TEST_PACKAGES = ./...

all: build-in-container

build:
	@GOOS=linux GOARCH=amd64 go build -o ${NAME} -buildvcs=false .

build-local:
	@go build -o ${NAME} -buildvcs=false .

build-image:
	@docker build -t ${NAME}:dev .

build-in-container: build-image
	@docker run -v $(PWD):/app -it ${NAME}:dev make build

interactive-in-container: build-image
	@docker run -v $(PWD):/app -it ${NAME}:dev /bin/bash

test:
	@go vet ${TEST_PACKAGES}
	@go test -race -cover -coverprofile cover.out ${TEST_PACKAGES}
	@go tool cover -func=cover.out | tail -n 1


