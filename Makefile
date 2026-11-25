GNOROOT ?= /home/ubuntu/gnome-tavern/gno
GNO_BIN ?= /home/ubuntu/gnome-tavern/bin/gno
ADDR    ?= g1zt8w45ecxhlsdse7hd5gwr6xzcaxy9zsej6hl2

.PHONY: all gno-test gno-lint build go-test e2e deploy-onyx

all: gno-test gno-lint build go-test

gno-test:
	GNOROOT=$(GNOROOT) $(GNO_BIN) test -root-dir $(GNOROOT) -v ./gno/p/$(ADDR)/ironclad ./gno/r/$(ADDR)/ironclad

gno-lint:
	GNOROOT=$(GNOROOT) $(GNO_BIN) lint -root-dir $(GNOROOT) -v ./gno/p/$(ADDR)/ironclad ./gno/r/$(ADDR)/ironclad

build:
	mkdir -p bin
	go build -o bin/ironclad ./cmd/ironclad
	go build -o bin/ironclad-server ./cmd/ironclad-server

go-test:
	go test -race -v ./...

e2e: build
	./scripts/e2e_gnodev.sh

deploy-onyx: build
	./scripts/deploy_onyx.sh
