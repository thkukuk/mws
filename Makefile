MWS_BIN := bin/mws

GO ?= go
GO_MD2MAN ?= go-md2man

VERSION := $(shell cat VERSION)
USE_VENDOR =
LOCAL_LDFLAGS = -buildmode=pie -ldflags "-X=github.com/thkukuk/mws/pkg/mws.Version=$(VERSION)"

.PHONY: all api build vendor
all: dep build

dep: ## Get the dependencies
	@$(GO) get -v -d ./...

update: ## Get and update the dependencies
	@$(GO) get -v -d -u ./...

tidy: ## Clean up dependencies
	@$(GO) mod tidy

vendor: dep ## Create vendor directory
	@$(GO) mod vendor

build: ## Build the binary files
	$(GO) build -v -o $(MWS_BIN) $(USE_VENDOR) $(LOCAL_LDFLAGS) ./cmd/mws

clean: ## Remove previous builds
	@rm -f $(MWS_BIN)

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


.PHONY: release
release: ## create release package from git
	git clone https://github.com/thkukuk/mws
	mv mws mws-$(VERSION)
	sed -i -e 's|USE_VENDOR =|USE_VENDOR = -mod vendor|g' mws-$(VERSION)/Makefile
	make -C mws-$(VERSION) vendor
	cp VERSION mws-$(VERSION)
	tar --exclude .git -cJf mws-$(VERSION).tar.xz mws-$(VERSION)
	rm -rf mws-$(VERSION)
