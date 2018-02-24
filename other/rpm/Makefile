PROJECT_NAME = toxcore
PROJECT_FULL_NAME = c-$(PROJECT_NAME)
PROJECT_VERSION = $(shell git describe | sed -e 's/^v//' -e 's/-/_/g')
PROJECT_COMMIT_ID = $(shell git rev-parse HEAD)
PROJECT_COMMIT_ID_SHORT = $(shell git rev-parse --short HEAD)
PROJECT_GIT_ROOT = $(shell git rev-parse --show-toplevel)

all:
	@echo available targets: spec srpm clean

spec: toxcore.spec

toxcore.spec:
	sed -r \
	  -e 's#@PROJECT_NAME@#$(PROJECT_NAME)#g' \
	  -e 's#@PROJECT_VERSION@#$(PROJECT_VERSION)#' \
	  -e 's#^(%define commit )0$$#\1$(PROJECT_COMMIT_ID)#' \
	  toxcore.spec.in > toxcore.spec

$(PROJECT_FULL_NAME)-$(PROJECT_COMMIT_ID_SHORT).tar.gz:
	( \
	  cd $(PROJECT_GIT_ROOT); \
	  git archive --prefix '$(PROJECT_FULL_NAME)-$(PROJECT_COMMIT_ID_SHORT)/' -o other/rpm/$(PROJECT_FULL_NAME)-$(PROJECT_COMMIT_ID_SHORT).tar.gz $(PROJECT_COMMIT_ID) \
	)

srpm: toxcore.spec $(PROJECT_FULL_NAME)-$(PROJECT_COMMIT_ID_SHORT).tar.gz
	rpmbuild --define "_sourcedir ." --define "_srcrpmdir ." -bs toxcore.spec

clean:
	rm -f toxcore.spec *.tar.gz *.rpm

.PHONY = clean srpm spec
