# SPDX-FileCopyrightText: 2026 Alexander R. Croft
# SPDX-License-Identifier: GPL-3.0-or-later

APP := macrun
DIST_DIR := dist
DIST_BIN_DIR := $(DIST_DIR)/bin

.PHONY: bump clean dist

bump:
	@current="$$(tr -d '\n' < VERSION)"; \
	if [ -z "$$current" ]; then \
		echo "VERSION is empty" >&2; \
		exit 1; \
	fi; \
	next="$$(printf '%s\n' "$$current" | awk -F. 'BEGIN { OFS = "." } { if (NF == 1) { print $$1 + 1 } else { $$NF = $$NF + 1; print $$0 } }')"; \
	printf '%s\n' "$$next" > VERSION; \
	awk -v version="$$next" ' \
		BEGIN { updated = 0 } \
		/^version = "/ && !updated { print "version = \"" version "\""; updated = 1; next } \
		{ print } \
		END { if (!updated) exit 2 } \
	' Cargo.toml > Cargo.toml.tmp; \
	status="$$?"; \
	if [ "$$status" -ne 0 ]; then \
		rm -f Cargo.toml.tmp; \
		echo "failed to update Cargo.toml version" >&2; \
		exit "$$status"; \
	fi; \
	mv Cargo.toml.tmp Cargo.toml; \
	echo "VERSION=$$next"; \
	echo "Cargo.toml version=$$next"

clean:
	rm -rf target

dist:
	@build="$$(awk 'NR == 1 { print $$1 + 1; exit }' BUILD)"; \
	printf '%s\n' "$$build" > BUILD; \
	echo "BUILD=$$build"
	@cargo build --release
	@mkdir -p $(DIST_BIN_DIR)
	@cp target/release/$(APP) $(DIST_BIN_DIR)/$(APP)
	@cp USER_GUIDE.md $(DIST_DIR)/USER_GUIDE.md
	@cp README.md $(DIST_DIR)/README.md
	@cp LICENSE $(DIST_DIR)/LICENSE
	@echo "dist ready in $(DIST_DIR)"