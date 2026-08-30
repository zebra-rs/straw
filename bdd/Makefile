# ── Per-worktree toolchain staging ───────────────────────────────────────
#
# A BDD run must exercise THIS worktree's binaries. `stage` builds them and
# copies the result into `.stage/bin`; the harness prepends that to PATH for
# every in-namespace command (see bdd/src/toolchain.rs) and reads nothing
# under /usr. Every test target runs `stage` first, so it is impossible to
# test a stale binary through make.
#
# Copies, not symlinks into target/: cargo rewrites target/<profile>/straw in
# place, so a rebuild during a run would otherwise swap the binary out from
# under it.
#
# PROFILE=debug builds faster; the default matches a real install (release),
# which the throughput-sensitive scenarios expect.
PROFILE ?= release
CARGO_PROFILE_FLAG := $(if $(filter release,$(PROFILE)),--release,)
TARGET_DIR ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),../target)
STAGE := .stage
STAGE_BINS := straw strawc test_client

CUCUMBER = $(MAKE) --no-print-directory stage && cargo test -p bdd --test cucumber

.DEFAULT_GOAL := all

# Populates a scratch directory and renames it into place, so an interrupted
# stage never leaves a half-filled .stage behind — the harness refuses to run
# against one rather than silently falling back to the host PATH.
.PHONY: stage
stage:
	cargo build $(CARGO_PROFILE_FLAG) -p straw --bins
	@rm -rf $(STAGE).tmp
	@mkdir -p $(STAGE).tmp/bin
	@install -m 0755 $(addprefix $(TARGET_DIR)/$(PROFILE)/,$(STAGE_BINS)) $(STAGE).tmp/bin/
	@rm -rf $(STAGE)
	@mv $(STAGE).tmp $(STAGE)
	@echo "[staged $(PROFILE) toolchain in $(CURDIR)/$(STAGE)]"

.PHONY: unstage
unstage:
	rm -rf $(STAGE) $(STAGE).tmp

# Whole suite, features in parallel. Each feature scopes its namespaces and
# pid files by tag, so they cannot collide.
.PHONY: all
all:
	rm -rf allure-results
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=4

# One feature by tag: `make tunnel_basic`, `make tunnel_hairpin`, …
# `BDD_KEEP=1 make tunnel_basic` leaves the topology and daemons up.
.PHONY: $(patsubst tests/features/%.feature,%,$(wildcard tests/features/*.feature))
$(patsubst tests/features/%.feature,%,$(wildcard tests/features/*.feature)):
	mkdir -p allure-results
	$(CUCUMBER) -- --concurrency=1 --tags "@$@"

# Unit tests of the harness itself (no root needed).
.PHONY: check
check:
	cargo test -p bdd --lib

.PHONY: report
report:
	rm -rf allure-report
	allure generate

.PHONY: serve
serve:
	rm -rf allure-report
	allure generate
	allure open

.PHONY: clean
clean:
	rm -rf allure-results allure-report logs
