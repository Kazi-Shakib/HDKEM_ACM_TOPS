# =============================================================================
# HDKEM artifact v8 — build for hdkem_implementation_new
#
# This Makefile fixes the Falcon/PQClean SHAKE linkage issue seen when the
# imported Falcon sources call OQS_SHA3_shake256_inc_* but the installed
# liboqs does not export those internal symbols.
#
# Files expected at repository root:
#   hdkem_client.c
#   hdkem_server.c
#   hdkem_bench.c
#   hdkem_wire.h
#   Makefile
#
# Files expected under src/:
#   hdkem_primitives.c
#   hdkem_primitives.h
#   oqs_shake_compat.c          <-- supplied with this Makefile
#   inner.h, api.h, codec.c, common.c, fft.c, fpr.c, keygen.c,
#   rng.c, sign.c, vrfy.c, pqclean.c
#
# If the Falcon/PQClean files live elsewhere:
#   make FALCON_DIR=/path/to/falcon/source
#
# Normal build:
#   make clean
#   make
#
# Paper experiment:
#   ./hdkem_server -m src -b 32 -n 500 -r gandalf
#   ./hdkem_client -m src -b 32 -n 500 -r gandalf -o client.csv
#   -r selects the ring-signature scheme: gandalf (default) or falconrs.
#   Both are implemented (hdkem_primitives.c). falconrs_sign/verify is this
#   artifact's own transcription of Algorithm 8 (Hashimoto/Katsumata/Niot/
#   Tucker/Wiggers) -- not the authors' reference implementation and not
#   yet cross-checked against it; see the block comment above
#   falconrs_sign() before citing -r falconrs numbers as reproducing the
#   paper's proven (mu,delta) bound.
#   ./hdkem_bench -n 2000 -b 32
#
# Conservative source:
#   ./hdkem_bench -n 2000 -b 48
# =============================================================================

MAKEFLAGS += --no-builtin-rules
.SUFFIXES:
.DEFAULT_GOAL := all

CC ?= gcc

# -----------------------------------------------------------------------------
# Project layout
# -----------------------------------------------------------------------------

HDKEM_SRC ?= src
INCLUDE_DIR ?= include
FALCON_DIR ?= $(HDKEM_SRC)

PRIM_C := $(HDKEM_SRC)/hdkem_primitives.c
PRIM_H := $(HDKEM_SRC)/hdkem_primitives.h
PRIM_O := $(HDKEM_SRC)/hdkem_primitives.o

SHAKE_COMPAT_C := $(HDKEM_SRC)/oqs_shake_compat.c
SHAKE_COMPAT_O := $(HDKEM_SRC)/oqs_shake_compat.o

WIRE_H := hdkem_wire.h

ENDPOINTS := hdkem_server hdkem_client
PROGRAMS  := hdkem_bench $(ENDPOINTS)
OBJECTS   := $(PRIM_O) $(SHAKE_COMPAT_O)

# -----------------------------------------------------------------------------
# Dependency discovery
# -----------------------------------------------------------------------------

OQS_CFLAGS := $(shell pkg-config --cflags liboqs 2>/dev/null)
OQS_LIBS   := $(shell pkg-config --libs liboqs 2>/dev/null)

ifeq ($(strip $(OQS_CFLAGS)),)
OQS_CFLAGS := -I/usr/local/include
endif

ifeq ($(strip $(OQS_LIBS)),)
ifneq ($(wildcard /usr/local/lib/liboqs.a),)
OQS_LIBS := /usr/local/lib/liboqs.a
else
OQS_LIBS := -loqs
endif
endif

SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS   := $(shell pkg-config --libs libsodium 2>/dev/null)

ifeq ($(strip $(SODIUM_LIBS)),)
SODIUM_LIBS := -lsodium
endif

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)

ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -lcrypto
endif

# -----------------------------------------------------------------------------
# Compiler / linker flags
# -----------------------------------------------------------------------------

CPPFLAGS += -D_GNU_SOURCE \
            -DHDKEM_WITH_OQS \
            -DHDKEM_QUIET \
            -I. \
            -I$(HDKEM_SRC) \
            -I$(FALCON_DIR) \
            $(if $(wildcard $(INCLUDE_DIR)),-I$(INCLUDE_DIR)) \
            $(OQS_CFLAGS) \
            $(SODIUM_CFLAGS) \
            $(OPENSSL_CFLAGS)

CFLAGS ?= -O2 -g
CFLAGS += -std=c11 \
          -Wall \
          -Wextra \
          -Wpedantic \
          -Wno-unused-parameter \
          -fno-omit-frame-pointer

# Benchmark-native build by default. Disable with:
#   make NATIVE=
NATIVE ?= -march=native
CFLAGS += $(NATIVE)

LDFLAGS +=

# Objects come before libraries in every executable rule.  This matters for
# static libraries such as /usr/local/lib/liboqs.a.
LDLIBS += $(OQS_LIBS) \
          $(OPENSSL_LIBS) \
          $(SODIUM_LIBS) \
          -ldl \
          -lm \
          -lpthread

# -----------------------------------------------------------------------------
# Default target
# -----------------------------------------------------------------------------

.PHONY: all
all: preflight $(PROGRAMS)

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------

.PHONY: preflight
preflight:
	@echo "HDKEM_SRC  = $(HDKEM_SRC)"
	@echo "FALCON_DIR = $(FALCON_DIR)"
	@echo "primitives = real (liboqs + Gandalf/Falcon)"
	@echo "SHAKE      = local OpenSSL compatibility layer"
	@test -f "$(PRIM_C)" || { \
		echo "ERROR: missing $(PRIM_C)"; \
		exit 1; \
	}
	@test -f "$(PRIM_H)" || { \
		echo "ERROR: missing $(PRIM_H)"; \
		exit 1; \
	}
	@test -f "$(SHAKE_COMPAT_C)" || { \
		echo "ERROR: missing $(SHAKE_COMPAT_C)"; \
		echo "Copy oqs_shake_compat.c into $(HDKEM_SRC)/"; \
		exit 1; \
	}
	@test -f "$(FALCON_DIR)/inner.h" || { \
		echo "ERROR: $(FALCON_DIR)/inner.h not found."; \
		echo "Find it with:"; \
		echo "  find . -name inner.h"; \
		echo "Then use:"; \
		echo "  make FALCON_DIR=/directory/containing/inner.h"; \
		exit 1; \
	}
	@test -f "$(FALCON_DIR)/api.h" || { \
		echo "ERROR: $(FALCON_DIR)/api.h not found."; \
		exit 1; \
	}
	@grep -Eq 'GANDALF_SIGNATURE_SIZE[[:space:]]+1236u?' "$(PRIM_H)" || { \
		echo "ERROR: $(PRIM_H) is not the aligned header."; \
		echo "Expected GANDALF_SIGNATURE_SIZE = 1236 (Gandalf CRYPTO'24, k=2: 606*2+24)."; \
		exit 1; \
	}
	@grep -Eq 'FALCONRS_SIGNATURE_SIZE[[:space:]]+1288u?' "$(PRIM_H)" || { \
		echo "ERROR: $(PRIM_H) is not the aligned header."; \
		echo "Expected FALCONRS_SIGNATURE_SIZE = 1288."; \
		exit 1; \
	}
	@grep -Eq 'ASCON_KEY_SIZE[[:space:]]+16u?' "$(PRIM_H)" || { \
		echo "ERROR: $(PRIM_H) does not define ASCON_KEY_SIZE = 16."; \
		exit 1; \
	}
	@echo "preflight: OK"

# -----------------------------------------------------------------------------
# Objects
# -----------------------------------------------------------------------------

# hdkem_primitives.c is a unity translation unit that includes the Falcon
# implementation source files. Depend on the main Falcon files so edits trigger
# a rebuild rather than leaving a stale primitive object.
FALCON_DEPS := \
	$(FALCON_DIR)/inner.h \
	$(FALCON_DIR)/api.h \
	$(FALCON_DIR)/codec.c \
	$(FALCON_DIR)/common.c \
	$(FALCON_DIR)/fft.c \
	$(FALCON_DIR)/fpr.c \
	$(FALCON_DIR)/keygen.c \
	$(FALCON_DIR)/rng.c \
	$(FALCON_DIR)/sign.c \
	$(FALCON_DIR)/vrfy.c \
	$(FALCON_DIR)/pqclean.c

$(PRIM_O): $(PRIM_C) $(PRIM_H) $(FALCON_DEPS)
	@echo "CC  $@"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(PRIM_C) -o $@

$(SHAKE_COMPAT_O): $(SHAKE_COMPAT_C)
	@echo "CC  $@"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(SHAKE_COMPAT_C) -o $@

# -----------------------------------------------------------------------------
# Executables
# -----------------------------------------------------------------------------

# hdkem_bench.c v8 has its own main(). Do not link old bench.c/bench.h.

hdkem_bench: hdkem_bench.c $(WIRE_H) $(PRIM_H) $(OBJECTS)
	@echo "LD  $@"
	$(CC) $(CPPFLAGS) $(CFLAGS) \
	      hdkem_bench.c $(OBJECTS) \
	      -o $@ $(LDFLAGS) $(LDLIBS)

hdkem_server: hdkem_server.c $(WIRE_H) $(PRIM_H) $(OBJECTS)
	@echo "LD  $@"
	$(CC) $(CPPFLAGS) $(CFLAGS) \
	      hdkem_server.c $(OBJECTS) \
	      -o $@ $(LDFLAGS) $(LDLIBS)

hdkem_client: hdkem_client.c $(WIRE_H) $(PRIM_H) $(OBJECTS)
	@echo "LD  $@"
	$(CC) $(CPPFLAGS) $(CFLAGS) \
	      hdkem_client.c $(OBJECTS) \
	      -o $@ $(LDFLAGS) $(LDLIBS)

# -----------------------------------------------------------------------------
# Reproduction helpers
# -----------------------------------------------------------------------------

.PHONY: paper-bench
paper-bench: all
	@echo
	@echo "Paper primitive benchmark:"
	@echo "  ./hdkem_bench -n 2000 -b 32"
	@echo
	@echo "End-to-end paper experiment, terminal 1:"
	@echo "  ./hdkem_server -m src -b 32 -n 500"
	@echo
	@echo "End-to-end paper experiment, terminal 2:"
	@echo "  ./hdkem_client -m src -b 32 -n 500 -o client.csv"

.PHONY: conservative-bench
conservative-bench: all
	./hdkem_bench -n 2000 -b 48

.PHONY: smoke
smoke: all
	./hdkem_bench -n 10 -b 32
	./hdkem_bench -n 10 -b 48

# -----------------------------------------------------------------------------
# Diagnostics
# -----------------------------------------------------------------------------

.PHONY: show-config
show-config:
	@echo "CC             = $(CC)"
	@echo "HDKEM_SRC      = $(HDKEM_SRC)"
	@echo "FALCON_DIR     = $(FALCON_DIR)"
	@echo "PRIM_O         = $(PRIM_O)"
	@echo "SHAKE_COMPAT_O = $(SHAKE_COMPAT_O)"
	@echo "CPPFLAGS       = $(CPPFLAGS)"
	@echo "CFLAGS         = $(CFLAGS)"
	@echo "OQS_LIBS       = $(OQS_LIBS)"
	@echo "OPENSSL_LIBS   = $(OPENSSL_LIBS)"
	@echo "SODIUM_LIBS    = $(SODIUM_LIBS)"
	@echo "LDLIBS         = $(LDLIBS)"

# Show whether the installed liboqs itself exports the incremental SHAKE names.
# The build does not require it because oqs_shake_compat.o supplies them.
.PHONY: check-oqs-shake
check-oqs-shake:
	@echo "Checking linked liboqs for OQS_SHA3_shake256_inc_init..."
	@nm -A /usr/local/lib/liboqs.a 2>/dev/null | \
	  grep 'OQS_SHA3_shake256_inc_init' || \
	  echo "not exported (expected; local compatibility layer is used)"

# -----------------------------------------------------------------------------
# Sanitizers
# -----------------------------------------------------------------------------

.PHONY: asan
asan:
	$(MAKE) clean
	$(MAKE) \
	  NATIVE= \
	  CFLAGS="-O1 -g -std=c11 -Wall -Wextra -Wpedantic -Wno-unused-parameter -fno-omit-frame-pointer -fsanitize=address,undefined" \
	  LDFLAGS="-fsanitize=address,undefined"
	./hdkem_bench -n 10 -b 32

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

.PHONY: clean
clean:
	rm -f $(PROGRAMS)
	rm -f $(PRIM_O) $(SHAKE_COMPAT_O)
	rm -f *.csv
	rm -f client.rsk client.rvk server.rsk server.rvk
	rm -f source_master.bin
