# NetGuard core (C11).  Targets: all, debug, test, clean.
#   make            -> ../bin/netguard[.exe]                (release, -O2)
#   make test       -> builds and runs ../bin/netguard_tests  (release flags)
#   make debug      -> ../bin/netguard-debug + test runner with
#                      -g -fsanitize=address,undefined, and runs the tests
#                      (use on Linux/WSL/macOS; MinGW has no sanitizers)
# Works with gcc or clang on Linux, macOS and WSL, and with MinGW-w64
# (mingw32-make) on Windows from cmd.exe, PowerShell or an MSYS shell.

ifeq ($(origin CC),default)
  CC := gcc
endif

WARN     := -std=c11 -Wall -Wextra
CPPFLAGS += -Iinclude -MMD -MP
REL_FLAGS := $(WARN) -O2
DBG_FLAGS := $(WARN) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
LDLIBS   := -lm

EXE :=
WINCMD :=
ifeq ($(OS),Windows_NT)
  EXE := .exe
  CPPFLAGS += -D__USE_MINGW_ANSI_STDIO=1
  # cmd.exe echoes the quotes, a POSIX sh does not
  ifeq ($(shell echo "cmd"),"cmd")
    WINCMD := 1
  endif
endif

ifeq ($(WINCMD),1)
  mkdir_p = if not exist $(subst /,\,$(1)) mkdir $(subst /,\,$(1))
  rm_rf   = if exist $(subst /,\,$(1)) rmdir /s /q $(subst /,\,$(1))
  rm_f    = if exist $(subst /,\,$(1)) del /q $(subst /,\,$(1))
  RUN     = $(subst /,\,$(1))
else
  mkdir_p = mkdir -p $(1)
  rm_rf   = rm -rf $(1)
  rm_f    = rm -f $(1)
  RUN     = $(1)
endif

BIN_DIR := ../bin
LIB_SRCS := lexer.c parser_fw.c parser_ng.c sema.c diag.c partition.c nfa.c dfa.c minimize.c \
            analysis.c optimize.c equiv.c classify.c oracle.c dot.c json.c bitset.c util.c ir.c pipeline.c compare.c
TEST_SRCS := test_main.c test_lexer.c test_parser.c test_partition.c test_automata.c \
             test_analysis.c test_equiv.c

REL_LIB  := $(addprefix build/rel/,$(LIB_SRCS:.c=.o))
DBG_LIB  := $(addprefix build/dbg/,$(LIB_SRCS:.c=.o))
REL_TEST := $(addprefix build/rel/tests/,$(TEST_SRCS:.c=.o))
DBG_TEST := $(addprefix build/dbg/tests/,$(TEST_SRCS:.c=.o))

NETGUARD       := $(BIN_DIR)/netguard$(EXE)
NETGUARD_TESTS := $(BIN_DIR)/netguard_tests$(EXE)
NETGUARD_DBG   := $(BIN_DIR)/netguard-debug$(EXE)
TESTS_DBG      := $(BIN_DIR)/netguard_tests-debug$(EXE)

.PHONY: all debug test clean

all: $(NETGUARD)

test: $(NETGUARD_TESTS) $(NETGUARD)
	$(call RUN,$(NETGUARD_TESTS)) ../examples

debug: $(NETGUARD_DBG) $(TESTS_DBG)
	$(call RUN,$(TESTS_DBG)) ../examples

$(NETGUARD): build/rel/main.o $(REL_LIB) | $(BIN_DIR)
	$(CC) $(REL_FLAGS) -o $@ $^ $(LDLIBS)

$(NETGUARD_TESTS): $(REL_TEST) $(REL_LIB) | $(BIN_DIR)
	$(CC) $(REL_FLAGS) -o $@ $^ $(LDLIBS)

$(NETGUARD_DBG): build/dbg/main.o $(DBG_LIB) | $(BIN_DIR)
	$(CC) $(DBG_FLAGS) -o $@ $^ $(LDLIBS)

$(TESTS_DBG): $(DBG_TEST) $(DBG_LIB) | $(BIN_DIR)
	$(CC) $(DBG_FLAGS) -o $@ $^ $(LDLIBS)

build/rel/%.o: src/%.c | build/rel
	$(CC) $(REL_FLAGS) $(CPPFLAGS) -c $< -o $@
build/dbg/%.o: src/%.c | build/dbg
	$(CC) $(DBG_FLAGS) $(CPPFLAGS) -c $< -o $@
build/rel/tests/%.o: tests/%.c | build/rel/tests
	$(CC) $(REL_FLAGS) $(CPPFLAGS) -c $< -o $@
build/dbg/tests/%.o: tests/%.c | build/dbg/tests
	$(CC) $(DBG_FLAGS) $(CPPFLAGS) -c $< -o $@

$(BIN_DIR) build/rel build/dbg build/rel/tests build/dbg/tests:
	$(call mkdir_p,$@)

clean:
	$(call rm_rf,build)
	$(call rm_f,$(NETGUARD))
	$(call rm_f,$(NETGUARD_TESTS))
	$(call rm_f,$(NETGUARD_DBG))
	$(call rm_f,$(TESTS_DBG))

-include $(REL_LIB:.o=.d) $(DBG_LIB:.o=.d) $(REL_TEST:.o=.d) $(DBG_TEST:.o=.d) build/rel/main.d build/dbg/main.d
