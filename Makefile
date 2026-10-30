# NetGuard top-level Makefile: delegates to core/Makefile.
#   make          build bin/netguard
#   make test     build and run the C unit tests
#   make debug    ASan/UBSan build + run the C tests under the sanitizers
#   make pytest   run the Python tests (needs: pip install flask pytest)
#   make clean

.PHONY: all debug test clean pytest

all debug test clean:
	$(MAKE) -C core $@

pytest: all
	python -m pytest -q tests_py
