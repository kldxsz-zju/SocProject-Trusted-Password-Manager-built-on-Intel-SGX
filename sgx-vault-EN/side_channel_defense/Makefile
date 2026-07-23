CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c++17

.PHONY: all test clean

all: test_oblivious_core

test_oblivious_core: ProtectedVaultCore.cpp ProtectedVaultCore.h test_oblivious_core.cpp
	$(CXX) $(CXXFLAGS) ProtectedVaultCore.cpp test_oblivious_core.cpp -o $@

test: test_oblivious_core
	./test_oblivious_core

clean:
	rm -f test_oblivious_core
