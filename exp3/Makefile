CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c++17

.PHONY: all clean
all: witness_server witness_client

witness_server: witness_server.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

witness_client: witness_client.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f witness_server witness_client witness_versions.db *.log *.sealed

