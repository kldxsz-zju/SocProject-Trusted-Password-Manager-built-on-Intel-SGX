SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
SEAL_POLICY ?= MRENCLAVE

CXX := g++
SGX_ARCH := x64
SGX_COMMON_FLAGS := -m64
APP_CXXFLAGS := $(SGX_COMMON_FLAGS) -O2 -Wall -Wextra -Wpedantic -std=c++17 \
  -IApp -IInclude -I$(SGX_SDK)/include
APP_CFLAGS := $(filter-out -std=c++17,$(APP_CXXFLAGS))
APP_LDFLAGS := $(SGX_COMMON_FLAGS) -L$(SGX_SDK)/lib64
ENCLAVE_CXXFLAGS := $(SGX_COMMON_FLAGS) -O2 -Wall -Wextra -Wpedantic -std=c++17 \
  -nostdinc -fvisibility=hidden -fpie -fstack-protector -IEnclave -IInclude \
  -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx
ENCLAVE_CFLAGS := $(filter-out -std=c++17,$(ENCLAVE_CXXFLAGS))
ENCLAVE_LDFLAGS := $(SGX_COMMON_FLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
  -L$(SGX_SDK)/lib64 -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
  -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
  -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
  -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
  -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
  -Wl,--version-script=Enclave/Enclave.lds

ifeq ($(SGX_MODE),HW)
  URTS_LIB := sgx_urts
  ENCLAVE_LDFLAGS := $(subst -lsgx_trts_sim,-lsgx_trts,$(ENCLAVE_LDFLAGS))
  ENCLAVE_LDFLAGS := $(subst -lsgx_tservice_sim,-lsgx_tservice,$(ENCLAVE_LDFLAGS))
else
  URTS_LIB := sgx_urts_sim
endif
ifeq ($(SGX_DEBUG),1)
  APP_CXXFLAGS += -g -DSGX_DEBUG
  APP_CFLAGS += -g -DSGX_DEBUG
  ENCLAVE_CXXFLAGS += -g -DSGX_DEBUG
  ENCLAVE_CFLAGS += -g -DSGX_DEBUG
endif
ifeq ($(SEAL_POLICY),MRSIGNER)
  ENCLAVE_CXXFLAGS += -DVAULT_POLICY_MRSIGNER
else ifneq ($(SEAL_POLICY),MRENCLAVE)
  $(error SEAL_POLICY must be MRENCLAVE or MRSIGNER)
endif

.PHONY: all clean run
all: app enclave.signed.so

App/Enclave_u.c: Enclave/Enclave.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --untrusted $< --search-path Enclave --search-path $(SGX_SDK)/include --untrusted-dir App
App/Enclave_u.h: App/Enclave_u.c
	@test -f $@

Enclave/Enclave_t.c: Enclave/Enclave.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --trusted $< --search-path Enclave --search-path $(SGX_SDK)/include --trusted-dir Enclave
Enclave/Enclave_t.h: Enclave/Enclave_t.c
	@test -f $@

App/Enclave_u.o: App/Enclave_u.c App/Enclave_u.h
	$(CC) $(APP_CFLAGS) -c $< -o $@
App/App.o: App/App.cpp App/Enclave_u.h Include/VaultTypes.h
	$(CXX) $(APP_CXXFLAGS) -c $< -o $@
app: App/App.o App/Enclave_u.o
	$(CXX) $^ $(APP_LDFLAGS) -l$(URTS_LIB) -lpthread -o $@

Enclave/Enclave_t.o: Enclave/Enclave_t.c Enclave/Enclave_t.h
	$(CC) $(ENCLAVE_CFLAGS) -c $< -o $@
Enclave/Enclave.o: Enclave/Enclave.cpp Enclave/Enclave_t.h Include/VaultTypes.h
	$(CXX) $(ENCLAVE_CXXFLAGS) -c $< -o $@
enclave.so: Enclave/Enclave.o Enclave/Enclave_t.o
	$(CXX) $^ $(ENCLAVE_LDFLAGS) -o $@

Enclave/Enclave_private.pem:
	openssl genrsa -3 -out $@ 3072
enclave.signed.so: enclave.so Enclave/Enclave_private.pem Enclave/Enclave.config.xml
	$(SGX_SDK)/bin/x64/sgx_sign sign -key Enclave/Enclave_private.pem -enclave enclave.so -out $@ -config Enclave/Enclave.config.xml

run: all
	./app
clean:
	rm -f app enclave.so enclave.signed.so App/*.o Enclave/*.o App/Enclave_u.* Enclave/Enclave_t.*
