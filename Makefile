# Hugin Network Scanner - Enhanced Production Makefile
PREFIX ?= /usr
ROOT_INSTALL_DIR := $(PREFIX)/share/hugin
EXECUTABLE_DIR := $(PREFIX)/local/bin

# Files and directories to install
INSTALL_DIRS := wordlists nmap service-probes

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -DHUGIN_VERSION=\"2.0\" -DPRODUCTION_BUILD
LDFLAGS := -llua5.3 -ldl -lm -lpthread  -lldns -lssl -lcrypto

# Core source files
CORE_SRC := \
	src/main.cpp \
	src/cli/arg_parser.cpp \
	src/engine/scan_engine.cpp \
	src/engine/service_detection.cpp \
	src/interfaces/visuals.cpp \
	src/utilities/nmap_parser.cpp \
	src/utilities/helper_functions.cpp

# Enhanced utilities (Phase 2)
ENHANCED_SRC := \
	src/utilities/enhanced_logging.cpp \
	src/utilities/output_formats.cpp

# Distributed scanning (Phase 3)
DISTRIBUTED_SRC := \
	src/distributed/scan_coordinator.cpp \
	src/distributed/protocol_handler.cpp \
	src/distributed/load_balancer.cpp

# Web interface (Phase 3)
WEB_SRC := \
	web/hugin_web_server.cpp \
	web/rest_api.cpp \
	web/websocket_handler.cpp \
	web/dashboard.cpp

# Authentication system removed - not needed for this implementation

# Test files
TEST_SRC := \
	tests/test_service_detection.cpp \
	tests/test_output_formats.cpp \
	tests/test_distributed.cpp

# All source files
SRC := $(CORE_SRC) $(ENHANCED_SRC)
OBJ := $(SRC:.cpp=.o)
TARGET := hugin

# Optional components (can be disabled)
ENABLE_DISTRIBUTED ?= 1
ENABLE_WEB ?= 1
ENABLE_AUTH ?= 0

ifeq ($(ENABLE_DISTRIBUTED),1)
	SRC += $(DISTRIBUTED_SRC)
	CXXFLAGS += -DENABLE_DISTRIBUTED
endif

ifeq ($(ENABLE_WEB),1)
	SRC += $(WEB_SRC)
	CXXFLAGS += -DENABLE_WEB
	LDFLAGS += -lmicrohttpd
endif

# Authentication components removed

# Build targets
.PHONY: all clean install uninstall test test-unit test-integration benchmark docs

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "Linking $(TARGET)..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

%.o: %.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Enhanced build options
debug: CXXFLAGS += -g -DDEBUG -O0
debug: $(TARGET)

release: CXXFLAGS += -O3 -DNDEBUG -flto
release: $(TARGET)

profile: CXXFLAGS += -pg -O2
profile: LDFLAGS += -pg
profile: $(TARGET)

# Static analysis
static-analysis:
	@echo "Running static analysis..."
	cppcheck --enable=all --std=c++17 src/ web/ tests/
	clang-tidy src/*.cpp src/*/*.cpp -checks=*

# Code formatting
format:
	@echo "Formatting code..."
	find src web tests -name "*.cpp" -o -name "*.h" | xargs clang-format -i

# Testing
test: test-unit test-integration

test-unit: $(TARGET)
	@echo "Running unit tests..."
	$(CXX) $(CXXFLAGS) -o test_runner $(TEST_SRC) $(filter-out src/main.o,$(OBJ)) $(LDFLAGS)
	./test_runner

test-integration: $(TARGET)
	@echo "Running integration tests..."
	./tests/integration_test.sh

# Performance benchmarking
benchmark: $(TARGET)
	@echo "Running performance benchmarks..."
	./tests/benchmark.sh

# Documentation generation
docs:
	@echo "Generating documentation..."
	doxygen Doxyfile
	@echo "Documentation generated in docs/"

# Installation
install: $(TARGET)
	@echo "Installing Hugin..."
	install -d $(DESTDIR)$(EXECUTABLE_DIR)
	install -m 755 $(TARGET) $(DESTDIR)$(EXECUTABLE_DIR)/
	install -d $(DESTDIR)$(ROOT_INSTALL_DIR)
	cp -r $(INSTALL_DIRS) $(DESTDIR)$(ROOT_INSTALL_DIR)/
	
	# Install web interface files if enabled
ifeq ($(ENABLE_WEB),1)
	install -d $(DESTDIR)$(ROOT_INSTALL_DIR)/web
	cp -r web/static web/templates $(DESTDIR)$(ROOT_INSTALL_DIR)/web/
endif
	
	# Install configuration files
	install -d $(DESTDIR)/etc/hugin
	cp config/*.conf $(DESTDIR)/etc/hugin/ 2>/dev/null || true
	
	# Install systemd service file
	install -d $(DESTDIR)/etc/systemd/system
	cp scripts/hugin.service $(DESTDIR)/etc/systemd/system/ 2>/dev/null || true
	
	@echo "Installation complete."
	@echo "Run 'sudo systemctl enable hugin' to enable the service."

uninstall:
	@echo "Uninstalling Hugin..."
	rm -f $(DESTDIR)$(EXECUTABLE_DIR)/$(TARGET)
	rm -rf $(DESTDIR)$(ROOT_INSTALL_DIR)
	rm -rf $(DESTDIR)/etc/hugin
	rm -f $(DESTDIR)/etc/systemd/system/hugin.service
	@echo "Uninstallation complete."

# Docker support
docker-build:
	@echo "Building Docker image..."
	docker build -t hugin:latest .

docker-run:
	@echo "Running Hugin in Docker..."
	docker run -it --rm --cap-add=NET_RAW hugin:latest

# Package creation
package-deb:
	@echo "Creating Debian package..."
	./scripts/build_deb.sh

package-rpm:
	@echo "Creating RPM package..."
	./scripts/build_rpm.sh

# Development helpers
dev-setup:
	@echo "Setting up development environment..."
	sudo apt update
	sudo apt install -y build-essential g++ libssl-dev liblua5.3-dev libldns-dev
	sudo apt install -y libmicrohttpd-dev cppcheck clang-tidy clang-format doxygen
	@echo "Development environment ready."

# Dependency checking
check-deps:
	@echo "Checking dependencies..."
	@which g++ > /dev/null || (echo "g++ not found" && exit 1)
	@pkg-config --exists lua5.3 || (echo "lua5.3 development files not found" && exit 1)
	@pkg-config --exists openssl || (echo "OpenSSL development files not found" && exit 1)
	@pkg-config --exists ldap || (echo "LDAP development files not found" && exit 1)
	@echo "All dependencies satisfied."

# Clean targets
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(OBJ) $(TARGET) test_runner
	rm -f src/*.o src/*/*.o web/*.o tests/*.o
	rm -rf docs/html docs/latex
	@echo "Build artifacts were cleaned."

clean-all: clean
	@echo "Cleaning all generated files..."
	rm -rf build/ dist/ *.deb *.rpm
	rm -f *.log *.prof gmon.out
	@echo "All generated files cleaned."

# Help target
help:
	@echo "Hugin Network Scanner - Build System"
	@echo "===================================="
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build the main executable (default)"
	@echo "  debug            - Build with debug symbols"
	@echo "  release          - Build optimized release version"
	@echo "  profile          - Build with profiling support"
	@echo "  test             - Run all tests"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  benchmark        - Run performance benchmarks"
	@echo "  static-analysis  - Run static code analysis"
	@echo "  format           - Format source code"
	@echo "  docs             - Generate documentation"
	@echo "  install          - Install Hugin system-wide"
	@echo "  uninstall        - Remove Hugin from system"
	@echo "  docker-build     - Build Docker image"
	@echo "  docker-run       - Run Hugin in Docker container"
	@echo "  package-deb      - Create Debian package"
	@echo "  package-rpm      - Create RPM package"
	@echo "  dev-setup        - Set up development environment"
	@echo "  check-deps       - Check build dependencies"
	@echo "  clean            - Clean build artifacts"
	@echo "  clean-all        - Clean all generated files"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Build options:"
	@echo "  ENABLE_DISTRIBUTED=0  - Disable distributed scanning"
	@echo "  ENABLE_WEB=0          - Disable web interface"
	@echo ""
	@echo "Examples:"
	@echo "  make                   - Build with all features"
	@echo "  make ENABLE_WEB=0      - Build without web interface"
	@echo "  make release           - Build optimized version"
	@echo "  make test              - Build and run tests"

# Version information
version:
	@echo "Hugin Network Scanner v2.0"
	@echo "Production-Ready Enterprise Edition"
	@echo "Build date: $(shell date)"
	@echo "Compiler: $(shell $(CXX) --version | head -n1)"
