# Set install prefix
PREFIX ?= /usr
ROOT_INSTALL_DIR := $(PREFIX)/share/hugin
EXECUTABLE_DIR := $(PREFIX)/local/bin

# Files and directories to install
INSTALL_DIRS := wordlists nmap

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS := -llua -ldl -lm -lpthread -lldap -llber -lldns

SRC := \
	src/main.cpp \
	src/cli/arg_parser.cpp \
	src/engine/scan_engine.cpp \
	src/interfaces/visuals.cpp \
	src/utilities/nmap_parser.cpp \
	src/utilities/helper_functions.cpp

OBJ := $(SRC:.cpp=.o)
TARGET := hugin

# Default build target
all: $(TARGET)
	@echo "Build complete: $(TARGET)"

# Link binary
$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Compile sources
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(OBJ) $(TARGET)
	@echo "Build artifacts were cleaned."

# Install target
install: $(TARGET)
	@echo "Installing to $(ROOT_INSTALL_DIR)..."
	mkdir -p "$(ROOT_INSTALL_DIR)"
	install -m 755 $(TARGET) "$(EXECUTABLE_DIR)/$(TARGET)"
	@for dir in $(INSTALL_DIRS); do \
		if [ -d "$$dir" ]; then \
			cp -r "$$dir" "$(ROOT_INSTALL_DIR)/"; \
		else \
			echo "Warning: directory $$dir not found"; \
		fi \
	done
	@echo "Installation complete."

# Uninstall target
uninstall:
	@echo "Removing $(ROOT_INSTALL_DIR) and $(EXECUTABLE_DIR)/$(TARGET)..."
	rm -rf "$(ROOT_INSTALL_DIR)"
	rm -f "$(EXECUTABLE_DIR)/$(TARGET)"
	@echo "Uninstall complete."

# Debug flag adds -DDEBUG for conditional compilation
ifeq ($(MAKECMDGOALS),debug)
    CXXFLAGS += -DDEBUG -g
endif

# Debug target
debug: $(TARGET)
	@echo "Installing DEBUG version to $(ROOT_INSTALL_DIR)..."
	mkdir -p "$(ROOT_INSTALL_DIR)"
	install -m 755 $(TARGET) "$(EXECUTABLE_DIR)/$(TARGET)"
	@for dir in $(INSTALL_DIRS); do \
		if [ -d "$$dir" ]; then \
			cp -r "$$dir" "$(ROOT_INSTALL_DIR)/"; \
		else \
			echo "Warning: directory $$dir not found"; \
		fi \
	done
	@echo "Installation complete."

.PHONY: all clean install uninstall