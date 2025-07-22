# Set install prefix
PREFIX ?= /usr
ROOT_INSTALL_DIR := $(PREFIX)/share/hugin

# Files and directories to install
INSTALL_DIRS := wordlists payloads

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS := -llua -ldl -lm -lpthread -lldap -llber -lldns

# Install target
install:
	@echo "Installing to $(ROOT_INSTALL_DIR)..."
	mkdir -p $(ROOT_INSTALL_DIR)
    # Install wordlists
	for dir in $(INSTALL_DIRS); do \
		cp -r $$dir $(ROOT_INSTALL_DIR)/ ; \
	done
	@echo "Installation complete."

# Uninstall target
uninstall:
	@echo "Removing $(ROOT_INSTALL_DIR)..."
	rm -rf $(ROOT_INSTALL_DIR)
	@echo "Uninstall complete."

SRC := \
    src/main.cpp \
    src/cli/arg_parser.cpp \
    src/engine/scan_engine.cpp \
    src/interfaces/visuals.cpp \
    src/utilities/helper_functions.cpp

OBJ := $(SRC:.cpp=.o)
TARGET := hugin

all:
    @echo "Building project..."
    $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
    @echo "Cleaning build artifacts..."
	rm -f $(OBJ)

.PHONY: all clean install