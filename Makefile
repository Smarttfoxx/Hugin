CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS := -llua -ldl -lm -lpthread -lldap -llber -lldns

SRC := \
    src/main.cpp \
    src/cli/arg_parser.cpp \
    src/engine/scan_engine.cpp \
    src/interfaces/visuals.cpp \
    src/utilities/helper_functions.cpp

OBJ := $(SRC:.cpp=.o)
TARGET := hugin

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
