# Compiler
CXX := gcc

# Target
TARGET := puntos 

# Source files
SRCS := puntos.c 

# Header files (for dependency tracking)
HDRS := 

# Compiler flags
# CFLAGS := -O3 -std=c17 -march=native \
#             -Wall -Wextra -Wno-unused-parameter \
# 			-I/opt/homebrew/opt/libomp/include \
#     -L/opt/homebrew/opt/libomp/lib \
#     -lomp \

CFLAGS := -O3 -std=c17 -march=native -fopenmp -Ofast -funroll-loops -flto

# Linker flags (empty but kept for clarity)
LDFLAGS :=

# Default rule
all: $(TARGET)

# Link
$(TARGET): $(SRCS) $(HDRS)
	$(CXX) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

# Clean
clean:
	rm -f $(TARGET)

.PHONY: all clean
