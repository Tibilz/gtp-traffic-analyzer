# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -pthread

# Source and header files (find all .c files in the src/ directory)
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, build/%.o, $(SRC))

# Output directory
BUILD_DIR = build

# Executable name
TARGET = $(BUILD_DIR)/monitor

# Rule to create the build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Rule to compile the program
all: $(BUILD_DIR) $(TARGET)

# Rule to build the target
$(TARGET): $(OBJ)
	@echo "Building target: $(TARGET)"
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)
	@echo "Target built: $(TARGET)"

# Rule to compile each object file
build/%.o: src/%.c
	@echo "Compiling: $< -> $@"
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean up the build directory
clean:
	rm -rf $(BUILD_DIR)
