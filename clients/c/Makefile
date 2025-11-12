CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
LDFLAGS = -lsodium
TEST_CFLAGS = $(CFLAGS) -DMUMBOJUMBO_TEST_BUILD

TARGET = mumbojumbo-client
TEST_TARGET = test-mumbojumbo-client
SOURCES = mumbojumbo-client.c
TEST_SOURCES = test-mumbojumbo-client.c
OBJECTS = $(SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
HEADER = mumbojumbo-client.h

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS specific flags (Homebrew libsodium)
    CFLAGS += -I/opt/homebrew/include
    LDFLAGS += -L/opt/homebrew/lib
endif

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_TARGET): test-mumbojumbo-client.o mumbojumbo-client-test.o
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HEADER)
	$(CC) $(CFLAGS) -c $< -o $@

test-mumbojumbo-client.o: test-mumbojumbo-client.c $(HEADER)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

mumbojumbo-client-test.o: mumbojumbo-client.c $(HEADER)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(OBJECTS) $(TEST_OBJECTS) mumbojumbo-client-test.o

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)
