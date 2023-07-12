CXX = g++ 

LDFLAGS = -L/usr/local/opt/openssl/lib
LDLIBS = -lssl -lcrypto

# list of source files
SOURCES := $(wildcard *.cpp)

# list of object files
OBJECTS := $(SOURCES:.cpp=.o)

# executable file
EXECUTABLE := main

# default target
all : $(EXECUTABLE)

$(EXECUTABLE) : $(OBJECTS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)

# compile all source file into object file
%.o : %.cpp
	$(CXX) -o $@ -c $<

.PHONY: clean
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)

