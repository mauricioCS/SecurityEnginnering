# Makefile 06 - User flags 

# Copyright (c) 2015, Monaco F. J. <monaco@icmc.usp.br>
#
# This file is part of POSIXeg.
#
# POSIXeg is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Objects

OBJECTS = obj/main.o obj/eml-rsa.o

BIN = main

# Maintainer flags

CPP_FLAGS = -I./include -std=c++11
C_FLAGS = -Wall
LD_FLAGS = -lgmpxx -lgmp
CC = g++

# Default target

all: $(BIN)

# Binary

$(BIN) : $(OBJECTS)
	$(CC) $^ $(LD_FLAGS) $(LDFLAGS) -o $@

# Pattern rule for object-source dependences

obj/%.o : src/%.cpp
	$(CC) $(CPP_FLAGS) $(CPPFLAGS) $(C_FLAGS) $(CFLAGS) -c $< -o $@

# Automatic object-header dependences
makefiles = $(OBJECTS:obj/%.o=obj/%.d) 
include $(makefiles)

obj/%.d : src/%.cpp
	$(CC) $(CPP_FLAGS) $(CPPFLAGS) -c $<  -MM -MT '$(<:.cpp=.o) $@' $< > $@

# Cleaning

.PHONY : clean

clean:
	find . -name "*.o" -exec rm -f {} \;
	find . -name "$(BIN)" -exec rm -f {} \;
	find . -name "*.d" -exec rm -f {} \;
	rm -f *~ \#*
