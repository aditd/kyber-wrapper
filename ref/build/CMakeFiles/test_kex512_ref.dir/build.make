# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.26

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.26.4/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.26.4/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/rdx/kyber/ref

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/rdx/kyber/ref/build

# Include any dependencies generated for this target.
include CMakeFiles/test_kex512_ref.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/test_kex512_ref.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/test_kex512_ref.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test_kex512_ref.dir/flags.make

CMakeFiles/test_kex512_ref.dir/test_kex.o: CMakeFiles/test_kex512_ref.dir/flags.make
CMakeFiles/test_kex512_ref.dir/test_kex.o: /Users/rdx/kyber/ref/test_kex.c
CMakeFiles/test_kex512_ref.dir/test_kex.o: CMakeFiles/test_kex512_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/test_kex512_ref.dir/test_kex.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/test_kex512_ref.dir/test_kex.o -MF CMakeFiles/test_kex512_ref.dir/test_kex.o.d -o CMakeFiles/test_kex512_ref.dir/test_kex.o -c /Users/rdx/kyber/ref/test_kex.c

CMakeFiles/test_kex512_ref.dir/test_kex.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_kex512_ref.dir/test_kex.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/test_kex.c > CMakeFiles/test_kex512_ref.dir/test_kex.i

CMakeFiles/test_kex512_ref.dir/test_kex.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_kex512_ref.dir/test_kex.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/test_kex.c -o CMakeFiles/test_kex512_ref.dir/test_kex.s

CMakeFiles/test_kex512_ref.dir/randombytes.o: CMakeFiles/test_kex512_ref.dir/flags.make
CMakeFiles/test_kex512_ref.dir/randombytes.o: /Users/rdx/kyber/ref/randombytes.c
CMakeFiles/test_kex512_ref.dir/randombytes.o: CMakeFiles/test_kex512_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/test_kex512_ref.dir/randombytes.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/test_kex512_ref.dir/randombytes.o -MF CMakeFiles/test_kex512_ref.dir/randombytes.o.d -o CMakeFiles/test_kex512_ref.dir/randombytes.o -c /Users/rdx/kyber/ref/randombytes.c

CMakeFiles/test_kex512_ref.dir/randombytes.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_kex512_ref.dir/randombytes.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/randombytes.c > CMakeFiles/test_kex512_ref.dir/randombytes.i

CMakeFiles/test_kex512_ref.dir/randombytes.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_kex512_ref.dir/randombytes.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/randombytes.c -o CMakeFiles/test_kex512_ref.dir/randombytes.s

# Object files for target test_kex512_ref
test_kex512_ref_OBJECTS = \
"CMakeFiles/test_kex512_ref.dir/test_kex.o" \
"CMakeFiles/test_kex512_ref.dir/randombytes.o"

# External object files for target test_kex512_ref
test_kex512_ref_EXTERNAL_OBJECTS =

test_kex512_ref: CMakeFiles/test_kex512_ref.dir/test_kex.o
test_kex512_ref: CMakeFiles/test_kex512_ref.dir/randombytes.o
test_kex512_ref: CMakeFiles/test_kex512_ref.dir/build.make
test_kex512_ref: libkyber512_ref.dylib
test_kex512_ref: libfips202_ref.dylib
test_kex512_ref: CMakeFiles/test_kex512_ref.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable test_kex512_ref"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_kex512_ref.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test_kex512_ref.dir/build: test_kex512_ref
.PHONY : CMakeFiles/test_kex512_ref.dir/build

CMakeFiles/test_kex512_ref.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test_kex512_ref.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test_kex512_ref.dir/clean

CMakeFiles/test_kex512_ref.dir/depend:
	cd /Users/rdx/kyber/ref/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/rdx/kyber/ref /Users/rdx/kyber/ref /Users/rdx/kyber/ref/build /Users/rdx/kyber/ref/build /Users/rdx/kyber/ref/build/CMakeFiles/test_kex512_ref.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test_kex512_ref.dir/depend

