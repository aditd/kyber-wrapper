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
include CMakeFiles/kyber512_90s_ref.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/kyber512_90s_ref.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/kyber512_90s_ref.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/kyber512_90s_ref.dir/flags.make

CMakeFiles/kyber512_90s_ref.dir/kex.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/kex.o: /Users/rdx/kyber/ref/kex.c
CMakeFiles/kyber512_90s_ref.dir/kex.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/kyber512_90s_ref.dir/kex.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/kex.o -MF CMakeFiles/kyber512_90s_ref.dir/kex.o.d -o CMakeFiles/kyber512_90s_ref.dir/kex.o -c /Users/rdx/kyber/ref/kex.c

CMakeFiles/kyber512_90s_ref.dir/kex.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/kex.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/kex.c > CMakeFiles/kyber512_90s_ref.dir/kex.i

CMakeFiles/kyber512_90s_ref.dir/kex.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/kex.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/kex.c -o CMakeFiles/kyber512_90s_ref.dir/kex.s

CMakeFiles/kyber512_90s_ref.dir/kem.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/kem.o: /Users/rdx/kyber/ref/kem.c
CMakeFiles/kyber512_90s_ref.dir/kem.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/kyber512_90s_ref.dir/kem.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/kem.o -MF CMakeFiles/kyber512_90s_ref.dir/kem.o.d -o CMakeFiles/kyber512_90s_ref.dir/kem.o -c /Users/rdx/kyber/ref/kem.c

CMakeFiles/kyber512_90s_ref.dir/kem.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/kem.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/kem.c > CMakeFiles/kyber512_90s_ref.dir/kem.i

CMakeFiles/kyber512_90s_ref.dir/kem.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/kem.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/kem.c -o CMakeFiles/kyber512_90s_ref.dir/kem.s

CMakeFiles/kyber512_90s_ref.dir/indcpa.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/indcpa.o: /Users/rdx/kyber/ref/indcpa.c
CMakeFiles/kyber512_90s_ref.dir/indcpa.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/kyber512_90s_ref.dir/indcpa.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/indcpa.o -MF CMakeFiles/kyber512_90s_ref.dir/indcpa.o.d -o CMakeFiles/kyber512_90s_ref.dir/indcpa.o -c /Users/rdx/kyber/ref/indcpa.c

CMakeFiles/kyber512_90s_ref.dir/indcpa.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/indcpa.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/indcpa.c > CMakeFiles/kyber512_90s_ref.dir/indcpa.i

CMakeFiles/kyber512_90s_ref.dir/indcpa.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/indcpa.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/indcpa.c -o CMakeFiles/kyber512_90s_ref.dir/indcpa.s

CMakeFiles/kyber512_90s_ref.dir/polyvec.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/polyvec.o: /Users/rdx/kyber/ref/polyvec.c
CMakeFiles/kyber512_90s_ref.dir/polyvec.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/kyber512_90s_ref.dir/polyvec.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/polyvec.o -MF CMakeFiles/kyber512_90s_ref.dir/polyvec.o.d -o CMakeFiles/kyber512_90s_ref.dir/polyvec.o -c /Users/rdx/kyber/ref/polyvec.c

CMakeFiles/kyber512_90s_ref.dir/polyvec.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/polyvec.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/polyvec.c > CMakeFiles/kyber512_90s_ref.dir/polyvec.i

CMakeFiles/kyber512_90s_ref.dir/polyvec.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/polyvec.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/polyvec.c -o CMakeFiles/kyber512_90s_ref.dir/polyvec.s

CMakeFiles/kyber512_90s_ref.dir/poly.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/poly.o: /Users/rdx/kyber/ref/poly.c
CMakeFiles/kyber512_90s_ref.dir/poly.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/kyber512_90s_ref.dir/poly.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/poly.o -MF CMakeFiles/kyber512_90s_ref.dir/poly.o.d -o CMakeFiles/kyber512_90s_ref.dir/poly.o -c /Users/rdx/kyber/ref/poly.c

CMakeFiles/kyber512_90s_ref.dir/poly.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/poly.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/poly.c > CMakeFiles/kyber512_90s_ref.dir/poly.i

CMakeFiles/kyber512_90s_ref.dir/poly.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/poly.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/poly.c -o CMakeFiles/kyber512_90s_ref.dir/poly.s

CMakeFiles/kyber512_90s_ref.dir/ntt.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/ntt.o: /Users/rdx/kyber/ref/ntt.c
CMakeFiles/kyber512_90s_ref.dir/ntt.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/kyber512_90s_ref.dir/ntt.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/ntt.o -MF CMakeFiles/kyber512_90s_ref.dir/ntt.o.d -o CMakeFiles/kyber512_90s_ref.dir/ntt.o -c /Users/rdx/kyber/ref/ntt.c

CMakeFiles/kyber512_90s_ref.dir/ntt.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/ntt.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/ntt.c > CMakeFiles/kyber512_90s_ref.dir/ntt.i

CMakeFiles/kyber512_90s_ref.dir/ntt.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/ntt.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/ntt.c -o CMakeFiles/kyber512_90s_ref.dir/ntt.s

CMakeFiles/kyber512_90s_ref.dir/cbd.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/cbd.o: /Users/rdx/kyber/ref/cbd.c
CMakeFiles/kyber512_90s_ref.dir/cbd.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/kyber512_90s_ref.dir/cbd.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/cbd.o -MF CMakeFiles/kyber512_90s_ref.dir/cbd.o.d -o CMakeFiles/kyber512_90s_ref.dir/cbd.o -c /Users/rdx/kyber/ref/cbd.c

CMakeFiles/kyber512_90s_ref.dir/cbd.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/cbd.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/cbd.c > CMakeFiles/kyber512_90s_ref.dir/cbd.i

CMakeFiles/kyber512_90s_ref.dir/cbd.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/cbd.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/cbd.c -o CMakeFiles/kyber512_90s_ref.dir/cbd.s

CMakeFiles/kyber512_90s_ref.dir/reduce.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/reduce.o: /Users/rdx/kyber/ref/reduce.c
CMakeFiles/kyber512_90s_ref.dir/reduce.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/kyber512_90s_ref.dir/reduce.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/reduce.o -MF CMakeFiles/kyber512_90s_ref.dir/reduce.o.d -o CMakeFiles/kyber512_90s_ref.dir/reduce.o -c /Users/rdx/kyber/ref/reduce.c

CMakeFiles/kyber512_90s_ref.dir/reduce.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/reduce.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/reduce.c > CMakeFiles/kyber512_90s_ref.dir/reduce.i

CMakeFiles/kyber512_90s_ref.dir/reduce.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/reduce.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/reduce.c -o CMakeFiles/kyber512_90s_ref.dir/reduce.s

CMakeFiles/kyber512_90s_ref.dir/verify.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/verify.o: /Users/rdx/kyber/ref/verify.c
CMakeFiles/kyber512_90s_ref.dir/verify.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/kyber512_90s_ref.dir/verify.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/verify.o -MF CMakeFiles/kyber512_90s_ref.dir/verify.o.d -o CMakeFiles/kyber512_90s_ref.dir/verify.o -c /Users/rdx/kyber/ref/verify.c

CMakeFiles/kyber512_90s_ref.dir/verify.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/verify.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/verify.c > CMakeFiles/kyber512_90s_ref.dir/verify.i

CMakeFiles/kyber512_90s_ref.dir/verify.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/verify.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/verify.c -o CMakeFiles/kyber512_90s_ref.dir/verify.s

CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o: CMakeFiles/kyber512_90s_ref.dir/flags.make
CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o: /Users/rdx/kyber/ref/symmetric-aes.c
CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o: CMakeFiles/kyber512_90s_ref.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building C object CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o -MF CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o.d -o CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o -c /Users/rdx/kyber/ref/symmetric-aes.c

CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/rdx/kyber/ref/symmetric-aes.c > CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.i

CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/rdx/kyber/ref/symmetric-aes.c -o CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.s

# Object files for target kyber512_90s_ref
kyber512_90s_ref_OBJECTS = \
"CMakeFiles/kyber512_90s_ref.dir/kex.o" \
"CMakeFiles/kyber512_90s_ref.dir/kem.o" \
"CMakeFiles/kyber512_90s_ref.dir/indcpa.o" \
"CMakeFiles/kyber512_90s_ref.dir/polyvec.o" \
"CMakeFiles/kyber512_90s_ref.dir/poly.o" \
"CMakeFiles/kyber512_90s_ref.dir/ntt.o" \
"CMakeFiles/kyber512_90s_ref.dir/cbd.o" \
"CMakeFiles/kyber512_90s_ref.dir/reduce.o" \
"CMakeFiles/kyber512_90s_ref.dir/verify.o" \
"CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o"

# External object files for target kyber512_90s_ref
kyber512_90s_ref_EXTERNAL_OBJECTS =

libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/kex.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/kem.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/indcpa.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/polyvec.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/poly.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/ntt.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/cbd.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/reduce.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/verify.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/symmetric-aes.o
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/build.make
libkyber512_90s_ref.dylib: CMakeFiles/kyber512_90s_ref.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/rdx/kyber/ref/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Linking C shared library libkyber512_90s_ref.dylib"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/kyber512_90s_ref.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/kyber512_90s_ref.dir/build: libkyber512_90s_ref.dylib
.PHONY : CMakeFiles/kyber512_90s_ref.dir/build

CMakeFiles/kyber512_90s_ref.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/kyber512_90s_ref.dir/cmake_clean.cmake
.PHONY : CMakeFiles/kyber512_90s_ref.dir/clean

CMakeFiles/kyber512_90s_ref.dir/depend:
	cd /Users/rdx/kyber/ref/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/rdx/kyber/ref /Users/rdx/kyber/ref /Users/rdx/kyber/ref/build /Users/rdx/kyber/ref/build /Users/rdx/kyber/ref/build/CMakeFiles/kyber512_90s_ref.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/kyber512_90s_ref.dir/depend

