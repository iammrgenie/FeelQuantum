# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Default target executed when no arguments are given to make.
default_target: all
.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/mrgenie/ecelgamal/native

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/mrgenie/ecelgamal/native

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache
.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache
.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/mrgenie/ecelgamal/native/CMakeFiles /home/mrgenie/ecelgamal/native//CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/mrgenie/ecelgamal/native/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean
.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named ecelgamal

# Build rule for target.
ecelgamal: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 ecelgamal
.PHONY : ecelgamal

# fast build rule for target.
ecelgamal/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal.dir/build.make CMakeFiles/ecelgamal.dir/build
.PHONY : ecelgamal/fast

#=============================================================================
# Target rules for targets named ecelgamal-lib

# Build rule for target.
ecelgamal-lib: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 ecelgamal-lib
.PHONY : ecelgamal-lib

# fast build rule for target.
ecelgamal-lib/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal-lib.dir/build.make CMakeFiles/ecelgamal-lib.dir/build
.PHONY : ecelgamal-lib/fast

#=============================================================================
# Target rules for targets named ecelgamal-jni-wrapper

# Build rule for target.
ecelgamal-jni-wrapper: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 ecelgamal-jni-wrapper
.PHONY : ecelgamal-jni-wrapper

# fast build rule for target.
ecelgamal-jni-wrapper/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal-jni-wrapper.dir/build.make CMakeFiles/ecelgamal-jni-wrapper.dir/build
.PHONY : ecelgamal-jni-wrapper/fast

ecelgamal.o: ecelgamal.c.o
.PHONY : ecelgamal.o

# target to build an object file
ecelgamal.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal.dir/build.make CMakeFiles/ecelgamal.dir/ecelgamal.c.o
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal-lib.dir/build.make CMakeFiles/ecelgamal-lib.dir/ecelgamal.c.o
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal-jni-wrapper.dir/build.make CMakeFiles/ecelgamal-jni-wrapper.dir/ecelgamal.c.o
.PHONY : ecelgamal.c.o

ecelgamal.i: ecelgamal.c.i
.PHONY : ecelgamal.i

# target to preprocess a source file
ecelgamal.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal.dir/build.make CMakeFiles/ecelgamal.dir/ecelgamal.c.i
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal-lib.dir/build.make CMakeFiles/ecelgamal-lib.dir/ecelgamal.c.i
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal-jni-wrapper.dir/build.make CMakeFiles/ecelgamal-jni-wrapper.dir/ecelgamal.c.i
.PHONY : ecelgamal.c.i

ecelgamal.s: ecelgamal.c.s
.PHONY : ecelgamal.s

# target to generate assembly for a file
ecelgamal.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal.dir/build.make CMakeFiles/ecelgamal.dir/ecelgamal.c.s
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal-lib.dir/build.make CMakeFiles/ecelgamal-lib.dir/ecelgamal.c.s
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal-jni-wrapper.dir/build.make CMakeFiles/ecelgamal-jni-wrapper.dir/ecelgamal.c.s
.PHONY : ecelgamal.c.s

plm.o: plm.cpp.o
.PHONY : plm.o

# target to build an object file
plm.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal.dir/build.make CMakeFiles/ecelgamal.dir/plm.cpp.o
.PHONY : plm.cpp.o

plm.i: plm.cpp.i
.PHONY : plm.i

# target to preprocess a source file
plm.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal.dir/build.make CMakeFiles/ecelgamal.dir/plm.cpp.i
.PHONY : plm.cpp.i

plm.s: plm.cpp.s
.PHONY : plm.s

# target to generate assembly for a file
plm.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/ecelgamal.dir/build.make CMakeFiles/ecelgamal.dir/plm.cpp.s
.PHONY : plm.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... ecelgamal"
	@echo "... ecelgamal-jni-wrapper"
	@echo "... ecelgamal-lib"
	@echo "... ecelgamal.o"
	@echo "... ecelgamal.i"
	@echo "... ecelgamal.s"
	@echo "... plm.o"
	@echo "... plm.i"
	@echo "... plm.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system
