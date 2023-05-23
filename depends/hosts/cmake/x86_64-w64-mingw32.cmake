# Sample toolchain file for building for Windows from an Ubuntu Linux system.
#
# Typical usage:
#    *) install cross compiler: `sudo apt-get install mingw-w64 g++-mingw-w64`
#    *) cd build
#    *) cmake -DCMAKE_TOOLCHAIN_FILE=~/Toolchain-Ubuntu-mingw32.cmake ..

set(CMAKE_SYSTEM_NAME Windows)
set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)

# specify the cross compiler
set (CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
set (CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
set (CMAKE_AS_COMPILER ${TOOLCHAIN_PREFIX}-as)

# where is the target environment
set (CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})

# search for programs in the build host directories
set (CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
set (CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set (CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Make sure Qt can be detected by CMake
set (QT_BINARY_DIR /usr/${TOOLCHAIN_PREFIX}/bin /usr/bin)
set (QT_INCLUDE_DIRS_NO_SYSTEM ON)

# set the resource compiler (RHBZ #652435)
set (CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)
set (CMAKE_MC_COMPILER ${TOOLCHAIN_PREFIX}-windmc)

# override boost thread component suffix as mingw-w64-boost is compiled with threadapi=win32
set (Boost_THREADAPI win32)

# These are needed for compiling lapack (RHBZ #753906)
set (CMAKE_Fortran_COMPILER ${TOOLCHAIN_PREFIX}-gfortran)
set (CMAKE_AR:FILEPATH ${TOOLCHAIN_PREFIX}-ar)
set (CMAKE_RANLIB:FILEPATH ${TOOLCHAIN_PREFIX}-ranlib)
