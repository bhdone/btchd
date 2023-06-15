set(CMAKE_SYSTEM_NAME macOSX)
# set(TOOLCHAIN_PREFIX "/workspace/depends/x86_64-apple-darwin14/native/bin/clang -target x86_64-apple-darwin14 -mmacosx-version-min=10.10 --sysroot /workspace/depends/SDKs/MacOSX10.11.sdk -mlinker-version=253.9 supports -fno-rtti -fno-exceptions")

# cross compilers to use for C and C++
set(SDK_PATH "/workspace/depends/SDKs")
set(OSX_MIN_VERSION "10.10")
set(OSX_SDK_VERSION "10.11")

set(LD64_VERSION "253.9")

set(HOST_NAME "x86_64-apple-darwin14")
set(OSX_SDK "${SDK_PATH}/MacOSX${OSX_SDK_VERSION}.sdk")

set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

set(CMAKE_C_FLAGS "-target ${HOST_NAME} -mmacosx-version-min=${OSX_MIN_VERSION} --sysroot ${OSX_SDK} -mlinker-version=${LD64_VERSION}")
set(CMAKE_CXX_FLAGS "-target ${HOST_NAME} -mmacosx-version-min=${OSX_MIN_VERSION} --sysroot ${OSX_SDK} -mlinker-version=${LD64_VERSION} -stdlib=libc++")

set(CMAKE_CXX_STANDARD 14)

set(darwin_native_toolchain native_cctools)

# target environment on the build host system
#   set 1st to dir with the cross compiler's C/C++ headers/libs
# set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})

# modify default behavior of FIND_XXX() commands to
# search for headers/libs in the target environment and
# search for programs in the build host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# build_darwin_CC:=$(shell xcrun -f clang)
# build_darwin_CXX:=$(shell xcrun -f clang++)
# build_darwin_AR:=$(shell xcrun -f ar)
# build_darwin_RANLIB:=$(shell xcrun -f ranlib)
# build_darwin_STRIP:=$(shell xcrun -f strip)
# build_darwin_OTOOL:=$(shell xcrun -f otool)
# build_darwin_NM:=$(shell xcrun -f nm)
# build_darwin_INSTALL_NAME_TOOL:=$(shell xcrun -f install_name_tool)
# build_darwin_SHA256SUM=shasum -a 256
# build_darwin_DOWNLOAD=curl --location --fail --connect-timeout $(DOWNLOAD_CONNECT_TIMEOUT) --retry $(DOWNLOAD_RETRIES) -o
#
# #darwin host on darwin builder. overrides darwin host preferences.
# darwin_CC=$(shell xcrun -f clang) -mmacosx-version-min=$(OSX_MIN_VERSION)
# darwin_CXX:=$(shell xcrun -f clang++) -mmacosx-version-min=$(OSX_MIN_VERSION) -stdlib=libc++
# darwin_AR:=$(shell xcrun -f ar)
# darwin_RANLIB:=$(shell xcrun -f ranlib)
# darwin_STRIP:=$(shell xcrun -f strip)
# darwin_LIBTOOL:=$(shell xcrun -f libtool)
# darwin_OTOOL:=$(shell xcrun -f otool)
# darwin_NM:=$(shell xcrun -f nm)
# darwin_INSTALL_NAME_TOOL:=$(shell xcrun -f install_name_tool)
# darwin_native_toolchain=
#
