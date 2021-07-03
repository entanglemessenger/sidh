# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.6.0)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

#enable_language(ASM)

#file(GLOB sidh-lib_SOURCES "src/main/cpp/random/random.c" "src/main/cpp/sha3/fips202.c" "src/main/cpp/P503/ARM64/fp_arm64.c" "src/main/cpp/P503/P503.c" "src/main/cpp/P503/ARM64/fp_arm64_asm.S")

file(GLOB sidh-lib_SOURCES "src/main/cpp/random/random.c" "src/main/cpp/sha3/fips202.c" "src/main/cpp/P503/generic/fp_generic.c" "src/main/cpp/P503/P503.c")

add_library( # Sets the name of the library.
             sidh-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             ${sidh-lib_SOURCES}  )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

add_definitions( -D_GENERIC_ )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       sidh-lib

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )