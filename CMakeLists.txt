cmake_minimum_required(VERSION 3.22)
project(enchant_hook_probe LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

FetchContent_Declare(
    preloader_android
    GIT_REPOSITORY https://github.com/LiteLDev/preloader-android.git
    GIT_TAG 0.2.2)
FetchContent_MakeAvailable(preloader_android)

FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 11.2.0)
set(FMT_DOC OFF CACHE BOOL "" FORCE)
set(FMT_TEST OFF CACHE BOOL "" FORCE)
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(fmt)

find_library(LL_LOG_LIB log)

add_library(hook_probe SHARED hook_probe.cpp)
set_target_properties(hook_probe PROPERTIES OUTPUT_NAME "hook_probe")
target_compile_options(hook_probe PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
target_link_libraries(hook_probe PRIVATE preloader fmt::fmt)
if(LL_LOG_LIB)
    target_link_libraries(hook_probe PRIVATE ${LL_LOG_LIB})
endif()
