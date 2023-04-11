cmake_minimum_required (VERSION 3.5.1)


project(HomomorphicBillings CXX)
#set(CMAKE_CXX_STANDARD 11) # use C++11
set(CMAKE_CXX_STANDARD 17)  # use C++17
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE)

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
### add directories for other OpenFHE modules as needed for your project

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

link_directories( ../tiny-aes )

### ADD YOUR FILES HERE

### add libraries (files with no main function that are usually compiled into .o files)
add_library( utils_ckks utils_ckks.cpp )
add_library( vectorutils vectorutils.hpp )
set_target_properties(vectorutils PROPERTIES LINKER_LANGUAGE CXX)
add_library( csprng csprng.h csprng.cpp )
target_compile_options( csprng PRIVATE  -Wall -msse2 -msse -maes  -O0 -march=native  )

# add tiny-AES
add_custom_target(
    libaes
    COMMAND make
    WORKING_DIRECTORY ../tiny-aes/
)


### add executables
# addind setup_and_billing
add_executable( setup_and_billing client_setup_and_server_billing.cpp )
target_link_libraries( setup_and_billing utils_ckks )
target_link_libraries( setup_and_billing vectorutils )
# addind sharing_total_deviation
add_executable( sharing_total_deviation sharing_total_deviation.cpp )
target_link_libraries( sharing_total_deviation csprng )
add_dependencies(sharing_total_deviation libaes )
target_compile_options( sharing_total_deviation PRIVATE  -O3 ../tiny-aes/aes.o  )
target_link_options( sharing_total_deviation PRIVATE  ../tiny-aes/aes.o  )
