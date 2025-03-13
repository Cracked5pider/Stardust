cmake_minimum_required( VERSION 3.20 )
project( stardust )

set( CMAKE_CXX_STANDARD 20 )
set( CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++ )

#
# set the header & source files
include_directories( include )
file( GLOB SOURCE
    src/*.cc
    test/*.cc
)

add_compile_definitions( DEBUG )
add_executable( stardust-exe ${SOURCE} )