cmake_minimum_required( VERSION 3.27 )
project( Stardust )

set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++ )
set( CMAKE_CXX_FLAGS    ${COMPILE_FLAGS} )

set( CMAKE_C_STANDARD   11 )
set( CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc )
set( CMAKE_C_FLAGS      ${COMPILE_FLAGS} )

include_directories( include )

set( STARDUST-SRC
        src/PreMain.c
        src/Main.c
        src/Ldr.c
        src/Utils.c
)

add_executable( Stardust ${STARDUST-SRC} )
