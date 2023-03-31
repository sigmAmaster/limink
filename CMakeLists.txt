cmake_minimum_required(VERSION 3.5)

project(LimInk VERSION 1.1.1 LANGUAGES CXX )

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


if(CMAKE_CXX_COMPILER_ID MATCHES "GNU") 
    #add_definitions()
    add_compile_options(-o3 -std=c++20)

elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang") 
    add_compile_options(-o3 -std=c++20)
   
# i dont know MSVC flags are correct or not
# and never had experince witj MSVC compiler
# use it on your own risk
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_compile_options(-o2 -GS -GT -GX -Od -nologo -std:c++20)

    else()
     message(FATAL_ERROR "Unsupported compiler: ${CMAKE_CXX_COMPILER_ID}")
    endif()


#find_package(crypt NAMES lcrypto++  )

set(PROJECT_SOURCES
     
    SSKmanager_KRS32.cpp
    SSKmanager_KRS32.hpp
    
       
    Pverf.hpp 
    Pverf.cpp 

    EncCore.hpp 
    EncCore.cpp 

    BShifter.hpp 
    BShifter.cpp 
    
    files.hpp 
    Ofiles.cpp 
    Ifiles.cpp 
    
    Package.hpp 
    Package.cpp

    main.cpp 

)

 

add_executable(limink ${PROJECT_SOURCES})

# change library path 
target_link_libraries(limink  PRIVATE /usr/local/lib/libcryptopp.a )

