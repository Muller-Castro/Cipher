cmake_minimum_required(VERSION 3.2)

project(Cipher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Cipher
	Main.cpp
	Cipher.h
	AES.h
	AES.cpp
	RSA.h
	RSA.cpp
)
