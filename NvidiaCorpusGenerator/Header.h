#pragma once
#include <Windows.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <filesystem>

#include "Global.h"
#include "Struct.h"

#define PrintLog( format, ... ) printf( "[ %s - %ld ] " format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ )
