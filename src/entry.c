#include <string.h>
#include "dynamic_libs/os_functions.h"
#include "dynamic_libs/gx2_functions.h"
#include "dynamic_libs/socket_functions.h"
#include "common/common.h"
#include "pygecko.h"
#include "main.h"

int __entry_menu(int argc, char **argv) {
	if (OSGetTitleID != 0 &&
		OSGetTitleID() != 0x000500101004A200 && // mii maker eur
		OSGetTitleID() != 0x000500101004A100 && // mii maker usa
		OSGetTitleID() != 0x000500101004A000)   // mii maker jpn)
	{
		InitOSFunctionPointers();
		InitSocketFunctionPointers();
		InitGX2FunctionPointers();

		start_pygecko();
		return EXIT_RELAUNCH_ON_LOAD;
	}

	//! *******************************************************************
	//! *                 Jump to our application                    *
	//! *******************************************************************
	return Menu_Main();
}