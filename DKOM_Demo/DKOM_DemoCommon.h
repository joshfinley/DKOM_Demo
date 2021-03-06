#pragma once

#define DKOM_DEMO_DEVICE 0x800
#define IOCTL_DKOM_DEMO_HIDE_PROCESS CTL_CODE(DKOM_DEMO_DEVICE, \
	0x8000, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DKOM_DEMO_HIDE_DRIVER CTL_CODE(DKOM_DEMO_DEVICE, \
	0x8001, METHOD_NEITHER, FILE_ANY_ACCESS)

struct ProcessData {
	ULONG pid;
};