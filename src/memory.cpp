#include "memory.h"


VirtualMemoryObj *gameMem = 0;

bool Read(void* address, void* buffer, size_t size)
{
	//return ReadProcessMemory(hProcess, address, buffer, size, nullptr);

	virt_read_raw_into( gameMem, (Address)address, (unsigned char*)buffer, size );
	return true;
}

bool ReaderInit(VirtualMemoryObj *memflow_mem)
{
	gameMem = memflow_mem;
	return true;
}