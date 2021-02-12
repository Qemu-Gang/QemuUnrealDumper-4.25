#pragma once
#include <cstdint>
#include "memflow_win32.h"

inline uint64_t Base;

bool Read(void* address, void* buffer, size_t size);

template<typename T>
T Read(void* address) 
{
	T buffer{};
	Read(address, &buffer, sizeof(T));
	return buffer;
}

bool ReaderInit(VirtualMemoryObj *memflow_mem);