#pragma once
namespace Scanning
{
	template <typename T>
	T PatternScanUnsafe(T pStart, UINT_PTR RegionSize, const char* szPattern, const char* szMask);

	UINT_PTR FindPattern(UINT_PTR base, const PBYTE Pattern, const char* Mask);
	UINT_PTR FindPatternIDA(UINT_PTR dwAddress, UINT_PTR dwLen, const char* bPattern);
}