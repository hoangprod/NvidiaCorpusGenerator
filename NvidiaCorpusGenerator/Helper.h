#pragma once

namespace Helper
{
	PIMAGE_SECTION_HEADER GetImageSection(const UINT_PTR image_base, const char* section);

	BOOL GetSectionData(const UINT_PTR image_base, const char* section, PVOID& OutSectionBase, ULONG& OutSectionSize);
}