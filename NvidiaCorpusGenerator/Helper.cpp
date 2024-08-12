#include "Header.h"
#include "Helper.h"

PIMAGE_SECTION_HEADER Helper::GetImageSection(const UINT_PTR image_base, const char* section)
{
	if (!image_base)
		return 0;

	const PIMAGE_DOS_HEADER pimage_dos_header = (PIMAGE_DOS_HEADER)(image_base);

	if (pimage_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	const PIMAGE_NT_HEADERS64 pimage_nt_headers = (PIMAGE_NT_HEADERS64)(image_base + pimage_dos_header->e_lfanew);

	if (pimage_nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	WORD NumOfSection = pimage_nt_headers->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(pimage_nt_headers);

	for (WORD i = 0; i < NumOfSection; i++)
	{
		if (strcmp((const char*)Section->Name, section) == 0)
			break;

		Section++;
	}

	return Section;
}

BOOL Helper::GetSectionData(const UINT_PTR image_base, const char* section, PVOID& OutSectionBase, ULONG& OutSectionSize)
{
	PIMAGE_SECTION_HEADER pimage_section = GetImageSection(image_base, section);

	if (!pimage_section)
		return FALSE;

	OutSectionBase = (PVOID)(image_base + pimage_section->VirtualAddress);
	OutSectionSize = pimage_section->Misc.VirtualSize;

	if(!OutSectionBase || !OutSectionSize)
		return FALSE;

	return TRUE;
}
