#include "Header.h"
#include "Scanning.h"

bool INT_ComparePattern(char* szSource, const char* szPattern, const char* szMask)
{
    for (; *szMask; ++szSource, ++szPattern, ++szMask)
        if (*szMask == 'x' && *szSource != *szPattern)
            return false;

    return true;
}

char* INT_PatternScan(char* pData, UINT_PTR RegionSize, const char* szPattern, const char* szMask, int Len)
{
    for (UINT i = 0; i != RegionSize - Len; ++i, ++pData)
        if (INT_ComparePattern(pData, szPattern, szMask))
            return pData;
    return nullptr;
}


UINT_PTR Scanning::FindPattern(UINT_PTR base, const PBYTE Pattern, const char* Mask) {
    PBYTE Start = (PBYTE)base;
    PIMAGE_NT_HEADERS NTHead = (PIMAGE_NT_HEADERS)(Start + ((PIMAGE_DOS_HEADER)Start)->e_lfanew);
    DWORD Len = NTHead->OptionalHeader.SizeOfImage;

    for (PBYTE region_it = Start; region_it < (Start + Len); ++region_it) {
        if (*region_it == *Pattern) {
            bool found = true;
            const unsigned char* pattern_it = Pattern, * mask_it = (const PBYTE)Mask, * memory_it = region_it;
            for (; *mask_it && (memory_it < (Start + Len)); ++mask_it, ++pattern_it, ++memory_it) {
                if (*mask_it != 'x') continue;
                if (*memory_it != *pattern_it) {
                    found = false;
                    break;
                }
            }

            if (found)
                return (uintptr_t)region_it;
        }
    }

    return 0;
}

UINT_PTR Scanning::FindPatternIDA(UINT_PTR dwAddress, UINT_PTR dwLen, const char* bPattern)
{
    if (!dwAddress || !dwLen || !bPattern)
        return 0;

    auto SwitchHex = [](CHAR c) -> CHAR
        {
            switch (c)
            {
            case '0': return 0;
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            case '8': return 8;
            case '9': return 9;
            case 'a': return 10;
            case 'b': return 11;
            case 'c': return 12;
            case 'd': return 13;
            case 'e': return 14;
            case 'f': return 15;

            case 'A': return 10;
            case 'B': return 11;
            case 'C': return 12;
            case 'D': return 13;
            case 'E': return 14;
            case 'F': return 15;
            default:
                break;
            }

            return 30;
        };

    auto GenerateMask = [SwitchHex](IN const char* Pattern, OUT char* NewPattern, OUT char* newMask) -> VOID
        {

            CHAR bMask[300] = { 0 };
            CHAR bPattern[300] = { 0 };
            CHAR bWildCardPosition[300] = { 0 };

            INT i = 0, length = 0;
            while (Pattern[i])
            {
                if (Pattern[i] != ' ') // Removing all white spaces
                    bPattern[length++] = Pattern[i];
                i++;
            } bPattern[length] = '\0';


            UINT64 l = 0;
            for (UINT64 k = 0; k < length;)
            {
                if (bPattern[k] == '?')
                {
                    k++;
                    bWildCardPosition[l] = true;
                    bPattern[l++] = '\xCC';
                    continue;
                }

                if (!bPattern[k])
                    break;

                BYTE b1 = SwitchHex(bPattern[k++]);
                BYTE b2 = SwitchHex(bPattern[k++]);
                BYTE b = (b1 << 4) | b2;

                bPattern[l++] = b;
            }
            bPattern[l] = '\0';

            for (size_t m = 0; m < l; m++)
            {
                if (bWildCardPosition[m]) // Replacing ? with \xCC byte
                {
                    bMask[m] = '?';
                }
                else
                {
                    bMask[m] = 'x';
                }
            }

            RtlCopyMemory(newMask, bMask, l);
            RtlCopyMemory(NewPattern, bPattern, l);
        };

    CHAR newMask[300] = { 0 };
    UCHAR newPattern[300] = { 0 };
    GenerateMask(bPattern, (CHAR*)newPattern, newMask);

    return Scanning::PatternScanUnsafe<UINT_PTR>(dwAddress, dwLen, (const char*)newPattern, newMask);
}

template <typename T>
T Scanning::PatternScanUnsafe(T pStart, UINT_PTR RegionSize, const char* szPattern, const char* szMask)
{
    char* pCurrent = (char*)pStart;
    auto Len = lstrlenA(szMask);

    if (Len > RegionSize)
        return 0;

    return (T)INT_PatternScan(pCurrent, RegionSize, szPattern, szMask, Len);
}