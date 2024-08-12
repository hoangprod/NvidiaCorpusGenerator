#pragma once

#pragma pack(push, 1)

// Since we are reversing these structs, we should make sure they are not padded in anyway
//
class EscapeSpecificConfig
{
public:
	unsigned int EscapeCode; //0x0000
	char pad_0004[4]; //0x0004
	unsigned int RequiredSize; //0x0008
	char pad_000C[4]; //0x000C
	unsigned __int16 UnknownSize; //0x0010
	char pad_0012[2]; //0x0012
	bool RequireAdmin; //0x0014
	char pad_0015[3]; //0x0015
	unsigned int Flags; //0x0018
	unsigned int Flags2; //0x001C
	char pad_0020[8]; //0x0020
	void* fnValidator; //0x0028
	char pad_0030[8]; //0x0030
}; //Size: 0x0038
static_assert(sizeof(EscapeSpecificConfig) == 0x38);

class EscapeTableConfig
{
public:
	unsigned int EscapeCodeUpperBit; //0x0000
	unsigned int Tag; //0x0004
	void* fnHandler; //0x0008
	EscapeSpecificConfig* pValidatorClass; //0x0010
}; //Size: 0x0018
static_assert(sizeof(EscapeTableConfig) == 0x18);

#pragma pack(pop)