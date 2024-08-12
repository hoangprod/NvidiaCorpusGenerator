#include "Header.h"
#include "Helper.h"
#include "Scanning.h"

#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>

void CreateCorpusFile(DWORD EscapeCode, DWORD RequiredSize, const char* DataFill)
{
	if (!DataFill)
	{
		PrintLog("DataFill is null, cannot create corpus file");
		return;
	}

	// The header is at least already 0x10 bytes
	//
	if (RequiredSize <= 0x10)
	{
		return;
	}

	// Ensure the folder "GeneratedCorpus" exists, create it if it doesn't
	std::string folderName = "GeneratedCorpus";
	std::filesystem::create_directories(folderName);

	// Create the corpus file with the escape code being the first 4 bytes and then the rest of the data being 0x0.
	// The corpus will also be 0x10 bytes less than required size since that is the header we will append to the data later
	//
	std::stringstream ss;
	ss << folderName << "\\corpus_0x" << std::hex << std::setw(8) << std::setfill('0') << EscapeCode << "_";

	if (DataFill[0] == '\xFF') {
		ss << "FF";
	}
	else if (DataFill[0] == '\x00') {
		ss << "00";
	}
	else {
		ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)DataFill[0];
	}


	std::string CorpusFilename = ss.str();

	std::ofstream CorpusFile(CorpusFilename, std::ios::binary);

	if (!CorpusFile.is_open())
	{
		PrintLog("Failed to create the corpus file: %s", CorpusFilename.data());
		return;
	}

	const unsigned char header[] = {
		0x41, 0x44, 0x56, 0x4e, 0x02, 0x00, 0x01, 0x00, 0x4c, 0x06, 0x00, 0x00,
		0x2a, 0x2a, 0x56, 0x4e
	};

	*(DWORD*)(header + 8) = RequiredSize;

	CorpusFile.write(reinterpret_cast<const char*>(header), sizeof(header));


	// Write the escape code
	//
	CorpusFile.write(reinterpret_cast<const char*>(&EscapeCode), sizeof(DWORD));

	// Write the rest of the data as 0xff
	//
	for (size_t i = 0; i < RequiredSize - (sizeof header + sizeof DWORD); i++)
	{
		CorpusFile.write(DataFill, 1);
	}

	CorpusFile.close();

	PrintLog("Created corpus file: %s", CorpusFilename.data());
}


void ProcessEscapeConfig(EscapeSpecificConfig* pConfig)
{
	if (!pConfig)
	{
		return;
	}

	while (pConfig->EscapeCode != -1)
	{
		PrintLog("----------> Escape Code: [0x%lx] Required Size [0x%lx], Required Admin (%s), Validator Offset (%llx)",
			pConfig->EscapeCode,
			pConfig->RequiredSize,
			pConfig->RequireAdmin ? "Yes" : "No",
			pConfig->fnValidator ? ((UINT_PTR)pConfig->fnValidator - (UINT_PTR)Global::hDriverModule) : 0);

		if (pConfig->RequireAdmin == false && pConfig->RequiredSize >= 0x10)
		{
			CreateCorpusFile(pConfig->EscapeCode, pConfig->RequiredSize, "\xFF");
			CreateCorpusFile(pConfig->EscapeCode, pConfig->RequiredSize, "\x00");
		}

		pConfig++;
	}
}


void ProcessEscapeTableConfig(EscapeTableConfig* pEscapeTable)
{
	if (!pEscapeTable)
	{
		return;
	}

	while (true)
	{
		bool bFinalEscapeCodeGroup = false;

		// Check if the escape code starts with 0xD, this is the final escape code group
		//
		if (pEscapeTable->EscapeCodeUpperBit == 0xD)
		{
			bFinalEscapeCodeGroup = true;
		}

		// Process the escape code
		//
		char Tag[5] = { 0 };
		memcpy(Tag, &pEscapeTable->Tag, 4);

		PrintLog("Escape Code Range: [0x0%xxxxxxx] Tag: [%s] Handler Offset [%llx]",
			pEscapeTable->EscapeCodeUpperBit,
			Tag,
			pEscapeTable->fnHandler ? ((UINT_PTR)pEscapeTable->fnHandler - (UINT_PTR)Global::hDriverModule) : 0);


		ProcessEscapeConfig(pEscapeTable->pValidatorClass);

		if (bFinalEscapeCodeGroup)
		{
			break;
		}

		pEscapeTable++;
	}
}


int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		PrintLog("Usage: %s <filename>", argv[0]);
		return 1;
	}

	std::string filename = argv[1];

	// Load the image from the file but don't start it, simply load it into memory
	//
	Global::hDriverModule = LoadLibraryExA(filename.data(), NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (Global::hDriverModule == NULL)
	{
		PrintLog("Failed to load the file: %s", filename.data());
		return 1;
	}

	if (!Helper::GetSectionData(reinterpret_cast<UINT_PTR>(Global::hDriverModule), ".rdata", Global::pDriverRdataBase, Global::uDriverRdataSize))
	{
		PrintLog("Failed to get the .rdata section data");
		return 1;
	}

	/*
	 * Essentially we are searching for this block of data in the .rdata section of the driver
	.rdata:0000000000D03F98 01 00 00 00                   escapeConfigRecord dd 1                 ; DATA XREF: VerifyEscapeData+17A↓o
	.rdata:0000000000D03F9C 2A 2A 56 4E                   aVn             db '**VN'               ; DATA XREF: VerifyEscapeData+EE↓o
	.rdata:0000000000D03FA0 F0 63 5B 01 00 00 00 00                       dq offset handle_1xxxxxxx
	.rdata:0000000000D03FA8 C0 D8 6C 01 00 00 00 00                       dq offset unk_16CD8C0
	.rdata:0000000000D03FB0 02 00 00 00                                   dd 2
	.rdata:0000000000D03FB4 58 44 56 4E                   aXdvn           db 'XDVN'
	.rdata:0000000000D03FB8 F0 50 5B 01 00 00 00 00                       dq offset handle_2xxxxxxx
	.rdata:0000000000D03FC0 90 1C 6D 01 00 00 00 00                       dq offset unk_16D1C90
	*/


	EscapeTableConfig* EscapeConfig = reinterpret_cast<EscapeTableConfig*>(Scanning::FindPatternIDA(
		reinterpret_cast<UINT_PTR>(Global::pDriverRdataBase),
		Global::uDriverRdataSize,
		"01 00 00 00 2a 2a 56 4e ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 02 00 00 00 58 44 56 4e"));

	if (!EscapeConfig)
	{
		PrintLog("Failed to find the EscapeConfig pattern, you probably will have to reverse this yourself in your version of nvlddmkm.sys");
		return 1;
	}

	// Bunk of the operations
	//
	ProcessEscapeTableConfig(EscapeConfig);

	return 0;
}
