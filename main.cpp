/*
Copyright (c) 2011 Matthew Endsley. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

THIS SOFTWARE IS PROVIDED BY MATTHEW ENDSLEY ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MATTHEW ENDSLEY OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOGDI

#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <Windows.h>
#include <DbgHelp.h>
#include <string>
#include <vector>
#include <tchar.h>

using namespace std;

struct FixHeader 
{
	string module;
	IMAGE_OPTIONAL_HEADER imageHeader;
	ULONG32 timeStamp;
};

static string wstr2mbcs(const wstring& str)
{
	unsigned codePage = GetOEMCP();

	unsigned newLength = WideCharToMultiByte(
		codePage, 0, str.c_str(), -1, 
		NULL, 0, NULL, NULL) - 1;

	string mbcs;
	mbcs.resize(newLength);

	WideCharToMultiByte(codePage, 0, str.c_str(), -1, 
		(LPSTR)mbcs.c_str(), newLength + 1, NULL, NULL);

	return mbcs;
}


static bool getExecutableChecksumAndSize(const char* _path, ULONG32* _timeStamp, IMAGE_OPTIONAL_HEADER* _header)
{
	FILE* fp = fopen(_path, "rb");
	if (!fp)
		return false;

	IMAGE_DOS_HEADER dosHeader;
	if (1 != fread(&dosHeader, sizeof(dosHeader), 1, fp))
	{
		fclose(fp);
		return false;
	}
	if (dosHeader.e_magic != 0x5A4D)
	{
		fclose(fp);
		return false;
	}

	fseek(fp, dosHeader.e_lfanew, SEEK_SET);
	IMAGE_NT_HEADERS ntHeader;
	if (1 != fread(&ntHeader, sizeof(ntHeader), 1, fp))
	{
		fclose(fp);
		return false;
	}
	fclose(fp);

	if (memcmp(&ntHeader.Signature, "PE\0\0", 4))
		return false;
	if (ntHeader.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER))
		return false;

	*_timeStamp = ntHeader.FileHeader.TimeDateStamp;
	*_header = ntHeader.OptionalHeader;
	return true;
}


static bool getRvaString(RVA rva, const char* mem, wstring* str)
{
	const MINIDUMP_STRING* mstr = (const MINIDUMP_STRING*)(mem + rva);
	if (IsBadReadPtr(mstr->Buffer, mstr->Length) != FALSE)
		return false;

	str->resize(mstr->Length / 2);
	memcpy(&((*str)[0]), mstr->Buffer, mstr->Length);
	return true;
}

static bool fixupDump(const char* _dumpPath, const vector<FixHeader>& headers)
{
	FILE* fp = fopen(_dumpPath, "rb");
	if (!fp)
		return false;

	const long fileSize = _filelength(_fileno(fp));
	char* data = new char[fileSize];
	fread(data, fileSize, 1, fp);
	fclose(fp);

	MINIDUMP_HEADER* header = (MINIDUMP_HEADER*)data;
	header->CheckSum = 0;
	if (header->Signature != MINIDUMP_SIGNATURE)
	{
		delete[] data;
		return false;
	}

	MINIDUMP_DIRECTORY* directory = (MINIDUMP_DIRECTORY*)(data + header->StreamDirectoryRva);
	for (int ii = 0; ii < (int)header->NumberOfStreams; ++ii)
	{
		if (directory[ii].StreamType == ModuleListStream)
		{
			MINIDUMP_MODULE_LIST* moduleList = (MINIDUMP_MODULE_LIST*)(data + directory[ii].Location.Rva);

			for (size_t i = 0; i < moduleList->NumberOfModules; i++)
			{
				MINIDUMP_MODULE* module = &moduleList->Modules[i];
				wstring moduleNameWide;
				getRvaString(module->ModuleNameRva, data, &moduleNameWide);

				string moduleName = wstr2mbcs(moduleNameWide);

				for (size_t j = 0; j < headers.size(); j++)
				{
					const FixHeader& header = headers[j];
					if (moduleName.find(header.module) != string::npos)
					{
						module->CheckSum = header.imageHeader.CheckSum;
						module->SizeOfImage = header.imageHeader.SizeOfImage;
						module->TimeDateStamp = header.timeStamp;

						printf("Fixed module %s\n", moduleName.c_str());
						continue;
					}
				}
			}
		}
	}

	fp = fopen(_dumpPath, "wb");
	if (!fp)
	{
		delete[] data;
		return false;
	}

	fwrite(data, fileSize, 1, fp);
	fclose(fp);

	delete[] data;
	return true;
}

static void cleanupDump(const char* _path)
{
	FILE* fp = fopen(_path, "rb");
	if (!fp)
		return;

	const long fileSize = _filelength(_fileno(fp));
	char* data = new char[fileSize];
	fread(data, fileSize, 1, fp);
	fclose(fp);

	MINIDUMP_HEADER* header = (MINIDUMP_HEADER*)data;
	const bool signatureMatches = (header->Signature == MINIDUMP_SIGNATURE);
	if (signatureMatches)
	{
		delete[] data;
		fclose(fp);
		return;
	}

	header = (MINIDUMP_HEADER*)(data + 8);
	if (header->Signature != MINIDUMP_SIGNATURE)
	{
		delete[] data;
		fclose(fp);
		return;
	}

	fp = fopen(_path, "wb");
	fwrite(data + 8, fileSize - 8, 1, fp);
	fclose(fp);
}


int main( int argc, char** argv )
{
	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s <dump file> <module1> <module2> <module3> ...\n", argv[0]);
		return -1;
	}

	const char* dumpFile = argv[1];

	vector<IMAGE_OPTIONAL_HEADER> headers;
	vector<ULONG32> timeStamps;

	vector<FixHeader> fixHeaders;
	
	for (size_t i = 2; i < argc; i++)
	{
		const char* module = argv[i];
		IMAGE_OPTIONAL_HEADER header;
		ULONG32 timeStamp;

		printf("Looking up checksum and size for module %s\n", module);

		if (!getExecutableChecksumAndSize(module, &timeStamp, &header))
		{
			fprintf(stderr, "Failed to lookup checksum for module '%s'\n", module);
			continue;
		}

		FixHeader fixHeader;
		fixHeader.module = module;
		fixHeader.imageHeader = header;
		fixHeader.timeStamp = timeStamp;
		
		fixHeaders.push_back(fixHeader);
	}

	cleanupDump(dumpFile);

	bool success = fixupDump(dumpFile, fixHeaders);
	if (success)
		printf("Fixed!\n");
	else
		printf("** Fixing failed\n");

	return 0;
}
