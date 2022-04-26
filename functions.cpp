#include "Header.h"

bool is64bit(const std::string& filename)
{
	LPVOID base;
	HANDLE file, fileMap;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_OPTIONAL_HEADER opt_header;
	file = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	std::cout << "\033[31m";
	if (file == NULL)
	{
		std::cout << "is64bit() : Failed to find file" << "\033[39m" << std::endl;
		return false;
	}
	fileMap = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (fileMap == NULL)
	{
		std::cout << "is64bit() : Failed to create file mapping" << "\033[39m" << std::endl;
		return false;
	}
	base = MapViewOfFile(fileMap, FILE_MAP_READ, 0, 0, 0);
	if (base == NULL)
	{
		std::cout << "is64bit() : Failed to map view of file" << "\033[39m" << std::endl;
		return false;
	}
	dos_header = (PIMAGE_DOS_HEADER)base;
	if (dos_header->e_magic != 'ZM')
	{
		std::cout << "is64bit() : Invalid PE" << "\033[39m" << std::endl;
		return false;
	}
	nt_header = (PIMAGE_NT_HEADERS)((LPVOID)((BYTE*)dos_header + dos_header->e_lfanew));
	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cout << "is64bit() : Invalid NT headers" << "\033[39m" << std::endl;
		return false;
	}
	opt_header = &nt_header->OptionalHeader;
	CloseHandle(file);
	CloseHandle(fileMap);
	if (opt_header->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return true;
	}
	else
	{
		return false;
	}
}
bool ChangeExeIcon(const wchar_t* exeFile, const wchar_t* iconFile)
{
	BOOL check;
	DWORD dwIconFileSize, dwBytesRead;
	HANDLE hIcon, hExe;
	ICONDIR iconDir;
	BYTE** iconImages;
	GRPICONDIR grpIconDir;
	WORD buffersize;
	BYTE* buffer;
	BYTE* pBuffer;
	std::cout << "\033[31m";
	hIcon = CreateFile(iconFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	dwIconFileSize = GetFileSize(hIcon, NULL);
	check = ReadFile(hIcon, (LPVOID) & (iconDir.idReserved), sizeof(WORD), &dwBytesRead, NULL);
	if (!check)
	{
		std::cout << "Change icon : Error in line " << __LINE__ << "\033[39m" << std::endl;
		return false;
	}	check = ReadFile(hIcon, (LPVOID) & (iconDir.idType), sizeof(WORD), &dwBytesRead, NULL);
	if (!check)
	{
		std::cout << "Change icon : Error in line " << __LINE__ << "\033[39m" << std::endl;
		return false;
	}	check = ReadFile(hIcon, (LPVOID) & (iconDir.idCount), sizeof(WORD), &dwBytesRead, NULL);
	if (!check)
	{
		std::cout << "Change icon : Error in line " << __LINE__ << "\033[39m" << std::endl;
		return false;
	}	
	iconDir.idEntries = (ICONDIRENTRY*)malloc(sizeof(ICONDIRENTRY) * iconDir.idCount);
	for (int i = 0; i < iconDir.idCount; i++) {
		check = ReadFile(hIcon, (LPVOID)&iconDir.idEntries[i], sizeof(ICONDIRENTRY), &dwBytesRead, NULL);
		if (!check)
		{
			std::cout << "Change icon : Error in line " << __LINE__ << "\033[39m" << std::endl;
			return false;
		}
	}
	iconImages = (BYTE**)malloc(sizeof(BYTE*) * iconDir.idCount);
	for (int i = 0; i < iconDir.idCount; i++) {
		iconImages[i] = (BYTE*)malloc(iconDir.idEntries[i].dwBytesInRes);
		SetFilePointer(hIcon, iconDir.idEntries[i].dwImageOffset, NULL, FILE_BEGIN);
		ReadFile(hIcon, iconImages[i], iconDir.idEntries[i].dwBytesInRes, &dwBytesRead, NULL);
	}
	grpIconDir.idReserved = iconDir.idReserved;
	grpIconDir.idType = iconDir.idType;
	grpIconDir.idCount = iconDir.idCount;
	buffersize = 3 * sizeof(WORD) + grpIconDir.idCount * sizeof(GRPICONDIRENTRY);
	buffer = (BYTE*)malloc(buffersize);
	pBuffer = buffer;
	CopyMemory(buffer, &grpIconDir.idReserved, sizeof(WORD));
	buffer = buffer + sizeof(WORD);
	CopyMemory(buffer, &grpIconDir.idType, sizeof(WORD));
	buffer = buffer + sizeof(WORD);
	CopyMemory(buffer, &grpIconDir.idCount, sizeof(WORD));
	buffer = buffer + sizeof(WORD);
	grpIconDir.idEntries = (GRPICONDIRENTRY*)malloc(grpIconDir.idCount * sizeof(GRPICONDIRENTRY));
	for (int i = 0; i < grpIconDir.idCount; i++) {
		grpIconDir.idEntries[i].bWidth = iconDir.idEntries[i].bWidth;
		CopyMemory(buffer, &grpIconDir.idEntries[i].bWidth, sizeof(BYTE));
		buffer = buffer + sizeof(BYTE);
		grpIconDir.idEntries[i].bHeight = iconDir.idEntries[i].bHeight;
		CopyMemory(buffer, &grpIconDir.idEntries[i].bHeight, sizeof(BYTE));
		buffer = buffer + sizeof(BYTE);
		grpIconDir.idEntries[i].bColorCount = iconDir.idEntries[i].bColorCount;
		CopyMemory(buffer, &grpIconDir.idEntries[i].bColorCount, sizeof(BYTE));
		buffer = buffer + sizeof(BYTE);
		grpIconDir.idEntries[i].bReserved = iconDir.idEntries[i].bReserved;
		CopyMemory(buffer, &grpIconDir.idEntries[i].bReserved, sizeof(BYTE));
		buffer = buffer + sizeof(BYTE);
		grpIconDir.idEntries[i].wPlanes = iconDir.idEntries[i].wPlanes;
		CopyMemory(buffer, &grpIconDir.idEntries[i].wPlanes, sizeof(WORD));
		buffer = buffer + sizeof(WORD);
		grpIconDir.idEntries[i].wBitCount = iconDir.idEntries[i].wBitCount;
		CopyMemory(buffer, &grpIconDir.idEntries[i].wBitCount, sizeof(WORD));
		buffer = buffer + sizeof(WORD);
		grpIconDir.idEntries[i].dwBytesInRes = iconDir.idEntries[i].dwBytesInRes;
		CopyMemory(buffer, &grpIconDir.idEntries[i].dwBytesInRes, sizeof(DWORD));
		buffer = buffer + sizeof(DWORD);
		grpIconDir.idEntries[i].nID = i + 1;
		CopyMemory(buffer, &grpIconDir.idEntries[i].nID, sizeof(WORD));
		buffer = buffer + sizeof(WORD);
	}

	hExe = BeginUpdateResource(exeFile, FALSE);
	check = UpdateResource(hExe, RT_GROUP_ICON, L"MAINICON", MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), pBuffer, buffersize);
	if (!check)
	{
		std::cout << "Change icon : Error in line " << __LINE__ << "\033[39m" << std::endl;
		return false;
	}	for (int i = 0; i < grpIconDir.idCount; i++) {
		check = UpdateResource(hExe, RT_ICON,
			MAKEINTRESOURCE(grpIconDir.idEntries[i].nID),
			MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
			iconImages[i],
			grpIconDir.idEntries[i].dwBytesInRes);
		if (!check)
		{
			std::cout << "Change icon : Error in line " << __LINE__ << "\033[39m" << std::endl;
			return false;
		}
	}
	EndUpdateResource(hExe, FALSE);
	check = CloseHandle(hIcon);
	if (!check)
	{
		std::cout << "Change icon : Error in line " << __LINE__ << "\033[39m" << std::endl;
		return false;
	}
	free(pBuffer);
	free(grpIconDir.idEntries);
	free(iconDir.idEntries);
	for (int i = 0; i < iconDir.idCount; i++)
	{
		free(iconImages[i]);
	}
	free(iconImages);
	return true;
}
double FileEntrophy(const char* path)
{
	std::ifstream file;
	std::map<char, size_t>* map;
	char temp;
	double result, frequency;
	std::streamsize fileLen;
	file.open(path, std::ios_base::ate);
	if (!file.is_open())
	{
		std::cout << "\033[31m" << "Invalid path to file" << std::endl;
		std::cout << "\033[39m";
		return 0;
	}
	fileLen = file.tellg();
	file.seekg(std::ios::beg);
	map = new std::map<char, size_t>;
	while (!file.eof())
	{
		temp = file.get();
		if (map->find(temp) == map->end())
		{
			map->insert(std::make_pair(temp, 1));
		}
		else
		{
			map->find(temp)->second += 1;
		}
	}
	result = 0.0;
	for (auto it = map->begin(); it != map->end(); it++)
	{
		frequency = (double)it->second / (double)fileLen;
		result -= frequency * log2(frequency);
	}
	file.close();
	delete map;
	return result;

}