#ifndef PE_HANDLER_H
#define PE_HANDLER_H
#include <Windows.h>
#include <vector>
#include <string>
#include <winnt.h>
#include <ImageHlp.h>
#pragma comment(lib,"imagehlp.lib")
template<typename NtHeaders, typename OptHeaders>
class PE_handler_32_64 {
private:
	bool isPeOpen;
	HANDLE _file, _file_map;
	LPVOID _base;
	PIMAGE_DOS_HEADER _dos_header;
	NtHeaders _nt_headers;
	OptHeaders _opt_headers;
public:
	PE_handler_32_64();
	~PE_handler_32_64();
	bool isOpen();
	void OpenPE(const std::string& filename);
	std::vector<std::string>* GetImportTab();
	DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER psh, NtHeaders pnt);
};

typedef PE_handler_32_64<PIMAGE_NT_HEADERS32, PIMAGE_OPTIONAL_HEADER32> PE_handler_32;
typedef PE_handler_32_64<PIMAGE_NT_HEADERS64, PIMAGE_OPTIONAL_HEADER64> PE_handler_64;
#endif // !PE_HANDLER_H
