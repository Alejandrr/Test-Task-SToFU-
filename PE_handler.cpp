#include "PE_handler.h"
#include "PE_exception.h"
template<typename NtHeaders, typename OptHeaders>
PE_handler_32_64<NtHeaders, OptHeaders>::PE_handler_32_64()
{
	isPeOpen = 0;
	_file = INVALID_HANDLE_VALUE;
	_file_map = INVALID_HANDLE_VALUE;
	_base = 0;
	_dos_header = 0;
	_nt_headers = 0;
	_opt_headers = 0;
}
template<typename NtHeaders, typename OptHeaders>
PE_handler_32_64<NtHeaders, OptHeaders>::~PE_handler_32_64()
{
	if (isPeOpen) {
		CloseHandle(_file);
		CloseHandle(_file_map);
	}
}
template<typename NtHeaders, typename OptHeaders>
bool PE_handler_32_64<NtHeaders, OptHeaders>::isOpen()
{
	return _base != 0x0;
}
template<typename NtHeaders, typename OptHeaders>
std::vector<std::string>* PE_handler_32_64<NtHeaders, OptHeaders>::GetImportTab()
{

	std::string libName;
	std::vector<std::string>* libs;
	PIMAGE_DELAYLOAD_DESCRIPTOR delayImportDs;
	PIMAGE_IMPORT_DESCRIPTOR importDs;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR boundImportDs;
	if (!isPeOpen)
	{
		throw PE_handler_exception("Missing path to PE file", PE_handler_exception::path_to_PE_missed);
		return NULL;
	}
	_dos_header = (PIMAGE_DOS_HEADER)_base;
	if (_dos_header->e_magic != 'ZM')
	{
		throw PE_handler_exception("Invalid PE", PE_handler_exception::bad_dos_header);
	}

	_nt_headers = (NtHeaders)((LPVOID)((BYTE*)_dos_header + ((PIMAGE_DOS_HEADER)_dos_header)->e_lfanew));
	if (_nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		throw PE_handler_exception("Invalid NT headers", PE_handler_exception::bad_nt_headers);
	}
	_opt_headers = &_nt_headers->OptionalHeader;
	int magic = _opt_headers->Magic;
	if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		throw PE_handler_exception("Unknown arhictecture of PE file", PE_handler_exception::bad_arhitecture);
	}
	importDs = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)_base + RvaToOffset(_opt_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
		IMAGE_FIRST_SECTION(_nt_headers), _nt_headers));
	libs = new std::vector<std::string>;
	delayImportDs = (PIMAGE_DELAYLOAD_DESCRIPTOR)((DWORD_PTR)_base + RvaToOffset(_opt_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress,
		IMAGE_FIRST_SECTION(_nt_headers), _nt_headers));
	if (importDs->FirstThunk == -1) // if bound import allowed 
	{
		boundImportDs = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD_PTR)_base + RvaToOffset(_opt_headers->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress,
			IMAGE_FIRST_SECTION(_nt_headers), _nt_headers));
		if (boundImportDs->NumberOfModuleForwarderRefs != 0)
		{

			/// Get Bound Import Table libs 
			while (boundImportDs->OffsetModuleName != 0)
			{
				libName = (LPSTR)((DWORD_PTR)_base + RvaToOffset(boundImportDs->OffsetModuleName,
					IMAGE_FIRST_SECTION(_nt_headers), _nt_headers));
				//std::cout << libName << std::endl;
				libs->push_back(libName);
				boundImportDs++;
			}
		}
	}
	/// Get Import Table libs
	while (importDs->Name != 0)
	{
		libName = (LPSTR)((DWORD_PTR)_base + RvaToOffset(importDs->Name,
			IMAGE_FIRST_SECTION(_nt_headers), _nt_headers));
		//std::cout << libName << std::endl;
		libs->push_back(libName);
		importDs++;
	}
	// Get Delay Import libs

	while (delayImportDs->DllNameRVA != 0 && delayImportDs->DllNameRVA > 3)
	{
		libName = (LPCSTR)((DWORD_PTR)_base + RvaToOffset(delayImportDs->DllNameRVA,
			IMAGE_FIRST_SECTION(_nt_headers), _nt_headers));
		//std::cout << libName << std::endl;
		libs->push_back(libName);
		delayImportDs++;
	}

	return libs;
}
template<typename NtHeaders, typename OptHeaders>
DWORD PE_handler_32_64<NtHeaders, OptHeaders>::RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER psh, NtHeaders pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}
template<typename NtHeaders, typename OptHeaders>
void PE_handler_32_64<NtHeaders, OptHeaders>::OpenPE(const std::string& filename)
{
	_file = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_file == NULL)
	{
		throw PE_handler_exception("Failed to find file", PE_handler_exception::unexist_pe_file);
	}
	_file_map = CreateFileMappingA(_file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (_file_map == NULL)
	{
		throw PE_handler_exception("Failed to create file mapping", PE_handler_exception::bad_pe_file);
	}
	_base = MapViewOfFile(_file_map, FILE_MAP_READ, 0, 0, 0);
	if (_base == NULL)
	{
		throw PE_handler_exception("Failed to map view of file", PE_handler_exception::bad_pe_file);
	}
	isPeOpen = true;
}