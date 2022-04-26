#ifndef HEADER_H
#define HEADER_H
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <map>

struct ICONDIRENTRY
{
	BYTE bWidth;               
	BYTE bHeight;              
	BYTE bColorCount;
	BYTE bReserved;            
	WORD wPlanes;              
	WORD wBitCount;            
	DWORD dwBytesInRes;         
	DWORD dwImageOffset;        
};
struct ICONDIR
{
	WORD idReserved;   
	WORD idType;       
	WORD idCount;      
	ICONDIRENTRY* idEntries; 
};
struct GRPICONDIRENTRY
{
	BYTE bWidth;
	BYTE bHeight;
	BYTE bColorCount;
	BYTE bReserved;
	WORD wPlanes;
	WORD wBitCount;
	DWORD dwBytesInRes;
	WORD nID;
};
struct GRPICONDIR
{
	WORD idReserved;
	WORD idType;
	WORD idCount;
	GRPICONDIRENTRY* idEntries;
};

bool is64bit(const std::string& filename);
bool ChangeExeIcon(const wchar_t* exeFile, const wchar_t* iconFile);
double FileEntrophy(const char* path);

#endif // !HEADER_H

