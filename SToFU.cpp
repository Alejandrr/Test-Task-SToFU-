#include <iostream>
#include <fstream>
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <map>
#include "Header.h"
#include "PE_handler.h"
#include "PE_exception.h"
#include "PE_handler.cpp"

int main(int argc, char* argv[])
{
	std::vector<std::string>* libsName = NULL;
	std::string filen;
	std::string ico;
	PE_handler_32 PEhandler;
	if (argc < 3)
	{
		std::cout << "\033[31m" << "Missing input parameter for .ico or .exe file!" << "\033[39m" << std::endl;
		return 1;
	}
	filen = argv[1];
	ico = argv[2];
	if (!ChangeExeIcon(std::wstring(filen.begin(), filen.end()).c_str(), std::wstring(ico.begin(), ico.end()).c_str()))
	{
		std::cout << "\033[31m";
		std::cout << "Icon don`t changed!" << std::endl;
		std::cout << "\033[39m";
	}
	else
	{
		std::cout << "\033[32m";
		std::cout << "Icon changed!" << std::endl;
		std::cout << "\033[39m";
	}
	try
	{
		if (is64bit(filen))
		{
			PE_handler_64 PEhandler;
			PEhandler.OpenPE(filen);
			libsName = PEhandler.GetImportTab();
		}
		else
		{
			PEhandler.OpenPE(filen);
			libsName = PEhandler.GetImportTab();
		}
	}
	catch (const PE_handler_exception& e)
	{
		std::cout << "\033[31m";
		std::cout << "PE handler exception: " << e.what() << std::endl;
		std::cout << "\033[39m";
	}
	if (libsName != NULL)
	{
		std::cout << "\033[32m" << "PE .dll imports :" << "\033[39m" << std::endl;
		for (auto it = libsName->begin(); it != libsName->end(); it++)
		{
			std::cout << it->c_str() << std::endl;
		}
		std::cout << "\033[32m" << "PE .dll imports with \"W\" letter :" << "\033[39m" << std::endl;
		for (auto it = libsName->begin(); it != libsName->end(); it++)
		{
			if (strchr(it->c_str(), 'w') || strchr(it->c_str(), 'W'))
			{
				std::cout << it->c_str() << std::endl;
			}
		}
	}
	std::cout << "\033[32m" << "PE file entropy : ";
	std::cout << FileEntrophy(filen.c_str()) << std::endl;
	std::cout << "\033[39m";
	std::cout << "\033[32m" << "Icon entropy : ";
	std::cout << FileEntrophy(ico.c_str()) << std::endl;
	std::cout << "\033[39m";
	delete libsName;
	return 0;
}