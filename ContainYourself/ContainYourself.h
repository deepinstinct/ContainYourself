#pragma once
#include "WcifsDefines.h"
#include "versionhelpers.h"

#include <iostream>

using std::cout;
using std::endl;

enum class ContainerUsage
{
	FileLinking,
	FileOverride
};

// Server or desktop OS
const bool IS_SERVER_OS = IsWindowsServer();

// TODO: Get the main volume NT path in runtime
const std::wstring MAIN_VOLUME_PATH(L"\\Device\\HarddiskVolume3");

class ContainYourself
{
public:
	static void InitContainer(HANDLE ProcessHandle, ContainerUsage Usage, PHANDLE SiloHandlePointer, const std::wstring& Volume = MAIN_VOLUME_PATH, DWORD Altitude = 0) noexcept(false);
	static void InitContainerUsingSilo(HANDLE SiloHandle, ContainerUsage Usage, const std::wstring& Volume = MAIN_VOLUME_PATH, DWORD Altitude = 0) noexcept(false);
	static void RemoveContainer(const std::wstring& Volume = MAIN_VOLUME_PATH) noexcept(false);
	static void CopyFileUsingWcifs(const std::wstring& SourceFileRelativePath,
	                               const std::wstring& TargetFileRelativePath,
	                               const std::wstring& SourceVolume = MAIN_VOLUME_PATH,
	                               const std::wstring& TargetVolume = MAIN_VOLUME_PATH,
	                               DWORD ReparseTag = IO_REPARSE_TAG_WCI_1) noexcept(false);

	static void SetWciReparsePoint(const std::wstring& SourceFilePath, const std::wstring& TargetFilePath, ULONG ReparseTag) noexcept(false);
	static void SetWciReparsePoint(HANDLE SourceFileHandle, const std::wstring& TargetFile, ULONG ReparseTag) noexcept(false);
	static void RemoveWciReparsePoint(const std::wstring& FilePath, ULONG ReparseTag) noexcept(false);

private:

	// Wcifs related functions
	static void AttachWcifsInstance(const std::wstring& Volume = MAIN_VOLUME_PATH, DWORD Altitude = 0);
	static void RegisterNewContainer(HANDLE SiloHandle, ContainerUsage Usage);
	static void CreateSilo(HANDLE ProcessHandle, PHANDLE SiloHandle);

	// Utility
	static void ValidateReparsePointsSupported();
	static void EnableProcessTokenPrivilege(const std::wstring& PrivilegeName);
	static void BuildDesktopWcifsSetUnionMessage(const std::wstring& SourceVolume, const std::wstring& TargetVolume, WcifsPortMessage** ReturnedMessage, DWORD* MessageSize);
	static void BuildServerWcifsSetUnionContextMessage(const std::wstring& SourceVolume, const std::wstring& TargetVolume, WcifsPortMessage** ReturnedMessage, DWORD* MessageSize);
	static void BuildDesktopWcifsRemoveUnionMessage(const std::wstring& Volume, WcifsPortMessage** ReturnedMessage, DWORD* MessageSize);
	static void BuildDesktopWcifsCopyFileMessage(const std::wstring& SourceFileRelativePath,
		const std::wstring& TargetFileRelativePath,
		const std::wstring& SourceVolume,
		const std::wstring& TargetVolume,
		DWORD ReparseTag,
		WcifsPortMessage** ReturnedMessage, 
		DWORD* MessageSize);
};