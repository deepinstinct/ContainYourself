#include "ContainYourself.h"
#include <fltUser.h>
#include <ntstatus.h>
#include <sstream>

#pragma comment (lib, "FltLib.lib")

inline std::string ToHex(const DWORD Number)
{
	std::ostringstream stream;
	stream << "0x" << std::hex << Number;
	return std::string(stream.str());
}

void ContainYourself::InitContainer(const HANDLE ProcessHandle, const ContainerUsage Usage,
                                    const PHANDLE SiloHandlePointer, const std::wstring& Volume, const DWORD Altitude) noexcept(false)
{
	try
	{
		CreateSilo(ProcessHandle, SiloHandlePointer);
	}
	catch (...)
	{
		if (*SiloHandlePointer)
			CloseHandle(*SiloHandlePointer);

		throw;
	}

	InitContainerUsingSilo(*SiloHandlePointer, Usage, Volume, Altitude);
}

void ContainYourself::InitContainerUsingSilo(const HANDLE SiloHandle, const ContainerUsage Usage, const std::wstring& Volume, const DWORD Altitude) noexcept(false)
{
	ValidateReparsePointsSupported();

	if (IS_SERVER_OS && ContainerUsage::FileLinking == Usage)
		throw std::runtime_error("[ContainYourself::InitContainer] File linking not supported on server OSs");

	if (ContainerUsage::FileOverride == Usage)
		EnableProcessTokenPrivilege(L"SeManageVolumePrivilege");

	AttachWcifsInstance(Volume, Altitude);

	RegisterNewContainer(SiloHandle, Usage);
}

void ContainYourself::RemoveContainer(const std::wstring& Volume) noexcept(false)
{
	WcifsPortMessage* messageHeader = nullptr;
	DWORD messageSize = 0;
	BuildDesktopWcifsRemoveUnionMessage(Volume, &messageHeader, &messageSize);

	std::unique_ptr<BYTE> messageReleaser(reinterpret_cast<BYTE*>(messageHeader));

	HANDLE portHandle;
	auto hResult = FilterConnectCommunicationPort(L"\\WcifsPort", FLT_PORT_FLAG_SYNC_HANDLE, nullptr, 0, nullptr,
	                                              &portHandle);
	if (FAILED(hResult))
		throw std::runtime_error(
			"[ContainYourself::RegisterNewContainer] Error connecting to wcifs minifilter. HRESULT: " +
			ToHex(hResult));

	WcifsPortMessageOutputBuffer wcifsOutputBuffer{};
	DWORD bytesReturned;
	hResult = FilterSendMessage(portHandle, messageHeader, messageSize, &wcifsOutputBuffer,
	                            sizeof(WcifsPortMessageOutputBuffer), &bytesReturned);
	if (!SUCCEEDED(hResult) || bytesReturned != sizeof(WcifsPortMessageOutputBuffer))
		throw std::runtime_error(
			"[ContainYourself::RegisterNewContainer] Error sending message to wcifs minifilter. HRESULT: " +
			ToHex(hResult));

	if (STATUS_SUCCESS != wcifsOutputBuffer.ReturnStatus)
		throw std::runtime_error(
			"[ContainYourself::RegisterNewContainer] Wcifs failed to parse message. Returned NT_STATUS: " +
			ToHex(wcifsOutputBuffer.ReturnStatus));
}

void ContainYourself::CopyFileUsingWcifs(const std::wstring& SourceFileRelativePath,
                                         const std::wstring& TargetFileRelativePath, const std::wstring& SourceVolume,
                                         const std::wstring& TargetVolume, const DWORD ReparseTag) noexcept(false)
{
	AttachWcifsInstance(SourceVolume);
	AttachWcifsInstance(TargetVolume);

	WcifsPortMessage* messageHeader = nullptr;
	DWORD messageSize = 0;
	BuildDesktopWcifsCopyFileMessage(SourceFileRelativePath, TargetFileRelativePath, SourceVolume, TargetVolume,
	                                 ReparseTag, &messageHeader, &messageSize);

	std::unique_ptr<BYTE> messageReleaser(reinterpret_cast<BYTE*>(messageHeader));

	HANDLE portHandle;
	auto hResult = FilterConnectCommunicationPort(L"\\WcifsPort", FLT_PORT_FLAG_SYNC_HANDLE, nullptr, 0, nullptr,
	                                              &portHandle);
	if (FAILED(hResult))
		throw std::runtime_error(
			"[ContainYourself::CopyFileUsingWcifs] Error connecting to wcifs minifilter. HRESULT: " +
			ToHex(hResult));

	WcifsPortMessageOutputBuffer wcifsOutputBuffer{};
	DWORD bytesReturned;
	hResult = FilterSendMessage(portHandle, messageHeader, messageSize, &wcifsOutputBuffer,
	                            sizeof(WcifsPortMessageOutputBuffer), &bytesReturned);
	if (!SUCCEEDED(hResult) || bytesReturned != sizeof(WcifsPortMessageOutputBuffer))
		throw std::runtime_error(
			"[ContainYourself::CopyFileUsingWcifs] Error sending message to wcifs minifilter. HRESULT: " +
			ToHex(hResult));

	if (STATUS_SUCCESS != wcifsOutputBuffer.ReturnStatus)
		throw std::runtime_error(
			"[ContainYourself::CopyFileUsingWcifs] Wcifs failed to parse message. Returned NT_STATUS: " +
			ToHex(wcifsOutputBuffer.ReturnStatus));
}

void ContainYourself::SetWciReparsePoint(const std::wstring& SourceFilePath, const std::wstring& TargetFilePath,
                                         const ULONG ReparseTag) noexcept(false)
{
	const auto sourceFileHandle = CreateFileW(SourceFilePath.c_str(),
	                                          GENERIC_READ | GENERIC_WRITE,
	                                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
	                                          nullptr,
	                                          OPEN_EXISTING,
	                                          FILE_ATTRIBUTE_NORMAL,
	                                          nullptr);

	if (INVALID_HANDLE_VALUE == sourceFileHandle)
		throw std::runtime_error(
			"[ContainYourself::SetWciReparsePoint] Error opening source file: " + ToHex(GetLastError()));

	SetWciReparsePoint(sourceFileHandle, TargetFilePath, ReparseTag);

	CloseHandle(sourceFileHandle);
}

void ContainYourself::SetWciReparsePoint(const HANDLE SourceFileHandle, const std::wstring& TargetFile,
                                         const ULONG ReparseTag) noexcept(false)
{
	ReparseDataBuffer reparseDataBuffer{};
	reparseDataBuffer.ReparseTag = ReparseTag;
	reparseDataBuffer.ReparseDataLength = sizeof(WcifsReparseDataBuffer);

	reparseDataBuffer.InternalBuffer.Version = 1;
	reparseDataBuffer.InternalBuffer.Guid = WCIFS_GUID;
	reparseDataBuffer.InternalBuffer.PathStringLength = TargetFile.length() * sizeof(WCHAR);
	memcpy(reparseDataBuffer.InternalBuffer.PathStringBuffer, TargetFile.c_str(),
	       reparseDataBuffer.InternalBuffer.PathStringLength);

	const auto device = DeviceIoControl(SourceFileHandle,
	                                    FSCTL_SET_REPARSE_POINT,
	                                    &reparseDataBuffer,
	                                    sizeof(ReparseDataBuffer),
	                                    nullptr,
	                                    0,
	                                    nullptr,
	                                    nullptr);

	if (!device)
		throw std::runtime_error("[ContainYourself::SetWciReparsePoint] Error setting file's reparse point");
}

void ContainYourself::RemoveWciReparsePoint(const std::wstring& FilePath, const ULONG ReparseTag) noexcept(false)
{
	const auto fileHandle = CreateFileW(FilePath.c_str(),
	                                    GENERIC_READ | GENERIC_WRITE,
	                                    0,
	                                    nullptr,
	                                    OPEN_EXISTING,
	                                    FILE_FLAG_OPEN_REPARSE_POINT,
	                                    nullptr);

	if (INVALID_HANDLE_VALUE == fileHandle)
		throw std::runtime_error(
			"[ContainYourself::RemoveWciReparsePoint] Error opening source file: " + ToHex(GetLastError()));

	ReparseDataBuffer reparseDataBuffer{};
	reparseDataBuffer.ReparseTag = ReparseTag;

	const auto device = DeviceIoControl(fileHandle,
	                                    FSCTL_DELETE_REPARSE_POINT,
	                                    &reparseDataBuffer,
	                                    sizeof(ReparseDataBuffer) - sizeof(WcifsReparseDataBuffer),
	                                    nullptr,
	                                    0,
	                                    nullptr,
	                                    nullptr);

	CloseHandle(fileHandle);

	if (!device)
		throw std::runtime_error("[ContainYourself::RemoveWciReparsePoint] Error deleting file's reparse point");
}

// ----------------------- Wcifs ----------------------- //

void ContainYourself::AttachWcifsInstance(const std::wstring& Volume, const DWORD Altitude)
{
	char buffer[1024];
	const auto instanceBasicInfo = reinterpret_cast<INSTANCE_FULL_INFORMATION*>(&buffer);

	// Traverse all loaded minifilter instances and look for wcifs.sys
	DWORD bytesReturned = 0;
	auto filterInstanceHandle = INVALID_HANDLE_VALUE;
	auto hResult = FilterInstanceFindFirst(
		WCI_DRIVER_NAME.c_str(),
		InstanceFullInformation,
		instanceBasicInfo,
		sizeof(buffer),
		&bytesReturned,
		&filterInstanceHandle);
	if (S_OK != hResult && HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) != hResult && HRESULT_FROM_WIN32(
		ERROR_FLT_FILTER_NOT_FOUND) != hResult)
		throw std::runtime_error(
			"[ContainYourself::AttachWcifsInstance] Error in FilterInstanceFindFirst. HRESULT: " +
			ToHex(hResult));

	auto instanceFound = false;
	do
	{
		if (0 == bytesReturned)
			break;

		std::wstring instanceName(
			reinterpret_cast<wchar_t*>(reinterpret_cast<char*>(instanceBasicInfo) + instanceBasicInfo->
				InstanceNameBufferOffset),
			instanceBasicInfo->InstanceNameLength / sizeof(wchar_t));

		std::wstring volumeName(
			reinterpret_cast<wchar_t*>(reinterpret_cast<char*>(instanceBasicInfo) + instanceBasicInfo->
				VolumeNameBufferOffset),
			instanceBasicInfo->VolumeNameLength / sizeof(wchar_t));

		if (WCI_INSTANCE_NAME == instanceName && Volume == volumeName)
		{
			instanceFound = true;
			break;
		}

		hResult = FilterInstanceFindNext(
			filterInstanceHandle,
			InstanceFullInformation,
			instanceBasicInfo,
			sizeof(buffer),
			&bytesReturned);
		if (S_OK != hResult)
			break;
	}
	while (true);

	if (instanceFound)
	{
		// Instance found
		FilterInstanceFindClose(filterInstanceHandle);
		return;
	}

	// If the driver is not loaded, gain SeLoadDriverPrivilege privilege and load it manually

	EnableProcessTokenPrivilege(L"SeLoadDriverPrivilege");

	hResult = FilterLoad(WCI_DRIVER_NAME.c_str());
	if (S_OK != hResult && HRESULT_FROM_WIN32(ERROR_SERVICE_ALREADY_RUNNING) != hResult && HRESULT_FROM_WIN32(
		ERROR_ALREADY_EXISTS) != hResult)
		throw std::runtime_error(
			"[ContainYourself::AttachWcifsInstance] Error when loading wcifs minifilter. HRESULT: " +
			ToHex(hResult));

	if (Altitude)
	{
		hResult = FilterAttachAtAltitude(
			WCI_DRIVER_NAME.c_str(),
			Volume.c_str(),
			std::to_wstring(Altitude).c_str(),
			WCI_INSTANCE_NAME.c_str(),
			WCI_INSTANCE_NAME.size(),
			nullptr);
	}
	else
	{
		hResult = FilterAttach(
			WCI_DRIVER_NAME.c_str(),
			Volume.c_str(),
			WCI_INSTANCE_NAME.c_str(),
			WCI_INSTANCE_NAME.size(),
			nullptr);
	}

	if (S_OK != hResult)
		throw std::runtime_error(
			"[ContainYourself::AttachWcifsInstance] Error when attaching wcifs minifilter. HRESULT: " +
			ToHex(hResult));
}

void ContainYourself::CreateSilo(const HANDLE ProcessHandle, const PHANDLE SiloHandle)
{
	SECURITY_ATTRIBUTES securityAttributes;
	securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	securityAttributes.lpSecurityDescriptor = nullptr;
	securityAttributes.bInheritHandle = 0;

	*SiloHandle = CreateJobObjectW(&securityAttributes, L"ContainYourselfJob");
	if (nullptr == *SiloHandle)
		throw std::runtime_error(
			"[ContainYourself::CreateSilo] Error creating job object: " + ToHex(GetLastError()));

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobExtendedInfo{};
	jobExtendedInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
	if (!SetInformationJobObject(*SiloHandle, JobObjectExtendedLimitInformation, &jobExtendedInfo,
	                             sizeof(jobExtendedInfo)))
		throw std::runtime_error(
			"[ContainYourself::CreateSilo] Error setting job information: " + ToHex(GetLastError()));

	if (!SetInformationJobObject(*SiloHandle, JobObjectCreateSilo, nullptr, 0))
		throw std::runtime_error(
			"[ContainYourself::CreateSilo] Error converting job to a silo: " + ToHex(GetLastError()));

	if (!AssignProcessToJobObject(*SiloHandle, ProcessHandle))
		throw std::runtime_error(
			"[ContainYourself::CreateSilo] Error assigning the process to the new silo: " + ToHex(
				GetLastError()));
}

void ContainYourself::RegisterNewContainer(const HANDLE SiloHandle, const ContainerUsage Usage)
{
	WcifsPortMessage* messageHeader = nullptr;
	DWORD messageSize = 0;

	switch (Usage)
	{
	case ContainerUsage::FileLinking:
		BuildDesktopWcifsSetUnionMessage(MAIN_VOLUME_PATH, MAIN_VOLUME_PATH, &messageHeader, &messageSize);
		reinterpret_cast<WcifsPortMessageSetUnion*>(&messageHeader->MessageData)->SiloHandle = SiloHandle;
		reinterpret_cast<WcifsPortMessageSetUnion*>(&messageHeader->MessageData)->NotSure = TAG_WCI_LINK_UNKNOWN_CONST;

		break;

	case ContainerUsage::FileOverride:
		if (IS_SERVER_OS)
		{
			BuildServerWcifsSetUnionContextMessage(MAIN_VOLUME_PATH, MAIN_VOLUME_PATH, &messageHeader, &messageSize);
			reinterpret_cast<WcifsPortMessageSetUnionContextServer*>(&messageHeader->MessageData)->SiloHandle =
				SiloHandle;
			reinterpret_cast<WcifsPortMessageSetUnionContextServer*>(&messageHeader->MessageData)->NotSure =
				TAG_WCI_UNKNOWN_CONST;
		}
		else
		{
			BuildDesktopWcifsSetUnionMessage(MAIN_VOLUME_PATH, MAIN_VOLUME_PATH, &messageHeader, &messageSize);
			reinterpret_cast<WcifsPortMessageSetUnion*>(&messageHeader->MessageData)->SiloHandle = SiloHandle;
			reinterpret_cast<WcifsPortMessageSetUnion*>(&messageHeader->MessageData)->NotSure = TAG_WCI_UNKNOWN_CONST;
		}

		break;

	default:
		throw std::runtime_error("[ContainYourself::RegisterNewContainer] Unknown ContainerUsage value.");
	}

	std::unique_ptr<BYTE> messageReleaser(reinterpret_cast<BYTE*>(messageHeader));

	HANDLE portHandle;
	auto hResult = FilterConnectCommunicationPort(L"\\WcifsPort", FLT_PORT_FLAG_SYNC_HANDLE, nullptr, 0, nullptr,
	                                              &portHandle);
	if (FAILED(hResult))
		throw std::runtime_error(
			"[ContainYourself::RegisterNewContainer] Error connecting to wcifs minifilter. HRESULT: " +
			ToHex(hResult));


	WcifsPortMessageOutputBuffer wcifsOutputBuffer{};
	DWORD bytesReturned;
	hResult = FilterSendMessage(portHandle, messageHeader, messageSize, &wcifsOutputBuffer,
	                            sizeof(WcifsPortMessageOutputBuffer), &bytesReturned);
	if (!SUCCEEDED(hResult) || bytesReturned != sizeof(WcifsPortMessageOutputBuffer))
		throw std::runtime_error(
			"[ContainYourself::RegisterNewContainer] Error sending message to wcifs minifilter. HRESULT: " +
			ToHex(hResult));

	if (STATUS_SUCCESS != wcifsOutputBuffer.ReturnStatus)
		throw std::runtime_error(
			"[ContainYourself::RegisterNewContainer] Wcifs failed to parse message. Returned NT_STATUS: " +
			ToHex(wcifsOutputBuffer.ReturnStatus));
}

// ---------------------- Utility ---------------------- //

void ContainYourself::ValidateReparsePointsSupported()
{
	// Check if the file system supports reparse points
	DWORD fileSystemFlags;
	if (!GetVolumeInformationA(nullptr,
	                           nullptr,
	                           0,
	                           nullptr,
	                           nullptr,
	                           &fileSystemFlags,
	                           nullptr,
	                           0))
		throw std::runtime_error(
			"[ContainYourself::ValidateReparsePointsSupported] Error retrieving volume information: " + ToHex(
				GetLastError()));


	if (!(fileSystemFlags & FILE_SUPPORTS_REPARSE_POINTS))
		throw std::runtime_error(
			"[ContainYourself::ValidateReparsePointsSupported] File system does not support reparse points: " +
			ToHex(GetLastError()));
}

void ContainYourself::EnableProcessTokenPrivilege(const std::wstring& PrivilegeName)
{
	TOKEN_PRIVILEGES tokenPrivileges{};
	LUID luid;

	if (!LookupPrivilegeValueW(nullptr, PrivilegeName.c_str(), &luid))
		throw std::runtime_error(
			"[ContainYourself::EnableProcessTokenPrivilege] Error when looking privilage value: " + ToHex(
				GetLastError()));

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	HANDLE tokenHandle = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES, &tokenHandle))
		throw std::runtime_error(
			"[ContainYourself::EnableProcessTokenPrivilege] Error when opening process token: " + ToHex(
				GetLastError()));

	if (!AdjustTokenPrivileges(tokenHandle, false, &tokenPrivileges, sizeof(tokenPrivileges), nullptr, nullptr))
		throw std::runtime_error(
			"[ContainYourself::EnableProcessTokenPrivilege] Error when adjusting token privileges: " + ToHex(
				GetLastError()));
}

void ContainYourself::BuildDesktopWcifsSetUnionMessage(const std::wstring& SourceVolume,
                                                       const std::wstring& TargetVolume,
                                                       WcifsPortMessage** ReturnedMessage, DWORD* MessageSize)
{
	*MessageSize = sizeof(WcifsPortMessage) + sizeof(WcifsPortMessageSetUnion) + 2 * (sizeof(VolumeUnion) + sizeof(
		ContainerRootId));
	const auto message = reinterpret_cast<WcifsPortMessage*>(new BYTE[*MessageSize]);

	message->MessageCode = SetUnion;
	message->MessageSize = *MessageSize;

	const auto messageData = reinterpret_cast<WcifsPortMessageSetUnion*>(&message->MessageData);
	messageData->MessageVersionOrCode = 1;
	messageData->MessageSize = *MessageSize - sizeof(WcifsPortMessage);
	messageData->NumberOfUnions = 2;
	messageData->InstanceNameLength = WCI_INSTANCE_NAME.length() * sizeof(wchar_t);
	memcpy(messageData->InstanceName, WCI_INSTANCE_NAME.c_str(), messageData->InstanceNameLength);
	messageData->ReparseTag = IO_REPARSE_TAG_WCI_1;
	messageData->ReparseTagLink = IO_REPARSE_TAG_WCI_LINK_1;

	const auto sourceVolumeUnion = reinterpret_cast<VolumeUnion*>(&messageData->UnionData);
	sourceVolumeUnion->Guid = WCIFS_GUID;
	sourceVolumeUnion->IsSourceVolume = true;
	sourceVolumeUnion->SizeOfVolumeName = sizeof(ContainerRootId);
	sourceVolumeUnion->GuidFlags = 0;

	const auto targetVolumeUnion = reinterpret_cast<VolumeUnion*>(reinterpret_cast<char*>(&messageData->UnionData) +
		sizeof(VolumeUnion));
	targetVolumeUnion->Guid = WCIFS_GUID;
	targetVolumeUnion->IsSourceVolume = false;
	targetVolumeUnion->SizeOfVolumeName = sizeof(ContainerRootId);
	targetVolumeUnion->GuidFlags = 0;

	const auto sourceContainerRootId = reinterpret_cast<ContainerRootId*>(reinterpret_cast<char*>(targetVolumeUnion) +
		sizeof(VolumeUnion));
	sourceContainerRootId->Size = sizeof(ContainerRootId);
	sourceContainerRootId->Length = SourceVolume.length() * sizeof(wchar_t);
	sourceContainerRootId->MaximumLength = sourceContainerRootId->Length;
	memcpy(sourceContainerRootId->Buffer, SourceVolume.c_str(), sourceContainerRootId->Length);

	const auto targetContainerRootId = reinterpret_cast<ContainerRootId*>(reinterpret_cast<char*>(sourceContainerRootId)
		+ sizeof(ContainerRootId));
	targetContainerRootId->Size = sizeof(ContainerRootId);
	targetContainerRootId->Length = TargetVolume.length() * sizeof(wchar_t);
	targetContainerRootId->MaximumLength = targetContainerRootId->Length;
	memcpy(targetContainerRootId->Buffer, TargetVolume.c_str(), targetContainerRootId->Length);

	sourceVolumeUnion->OffsetOfVolumeName = static_cast<DWORD>(reinterpret_cast<char*>(sourceContainerRootId) -
		reinterpret_cast<char*>(messageData));
	targetVolumeUnion->OffsetOfVolumeName = static_cast<DWORD>(reinterpret_cast<char*>(targetContainerRootId) -
		reinterpret_cast<char*>(messageData));

	*ReturnedMessage = message;
}

void ContainYourself::BuildServerWcifsSetUnionContextMessage(const std::wstring& SourceVolume,
                                                             const std::wstring& TargetVolume,
                                                             WcifsPortMessage** ReturnedMessage, DWORD* MessageSize)
{
	*MessageSize = sizeof(WcifsPortMessage) + sizeof(WcifsPortMessageSetUnionContextServer) + 2 * (sizeof(VolumeUnion) +
		sizeof(ContainerRootId));
	const auto message = reinterpret_cast<WcifsPortMessage*>(new BYTE[*MessageSize]);

	message->MessageCode = SetUnionContext;
	message->MessageSize = *MessageSize;

	const auto messageData = reinterpret_cast<WcifsPortMessageSetUnionContextServer*>(&message->MessageData);
	messageData->MessageSize = *MessageSize - sizeof(WcifsPortMessage);
	messageData->NumberOfUnions = 2;

	const auto sourceVolumeUnion = reinterpret_cast<VolumeUnion*>(&messageData->UnionData);
	sourceVolumeUnion->Guid = WCIFS_GUID;
	sourceVolumeUnion->IsSourceVolume = true;
	sourceVolumeUnion->SizeOfVolumeName = sizeof(ContainerRootId);
	sourceVolumeUnion->GuidFlags = 0;

	const auto targetVolumeUnion = reinterpret_cast<VolumeUnion*>(reinterpret_cast<char*>(&messageData->UnionData) +
		sizeof(VolumeUnion));
	targetVolumeUnion->Guid = WCIFS_GUID;
	targetVolumeUnion->IsSourceVolume = false;
	targetVolumeUnion->SizeOfVolumeName = sizeof(ContainerRootId);
	targetVolumeUnion->GuidFlags = 0;

	const auto sourceContainerRootId = reinterpret_cast<ContainerRootId*>(reinterpret_cast<char*>(targetVolumeUnion) +
		sizeof(VolumeUnion));
	sourceContainerRootId->Size = sizeof(ContainerRootId);
	sourceContainerRootId->Length = SourceVolume.length() * sizeof(wchar_t);
	sourceContainerRootId->MaximumLength = sourceContainerRootId->Length;
	memcpy(sourceContainerRootId->Buffer, SourceVolume.c_str(), sourceContainerRootId->Length);

	const auto targetContainerRootId = reinterpret_cast<ContainerRootId*>(reinterpret_cast<char*>(sourceContainerRootId)
		+ sizeof(ContainerRootId));
	targetContainerRootId->Size = sizeof(ContainerRootId);
	targetContainerRootId->Length = TargetVolume.length() * sizeof(wchar_t);
	targetContainerRootId->MaximumLength = targetContainerRootId->Length;
	memcpy(targetContainerRootId->Buffer, TargetVolume.c_str(), targetContainerRootId->Length);

	sourceVolumeUnion->OffsetOfVolumeName = static_cast<DWORD>(reinterpret_cast<char*>(sourceContainerRootId) -
		reinterpret_cast<char*>(messageData));
	targetVolumeUnion->OffsetOfVolumeName = static_cast<DWORD>(reinterpret_cast<char*>(targetContainerRootId) -
		reinterpret_cast<char*>(messageData));

	*ReturnedMessage = message;
}

void ContainYourself::BuildDesktopWcifsRemoveUnionMessage(const std::wstring& Volume,
                                                          WcifsPortMessage** ReturnedMessage, DWORD* MessageSize)
{
	*MessageSize = sizeof(WcifsPortMessage) + sizeof(WcifsPortMessageRemoveUnionContext) + sizeof(VolumeUnion) + sizeof(
		ContainerRootId);
	const auto message = reinterpret_cast<WcifsPortMessage*>(new BYTE[*MessageSize]);

	memset(message, 0, *MessageSize);

	message->MessageCode = RemoveUnionContext;
	message->MessageSize = *MessageSize;

	const auto messageData = reinterpret_cast<WcifsPortMessageRemoveUnionContext*>(&message->MessageData);
	messageData->MessageVersionOrCode = 160;
	messageData->InstanceNameLength = WCI_INSTANCE_NAME.length() * sizeof(wchar_t);
	memcpy(messageData->InstanceName, WCI_INSTANCE_NAME.c_str(), messageData->InstanceNameLength);
	messageData->MessageSize = *MessageSize - sizeof(WcifsPortMessage);

	const auto sourceVolumeUnion = reinterpret_cast<VolumeUnion*>(&messageData->UnionData);
	sourceVolumeUnion->Guid = WCIFS_GUID;
	sourceVolumeUnion->IsSourceVolume = true;
	sourceVolumeUnion->SizeOfVolumeName = sizeof(ContainerRootId);
	sourceVolumeUnion->GuidFlags = 0;

	const auto sourceContainerRootId = reinterpret_cast<ContainerRootId*>(reinterpret_cast<char*>(sourceVolumeUnion) +
		sizeof(VolumeUnion));
	sourceContainerRootId->Size = sizeof(ContainerRootId);
	sourceContainerRootId->Length = Volume.length() * sizeof(wchar_t);
	sourceContainerRootId->MaximumLength = sourceContainerRootId->Length;
	memcpy(sourceContainerRootId->Buffer, Volume.c_str(), sourceContainerRootId->Length);

	sourceVolumeUnion->OffsetOfVolumeName = static_cast<DWORD>(reinterpret_cast<char*>(sourceContainerRootId) -
		reinterpret_cast<char*>(messageData));

	*ReturnedMessage = message;
}

void ContainYourself::BuildDesktopWcifsCopyFileMessage(const std::wstring& SourceFileRelativePath,
                                                       const std::wstring& TargetFileRelativePath,
                                                       const std::wstring& SourceVolume,
                                                       const std::wstring& TargetVolume,
                                                       const DWORD ReparseTag, WcifsPortMessage** ReturnedMessage,
                                                       DWORD* MessageSize)
{
	const auto sizeOfSourceFileRelativePath = SourceFileRelativePath.size() * sizeof(wchar_t);
	const auto sizeOfTargetFileRelativePath = TargetFileRelativePath.size() * sizeof(wchar_t);

	*MessageSize = sizeof(WcifsPortMessage) + sizeof(WcifsPortMessageCopyFileHandler) + 2 * sizeof(ContainerRootId) +
		sizeOfSourceFileRelativePath + sizeOfTargetFileRelativePath;

	const auto message = reinterpret_cast<WcifsPortMessage*>(new BYTE[*MessageSize]);

	memset(message, 0, *MessageSize);

	message->MessageCode = WcCopyFile;
	message->MessageSize = *MessageSize;

	const auto messageData = reinterpret_cast<WcifsPortMessageCopyFileHandler*>(&message->MessageData);
	messageData->MessageVersionOrCode = 148;
	messageData->InstanceNameLength = WCI_INSTANCE_NAME.length() * sizeof(wchar_t);
	memcpy(messageData->InstanceName, WCI_INSTANCE_NAME.c_str(), messageData->InstanceNameLength);
	messageData->MessageSize = *MessageSize - sizeof(WcifsPortMessage);
	messageData->ReparseTag = ReparseTag;

	const auto sourceContainerRootId = reinterpret_cast<ContainerRootId*>(&messageData->UnionData);
	sourceContainerRootId->Size = sizeof(ContainerRootId);
	sourceContainerRootId->Length = SourceVolume.length() * sizeof(wchar_t);
	sourceContainerRootId->MaximumLength = sourceContainerRootId->Length;
	memcpy(sourceContainerRootId->Buffer, SourceVolume.c_str(), sourceContainerRootId->Length);

	const auto targetContainerRootId = reinterpret_cast<ContainerRootId*>(reinterpret_cast<char*>(sourceContainerRootId)
		+ sizeof(ContainerRootId));
	targetContainerRootId->Size = sizeof(ContainerRootId);
	targetContainerRootId->Length = TargetVolume.length() * sizeof(wchar_t);
	targetContainerRootId->MaximumLength = targetContainerRootId->Length;
	memcpy(targetContainerRootId->Buffer, TargetVolume.c_str(), targetContainerRootId->Length);

	const auto sourceFileRelativePath = reinterpret_cast<char*>(targetContainerRootId) + sizeof(ContainerRootId);
	memcpy(sourceFileRelativePath, SourceFileRelativePath.c_str(), sizeOfSourceFileRelativePath);

	const auto targetFileRelativePath = reinterpret_cast<char*>(sourceFileRelativePath) + sizeOfSourceFileRelativePath;
	memcpy(targetFileRelativePath, TargetFileRelativePath.c_str(), sizeOfTargetFileRelativePath);

	messageData->OffsetToSourceContainerRootId = static_cast<DWORD>(reinterpret_cast<char*>(sourceContainerRootId) -
		reinterpret_cast<char*>(messageData));
	messageData->SizeOfSourceContainerRootId = sizeof(ContainerRootId);

	messageData->OffsetToTargetContainerRootId = static_cast<DWORD>(reinterpret_cast<char*>(targetContainerRootId) -
		reinterpret_cast<char*>(messageData));
	messageData->SizeOfTargetContainerRootId = sizeof(ContainerRootId);

	messageData->OffsetToSourceFileRelativePath = static_cast<DWORD>(reinterpret_cast<char*>(sourceFileRelativePath) -
		reinterpret_cast<char*>(messageData));
	messageData->SizeOfSourceFileRelativePath = sizeOfSourceFileRelativePath;

	messageData->OffsetToTargetFileRelativePath = static_cast<DWORD>(reinterpret_cast<char*>(targetFileRelativePath) -
		reinterpret_cast<char*>(messageData));
	messageData->SizeOfTargetFileRelativePath = sizeOfTargetFileRelativePath;

	*ReturnedMessage = message;
}
