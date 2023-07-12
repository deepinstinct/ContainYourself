#pragma once
#include <string>
#include <Windows.h>

const std::wstring WCI_DRIVER_NAME(L"wcifs");
const std::wstring WCI_INSTANCE_NAME(L"wcifs Instance");

// I couldn't determine what these fields represent when reverse-engineering the driver
// When creating a silo that uses the WCI_1 tag, it needs to be 3. For WCI_LINK_1 - 2.
constexpr DWORD TAG_WCI_UNKNOWN_CONST = 3;
constexpr DWORD TAG_WCI_LINK_UNKNOWN_CONST = 2;

constexpr GUID WCIFS_GUID = { 0x8264f677, 0x40b0, 0x4Ca5, { 0xBF, 0x9A, 0x94, 0x4A, 0xC2, 0xDA, 0x80, 0x87 } };

enum WcifsMessageCodes
{
	SetUnionContext = 0,
	CopyFileAsPlaceHolder = 2,
	WcCopyFile = 4,
	RemoveUnionContext = 8,
	SetUnion = 10
};

#pragma pack(1)
struct WcifsReparseDataBuffer
{
	/*0*/  ULONG Version;
	/*4*/  ULONG Reserved; 
	/*8*/  GUID Guid;
	/*24*/ USHORT PathStringLength;
	/*26*/ wchar_t PathStringBuffer[100];
};

struct ReparseDataBuffer
{
	/*0*/ ULONG  ReparseTag;
	/*4*/ USHORT ReparseDataLength;
	/*6*/ USHORT UnparsedNameLength;
	/*8*/ WcifsReparseDataBuffer InternalBuffer;
};

struct ContainerRootId
{
	/*0*/ USHORT Size;
	/*2*/ USHORT Length;
	/*4*/ USHORT MaximumLength;
	/*6*/ wchar_t Buffer[23];
};
#pragma pack(4)

struct VolumeUnion
{
	/*0*/  GUID Guid;
	/*16*/ BOOL IsSourceVolume;
	/*20*/ DWORD OffsetOfVolumeName; // This points to a ContainerRootId structure
	/*24*/ WORD SizeOfVolumeName;
	/*26*/ WORD GuidFlags;
};

struct WcifsPortMessageSetUnionContext
{
	/*0*/   DWORD MessageVersionOrCode;
	/*4*/   DWORD MessageSize;
	/*8*/   DWORD NumberOfUnions;
	/*12*/  wchar_t InstanceName[50];
	/*112*/ DWORD InstanceNameLength;
	/*116*/ DWORD ReparseTag;
	/*120*/ DWORD NotSure;
	/*124*/ DWORD Reserved;
	/*128*/ HANDLE SiloHandle;
	/*136*/ char UnionData[]; // 2 * VolumeUnion & ContainerRootId
};

struct WcifsPortMessageRemoveUnionContext
{
	/*0*/   DWORD MessageVersionOrCode;
	/*4*/   DWORD MessageSize;
	/*8*/   DWORD Reserved1;
	/*12*/  wchar_t InstanceName[50];
	/*112*/ DWORD InstanceNameLength;
	/*116*/ DWORD Reserved2[3];
	/*128*/ char UnionData[];
};

struct WcifsPortMessageSetUnion
{
	/*0*/   DWORD MessageVersionOrCode;
	/*4*/   DWORD MessageSize;
	/*8*/   DWORD NumberOfUnions;
	/*12*/  wchar_t InstanceName[50];
	/*112*/ DWORD InstanceNameLength;
	/*116*/ DWORD ReparseTag;
	/*120*/ DWORD ReparseTagLink;
	/*124*/ DWORD NotSure;
	/*128*/ HANDLE SiloHandle;
	/*136*/ char UnionData[];
};

struct WcifsPortMessageCopyFileHandler
{
	/*0*/   DWORD MessageVersionOrCode;
	/*4*/   DWORD MessageSize;
	/*8*/   wchar_t InstanceName[50];
	/*108*/ DWORD InstanceNameLength;
	/*112*/ DWORD ReparseTag;
	/*116*/ DWORD OffsetToSourceContainerRootId;
	/*120*/ DWORD SizeOfSourceContainerRootId;
	/*124*/ DWORD OffsetToTargetContainerRootId;
	/*128*/ DWORD SizeOfTargetContainerRootId;
	/*132*/ DWORD OffsetToSourceFileRelativePath;
	/*136*/ DWORD SizeOfSourceFileRelativePath;
	/*140*/ DWORD OffsetToTargetFileRelativePath;
	/*144*/ DWORD SizeOfTargetFileRelativePath;
	/*148*/ char UnionData[]; // 2 * ContainerRootId + source & target relative paths
};

struct WcifsPortMessage
{
	/*0*/ DWORD MessageCode;
	/*4*/ DWORD MessageSize;
	/*8*/ char MessageData[];
};

struct WcifsPortMessageOutputBuffer
{
	/*0*/ DWORD Code1;
	/*4*/ DWORD Code2;
	/*8*/ NTSTATUS ReturnStatus;
};

// Server structs

struct WcifsPortMessageSetUnionContextServer
{
	/*0*/   DWORD MessageSize;
	/*4*/   DWORD NumberOfUnions;
	/*8*/   DWORD NotSure;
	/*12*/  DWORD Reserved;
	/*16*/  HANDLE SiloHandle;
	/*24*/  char UnionData[]; // Same as desktop
};

struct WcifsPortMessageCopyFileHandlerServer
{
	/*0*/   DWORD MessageSize;
	/*4*/   DWORD OffsetToSourceContainerRootId;
	/*8*/   DWORD SizeOfSourceContainerRootId;
	/*12*/  DWORD OffsetToTargetContainerRootId;
	/*16*/  DWORD SizeOfTargetContainerRootId;
	/*20*/  DWORD OffsetToSourceFileRelativePath;
	/*24*/  DWORD SizeOfSourceFileRelativePath;
	/*28*/  DWORD OffsetToTargetFileRelativePath;
	/*32*/  DWORD SizeOfTargetFileRelativePath;
	/*36*/  char UnionData[]; // 2 * ContainerRootId + source & target relative paths
};