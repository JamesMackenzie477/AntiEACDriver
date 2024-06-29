// #include <ntddk.h>
#include <ntifs.h>

// EPROCESS object definition.
typedef struct _EPROCESS_T
{
	PEX_RUNDOWN_REF RundownProtect; // 0x178
	ULONGLONG Wow64Process; // 0x320
	ULONG Flags2; // 0x43C
} EPROCESS_T, *PEPROCESS_T;

// Imports the debug object type.
// extern POBJECT_TYPE *DbgkDebugObjectType;
// ULONG NTAPI DbgkpPostFakeProcessCreateMessages(PVOID pProcess, PVOID pDebug, PVOID* Out);
// NTSTATUS NTAPI DbgkpSetProcessDebugObject(PVOID pProcess, PVOID pDebug, ULONG Result, PVOID In);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

NTSTATUS NTAPI ZwQuerySystemInformation(_In_ ULONG SystemInformationClass, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);

// defines mmcopyvrtualmemory for later use
NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

// struct that contains a programs parameters
typedef struct _IO_PARAMETERS
{
	DWORD64 ProcessId;
	DWORD64 Address;
	SIZE_T Length;
	DWORD64 Data;
} IO_PARAMETERS, *PIO_PARAMETERS;

// struct that contains a programs parameters
typedef struct _DEBUG_PARAMETERS
{
	HANDLE hProcess;
	HANDLE hDebug;
} DEBUG_PARAMETERS, *PDEBUG_PARAMETERS;

// sets up our ioctls
#define HXD_READ_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HXD_WRITE_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HXD_DEBUG_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

// creates our strings
UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\SexyBob");
UNICODE_STRING DeviceLink = RTL_CONSTANT_STRING(L"\\DosDevices\\SexyBob");