#include "HxDriver.h"

// HxDriver
// created by hunter24957
// fuck EAC...

// gets the specified module
PRTL_PROCESS_MODULE_INFORMATION GetModule(LPCSTR lpModule)
{
	// stores the status
	NTSTATUS Status;
	// stores the return length
	ULONG Length = 1000;
	// creates a pool to store the modules
	PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, NULL);
	// ensures the buffer allocated fine
	if (Buffer)
	{
		// gets the kernel module array
		while ((Status = ZwQuerySystemInformation(0x0B, Buffer, Length, &Length)) == 0xC0000004)
		{
			// free the current pool
			ExFreePoolWithTag(Buffer, NULL);
			// creates a pool to store the modules
			Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, NULL);
			// ensures the buffer allocated fine
			if (!Buffer) return NULL;
		}
		// ensures the status of the function is fine
		if (NT_SUCCESS(Status))
		{
			// casts the pointer
			PRTL_PROCESS_MODULES Modules = Buffer;
			// iterates through the modules
			for (int i = 0; i < Modules->NumberOfModules; i++)
			{
				// finds the module
				if (strcmp(Modules->Modules[i].FullPathName, lpModule) == 0)
				{
					// creates a pool to store the module structure
					PRTL_PROCESS_MODULE_INFORMATION Module = ExAllocatePoolWithTag(NonPagedPool, sizeof(RTL_PROCESS_MODULE_INFORMATION), NULL);
					// copies the module information to the new buffer
					memcpy(Module, &Modules->Modules[i], sizeof(RTL_PROCESS_MODULE_INFORMATION));
					// deallocates the pool
					ExFreePoolWithTag(Buffer, NULL);
					// returns the module
					return Module;
				}
			}
		}
		// free the current pool
		ExFreePoolWithTag(Buffer, NULL);
	}
	// function failed
	return NULL;
}

// returns the base address of the kernel
PVOID GetKernelBase()
{
	// returns the kernel base
	return GetModule("\\SystemRoot\\system32\\ntoskrnl.exe")->ImageBase;
}

ULONG NTAPI DbgkpPostFakeProcessCreateMessages(PVOID pProcess, PVOID pDebug, PVOID* Out)
{
	typedef ULONG(NTAPI * _DbgkpPostFakeProcessCreateMessages)(PVOID, PVOID, PVOID*);
	_DbgkpPostFakeProcessCreateMessages Function = (PUCHAR)GetKernelBase() + 0x4C8050;
	return Function(pProcess, pDebug, Out);
}

NTSTATUS NTAPI DbgkpSetProcessDebugObject(PVOID pProcess, PVOID pDebug, ULONG Result, PVOID In)
{
	typedef NTSTATUS(NTAPI * _DbgkpSetProcessDebugObject)(PVOID, PVOID, ULONG, PVOID);
	_DbgkpSetProcessDebugObject Function = (PUCHAR)GetKernelBase() + 0x4C4CC0;
	return Function(pProcess, pDebug, Result, In);
}

// Starts debugging the specified process.
// hProcess - A handle to the process to debug.
// hObject - A handle to the debug object that will be used.
NTSTATUS NtDebugActiveProcess(_In_ HANDLE hProcess, _In_ HANDLE hDebug)
{
	// Stores the function status.
	NTSTATUS Status;
	// Gets the previous processor access mode.
	UCHAR AccessMode = *(UCHAR*)(__readgsqword(0x188) + 0x1F6);
	// Recieves the eprocess pointer.
	PEPROCESS_T pProcess;
	// Gets the eprocess address of the process handle (will lock the object so it can be edited).
	Status = ObReferenceObjectByHandle(hProcess, 0x800, PsProcessType, AccessMode, &pProcess, 0);
	// Validates the status.
	if (NT_SUCCESS(Status))
	{
		// Stores the debug object
		PVOID pDebug;
		// gets the debug object type address
		POBJECT_TYPE **DbgkDebugObjectType = (PUCHAR)GetKernelBase() + 0x204BB8;
		// Gets the object address of the debug object handle.
		Status = ObReferenceObjectByHandle(hDebug, 0x2, *DbgkDebugObjectType, AccessMode, &pDebug, 0);
		// Validates the status.
		if (NT_SUCCESS(Status))
		{
			// Allows us to safely access the eprocess object.
			if (ExAcquireRundownProtection(&pProcess->RundownProtect))
			{
				// Does some stuff with the debug object and the eprocess object.

				// PVOID Out;
				// ULONG Result = DbgkpPostFakeProcessCreateMessages(pProcess, pDebug, &Out);
				// Status = DbgkpSetProcessDebugObject(pProcess, pDebug, Result, Out);

				// Releases the object reference.
				ExReleaseRundownProtection(&pProcess->RundownProtect);
			}
			// Dereferences the debug object.
			ObfDereferenceObject(pDebug);
			// Returns the status.
			Status = STATUS_PROCESS_IS_TERMINATING;
		}
		// Dereferences the process object.
		ObfDereferenceObject(pProcess);
	}
	// Returns the status of the previous function.
	return Status;
}

// reads a processes memory
NTSTATUS HxReadProcessMemory(DWORD64 processId, PVOID targetAddress, PVOID bufferAddress, SIZE_T length, PSIZE_T bytes)
{
	// stores our status
	NTSTATUS status;
	// stores the target process
	PEPROCESS targetProcess;
	// gets the process by id
	status = PsLookupProcessByProcessId(&processId, &targetProcess);
	// checks if the function failed
	if (!NT_SUCCESS(status)) return status;
	// gets our process
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	// copies the memory
	status = MmCopyVirtualMemory(targetProcess, targetAddress, SourceProcess, bufferAddress, length, KernelMode, bytes);
	// returns the status
	return status;
}

// writes to a processes memory
NTSTATUS HxWriteProcessMemory(DWORD64 processId, PVOID targetAddress, PVOID bufferAddress, SIZE_T length, PSIZE_T bytes)
{
	// stores our status
	NTSTATUS status;
	// stores the target process
	PEPROCESS targetProcess;
	// gets the process by id
	status = PsLookupProcessByProcessId(&processId, &targetProcess);
	// checks if the function failed
	if (!NT_SUCCESS(status)) return status;
	// gets our process
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	// copies the memory
	status = MmCopyVirtualMemory(SourceProcess, bufferAddress, targetProcess, targetAddress, length, KernelMode, bytes);
	// returns the status
	return status;
}

// handles our device io polls
NTSTATUS IOHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	// stores our status
	NTSTATUS status;
	// stores our bytes read/written
	SIZE_T Bytes = 0;
	// gets the stack location of our command
	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	// reads the given buffer
	PIO_PARAMETERS Parameters = Irp->AssociatedIrp.SystemBuffer;
	// if the stack location exists
	if (StackLocation)
	{
		// checks the recieved ioctl
		switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
		{
			// if the application wants to read a processes memory
		case HXD_READ_PROCESS_MEMORY:
			// reads a processes memory
			status = HxReadProcessMemory(Parameters->ProcessId, &Parameters->Address, &Parameters->Data, Parameters->Length, &Bytes);
			// breaks out of switch
			break;
			// if the application wants to write to a processes memory
		case HXD_WRITE_PROCESS_MEMORY:
			// writes a processes memory
			status = HxWriteProcessMemory(Parameters->ProcessId, &Parameters->Address, &Parameters->Data, Parameters->Length, &Bytes);
			// breaks out of switch
			break;
			// if the application wants to debug another application
		case HXD_DEBUG_PROCESS:
			// casts the input buffer to the debug parameters
			status = NtDebugActiveProcess(((PDEBUG_PARAMETERS)Parameters)->hProcess, ((PDEBUG_PARAMETERS)Parameters)->hDebug);
			// if there is not a valid ioctl code
		default:
			// sets our job status
			status = STATUS_INVALID_DEVICE_REQUEST;
			// breaks out of switch
			break;
		}
	}
	// sets our job status
	Irp->IoStatus.Status = status;
	// sets our job information
	Irp->IoStatus.Information = Bytes;
	// completes our job request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	// returns our status
	return status;
}

// a handler for when a program calls create file
NTSTATUS CreateHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	// sets our status as successful
	Irp->IoStatus.Status = STATUS_SUCCESS;
	// sets our info to null
	Irp->IoStatus.Information = 0;
	// completes the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	// returns the status
	return STATUS_SUCCESS;
}

// a handler for when a program closes connection
NTSTATUS CloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	// sets our status as successful
	Irp->IoStatus.Status = STATUS_SUCCESS;
	// sets our info to null
	Irp->IoStatus.Information = 0;
	// completes the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	// returns the status
	return STATUS_SUCCESS;
}

// our driver unload routine
VOID Unload(PDRIVER_OBJECT DriverObject)
{
	// deletes our symbolic link
	IoDeleteSymbolicLink(&DeviceLink);
	// deletes our device
	IoDeleteDevice(DriverObject->DeviceObject);
	// notifies the debug
	DbgPrint(("Driver unloaded.\r\n"));
}

// the main entry of the driver
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	// stores our status
	NTSTATUS status;
	// stores our device object
	PDEVICE_OBJECT Device;
	// creates our io device
	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &Device);
	// handles our error
	if (!NT_SUCCESS(status))
	{
		// notify the debug
		KdPrint(("There was a problem creating the device.\r\n"));
		// returns our status to the kernal
		return status;
	}
	// sets the devices symbolic link so programs can communicate with it
	status = IoCreateSymbolicLink(&DeviceLink, &DeviceName);
	// handles our error
	if (!NT_SUCCESS(status))
	{
		// deletes our device
		IoDeleteDevice(Device);
		// notify the debug
		KdPrint(("There was a problem creating a symbolic link.\r\n"));
		// returns our status to the kernal
		return status;
	}
	// sets our unload callback
	DriverObject->DriverUnload = Unload;
	// sets up our io handler function
	// this is what will be called when an application wants to talk
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOHandler;
	// sets our create and close handlers
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseHandler;
	// returns our status to the kernal
	return status;
}