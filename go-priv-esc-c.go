package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	MAX_PATH                  = 260

	SE_PRIVILEGE_ENABLED = 0x00000002
)

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type PEB struct {
	BeingDebugged      byte
	Reserved1          [7]byte // Adjust the size based on x64 or x86 architecture
	Reserved2          [2]uintptr
	ProcessParameters  uintptr
	Reserved3          [520]byte // Adjust the size based on x64 or x86 architecture
	SessionId          uintptr
	Reserved4          [8]byte // Adjust the size based on x64 or x86 architecture
	NumberOfProcessors uintptr
}

type RTL_USER_PROCESS_PARAMETERS struct {
	Reserved1         [16]byte // Adjust the size based on x64 or x86 architecture
	Reserved2         [10]uintptr
	ImagePathName     UNICODE_STRING
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// Declare external Windows API functions
var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modntdll    = syscall.NewLazyDLL("ntdll.dll")

	procOpenProcess             = modkernel32.NewProc("OpenProcess")
	procReadProcessMemory       = modkernel32.NewProc("ReadProcessMemory")
	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
	procQueryFullProcessImageName = modkernel32.NewProc("QueryFullProcessImageNameW")
)

// Define PROCESS_ACCESS_RIGHTS for different versions of Windows
var PROCESS_ACCESS_RIGHTS uint32

func init() {
	// Set the PROCESS_ACCESS_RIGHTS based on the current Windows version
	v, _ := syscall.GetVersion()
	if v&0xFF >= 6 {
		PROCESS_ACCESS_RIGHTS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
	} else {
		PROCESS_ACCESS_RIGHTS = 0x0400 | 0x0010
	}
}

// Function to get the process image file name
func getProcessImageFileName(processHandle syscall.Handle) (string, error) {
	buffer := make([]uint16, MAX_PATH)
	var bufferSize uint32 = MAX_PATH
	ret, _, err := procQueryFullProcessImageName.Call(uintptr(processHandle), uintptr(0), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&bufferSize)))
	if ret == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buffer), nil
}

func main() {
	// Define the process ID for the target process
	processID := uintptr(8952) // Replace 1234 with the actual process ID you want to query

	// Open the target process with the required permissions
	processHandle, err := syscall.OpenProcess(PROCESS_ACCESS_RIGHTS, false, uint32(processID))
	if err != nil {
		fmt.Println("Failed to open the process. Is the process ID correct?")
		return
	}
	defer syscall.CloseHandle(processHandle)

	// Query the PEB information
	var processBasicInfo PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	status, _, _ := procNtQueryInformationProcess.Call(uintptr(processHandle), 0, uintptr(unsafe.Pointer(&processBasicInfo)), unsafe.Sizeof(processBasicInfo), uintptr(unsafe.Pointer(&returnLength)))
	if status != 0 {
		fmt.Println("Error calling NtQueryInformationProcess:", status)
		return
	}

	// Read the entire PEB structure from memory
	var peb PEB
	var bytesRead uintptr
	status, _, _ = procReadProcessMemory.Call(uintptr(processHandle), processBasicInfo.PebBaseAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&bytesRead)))
	if status == 0 || bytesRead != unsafe.Sizeof(peb) {
		fmt.Println("Error calling ReadProcessMemory (PEB):", status)
		return
	}

	// Print the PEB fields
	fmt.Println("BeingDebugged:", peb.BeingDebugged)
	fmt.Println("NumberOfProcessors:", peb.NumberOfProcessors)

	// Get the process image file name
	imagePath, err := getProcessImageFileName(processHandle)
	if err != nil {
		fmt.Println("Error getting process image file name:", err)
	} else {
		fmt.Println("ImagePathName:", imagePath)
	}

	// Add more fields here as needed

	// Add more validation checks here if needed.
}
