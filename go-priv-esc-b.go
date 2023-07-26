package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
)

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type PEB struct {
	// You can define other fields from the PEB structure as needed for validation
	BeingDebugged byte
}

func main() {
	// Load the necessary Windows DLLs
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")

	// Get a pointer to the required functions from the loaded DLLs
	openProcess := kernel32.NewProc("OpenProcess")
	queryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
	readProcessMemory := kernel32.NewProc("ReadProcessMemory") // Use kernel32.dll for ReadProcessMemory

	// Define the process ID for the target process
	processID := uintptr(8952) // Replace 1234 with the actual process ID you want to query

	// Open the target process with the PROCESS_QUERY_INFORMATION permission
	processHandle, _, _ := openProcess.Call(uintptr(PROCESS_QUERY_INFORMATION), 0, processID)
	if processHandle == 0 {
		fmt.Println("Failed to open the process. Is process ID correct?")
		return
	}
	defer syscall.CloseHandle(syscall.Handle(processHandle))

	// Query the PEB information
	var processBasicInfo PROCESS_BASIC_INFORMATION
	_, _, _ = queryInformationProcess.Call(processHandle, 0, uintptr(unsafe.Pointer(&processBasicInfo)), unsafe.Sizeof(processBasicInfo), 0)

	fmt.Println("processBasicInfo", processBasicInfo)

	reserved1 := processBasicInfo.Reserved1
	fmt.Println("Reserved1", reserved1)

	pebBaseAddress := processBasicInfo.PebBaseAddress
	fmt.Println("pebBaseAddress", pebBaseAddress)

	reserved2 := processBasicInfo.Reserved2
	fmt.Println("Reserved2", reserved2)

	uniqueProcessId := processBasicInfo.UniqueProcessId
	fmt.Println("uniquProcessId", uniqueProcessId)

	reserved3 := processBasicInfo.Reserved3
	fmt.Println("Reserved3", reserved3)

	// Now you have the PEB base address, and you can access PEB information as needed.

	// Validate the PEB address by accessing the BeingDebugged flag
	var peb PEB
	var bytesRead uintptr
	rpm1, rpm2, err := readProcessMemory.Call(processHandle, pebBaseAddress+0x2, uintptr(unsafe.Pointer(&peb.BeingDebugged)), 1, uintptr(unsafe.Pointer(&bytesRead)))
	fmt.Println("rpm1: ", rpm1)
	fmt.Println("rpm2: ", rpm2)

	if err != nil {
		fmt.Println("Results of ReadProcessMemory:", err)
		return
	}

	if bytesRead != 1 {
		fmt.Println("Bytes read:", bytesRead)
		return
	}

	// If the BeingDebugged flag is set to 1, it indicates that the process is being debugged.
	if peb.BeingDebugged == 1 {
		fmt.Println("Process is being debugged.")
	} else {
		fmt.Println("Process is not being debugged.")
	}

	// Add more validation checks here if needed.
}