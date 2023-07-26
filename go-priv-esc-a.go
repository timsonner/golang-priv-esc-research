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

func main() {
    // Load the necessary Windows DLL
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    ntdll := syscall.NewLazyDLL("ntdll.dll")

    // Get a pointer to the required functions from the loaded DLLs
    openProcess := kernel32.NewProc("OpenProcess")
    queryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

    // Define the process ID for the target process
    processID := uintptr(8952) // Replace 1234 with the actual process ID you want to query

    // Open the target process with the PROCESS_QUERY_INFORMATION permission
    processHandle, _, _ := openProcess.Call(uintptr(PROCESS_QUERY_INFORMATION), 0, processID)
    if processHandle == 0 {
        fmt.Println("Failed to open the process")
        return
    }
    defer syscall.CloseHandle(syscall.Handle(processHandle))

    // Query the PEB information
    var processBasicInfo PROCESS_BASIC_INFORMATION
    _, _, _ = queryInformationProcess.Call(processHandle, 0, uintptr(unsafe.Pointer(&processBasicInfo)), unsafe.Sizeof(processBasicInfo), 0)

    // Get the PEB base address
    pebBaseAddress := processBasicInfo.PebBaseAddress

    // Now you have the PEB base address, and you can access PEB information as needed.

    // For querying LUA token or permissions, you would need to use additional functions and structures
    // from the Windows API.

    fmt.Printf("PEB Base Address: 0x%X\n", pebBaseAddress)
}
