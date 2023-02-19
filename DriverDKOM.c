void DriverDKOM(PDRIVER_OBJECT pDriver, ULONG64 kernelBase, ULONG64 kernelSize)
{

  typedef NTSTATUS(NTAPI* pMiProcessLoaderEntry)(PVOID pDriverSection, int bLoad);
  pMiProcessLoaderEntry MiProcessLoaderEntry;
  
  // If function is not exported by the kernel, you don't need to import the function directly to be able to call it. You can, for example, pattern scan for the function, cast the returned address to a typedef function type, 
	// and then call that. 

	// 48 8B C4 48 89 58 08 48 89 68 18 48 89 70 20 57 48 83 EC 30 65 48 8B 2C 25 ? ? ? ?
	UCHAR pattern[] = "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x18\x48\x89\x70\x20\x57\x48\x83\xEC\x30\x65\x48\x8B\x2C\x25\x00\x00\x00\x00\x48\x83\xCE\xFF";
	pMiProcessLoaderEntryAddress = FindPatternEx(kernelBase, kernelSize, (BYTE*)pattern, "xxxxxxxxxxxxxxxxxxxxxxxxx????xxxx", (INT32)sizeof(pattern));	

  // I tested this DKOM for about 12 hours without PatchGuard BSDO on Win10 Pro 22H2.
	if (pMiProcessLoaderEntryAddress != 0)
	{
    
    MiProcessLoaderEntry = (pMiProcessLoaderEntry)pMiProcessLoaderEntryAddress;
		DbgPrintEx(0, 0, "[+] MiProcessLoaderEntryAddress: 0x%I64X \n", pMiProcessLoaderEntryAddress);
		
		NTSTATUS status = MiProcessLoaderEntry(pDriver->DriverSection, FALSE); // Removes a driver entry from the PsLoadedModuleList using the kernel mechanism. The driver will not be visible in "Nt" "Zw" QuerySystemInformation(SystemModuleInformation)" lists neither. The other benefit is that your driver cannot be dumped (not at least too easily) allowing you to have 1000+1 users even with a valid EV certificate.

		// After this, the driver cannot be unloaded without KERNEL_SECURITY_CHECK_FAILURE (0x139) BSDO. If you NULL the entry in the driver directory for this "DRIVER_OBJECT". 
		// This BSDO will not occur on reboot or shutdown and most importantly bypasses EAC's driver object check that's not backed by module
    
    MiProcessLoaderEntry = (pMiProcessLoaderEntry)pMiProcessLoaderEntryAddress;
		DbgPrintEx(0, 0, "[+] MiProcessLoaderEntryAddress: 0x%I64X \n", pMiProcessLoaderEntryAddress);
		
		NTSTATUS status = MiProcessLoaderEntry(pDriver->DriverSection, FALSE); // Removes a driver entry from the PsLoadedModuleList using the kernel mechanism. The driver will not be visible in "Nt" "Zw" QuerySystemInformation(SystemModuleInformation)" lists neither. The other benefit is that your driver cannot be dumped (not at least too easily) allowing you to have 1000+1 users even with a valid EV certificate.

		// After this, the driver cannot be unloaded without KERNEL_SECURITY_CHECK_FAILURE (0x139) BSDO. If you NULL the entry in the driver directory for this "DRIVER_OBJECT". 
		// This BSDO will not occur on reboot or shutdown and most importantly bypasses EAC's driver object check that's not backed by module
    
  }
  

}
