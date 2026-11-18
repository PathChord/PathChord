// Test-only Windows token and Named Pipe probe; run in a disposable guest.
using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public static class PathChordPackageTokenProbe {
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct PRIVILEGE { public uint Count; public LUID Luid; public uint Attributes; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref PRIVILEGE privileges, int length, IntPtr previous, IntPtr returned);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool LogonUser(string name, string domain, string password, int type, int provider, out IntPtr token);
    public sealed class Result { public string Sid; public string Response; public bool AccessDenied; }
    static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static void Check(bool value, string operation) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error(), operation); }
    public static void EnableDebugPrivilege() {
        IntPtr token; Check(OpenProcessToken(GetCurrentProcess(), 0x28, out token));
        try {
            LUID luid; Check(LookupPrivilegeValue(null, "SeDebugPrivilege", out luid));
            PRIVILEGE privilege = new PRIVILEGE {Count=1, Luid=luid, Attributes=2};
            Check(AdjustTokenPrivileges(token, false, ref privilege, 0, IntPtr.Zero, IntPtr.Zero));
            int error = Marshal.GetLastWin32Error(); if (error != 0) throw new Win32Exception(error);
        } finally { CloseHandle(token); }
    }
    public static Result Owner(int pid, string pipeName) {
        IntPtr process = OpenProcess(0x1000, false, pid);
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess(owner)");
        IntPtr token = IntPtr.Zero;
        try { Check(OpenProcessToken(process, 0x000A, out token), "OpenProcessToken(owner)"); return Probe(token, pipeName, false); }
        finally { if (token != IntPtr.Zero) CloseHandle(token); CloseHandle(process); }
    }
    public static Result OrdinaryUser(string username, string password, string pipeName) {
        IntPtr token; Check(LogonUser(username, ".", password, 2, 0, out token));
        try { return Probe(token, pipeName, true); } finally { CloseHandle(token); }
    }
    public static Result AuthorizedUser(string username, string password, string pipeName) {
        IntPtr token; Check(LogonUser(username, ".", password, 2, 0, out token), "LogonUser(authorized owner)");
        try { return Probe(token, pipeName, false); } finally { CloseHandle(token); }
    }
    static Result Probe(IntPtr token, string pipeName, bool expectDenied) {
        Check(ImpersonateLoggedOnUser(token), "ImpersonateLoggedOnUser(owner)");
        try {
            Result result = new Result {Sid=WindowsIdentity.GetCurrent().User.Value};
            using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous)) {
                try { pipe.Connect(3000); }
                catch (UnauthorizedAccessException) { result.AccessDenied = true; return result; }
                if (expectDenied) throw new Exception("Ordinary user connected to the private service control pipe.");
                byte[] request = Encoding.UTF8.GetBytes("{\"api_version\":\"1\",\"operation\":\"status.get\",\"request_id\":\"package-owner-probe\",\"actor\":{\"id\":\"owner-probe\",\"capabilities\":[\"status:read\"]},\"body\":{}}");
                byte[] prefix = {(byte)(0x40 | (request.Length >> 8)), (byte)request.Length};
                pipe.Write(prefix, 0, prefix.Length); pipe.Write(request, 0, request.Length); pipe.Flush();
                byte[] first = Read(pipe, 1); int width = 1 << (first[0] >> 6);
                byte[] rest = Read(pipe, width - 1); long length = first[0] & 63;
                foreach (byte item in rest) length = (length << 8) | item;
                if (length < 1 || length > 1048576) throw new Exception("Invalid control response size.");
                result.Response = Encoding.UTF8.GetString(Read(pipe, (int)length));
                return result;
            }
        } finally { Check(RevertToSelf()); }
    }
    static byte[] Read(Stream stream, int length) {
        byte[] bytes = new byte[length]; int offset = 0;
        while (offset < length) {
            var task = stream.ReadAsync(bytes, offset, length-offset);
            if (!task.Wait(5000)) throw new TimeoutException("Control response deadline exceeded.");
            int read = task.Result; if (read == 0) throw new EndOfStreamException(); offset += read;
        }
        return bytes;
    }
}
