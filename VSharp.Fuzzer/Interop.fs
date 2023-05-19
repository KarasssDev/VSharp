module VSharp.Fuzzer.Interop

open System
open System.Runtime.InteropServices
open System.Text
open Microsoft.FSharp.NativeInterop

open VSharp


#nowarn "9"

[<DllImport("libvsharpCoverage", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
extern void private SetEntryMain(byte* assemblyName, int assemblyNameLength, byte* moduleName, int moduleNameLength, int methodToken)

[<DllImport("libvsharpCoverage", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
extern void private GetHistory(nativeint size, nativeint data)

[<DllImport("libc")>]
extern IntPtr private getpwnam(string name)

module LinuxCalls =
    type private Passwd =
        struct
            val name: string
            val password: string
            val uid: uint
            val gid: uint
            val gecos: string
            val directory: string
            val shell: string
        end

    let getUserInfo username =
        let ptr = getpwnam username
        let passwd = Marshal.PtrToStructure<Passwd> ptr
        passwd.uid, passwd.gid

    let getCurrentUserInfo () =
        let username = Environment.GetEnvironmentVariable("USER")
        getUserInfo username

module InstrumenterCalls =
    let getRawHistory () =
        let sizePtr = NativePtr.stackalloc<uint> 1
        let dataPtrPtr = NativePtr.stackalloc<nativeint> 1

        GetHistory(NativePtr.toNativeInt sizePtr, NativePtr.toNativeInt dataPtrPtr)

        let size = NativePtr.read sizePtr |> int
        let dataPtr = NativePtr.read dataPtrPtr

        let data = Array.create size (byte 0)
        Marshal.Copy(dataPtr, data, 0, size)
        data

    let setEntryMain (assembly: Reflection.Assembly) (moduleName: string) (methodToken: int) =
        let assemblyNamePtr = fixed assembly.FullName.ToCharArray()
        let moduleNamePtr = fixed moduleName.ToCharArray()
        let assemblyNameLength = assembly.FullName.Length
        let moduleNameLength = moduleName.Length
        SetEntryMain(assemblyNamePtr |> NativePtr.toVoidPtr |> NativePtr.ofVoidPtr, assemblyNameLength, moduleNamePtr |> NativePtr.toVoidPtr |> NativePtr.ofVoidPtr, moduleNameLength, methodToken)
