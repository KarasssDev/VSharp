module VSharp.Fuzzer.Interop

open System
open System.Runtime.InteropServices
open System.Text
open Microsoft.FSharp.NativeInterop

open VSharp.Fuzzer.Coverage
open VSharp


#nowarn "9"

[<DllImport("libvsharpConcolic", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
extern void private SetEntryMain(byte* assemblyName, int assemblyNameLength, byte* moduleName, int moduleNameLength, int methodToken)

[<DllImport("libvsharpConcolic", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
extern void private GetHistory(nativeint size, nativeint data)

[<DllImport("libc")>]
extern IntPtr private getpwnam(string name)


module private Deserialization = 
    let mutable private dataOffset = 0

    let resetOffset () = dataOffset <- 0

    let private increaseOffset i =
        dataOffset <- dataOffset + i

    let readInt32 data = 
        let result = BitConverter.ToInt32(data, dataOffset)
        increaseOffset sizeof<int32>
        result

    let readUInt32 data = 
        let result = BitConverter.ToUInt32(data, dataOffset)
        increaseOffset sizeof<uint32>
        result

    let readString data =
        let size = readUInt32 data |> int
        let result = Array.sub data dataOffset (2 * size - 2)
        increaseOffset (2 * size)
        Logger.error $"""{result |> Array.map string |> String.concat " "}"""
        Logger.error $"{Encoding.Unicode.GetString(result)} {result |> Array.length} {Encoding.Unicode.GetString(result) |> fun x -> x.Length}"
        Encoding.Unicode.GetString(result)

    let deserializeMethodData data =
        let methodToken = readUInt32 data
        let assemblyName = readString data 
        let moduleName = readString data
        {| MethodToken = methodToken; AssemblyName = assemblyName; ModuleName = moduleName |}

    let deserializeCoverageInfo data =
        let offset = readUInt32 data
        let event = readInt32 data
        let methodId = readInt32 data
        {| Offset = offset; Event = event; MethodId = methodId |}

    let deserializeArray elementDeserializer data =
        let arraySize = readInt32 data
        Array.init arraySize (fun _ -> elementDeserializer data)

    let deserializeHistory data =
        let methodsData = deserializeArray deserializeMethodData data
        let coverageInfo = deserializeArray deserializeCoverageInfo data

        coverageInfo
        |> Seq.map (fun x ->
            let methodData = methodsData[x.MethodId]
            {
                assemblyName = methodData.AssemblyName
                moduleName = methodData.ModuleName
                methodToken = int methodData.MethodToken
                offset = int x.Offset
            }
        )
        |> Seq.toArray

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
    let getHistory () =
        let sizePtr = NativePtr.stackalloc<uint> 1
        let dataPtrPtr = NativePtr.stackalloc<nativeint> 1
        Logger.error $"pointer before: {NativePtr.toNativeInt dataPtrPtr}"
        Logger.error $"value before: {NativePtr.read dataPtrPtr}"

        Deserialization.resetOffset ()
        GetHistory(NativePtr.toNativeInt sizePtr, NativePtr.toNativeInt dataPtrPtr)

        let size = NativePtr.read sizePtr |> int
        let dataPtr = NativePtr.read dataPtrPtr

        let data = Array.create size (byte 0)
        Marshal.Copy(dataPtr, data, 0, size)

        try
            let history = Deserialization.deserializeArray Deserialization.deserializeHistory data
            Marshal.FreeCoTaskMem(dataPtr)
            history
        with
        | e ->
            Logger.error $"{e.Message}\n\n{e.StackTrace}"
            failwith "kek"

    let setEntryMain (assembly: Reflection.Assembly) (moduleName: string) (methodToken: int) =
        let assemblyNamePtr = fixed assembly.FullName.ToCharArray()
        let moduleNamePtr = fixed moduleName.ToCharArray()
        let assemblyNameLength = assembly.FullName.Length
        let moduleNameLength = moduleName.Length
        SetEntryMain(assemblyNamePtr |> NativePtr.toVoidPtr |> NativePtr.ofVoidPtr, assemblyNameLength, moduleNamePtr |> NativePtr.toVoidPtr |> NativePtr.ofVoidPtr, moduleNameLength, methodToken)
