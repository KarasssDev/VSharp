module VSharp.Fuzzer.InteropSyncCalls

open System
open System.Reflection
open System.Runtime.InteropServices
open System.Text
open Microsoft.FSharp.NativeInterop
open VSharp.Fuzzer.Coverage

[<DllImport("libvsharpConcolic", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
extern void private SetEntryMain(byte* assemblyName, int assemblyNameLength, byte* moduleName, int moduleNameLength, int methodToken)

[<DllImport("libvsharpConcolic", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
extern void private GetHistory(nativeint size, nativeint data)

module private Deserialization =
    let mutable private dataOffset = 0
    let private increaseOffset i =
        dataOffset <- dataOffset + i
    let resetOffset () =
        dataOffset <- 0

    let private deserializeInt32 data =
        let result = BitConverter.ToInt32(data, dataOffset)
        increaseOffset sizeof<int32>
        result

    let private deserializeUInt32 data =
        let result = BitConverter.ToUInt32(data, dataOffset)
        increaseOffset sizeof<uint32>
        result

    let private deserializeString data =
        let size = deserializeUInt32 data |> int
        let result = Array.sub data dataOffset (2 * size - 2)
        increaseOffset (2 * size)
        Encoding.Unicode.GetString(result)

    let private deserializeMethodData data =
        let methodToken = deserializeUInt32 data
        let assemblyName = deserializeString data
        let moduleName = deserializeString data
        {| MethodToken = methodToken; AssemblyName = assemblyName; ModuleName = moduleName |}

    let private deserializeCoverageInfo data =
        let offset = deserializeUInt32 data
        let event = deserializeInt32 data
        let methodId = deserializeInt32 data
        {| Offset = offset; Event = event; MethodId = methodId |}

    let private deserializeArray elementDeserializer data =
        let arraySize = deserializeInt32 data
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

    let deserializeHistories = deserializeArray deserializeHistory



#nowarn "9"
let getHistories () =
    let sizePtr = NativePtr.stackalloc<uint> 1
    let dataPtrPtr = NativePtr.stackalloc<nativeint> 1

    GetHistory(NativePtr.toNativeInt sizePtr, NativePtr.toNativeInt dataPtrPtr)

    let size = NativePtr.read sizePtr |> int
    let dataPtr = NativePtr.read dataPtrPtr
    let data = Array.create size (byte 0)

    Marshal.Copy(dataPtr, data, 0, size)
    Deserialization.resetOffset ()
    let history = Deserialization.deserializeHistories data
    Marshal.FreeCoTaskMem(dataPtr)

    history

let setEntryMain (assembly: Assembly) (moduleName: string) methodToken =
    let assemblyNamePtr = fixed assembly.FullName.ToCharArray()
    let moduleNamePtr = fixed moduleName.ToCharArray()
    let assemblyNameLength = assembly.FullName.Length
    let moduleNameLength = moduleName.Length
    SetEntryMain(
        assemblyNamePtr |> NativePtr.toVoidPtr |> NativePtr.ofVoidPtr,
        assemblyNameLength,
        moduleNamePtr |> NativePtr.toVoidPtr |> NativePtr.ofVoidPtr,
        moduleNameLength,
        methodToken
    )
