module internal VSharp.Fuzzer.Coverage

open System.IO
open System.Reflection
open System.Runtime.InteropServices
open Microsoft.FSharp.NativeInterop
open VSharp

#nowarn "9"

[<DllImport("libvsharpCoverage", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
extern void private SetEntryMain(byte* assemblyName, int assemblyNameLength, byte* moduleName, int moduleNameLength, int methodToken)

[<DllImport("libvsharpCoverage", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
extern void private GetHistory(nativeint size, nativeint data)

let inline castPtr ptr  =
    ptr |> NativePtr.toVoidPtr |> NativePtr.ofVoidPtr

type CoverageTool() =
    let mutable entryMainWasSet = false
    let isToolAttached =
        System.Environment.GetEnvironmentVariable("CORECLR_PROFILER") = "{2800fea6-9667-4b42-a2b6-45dc98e77e9e}" &&
        System.Environment.GetEnvironmentVariable("CORECLR_ENABLE_PROFILING") = "1"

    do
        if not isToolAttached then internalfail "Coverage tool wasn't attached"

    member this.GetRawHistory () =
        if not entryMainWasSet then Prelude.internalfail "Try call SetEntryMain, while entryMain wasn't set"
        let sizePtr = NativePtr.stackalloc<uint> 1
        let dataPtrPtr = NativePtr.stackalloc<nativeint> 1

        GetHistory(NativePtr.toNativeInt sizePtr, NativePtr.toNativeInt dataPtrPtr)

        let size = NativePtr.read sizePtr |> int
        let dataPtr = NativePtr.read dataPtrPtr

        let data = Array.zeroCreate<byte> size
        Marshal.Copy(dataPtr, data, 0, size)
        data

    member this.SetEntryMain (assembly: Assembly) (moduleName: string) (methodToken: int) =
        entryMainWasSet <- true
        let assemblyNamePtr = fixed assembly.FullName.ToCharArray()
        let moduleNamePtr = fixed moduleName.ToCharArray()
        let assemblyNameLength = assembly.FullName.Length
        let moduleNameLength = moduleName.Length
        SetEntryMain(castPtr assemblyNamePtr, assemblyNameLength, castPtr moduleNamePtr, moduleNameLength, methodToken)


    static member AttachCoverageTool (info: System.Diagnostics.ProcessStartInfo) =
        let extension =
            if RuntimeInformation.IsOSPlatform(OSPlatform.Windows) then ".dll"
            elif RuntimeInformation.IsOSPlatform(OSPlatform.Linux) then ".so"
            elif RuntimeInformation.IsOSPlatform(OSPlatform.OSX) then ".dylib"
            else __notImplemented__()
        info.EnvironmentVariables.["CORECLR_PROFILER"] <- "{2800fea6-9667-4b42-a2b6-45dc98e77e9e}"
        info.EnvironmentVariables.["CORECLR_ENABLE_PROFILING"] <- "1"
        info.EnvironmentVariables.["CORECLR_PROFILER_PATH"] <- $"{Directory.GetCurrentDirectory()}{Path.DirectorySeparatorChar}libvsharpCoverage{extension}"
        info

type CoverageTracker () =

    let visitedLocations = System.Collections.Generic.HashSet<CoverageLocation>()

    member this.AddLocations (locations: CoverageLocation seq) =
        let isNewCoverage = Seq.exists (visitedLocations.Contains >> not) locations
        if isNewCoverage then Seq.iter (visitedLocations.Add >> ignore) locations
        isNewCoverage
