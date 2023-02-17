namespace VSharp.Fuzzer

open System
open System.Diagnostics
open System.IO
open System.IO.Pipes
open System.Runtime.InteropServices
open VSharp

type Message =
    | Kill
    | Fuzz of string * int

    static member serialize msg =
        match msg with
        | Kill -> "Kill"
        | Fuzz (moduleName, methodToken) -> $"Fuzz %s{moduleName} %d{methodToken}"

    static member deserialize (str: string) =
        let parts = str.Split [|' '|]
        match parts[0] with
        | "Kill" -> Kill
        | "Fuzz" -> Fuzz (parts[1], int parts[2])
        | _ -> failwith "Unknown message"

type private FuzzerPipeClient () =
    let io = new NamedPipeClientStream(".", "FuzzerPipe", PipeDirection.Out)
    let writer = new StreamWriter(io)

    do
        io.Connect()
        Logger.error "Connected!"
        writer.AutoFlush <- true

    member this.SendMessage msg =
        async {
            do! writer.WriteAsync $"{Message.serialize msg}\n" |> Async.AwaitTask
        }

type FuzzerInteraction (pathToAssembly, outputDir) =
    // TODO: find correct path to the client
    let extension =
        if RuntimeInformation.IsOSPlatform(OSPlatform.Windows) then ".dll"
        elif RuntimeInformation.IsOSPlatform(OSPlatform.Linux) then ".so"
        elif RuntimeInformation.IsOSPlatform(OSPlatform.OSX) then ".dylib"
        else __notImplemented__()
    let pathToClient = "libvsharpConcolic" + extension
    let profiler = sprintf "%s%c%s" (Directory.GetCurrentDirectory()) Path.DirectorySeparatorChar pathToClient

    let proc =
        let config =
            let info = ProcessStartInfo()
            info.EnvironmentVariables.["CORECLR_PROFILER"] <- "{2800fea6-9667-4b42-a2b6-45dc98e77e9e}"
            info.EnvironmentVariables.["CORECLR_ENABLE_PROFILING"] <- "1"
            info.EnvironmentVariables.["CORECLR_PROFILER_PATH"] <- profiler
            info.WorkingDirectory <- Directory.GetCurrentDirectory()
            info.FileName <- "dotnet"
            info.Arguments <- $"VSharp.Fuzzer.dll %s{pathToAssembly} %s{outputDir}"
            info.UseShellExecute <- false
            info.RedirectStandardInput <- false
            info.RedirectStandardOutput <- false
            info.RedirectStandardError <- false
            info
        Logger.error "Started!"
        Process.Start(config)

    let client = FuzzerPipeClient()
    member this.Fuzz (moduleName: string, methodToken: int) = client.SendMessage (Fuzz (moduleName, methodToken))
    member this.Wait () =
        async {
            do! client.SendMessage Kill
            Logger.error "Kill sent"
            do! proc.WaitForExitAsync () |> Async.AwaitTask
            Logger.error "Exited"
        }

    member this.Kill () = Logger.error "Dispose"; proc.Kill ()


type ProcessTask (act, proc: Process) =
    inherit System.Threading.Tasks.Task(act)

    interface IDisposable with
        member this.Dispose () =
            (this :> System.Threading.Tasks.Task).Dispose ()
            proc.Kill ()
