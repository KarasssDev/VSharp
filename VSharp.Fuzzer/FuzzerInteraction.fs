namespace VSharp.Fuzzer

open System
open System.Diagnostics
open System.IO
open System.IO.Pipes
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

    let proc =
        let config =
            let info = ProcessStartInfo()
            info.FileName <- "dotnet"
            info.Arguments <- $"/home/viktor/RiderProjects/VSharp/VSharp.Fuzzer/bin/Release/net6.0/VSharp.Fuzzer.dll %s{pathToAssembly} %s{outputDir}"
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
