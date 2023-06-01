namespace VSharp.Fuzzer

open System.Diagnostics
open System.IO
open System.Net.Sockets
open System.Reflection
open System.Runtime.InteropServices
open System.Threading
open System.Threading.Tasks
open VSharp
open VSharp.Fuzzer.Message

[<RequireQualifiedAccess>]
type Interactor (
    cancellationToken: CancellationToken,
    saveStatistic: codeLocation seq -> unit,
    dllPaths: string seq,
    outputPath: string
    ) =

    let ioTokenSource = new CancellationTokenSource ()
    let ioToken = ioTokenSource.Token
    let mainToken = CancellationTokenSource.CreateLinkedTokenSource([| ioToken; cancellationToken |]).Token

    let startFuzzerProcess () =

        let extension =
            if RuntimeInformation.IsOSPlatform(OSPlatform.Windows) then ".dll"
            elif RuntimeInformation.IsOSPlatform(OSPlatform.Linux) then ".so"
            elif RuntimeInformation.IsOSPlatform(OSPlatform.OSX) then ".dylib"
            else __notImplemented__()

        let config =
            let info = ProcessStartInfo()
            info.EnvironmentVariables.["CORECLR_PROFILER"] <- "{2800fea6-9667-4b42-a2b6-45dc98e77e9e}"
            info.EnvironmentVariables.["CORECLR_ENABLE_PROFILING"] <- "1"
            info.EnvironmentVariables.["CORECLR_PROFILER_PATH"] <- $"{Directory.GetCurrentDirectory()}{Path.DirectorySeparatorChar}libvsharpCoverage{extension}"
            info.WorkingDirectory <- Directory.GetCurrentDirectory()
            info.FileName <- "dotnet"
            info.Arguments <- $"VSharp.Fuzzer.dll {outputPath}"
            info.UseShellExecute <- false
            info.RedirectStandardInput <- false
            info.RedirectStandardOutput <- false
            info.RedirectStandardError <- true
            info

        Process.Start(config)

    let startFuzzerContainer () = Docker.startFuzzer outputPath dllPaths

    let mutable communicator = Unchecked.defaultof<FuzzerCommunicator<ClientMessage, ServerMessage>>
    let mutable fuzzer = Unchecked.defaultof<Process>


    let startFuzzer () =
        #if DEBUGFUZZER
        startFuzzerProcess ()
        #else
        // startFuzzerContainer ()
        startFuzzerProcess ()
        #endif

    let connectFuzzer () =
        let connect (tcpClient: TcpClient) =
            task {
                let mutable connected = false
                while not connected do
                    try
                        do! tcpClient.ConnectAsync("localhost", Docker.fuzzerContainerPort, cancellationToken)
                        connected <- true
                    with _ -> Thread.Sleep(100)
            }

        let init  =
            task {
                let tcpClient = new TcpClient()
                do! connect tcpClient
                return tcpClient.GetStream ()
            }

        let onIoFail (e: exn) = Logger.error $"Communication with fuzzer failed with: {e.Message}"

        FuzzerCommunicator(
            init,
            ClientMessage.serialize,
            ServerMessage.deserialize,
            mainToken,
            onIoFail
        )

    let methods = System.Collections.Generic.Dictionary<int, Method>()
    let toSiliStatistic (loc: CoverageLocation seq) =

        let getMethod l =
            match methods.TryGetValue(l.methodToken) with
            | true, m -> m
            | false, _ ->
                let methodBase = Reflection.resolveMethodBase l.assemblyName l.moduleName l.methodToken
                let method = Application.getMethod methodBase
                methods.Add (l.methodToken, method)
                method

        let toCodeLocation l =
            {
                offset = LanguagePrimitives.Int32WithMeasure l.offset
                method = getMethod l
            }

        loc |> Seq.map toCodeLocation

    let traceInteraction (log: string) = Logger.traceWithTag Logger.fuzzerInteractionTraceTag $"{log}"

    let handleRequest msg =
        task {
            match msg with
            | Statistics s ->
                let deserializedStatistic = CoverageDeserializer.getHistory s
                assert (deserializedStatistic.Length = 1)
                deserializedStatistic[0] |> toSiliStatistic |> saveStatistic
                return false
            | End ->
                //ioTokenSource.Cancel()
                return true
        }

    member private this.Fuzz (moduleName: string, methodToken: int) =
        traceInteraction $"Send to fuzz {methodToken}"
        communicator.SendMessage (Fuzz (moduleName, methodToken))

    member private this.WaitStatistics ()  =
        task {
            do! communicator.SendMessage Kill
            traceInteraction "Kill message sent to fuzzer"
            do! communicator.ReadAll handleRequest
            do! fuzzer.WaitForExitAsync ioToken |> Async.AwaitTask
            traceInteraction "Fuzzer stopped"
        }

    member private this.Setup assembly = Setup assembly |> communicator.SendMessage

    member this.StartFuzzing (targetAssemblyPath: string) (isolated: MethodBase seq) (onCanceled: unit -> unit) =
        fuzzer <- startFuzzer ()
        communicator <- connectFuzzer ()

        mainToken.Register(fun () ->
            if not fuzzer.HasExited  then
                fuzzer.Kill ()
        ) |> ignore

        task {
            try
                do! this.Setup targetAssemblyPath
                for m in isolated do
                    do! this.Fuzz(m.Module.FullyQualifiedName, m.MetadataToken)
                do! this.WaitStatistics ()
            with :? TaskCanceledException -> onCanceled ()
        }

