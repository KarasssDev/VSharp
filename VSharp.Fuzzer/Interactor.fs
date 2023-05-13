namespace VSharp.Fuzzer

open System.Diagnostics
open System.IO
open System.Net.Sockets
open System.Reflection
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


    let startFuzzerProcess () =
        let config =
            let info = ProcessStartInfo()
            info.EnvironmentVariables.["CORECLR_PROFILER"] <- "{2800fea6-9667-4b42-a2b6-45dc98e77e9e}"
            info.EnvironmentVariables.["CORECLR_ENABLE_PROFILING"] <- "1"
            info.EnvironmentVariables.["CORECLR_PROFILER_PATH"] <- $"{Directory.GetCurrentDirectory()}{Path.DirectorySeparatorChar}libvsharpCoverage.so"
            info.WorkingDirectory <- Directory.GetCurrentDirectory()
            info.FileName <- "dotnet"
            info.Arguments <- $"VSharp.Fuzzer.dll {outputPath} --debug-log-verbosity"
            info.UseShellExecute <- false
            info.RedirectStandardInput <- false
            info.RedirectStandardOutput <- false
            info.RedirectStandardError <- false
            info
        Process.Start(config)

    let startFuzzerContainer () = Docker.startFuzzer outputPath dllPaths

    let ioTokenSource = new CancellationTokenSource ()
    let ioToken = ioTokenSource.Token
    let mainToken = CancellationTokenSource.CreateLinkedTokenSource([| ioToken; cancellationToken |]).Token

    let fuzzerContainer = startFuzzerContainer ()

    let killFuzzer () = fuzzerContainer.Kill ()

    let client =
        let connect (tcpClient: TcpClient) =
            task {
                let mutable connected = false
                while not connected do
                    try
                        Logger.error "try to connect"
                        do! tcpClient.ConnectAsync("localhost", Docker.fuzzerContainerPort, cancellationToken)
                        connected <- true
                        Logger.error "Connected!!!!"
                    with _ -> Thread.Sleep(100)
            }

        let init  =
            task {
                let tcpClient = new TcpClient()
                do! connect tcpClient
                return tcpClient.GetStream ()
            }

        let onIoFail (e: exn) = raise (TargetInvocationException($"Fuzzer error: {e.Message}" , e))
            //Logger.error $"Communication with fuzzer failed with: {e.Message}"

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

    let handleRequest msg =
        task {
            match msg with
            | Statistics s ->
                let deserializedStatistic = CoverageDeserializer.getHistory s
                assert (deserializedStatistic.Length = 1)
                deserializedStatistic[0] |> toSiliStatistic |> saveStatistic
                Logger.error "received stat"
                return false
            | End ->
                Logger.error "received end"
                ioTokenSource.Cancel()
                return true
        }

    do
        mainToken.Register(fun () ->
            killFuzzer ()
            Logger.warning "Fuzzer killed"
        ) |> ignore

    member private this.Fuzz (moduleName: string, methodToken: int) =
        Logger.error $"Send to fuzz {methodToken}"
        client.SendMessage (Fuzz (moduleName, methodToken))

    member private this.WaitStatistics ()  =
        task {
            do! client.SendMessage Kill
            Logger.error "Kill message sent to fuzzer"
            do! client.ReadAll handleRequest
            do! fuzzerContainer.WaitForExitAsync ioToken |> Async.AwaitTask
            Logger.error "Fuzzer stopped"
        }

    member private this.Setup assembly = Setup assembly |> client.SendMessage

    member this.StartFuzzing (targetAssemblyPath: string) (isolated: MethodBase seq) (onCanceled: unit -> unit) =
         task {
            try
                do! this.Setup targetAssemblyPath
                for m in isolated do
                    do! this.Fuzz(m.Module.FullyQualifiedName, m.MetadataToken)
                do! this.WaitStatistics ()
            with :? TaskCanceledException -> onCanceled ()
         }

