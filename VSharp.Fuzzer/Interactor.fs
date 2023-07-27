namespace VSharp.Fuzzer

open System
open System.Diagnostics
open System.IO
open System.Net.Sockets
open System.Reflection
open System.Runtime.InteropServices
open System.Runtime.Serialization
open System.Runtime.Serialization.Formatters.Binary
open System.Threading
open System.Threading.Tasks
open VSharp
open VSharp.Fuzzer.Communication
open Logger
open VSharp.Fuzzer.Coverage

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

        let config =
            let info = ProcessStartInfo()
            info.WorkingDirectory <- Directory.GetCurrentDirectory()
            info.FileName <- "dotnet"
            info.Arguments <- $"VSharp.Fuzzer.dll {outputPath}"
            info.UseShellExecute <- false
            info.RedirectStandardInput <- false
            info.RedirectStandardOutput <- false
            info.RedirectStandardError <- true
            CoverageTool.AttachCoverageTool info

        Process.Start(config)


    let mutable communicator = Unchecked.defaultof<ICommunicator<ClientMessage, ServerMessage>>
    let mutable fuzzer = Unchecked.defaultof<Process>

    let startFuzzer () =
        #if DEBUGFUZZER
        startFuzzerProcess ()
        #else
        // startFuzzerContainer ()
        startFuzzerProcess ()
        #endif

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

    let onIoFail (e: exn) = error $"Communication with fuzzer failed with: {e.Message}"

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
        traceCommunication $"Send to fuzz {methodToken}"
        communicator.SendMessage (Fuzz (moduleName, methodToken))

    member private this.WaitStatistics ()  =
        task {
            do! communicator.SendMessage Kill
            traceCommunication "Kill message sent to fuzzer"
            do! communicator.ReadMessages handleRequest
            do! fuzzer.WaitForExitAsync ioToken |> Async.AwaitTask
            traceCommunication "Fuzzer stopped"
        }

    member private this.Setup assembly = Setup assembly |> communicator.SendMessage

    member this.StartFuzzing (targetAssemblyPath: string) (isolated: MethodBase seq) (onCanceled: unit -> unit) =
        fuzzer <- startFuzzer ()
        communicator <- TcpCommunicator.createTcpClientCommunicator ioToken onIoFail

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

    member this.FinishedSuccessfully with get () = this.Finished && fuzzer.ExitCode = 0
    member this.Finished with get () = fuzzer.HasExited
