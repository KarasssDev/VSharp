module VSharp.Fuzzer.Interaction

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

type private Interactor (
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
            Coverage.attachCoverageTool info

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

type private Application (outputDir: string) =

    let ioTokenSource = new CancellationTokenSource()
    let ioToken = ioTokenSource.Token

    let server =

        let onIoFail (e: exn) =
            Logger.error $"IO error: {e.Message}\n{e.StackTrace}"

        TcpCommunicator.createTcpServerCommunicator ioToken onIoFail

    let mutable assembly = Unchecked.defaultof<Assembly>

    let mutable freeId = -1
    let nextId () =
        freeId <- freeId + 1
        freeId

    let onEachFuzzingResult method fuzzingResult = task {
        let test = UnitTest.fuzzingResultToTest fuzzingResult
        match test with
        | Some test ->
            traceFuzzing "Test successfully generated"
            let filePath = $"{outputDir}{Path.DirectorySeparatorChar}fuzzer_test_{nextId ()}.vst"
            do! server.SendMessage (Statistics fuzzingResult.rawCoverage)
            traceCommunication "Sent raw history"
            test.Serialize filePath
            traceCommunication $"Test saved to {filePath}"
        | None -> traceFuzzing "Test generation failed"
    }

    let handleRequest command =
        task {
            match command with
            | Setup pathToTargetAssembly ->
                traceCommunication $"Received: Setup {pathToTargetAssembly}"
                assembly <- AssemblyManager.LoadFromAssemblyPath pathToTargetAssembly
                traceFuzzing $"Target assembly was set to {assembly.FullName}"
                return false
            | Fuzz (moduleName, methodToken) ->
                traceCommunication $"Received: Fuzz {moduleName} {methodToken}"
                let methodBase = Reflection.resolveMethodBaseFromAssembly assembly moduleName methodToken
                traceFuzzing $"Resolved MethodBase {methodToken}"
                let method = Application.getMethod methodBase
                traceFuzzing $"Resolved Method {methodToken}"
                Coverage.setEntryMain assembly moduleName methodToken
                traceFuzzing $"Was set entry main {moduleName} {methodToken}"
                let rnd = Random(100)
                do! Fuzzer.primitiveFuzz method rnd (onEachFuzzingResult method)
                traceCommunication $"Successfully fuzzed {moduleName} {methodToken}"
                return false
            | Kill ->
                traceCommunication "Received: Kill"
                do! server.SendMessage End
                return true
        }

    member this.Start onError =
        task {
            try
                do! server.ReadMessages handleRequest
            with e ->
                ioTokenSource.Cancel()
                onError e
        }

let internal startFuzzer outputDir =
    let onError (e: exn) =
        errorFuzzing $"Unhandled exception: {e}"
        exit 1
    setupLogger outputDir
    (Application outputDir).Start(onError).Wait()
    0

let startFuzzing (methods: MethodBase seq) saveStatistic outputDir cancellationToken =
    task {
        let targetAssemblyPath = (Seq.head methods).Module.Assembly.Location
        let dllsPaths = [Directory.GetParent(targetAssemblyPath).FullName]
        let onCancelled () = error "Fuzzer canceled"
        let interactor = Interactor(cancellationToken, saveStatistic, dllsPaths, outputDir)
        do! interactor.StartFuzzing targetAssemblyPath methods onCancelled
        assert interactor.FinishedSuccessfully
    }
