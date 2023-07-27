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


type internal Application (outputDir: string) =

    let ioTokenSource = new CancellationTokenSource()
    let ioToken = ioTokenSource.Token

    let server =
        let onIoFail (e: exn) = error $"IO error: {e.Message}\n{e.StackTrace}"
        TcpCommunicator.createTcpServerCommunicator ioToken onIoFail

    let mutable assembly = Unchecked.defaultof<Assembly>

    let mutable freeId = -1
    let nextId () =
        freeId <- freeId + 1
        freeId

    let coverageTracker = CoverageTracker()
    let coverageTool = CoverageTool()
    let fuzzer = Fuzzer.Fuzzer(coverageTool)

    let onEachFuzzingResult (test: UnitTest option) coverage = task {
        //let isNewCoverage = coverageTracker.AddLocations fuzzingResult.coverage
        //if isNewCoverage then
        //traceFuzzing "New coverage!"
        //let test = UnitTest.fuzzingResultToTest fuzzingResult
        match test with
        | Some test ->
            traceFuzzing "Test successfully generated"
            let filePath = $"{outputDir}{Path.DirectorySeparatorChar}fuzzer_test_{nextId ()}.vst"
            do! server.SendMessage (Statistics coverage)
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
                coverageTool.SetEntryMain assembly moduleName methodToken
                traceFuzzing $"Was set entry main {moduleName} {methodToken}"
                let rnd = Random(100)
                //do! fuzzer.AsyncFuzz method rnd onEachFuzzingResult
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
