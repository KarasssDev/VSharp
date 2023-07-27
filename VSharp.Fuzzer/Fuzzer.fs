namespace VSharp.Fuzzer

open System
open System.Collections.Generic
open System.IO
open System.Reflection
open System.Threading.Tasks
open MessagePack
open VSharp
open VSharp.Core
open VSharp.Fuzzer.Coverage
open VSharp.Fuzzer.Generator
open VSharp.Fuzzer.TypeSolver
open VSharp.Fuzzer.UnitTest
open Logger
open DotNetIsolator

type internal Fuzzer(coverageTool: CoverageTool) =


    let typeSolver = TypeSolver()
    let generator = Generator(typeSolver)
    let host = (new IsolatedRuntimeHost()).WithBinDirectoryAssemblyLoader()

    let copyArgs (args: obj array) =
        let wrap o = { object = o }
        let unwrap pa = pa.object
        let copier = Utils.Copier()
        args |> Array.map (wrap >> copier.DeepCopy >> unwrap)

    let objToInvocationResult (obj: obj) =
        match obj with
        | :? TargetInvocationException as e -> Thrown e.InnerException
        | _ -> Returned obj

    let invoke (method: MethodBase) this args () =
        try
            let returned = method.Invoke(this, copyArgs args)
            traceFuzzing "Method returned"
            returned
        with
        | :? TargetInvocationException as e ->
            traceFuzzing "Method thrown exception"
            e

    let generateCase (method: MethodBase) (rnd: Random) =
        let thisType = method.DeclaringType

        let this =
            if Reflection.hasThis method
            then generator.Generate rnd thisType
            else null

        let argsTypes =
            method.GetParameters()
            |> Array.map (fun info -> info.ParameterType)

        let args =
            argsTypes
            |> Array.map (generator.Generate rnd)

        {| this = this; thisType = thisType; args = args; argsTypes = argsTypes |}


    member this.Invoke method =
        let rnd = Random()
        let case = generateCase method rnd
        let allocatedObjects = generator.RefreshAllocatedObjects ()
        let referencedObjects = generator.RefreshReferencedObjects ()
        let instantiatedMocks = generator.RefreshInstantiatedMocks ()
        traceFuzzing "Generated test case"

        let obj = invoke method case.this case.args ()
        let invocationResult = objToInvocationResult obj
        traceFuzzing "Invoked successfully"

        {
            method = Application.getMethod method
            this = case.this
            thisType = case.thisType
            args = case.args
            argsTypes = case.argsTypes
            rawCoverage = [||]
            coverage = [||]
            result = invocationResult
            mocks = typeSolver.GetMocks ()
            typeStorage = typeStorage()
            allocatedObjects = allocatedObjects
            referencedObjects = referencedObjects
            instantiatedMocks = instantiatedMocks
        } |> fuzzingResultToTest |> Option.map (fun x -> x.SerializeToString())

    member this.FuzzOnce (method: MethodBase) =
        let runtime = new IsolatedRuntime(host)
        let test = runtime.Invoke(Func<string option>(fun () -> this.Invoke method))

        let rawCoverage = coverageTool.GetRawHistory()
        traceFuzzing "Received raw history"

        let coverage = (CoverageDeserializer.getHistory rawCoverage)[0]
        traceFuzzing "History deserialized"

        {| test = test |> Option.map UnitTest.DeserializeFromString; coverage = rawCoverage |}
        // {
        //     method = Application.getMethod method
        //     this = case.this
        //     thisType = case.thisType
        //     args = case.args
        //     argsTypes = case.argsTypes
        //     rawCoverage = rawCoverage
        //     coverage = coverage
        //     result = invocationResult
        //     mocks = typeSolver.GetMocks ()
        //     typeStorage = typeStorage
        //     allocatedObjects = allocatedObjects
        //     referencedObjects = referencedObjects
        //     instantiatedMocks = instantiatedMocks
        // }

    member this.AsyncFuzz (method: Method) rnd (onEach: UnitTest option -> byte[] -> Task<unit>) =
        task {
            try
                traceFuzzing $"Start fuzzing: {method.Name}"
                match typeSolver.SolveGenericMethodParameters method (generator.Generate rnd) with
                | Some(method, typeStorage) ->
                    traceFuzzing "Generics successfully solved"
                    for i in 0..Options.options.MaxTestsCount do
                        traceFuzzing $"Start fuzzing iteration {i}"
                        let result = this.FuzzOnce method
                        do! onEach result.test result.coverage
                | None -> traceFuzzing "Generics solving failed"
            with
                | :? InsufficientInformationException as e ->
                    errorFuzzing $"Insufficient information: {e.Message}\nStack trace:\n{e.StackTrace}"
                | :? NotImplementedException as e ->
                    errorFuzzing $"Not implemented: {e.Message}\nStack trace:\n{e.StackTrace}"
        }

    // member this.Fuzz (method: Method) rnd onEach =
    //     let task = this.AsyncFuzz method rnd (fun x -> task { onEach x })
    //     task.Wait()
