namespace VSharp.Fuzzer

open System
open System.Collections.Generic
open System.Reflection
open System.Threading.Tasks
open VSharp
open VSharp.Core
open System.Runtime.InteropServices
open VSharp.Fuzzer.TypeSolver
open Logger


type internal InvocationResult =
    | Thrown of exn
    | Returned of obj

type internal FuzzingResult = {
    method: Method
    this: obj
    thisType: Type
    args: obj array
    argsTypes: Type array
    rawCoverage: byte[]
    coverage: CoverageLocation[]
    result: InvocationResult
    mocks: Dictionary<ITypeMock, Mocking.Type>
    typeStorage: typeStorage
    referencedObjects: HashSet<obj>
    allocatedObjects: HashSet<obj>
    instantiatedMocks: Dictionary<obj, ITypeMock>
}

module internal Fuzzer =

    let private copyArgs (args: obj array) =
        let wrap o = { object = o }
        let unwrap pa = pa.object
        let copier = Utils.Copier()
        args |> Array.map (wrap >> copier.DeepCopy >> unwrap)


    let private invoke (method: MethodBase) this args () =
        try
            let returned = method.Invoke(this, copyArgs args)
            traceFuzzing "Method returned"
            Returned returned
        with
        | :? TargetInvocationException as e ->
            traceFuzzing "Method thrown exception"
            Thrown e.InnerException

    let private generateCase (method: MethodBase) (rnd: Random) =
        let thisType = method.DeclaringType

        let this =
            if Reflection.hasThis method
            then Generator.generate rnd thisType
            else null

        let argsTypes =
            method.GetParameters()
            |> Array.map (fun info -> info.ParameterType)

        let args =
            argsTypes
            |> Array.map (Generator.generate rnd)

        {| this = this; thisType = thisType; args = args; argsTypes = argsTypes |}

    let primitiveFuzz (method: Method) (rnd: Random) (onEach: FuzzingResult -> Task<unit>) =
        task {
            try
                traceFuzzing $"Start fuzzing: {method.Name}"
                match solveGenericMethodParameters method (Generator.generate rnd) with
                | Some(method, typeStorage) ->
                    traceFuzzing "Generics successfully solved"
                    for i in 0..Options.options.MaxTestsCount do
                        traceFuzzing $"Start fuzzing iteration {i}"
                        let case = generateCase method rnd
                        traceFuzzing "Generated test case"
                        let allocatedObjects = Generator.getAllocatedObjects ()
                        let invocationResult = invoke method case.this case.args ()
                        traceFuzzing "Invoked successfully"
                        let rawCoverage = Coverage.getRawHistory()
                        traceFuzzing "Received raw history"
                        let coverage = (CoverageDeserializer.getHistory rawCoverage)[0]
                        traceFuzzing "History deserialized"
                        do! onEach {
                            method = Application.getMethod method
                            this = case.this
                            thisType = case.thisType
                            args = case.args
                            argsTypes = case.argsTypes
                            rawCoverage = rawCoverage
                            coverage = coverage
                            result = invocationResult
                            mocks = getMocks ()
                            typeStorage = typeStorage
                            allocatedObjects = allocatedObjects
                            referencedObjects = Generator.getReferencedObjects ()
                            instantiatedMocks = Generator.getInstantiatedMocks ()
                        }
                | None -> traceFuzzing "Generics solving failed"
            with
                | :? InsufficientInformationException as e ->
                    errorFuzzing $"Insufficient information: {e.Message}\nStack trace:\n{e.StackTrace}"
                | :? NotImplementedException as e ->
                    errorFuzzing $"Not implemented: {e.Message}\nStack trace:\n{e.StackTrace}"
        }





