namespace VSharp.Fuzzer

open System
open System.Collections.Generic
open System.Reflection

open System.Reflection.Emit
open System.Text
open System.Threading.Tasks
open VSharp
open VSharp.Core
open VSharp.Fuzzer.FuzzerInfo

[<RequireQualifiedAccess>]
module Logger =
    let private fuzzerTag = "Fuzzer"
    let setupLogger (logFileFolderPath: string) =
        let writer = new System.IO.StreamWriter (
            System.IO.File.OpenWrite $"{logFileFolderPath}{System.IO.Path.DirectorySeparatorChar}fuzzer.log"
        )
        Console.SetError writer
        Logger.setTagFilter (fun t -> t = fuzzerTag)
        Logger.configureWriter writer

    let setDebugVerbosity () = Logger.currentLogLevel <- Logger.Trace
    let logError fmt = Logger.errorWithTag fuzzerTag fmt
    let logWarning fmt = Logger.warningWithTag fuzzerTag fmt
    let logInfo fmt = Logger.infoWithTag fuzzerTag fmt
    let logTrace fmt = Logger.traceWithTag fuzzerTag fmt
    let formatArray (arr: 'a array) =
        let builder = StringBuilder()
        for i in 0..arr.Length - 1 do
            builder.AppendLine $"{i}: {arr[i].ToString()}" |> ignore
        builder.ToString ()

type FuzzingMethodInfo = {
    Method: MethodBase
    ArgsInfo: (Generator.Config.GeneratorConfig * Type) array
    ThisInfo: (Generator.Config.GeneratorConfig * Type) option
}

type FuzzingResult =
    | Thrown of (obj * Type) array * exn
    | Returned of (obj * Type) array * obj

type Fuzzer ()  =

    let mutable method = Unchecked.defaultof<IMethod>
    let mutable methodBase = Unchecked.defaultof<MethodBase>
    let typeMocks = Dictionary<Type list, ITypeMock>()
    let typeMocksCache = Dictionary<ITypeMock, Type>()

    let moduleBuilder = lazy(
        let dynamicAssemblyName = "VSharpFuzzerTypeMocks"
        let assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(AssemblyName dynamicAssemblyName, AssemblyBuilderAccess.Run)
        assemblyBuilder.DefineDynamicModule dynamicAssemblyName
    )

    member val private Config = defaultFuzzerConfig with get, set
    member val private Generator = Generator.Generator.generate with get

    member private this.SolveGenerics (method: IMethod) (moduleBuilder: ModuleBuilder) (model: model option): MethodBase option =
        let typeModel =
            match model with
            | Some (StateModel (_, typeModel)) -> typeModel
            | None -> typeModel.CreateEmpty()
            | _ -> __unreachable__()

        let getConcreteType =
            function
            | ConcreteType t -> t
            | MockType mock -> __notImplemented__ ()
                // let getMock () =
                //     let freshMock = Mocking.Type(mock.Name)
                //     for t in mock.SuperTypes do
                //         freshMock.AddSuperType t
                //     for m in typeModel.typeMocks do
                //         let rnd = Random(Int32.MaxValue)
                //         let genClause () = this.Generator rnd Generator.Config.defaultGeneratorConfig m.BaseMethod.ReturnType
                //         let clauses = Array.zeroCreate this.Config.MaxClauses |> Array.map genClause
                //         freshMock.AddMethod(m.BaseMethod, clauses)
                //     freshMock.Build moduleBuilder
                // typeMocks.Add (mock.SuperTypes |> List.ofSeq, mock)
                // Dict.getValueOrUpdate typeMocksCache mock getMock

        try
            // Fix generics
            match SolveGenericMethodParameters typeModel method with
            | Some(classParams, methodParams) ->
                let classParams = classParams |> Array.map getConcreteType
                let methodParams = methodParams |> Array.map getConcreteType
                if classParams.Length = methodBase.DeclaringType.GetGenericArguments().Length &&
                    (methodBase.IsConstructor || methodParams.Length = methodBase.GetGenericArguments().Length) then
                    let declaringType = Reflection.concretizeTypeParameters methodBase.DeclaringType classParams
                    let methodBase = Reflection.concretizeMethodParameters declaringType methodBase methodParams
                    Some methodBase
                else
                    None
            | _ -> None
        with :? InsufficientInformationException -> None

    member private this.GetInfo (state: state option) =
        let model = Option.map (fun s -> s.model) state
        let methodBase =
            match this.SolveGenerics method (moduleBuilder.Force ()) model with
            | Some methodBase -> methodBase
            | None ->
                let errorMessage = "Can't solve generic parameters"
                Logger.logError $"{errorMessage}"
                internalfail $"{errorMessage}"
        let argsInfo =
            method.Parameters
            |> Array.map (fun x -> Generator.Config.defaultGeneratorConfig, x.ParameterType)
        let thisInfo =
            if method.HasThis then
                Some (Generator.Config.defaultGeneratorConfig, method.DeclaringType)
            else
                None
        { Method = methodBase; ArgsInfo = argsInfo; ThisInfo = thisInfo }

    member private this.FuzzOnce (iteration: int) (methodInfo: FuzzingMethodInfo) (rnd: Random) =
        try
            Logger.logTrace $"Start fuzzing iteration {iteration}"
            let method = methodInfo.Method
            let args = methodInfo.ArgsInfo |> Array.map (fun (config, t) -> this.Generator rnd config t, t)
            let mutable obj = null
            if Reflection.hasThis method then
                let config, t = methodInfo.ThisInfo.Value
                obj <- this.Generator rnd config t

            let argsWithThis = Array.append [|obj, method.DeclaringType|] args

            try
                Logger.logTrace $"Invoke method with \n{Logger.formatArray argsWithThis}"
                let returned = method.Invoke(obj, Array.map fst args)
                Logger.logTrace $"Method returned {returned}"
                Returned (argsWithThis, returned) |> Some
            with
            | :? TargetInvocationException as e ->
                Logger.logTrace $"Method thrown {e.InnerException.Message}"
                Thrown (argsWithThis, e.InnerException) |> Some
        with
            | e ->
                Logger.logWarning $"Fuzzing iteration {iteration} failed with: {e.Message}"
                None

    member this.FuzzOnceWithTimeout (methodInfo: FuzzingMethodInfo) (iteration: int) (rnd: Random) =
        let fuzzOnce = System.Threading.Tasks.Task.Run(fun () -> this.FuzzOnce iteration methodInfo rnd)
        let finished = fuzzOnce.Wait(this.Config.Timeout)
        if finished then fuzzOnce.Result else Logger.logInfo $"Fuzzer iteration {iteration} failed with time limit"; None

    member private this.FillState (args : array<obj * Type>) =
        // Creating state
        let state = Memory.EmptyState()
        state.model <- Memory.EmptyModel method (typeModel.CreateEmpty())
        // Creating first frame and filling stack
        let this =
            if method.HasThis then
                Some (Memory.ObjectToTerm state (fst (Array.head args)) method.DeclaringType)
            else None
        let args = Array.tail args
        let createTerm (arg, argType) = Memory.ObjectToTerm state arg argType |> Some
        let parameters = Array.map createTerm args |> List.ofArray

        Memory.InitFunctionFrame state method this (Some parameters)
        // Filling used type mocks
        let typeModel =
            match state.model with
            | StateModel(_, typeModel) -> typeModel

        for mock in typeMocks do typeModel.typeMocks.Add mock

        match state.model with
        | StateModel (model, _) ->
            Memory.InitFunctionFrame model method this (Some parameters)
        | _ -> __unreachable__()

        // Returning filled state
        state

    member private this.FuzzingResultToCompletedState (result: FuzzingResult) =
        match result with
        | Returned (args, returned) ->
            let state = this.FillState args
            // Pushing result onto evaluation stack
            let returnType = Reflection.getMethodReturnType methodBase
            let returnedTerm = Memory.ObjectToTerm state returned returnType
            state.evaluationStack <- EvaluationStack.Push returnedTerm state.evaluationStack
            state
        | Thrown(args, exn) ->
            let state = this.FillState args
            // Filling exception register
            let exnType = exn.GetType()
            let exnRef = Memory.AllocateConcreteObject state exn exnType
            // TODO: check if exception was thrown by user or by runtime
            state.exceptionsRegister <- Unhandled(exnRef, false)
            state

    member this.Fuzz target =
        method <- target
        methodBase <- method.MethodBase

        let seed = Int32.MaxValue // Magic const!!!!
        let info = this.GetInfo None
        let rndGenerator = Random(seed)
        [0..this.Config.MaxTest]
        |> List.map (fun _ -> Random(rndGenerator.Next() |> int))
        |> List.mapi (this.FuzzOnceWithTimeout info)
        |> List.choose id
        |> List.map this.FuzzingResultToCompletedState
        |> Seq.ofList

    member this.FuzzWithAction target (action: state -> Task<unit>) =
        method <- target
        methodBase <- method.MethodBase

        let seed = Int32.MaxValue // Magic const!!!!
        let info = this.GetInfo None
        let rndGenerator = Random(seed)
        let rnds =
            [0..this.Config.MaxTest]
            |> List.map (fun _ -> Random(rndGenerator.Next() |> int))
        task {
            let mutable iteration = 0
            for rnd in rnds do
                let result = this.FuzzOnceWithTimeout info iteration rnd
                iteration <- iteration + 1
                match result with
                | Some v -> do! this.FuzzingResultToCompletedState v |> action
                | None -> ()
        }

    member this.Configure config =
        this.Config <- config
