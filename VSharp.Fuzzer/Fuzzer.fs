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
open VSharp.Interpreter.IL

[<RequireQualifiedAccess>]
module Logger =

    let setupLogger (logFileFolderPath: string) =
        let writer = new System.IO.StreamWriter (
            System.IO.File.OpenWrite $"{logFileFolderPath}{System.IO.Path.DirectorySeparatorChar}fuzzer.log"
        )
        Console.SetError writer
        Logger.configureWriter writer
        #if DEBUG || DEBUGFUZZER
        Logger.enableTag Logger.fuzzerTraceTag
        // Logger.suppressTag Logger.noTag
        Logger.currentLogLevel <- Logger.Trace
        #endif

    let logError fmt = Logger.errorWithTag Logger.fuzzerTraceTag fmt
    let logWarning fmt = Logger.warningWithTag Logger.fuzzerTraceTag fmt
    let logInfo fmt = Logger.infoWithTag Logger.fuzzerTraceTag fmt
    let logTrace fmt = Logger.traceWithTag Logger.fuzzerTraceTag fmt

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

    let mutable method = Unchecked.defaultof<Method>
    let mutable methodBase = Unchecked.defaultof<MethodBase>
    let typeStorage = typeStorage()

    member val private Config = defaultFuzzerConfig with get, set
    member val private Generator = Generator.Generator.generate with get

    member private this.GetConcreteType st  =
        match st with
        | ConcreteType t -> t
        | MockType _ -> raise (InsufficientInformationException("Mocking not implemented"))

    member private this.SolveGenerics (method: IMethod): MethodBase option =
        let failSolving () =
            Logger.logInfo "Can't solve generic parameters"
            None
        try
            match SolveGenericMethodParameters typeStorage method with
            | Some(classParams, methodParams) ->
                let classParams = classParams |> Array.map this.GetConcreteType
                let methodParams = methodParams |> Array.map this.GetConcreteType
                if classParams.Length = methodBase.DeclaringType.GetGenericArguments().Length &&
                    (methodBase.IsConstructor || methodParams.Length = methodBase.GetGenericArguments().Length) then
                    let declaringType = Reflection.concretizeTypeParameters methodBase.DeclaringType classParams
                    let methodBase = Reflection.concretizeMethodParameters declaringType methodBase methodParams
                    Some methodBase
                else
                    failSolving ()
            | _ ->
                failSolving ()
        with :? InsufficientInformationException ->
            failSolving ()

    member private this.GetInfo () =
        let argsInfo =
            method.Parameters
            |> Array.map (fun x -> Generator.Config.defaultGeneratorConfig, x.ParameterType)

        let thisInfo =
            if method.HasThis then
                Some (Generator.Config.defaultGeneratorConfig, method.DeclaringType)
            else
                None
        
        this.SolveGenerics method
        |> Option.map (fun methodBase -> { Method = methodBase; ArgsInfo = argsInfo; ThisInfo = thisInfo })

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
        let fuzzOnce = Task.Run(fun () -> this.FuzzOnce iteration methodInfo rnd)
        let finished = fuzzOnce.Wait(this.Config.Timeout)
        if finished then fuzzOnce.Result else Logger.logInfo $"Fuzzer iteration {iteration} failed with time limit"; None

    member this.FuzzingResultToTest (result: FuzzingResult) =
        match result with
        | Returned (args, returned) -> TestGenerator.fuzzingResultToTest method args (Some returned) None
        | Thrown (args, ex) -> TestGenerator.fuzzingResultToTest method args None (Some ex)

    member this.FuzzWithAction (targetMethod: Method) (action: UnitTest option -> Task<unit>) =
        method <- targetMethod
        methodBase <- (method :> IMethod).MethodBase

        match this.GetInfo () with
        | Some info -> 
            let seed = Int32.MaxValue // Magic const!!!!
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
                    | Some v -> do! v |> this.FuzzingResultToTest |> action
                    | None -> ()
            }
        | None -> task { return () }

    member this.Configure config =
        this.Config <- config
