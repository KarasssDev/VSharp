namespace VSharp.Fuzzer

open System
open System.Reflection

open System.Text
open System.Threading
open System.Threading.Tasks
open JetBrains.Lifetimes
open VSharp
open VSharp.Core
open VSharp.Fuzzer.Config
open VSharp.Interpreter.IL

[<RequireQualifiedAccess>]
module Logger =

    let setupLogger (logFileFolderPath: string) =
        let writer = new System.IO.StreamWriter (
            System.IO.File.OpenWrite $"{logFileFolderPath}{System.IO.Path.DirectorySeparatorChar}fuzzer.log"
        )
        Logger.configureWriter writer
        #if DEBUG || DEBUGFUZZER
        Logger.enableTag Logger.fuzzerTraceTag
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
    ArgsInfo: (GeneratorConfig * Type) array
    ThisInfo: (GeneratorConfig * Type) option
}

type FuzzingResult =
    | Thrown of (obj * Type) array * exn
    | Returned of (obj * Type) array * obj

type Fuzzer ()  =

    let mutable method = Unchecked.defaultof<Method>
    let mutable methodBase = Unchecked.defaultof<MethodBase>
    let ignoreIfNotFinished = false
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
            |> Array.map (fun x -> defaultGeneratorConfig, x.ParameterType)

        let thisInfo =
            if method.HasThis then
                Some (defaultGeneratorConfig, method.DeclaringType)
            else
                None
        
        this.SolveGenerics method
        |> Option.map (fun methodBase -> { Method = methodBase; ArgsInfo = argsInfo; ThisInfo = thisInfo })

    member private this.FuzzOnceWithTimeout (iteration: int) (methodInfo: FuzzingMethodInfo) (rnd: Random) =
        try

            Logger.logTrace $"Start fuzzing iteration {iteration}"
            let method = methodInfo.Method
            let args = methodInfo.ArgsInfo |> Array.map (fun (config, t) -> this.Generator rnd config t, t)
            let mutable obj = null
            if Reflection.hasThis method then
                let config, t = methodInfo.ThisInfo.Value
                obj <- this.Generator rnd config t

            let argsWithThis = Array.append [|obj, method.DeclaringType|] args

            let invoke () =
                try
                    Logger.logTrace $"Invoke method with \n{Logger.formatArray argsWithThis}"
                    let returned = method.Invoke(obj, Array.map fst args)
                    Logger.logTrace $"Method returned {returned}"
                    Returned (argsWithThis, returned)
                with
                | :? TargetInvocationException as e ->
                    Logger.logTrace $"Method thrown {e.InnerException.Message}"
                    Thrown (argsWithThis, e.InnerException)
            
            let invokeTask = Task.Run(invoke)
            if invokeTask.Wait(defaultFuzzerConfig.Timeout) then
                invokeTask.Result |> Some
            elif not ignoreIfNotFinished then
                Logger.logWarning "Time limit per method exceed, fuzzer stopped"
                exit 0
            else
                None
        with e ->
            Logger.logWarning $"Fuzzing iteration {iteration} failed with: {e.Message}"
            None

    // member this.FuzzOnceWithTimeout (methodInfo: FuzzingMethodInfo) (iteration: int) (rnd: Random) =
    //     let timeoutTokenSource = new CancellationTokenSource(this.Config.Timeout)
    //     let fuzzOnce = Task.Run((fun () -> this.FuzzOnce iteration methodInfo rnd), timeoutTokenSource.Token)
    //     if fuzzOnce.IsCompleted then
    //         fuzzOnce.Result
    //     else
    //         fuzzOnce.Wait()
    //         assert fuzzOnce.IsCanceled
    //         Logger.logInfo $"Fuzzer iteration {iteration} failed with time limit"
    //         None

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
                    let result = this.FuzzOnceWithTimeout iteration info rnd
                    iteration <- iteration + 1
                    match result with
                    | Some v -> do! v |> this.FuzzingResultToTest |> action
                    | None -> ()
            }
        | None -> task { return () }

    member this.Configure config =
        this.Config <- config
