module internal VSharp.Fuzzer.UnitTest

open System
open System.Collections.Generic
open System.Reflection
open FSharpx.Collections
open VSharp
open VSharp.Core
open VSharp.Fuzzer.TypeSolver
open VSharp.Interpreter.IL
open VSharp.TypeUtils

let fuzzingResultToTest (fuzzingResult: FuzzingResult) =

    // Creating state
    let m = fuzzingResult.method
    let state = Memory.EmptyState()
    state.model <- Memory.EmptyModel m
    Logger.traceGeneration "State created"

    Logger.errorFuzzing $"Referenced: {fuzzingResult.referencedObjects |> Seq.toList}"
    state.typeStorage <- fuzzingResult.typeStorage

    let model =
        match state.model with
        | StateModel state -> state
        | _ -> failwith ""

    let freshAddress () =
        state.currentTime <- VectorTime.advance state.currentTime
        state.currentTime

    let allocateMock mock typ =
        let concreteAddress = freshAddress ()
        assert(not <| PersistentDict.contains concreteAddress state.allocatedTypes)
        state.allocatedTypes <- PersistentDict.add concreteAddress (MockType mock) state.allocatedTypes
        HeapRef (ConcreteHeapAddress concreteAddress) typ

    // static member private AllocateByRefParameters initialState (method : Method) =
    //     let allocateIfByRef (pi : ParameterInfo) =
    //         if pi.ParameterType.IsByRef then
    //             if Memory.CallStackSize initialState = 0 then
    //                 Memory.NewStackFrame initialState None []
    //             let typ = pi.ParameterType.GetElementType()
    //             let position = pi.Position + 1
    //             let stackRef = Memory.AllocateTemporaryLocalVariableOfType initialState pi.Name position typ
    //             Some stackRef
    //         else
    //             None
    //     method.Parameters |> Array.map allocateIfByRef |> Array.toList

    let allocateByRefParameters () =
        let allocateIfByRef (pi : ParameterInfo) =
            if pi.ParameterType.IsByRef then
                if Memory.CallStackSize state = 0 then
                    Memory.NewStackFrame state None []
                let typ = pi.ParameterType.GetElementType()
                let position = pi.Position + 1
                let stackRef = Memory.AllocateTemporaryLocalVariableOfType state pi.Name position typ
                Some stackRef
            else
                None
        fuzzingResult.method.Parameters |> Array.map allocateIfByRef |> Array.toList

    let allocateRef (pi: ParameterInfo) obj =
        let typ = pi.ParameterType.GetElementType()
        let position = pi.Position + 1
        let allocatedObject = Memory.ObjectToTerm state obj typ
        Memory.AllocateTemporaryLocalVariable model position typ allocatedObject

    let (|Mock|Ref|Obj|) arg =
        if fuzzingResult.instantiatedMocks.ContainsKey arg then
            Logger.errorFuzzing $"Mock: {arg}"
            Mock fuzzingResult.instantiatedMocks[arg]
        elif fuzzingResult.referencedObjects.Contains arg then
            Logger.errorFuzzing $"Ref: {arg}"
            Ref
        else
            Logger.errorFuzzing $"Obj: {arg}"
            Obj

    // Creating first frame and filling stack
    let this =
        if m.HasThis then
            Some (Memory.ObjectToTerm state fuzzingResult.this fuzzingResult.thisType)
        else None

    let createTerm (arg, pi: ParameterInfo) =
        let argType = pi.ParameterType
        let result =
            match arg with
            | Mock mock -> allocateMock mock argType
            | Ref -> allocateRef pi arg
            | Obj -> Memory.ObjectToTerm state arg argType
        Some result

    let hasByRefParameters = fuzzingResult.method.Parameters |> Array.exists (fun pi -> pi.ParameterType.IsByRef)
    if hasByRefParameters then
        Memory.NewStackFrame state None []
        //Memory.NewStackFrame model None []

    let parameters =
        Array.zip fuzzingResult.args fuzzingResult.method.Parameters
        |> Array.map createTerm
        |> List.ofArray
    Memory.InitFunctionFrame state m this (Some parameters)
    Memory.InitFunctionFrame model m this (Some parameters)

    // Filling invocation result
    match fuzzingResult.result with
    | Thrown ex ->
        let exType = ex.GetType()
        // Filling exception register
        let exRef = Memory.AllocateConcreteObject state ex exType
        // TODO: check if exception was thrown by user or by runtime
        state.exceptionsRegister <- Unhandled(exRef, false)
    | Returned obj ->
        // Pushing result onto evaluation stack
        let returnedTerm = Memory.ObjectToTerm state obj m.ReturnType
        state.evaluationStack <- EvaluationStack.Push returnedTerm state.evaluationStack


    // Logger.traceGeneration $"Generation finished!\nResulting state:\n{Print.Dump state}"
    // Create test from filled state
    try
        TestGenerator.state2testWithMockingCache false m state fuzzingResult.mocks ""
    with e ->
        Logger.errorFuzzing $"{e}"
        exit 1

