module internal VSharp.Fuzzer.UnitTest

open System
open System.Collections.Generic
open System.Reflection
open FSharpx.Collections
open Microsoft.FSharp.NativeInterop
open VSharp
open VSharp.Core
open VSharp.Fuzzer.TypeSolver
open VSharp.Interpreter.IL
open VSharp.TypeUtils

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

    let allocateArgumentAsLocalVariable (pi: ParameterInfo) obj =
        let typ = pi.ParameterType.GetElementType()
        let position = pi.Position + 1
        let allocatedObject = Memory.ObjectToTerm state obj typ
        Memory.AllocateTemporaryLocalVariable model position typ allocatedObject

    let allocateRef = allocateArgumentAsLocalVariable

    let allocatePointer (pi: ParameterInfo) obj =
        assert pi.ParameterType.IsPointer
        let pointer = Pointer.Unbox obj
        let realObj = System.Runtime.CompilerServices.Unsafe.Read pointer

        let realObjType = pi.ParameterType.GetElementType()
        let heapAddress =
            match (Memory.AllocateConcreteObject state realObj realObjType).term with
            | HeapRef (address, _ ) -> address
            | _ -> __unreachable__ ()

        let heapLocation = HeapLocation (heapAddress, realObjType)
        let ptr = Ptr heapLocation realObjType (MakeNumber 0)
        ptr

    let (|Mock|Ref|Pointer|Obj|) arg =
        if fuzzingResult.instantiatedMocks.ContainsKey arg then
            Logger.errorFuzzing $"Mock: {arg}"
            Mock fuzzingResult.instantiatedMocks[arg]
        elif fuzzingResult.referencedObjects.Contains arg then
            Logger.errorFuzzing $"Ref: {arg}"
            Ref
        elif fuzzingResult.allocatedObjects.Contains arg then
            Pointer
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
            | Mock mock -> Memory.AllocateMock state mock argType
            | Ref -> allocateRef pi arg
            | Pointer -> allocatePointer pi arg
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
        state.exceptionsRegister <- Unhandled(exRef, false, "")
    | Returned obj ->
        // Pushing result onto evaluation stack
        let returnedTerm = Memory.ObjectToTerm state obj m.ReturnType
        state.evaluationStack <- EvaluationStack.Push returnedTerm state.evaluationStack


    // Logger.traceGeneration $"Generation finished!\nResulting state:\n{Print.Dump state}"
    // Create test from filled state
    TestGenerator.state2testWithMockingCache false m state fuzzingResult.mocks ""

