namespace VSharp.System

open System
open global.System

open VSharp
open VSharp.Core
open VSharp.Interpreter.IL
open VSharp.Interpreter.IL.CilStateOperations

// ------------------------------ System.ReadOnlySpan --------------------------------

module internal ReadOnlySpan =

    let private isContentReferenceField fieldId =
        let name = fieldId.name
        name = "_pointer" || name = "_reference"

    let private isLengthField fieldId =
        fieldId.name = "_length"

    let ptrFieldIsByRef (ptrFieldType : Type) =
        ptrFieldType.FullName.Contains("System.ByReference")

    let readOnlySpanType() =
        typeof<int>.Assembly.GetType("System.ReadOnlySpan`1")

    let private CreateArrayRef address indices (eType : Type, dim, isVector as arrayType) =
        if isVector && indices = [MakeNumber 0] then
            HeapRef address (eType.MakeArrayType())
        elif indices = List.init dim (fun _ -> MakeNumber 0) then
            HeapRef address (eType.MakeArrayType dim)
        else ArrayIndex(address, indices, arrayType) |> Ref

    let GetLength (state : state) (spanStruct : term) =
        let spanFields = Terms.TypeOf spanStruct |> Reflection.fieldsOf false
        assert(Array.length spanFields = 2)
        let lenField = spanFields |> Array.find (fst >> isLengthField) |> fst
        Memory.ReadField state spanStruct lenField

    let GetContents (cilState : cilState) (spanStruct : term) =
        let spanFields = Terms.TypeOf spanStruct |> Reflection.fieldsOf false
        assert(Array.length spanFields = 2)
        let state = cilState.state
        let ptrField = spanFields |> Array.find (fst >> isContentReferenceField) |> fst
        let lenField = spanFields |> Array.find (fst >> isLengthField) |> fst
        let len = readField cilState spanStruct lenField
        let ptrFieldValue = readField cilState spanStruct ptrField
        let ptrFieldType = ptrField.typ
        let ptr =
            if ptrFieldIsByRef ptrFieldType then
                // Case for .NET 6, where Span contains 'System.ByReference' field
                let byRefFields = Terms.TypeOf ptrFieldValue |> Reflection.fieldsOf false
                assert(Array.length byRefFields = 1)
                let byRefField = byRefFields |> Array.find (fst >> ByReference.isValueField) |> fst
                readField cilState ptrFieldValue byRefField
            else
                // Case for .NET 7, where Span contains 'Byte&' field
                ptrFieldValue
        let ref =
            match ptr.term with
            // Case for char span made from string
            | Ref(ClassField(address, field)) when field = Reflection.stringFirstCharField ->
                let address, arrayType = Memory.StringArrayInfo state address None
                CreateArrayRef address [MakeNumber 0] arrayType
            | Ref(ArrayIndex(addr, indices, arrayType)) ->
                CreateArrayRef addr indices arrayType
            | HeapRef(address, _) ->
                let t = MostConcreteTypeOfRef state ptr
                if TypeUtils.isArrayType t then ptr
                elif t = typeof<string> then
                    let address, arrayType = Memory.StringArrayInfo state address None
                    CreateArrayRef address [MakeNumber 0] arrayType
                elif TypeUtils.isValueType t && len = MakeNumber 1 then
                    HeapReferenceToBoxReference ptr
                else internalfail $"GetContents: unexpected pointer {ptr}"
            | DetachedPtr _ -> ptr
            | Ptr(HeapLocation(_, t) as pointerBase, sightType, offset) ->
                // TODO: add 'TryPtrToRef' to ctor
                match TryPtrToRef state pointerBase sightType offset with
                | Some(ArrayIndex(address, indices, arrayType)) -> CreateArrayRef address indices arrayType
                | Some address -> Ref address
                | None when t.IsSZArray || t = typeof<string> -> ptr
                | None -> internalfail $"GetContentsRef: unexpected pointer to contents {ptr}"
            | Ptr(pointerBase, sightType, offset) when len = MakeNumber 1 ->
                match TryPtrToRef state pointerBase sightType offset with
                | Some address -> Ref address
                | _ -> ptr
            | _ -> internalfail $"GetContentsRef: unexpected reference to contents {ptr}"
        ref, len

    let private IsArrayContents ref =
        match ref.term with
        | HeapRef(_, t)
        | Ptr(HeapLocation(_, t), _, _) ->
            TypeUtils.isArrayType t || t = typeof<string>
        | Ref(ArrayIndex _) -> true
        | _ -> false

    let GetItem (i : IInterpreter) (cilState : cilState) (args : term list) =
        assert(List.length args = 3)
        let this, wrappedType, index = args[0], args[1], args[2]
        let t = Helpers.unwrapType wrappedType
        let span = read cilState this
        let ref, len = GetContents cilState span
        let checkIndex cilState k =
            let readIndex cilState k =
                let ref =
                    if IsArrayContents ref then
                        Memory.ReferenceArrayIndex cilState.state ref [index] (Some t)
                    elif index = MakeNumber 0 then
                        assert(TypeOfLocation ref = t)
                        ref
                    else internalfail $"GetItemFromReadOnlySpan: unexpected contents ref {ref}"
                push ref cilState
                List.singleton cilState |> k
            StatedConditionalExecutionCIL cilState
                (fun state k -> k (Arithmetics.Less index len, state))
                readIndex
                (i.Raise i.IndexOutOfRangeException)
                k
        i.NpeOrInvoke cilState ref checkIndex id

    let private InitSpanStruct cilState spanStruct refToFirst length =
        let spanFields = Terms.TypeOf spanStruct |> Reflection.fieldsOf false
        assert(Array.length spanFields = 2)
        let ptrField, ptrFieldInfo = spanFields |> Array.find (fst >> isContentReferenceField)
        let ptrFieldType = ptrFieldInfo.FieldType
        let spanWithPtrField =
            if ptrFieldIsByRef ptrFieldType then
                // Case for .NET 6, where Span contains 'System.ByReference' field
                let byRef = Memory.DefaultOf ptrFieldType
                let byRefFields = Reflection.fieldsOf false ptrFieldType
                assert(Array.length byRefFields = 1)
                let valueField = byRefFields |> Array.find (fst >> ByReference.isValueField) |> fst
                let initializedByRef = writeStructField cilState byRef valueField refToFirst
                writeStructField cilState spanStruct ptrField initializedByRef
            else
                // Case for .NET 7, where Span contains 'Byte&' field
                writeStructField cilState spanStruct ptrField refToFirst
        let lengthField = spanFields |> Array.find (fst >> isLengthField) |> fst
        writeStructField cilState spanWithPtrField lengthField length

    let private CommonCtor (cilState : cilState) this refToFirst length =
        let span = read cilState this
        let initializedSpan = InitSpanStruct cilState span refToFirst length
        write cilState this initializedSpan

    let CtorFromPtr (i : IInterpreter) (cilState : cilState) (args : term list) : cilState list =
        assert(List.length args = 4)
        let this, wrappedType, ptr, size = args[0], args[1], args[2], args[3]
        let t = Helpers.unwrapType wrappedType
        let ctor cilState k =
            let state = cilState.state
            let ptr =
                if isStackArray cilState ptr then
                    // Ptr came from localloc instruction
                    Memory.AllocateVectorArray state size t
                elif MostConcreteTypeOfRef state ptr = t then ptr
                else Types.Cast ptr (t.MakePointerType())
            CommonCtor cilState this ptr size |> k
        StatedConditionalExecutionCIL cilState
            (fun state k -> k (Arithmetics.GreaterOrEqual size (MakeNumber 0), state))
            ctor
            (i.Raise i.ArgumentOutOfRangeException)
            id

    let CtorFromArray (_ : IInterpreter) (cilState : cilState) (args : term list) : cilState list =
        assert(List.length args = 3)
        let this, arrayRef = args[0], args[2]
        let state = cilState.state
        let refToFirstElement = Memory.ReferenceArrayIndex state arrayRef [MakeNumber 0] None
        let lengthOfArray = Memory.ArrayLengthByDimension state arrayRef (MakeNumber 0)
        CommonCtor cilState this refToFirstElement lengthOfArray

    let CreateFromString (_ : IInterpreter) (cilState : cilState) (args : term list) : cilState list =
        assert(List.length args = 1)
        let string = args[0]
        let spanType = readOnlySpanType().MakeGenericType(typeof<char>)
        let span = Memory.DefaultOf spanType
        let state = cilState.state
        let refToFirst = Memory.ReferenceField state string Reflection.stringFirstCharField
        let length = Memory.StringLength state string
        let spanStruct = InitSpanStruct cilState span refToFirst length
        push spanStruct cilState
        List.singleton cilState
