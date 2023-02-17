namespace VSharp.Fuzzer

open System.Runtime.InteropServices
open VSharp
open System.Reflection
open System.Reflection.Emit
open System.Collections.Generic
open VSharp.Interpreter.IL

// TODO: delete all after c++ instrumentation
[<type: StructLayout(LayoutKind.Sequential, Pack=1, CharSet=CharSet.Ansi)>]
type probesCov = {
    mutable trackCoverage : uint64
    mutable brtrue : uint64
    mutable brfalse : uint64
    mutable switch : uint64
    mutable enter : uint64
    mutable enterMain : uint64
    mutable leave : uint64
    mutable leaveMain_0 : uint64
    mutable leaveMain_4 : uint64
    mutable leaveMain_8 : uint64
    mutable leaveMain_f4 : uint64
    mutable leaveMain_f8 : uint64
    mutable leaveMain_p : uint64
    mutable finalizeCall : uint64
}
with
    member private x.Probe2str =
        let map = System.Collections.Generic.Dictionary<uint64, string>()
        typeof<probesCov>.GetFields() |> Seq.iter (fun fld -> map.Add(fld.GetValue x |> unbox, fld.Name))
        map
    member x.AddressToString (address : int64) =
        let result = ref ""
        if x.Probe2str.TryGetValue(uint64 address, result) then "probe_" + result.Value
        else toString address

type InstrumenterCoverage(probes : probesCov) =
    // TODO: should we consider executed assembly build options here?
    let ldc_i : opcode = (if System.Environment.Is64BitOperatingSystem then OpCodes.Ldc_I8 else OpCodes.Ldc_I4) |> VSharp.OpCode
    let mutable currentStaticFieldID = 0
    let staticFieldIDs = Dictionary<int, FieldInfo>()

    let mutable currentFunctionID = 0
    let functionsIDs = Dictionary<int, MethodInfo>()

    let mutable entryPoint : Option<MethodBase> = None

    member public x.setEntryPoint entryMethod = entryPoint <- Some entryMethod

    static member private instrumentedFunctions = HashSet<MethodBase>()
    [<DefaultValue>] val mutable tokens : signatureTokens
    [<DefaultValue>] val mutable rewriter : ILRewriter
    [<DefaultValue>] val mutable m : MethodBase

    member x.StaticFieldByID id = staticFieldIDs[id]
    member x.FunctionByID id = functionsIDs[id]

    member private x.MkCalli(instr : ilInstr byref, signature : uint32) =
        instr <- x.rewriter.NewInstr OpCodes.Calli
        instr.arg <- Arg32 (int32 signature)

    member private x.PrependInstr(opcode, arg, beforeInstr : ilInstr byref) =
        let mutable newInstr = x.rewriter.CopyInstruction(beforeInstr)
        x.rewriter.InsertAfter(beforeInstr, newInstr)
        swap &newInstr &beforeInstr
        newInstr.opcode <- VSharp.OpCode opcode
        newInstr.arg <- arg
        newInstr

    member private x.PrependNop(beforeInstr : ilInstr byref) =
        x.PrependInstr(OpCodes.Nop, NoArg, &beforeInstr)

    member private x.PrependBranch(opcode, beforeInstr : ilInstr byref) =
        x.PrependInstr(opcode, NoArg (*In chain of prepends, the address of instruction constantly changes. Deferring it.*), &beforeInstr)

    member private x.AppendInstr (opcode : OpCode) arg (afterInstr : ilInstr) =
        let dupInstr = x.rewriter.NewInstr opcode
        dupInstr.arg <- arg
        x.rewriter.InsertAfter(afterInstr, dupInstr)

    member private x.AppendNop (afterInstr : ilInstr) =
        x.AppendInstr OpCodes.Nop NoArg afterInstr
        afterInstr.next

    member private x.PrependDup(beforeInstr : ilInstr byref) = x.PrependInstr(OpCodes.Dup, NoArg, &beforeInstr)
    member private x.AppendDup afterInstr = x.AppendInstr OpCodes.Dup NoArg afterInstr

    member private x.PrependProbe(methodAddress : uint64, args : (OpCode * ilInstrOperand) list, signature, beforeInstr : ilInstr byref) =
        let result = beforeInstr
        let mutable newInstr = x.rewriter.CopyInstruction(beforeInstr)
        x.rewriter.InsertAfter(beforeInstr, newInstr)
        swap &newInstr &beforeInstr

        match args with
        | (opcode, arg)::tail ->
            newInstr.opcode <- VSharp.OpCode opcode
            newInstr.arg <- arg
            for opcode, arg in tail do
                let newInstr = x.rewriter.NewInstr opcode
                newInstr.arg <- arg
                x.rewriter.InsertBefore(beforeInstr, newInstr)

            newInstr <- x.rewriter.NewInstr ldc_i
            newInstr.arg <- Arg64 (int64 methodAddress)
            x.rewriter.InsertBefore(beforeInstr, newInstr)
        | [] ->
            newInstr.opcode <- ldc_i
            newInstr.arg <- Arg64 (int64 methodAddress)

        x.MkCalli(&newInstr, signature)
        x.rewriter.InsertBefore(beforeInstr, newInstr)
        result

    member private x.PrependProbeWithOffset(methodAddress : uint64, args : (OpCode * ilInstrOperand) list, signature, beforeInstr : ilInstr byref) =
        x.PrependProbe(methodAddress, List.append args [(OpCodes.Ldc_I4, beforeInstr.offset |> int32 |> Arg32)], signature, &beforeInstr)

    member private x.AppendProbe(methodAddress : uint64, args : (OpCode * ilInstrOperand) list, signature, afterInstr : ilInstr) =
        let mutable calliInstr = afterInstr
        x.MkCalli(&calliInstr, signature)
        x.rewriter.InsertAfter(afterInstr, calliInstr)

        let newInstr = x.rewriter.NewInstr ldc_i
        newInstr.arg <- Arg64 (int64 methodAddress)
        x.rewriter.InsertAfter(afterInstr, newInstr)

        for opcode, arg in List.rev args do
            let newInstr = x.rewriter.NewInstr opcode
            newInstr.arg <- arg
            x.rewriter.InsertAfter(afterInstr, newInstr)

        calliInstr

    // NOTE: offset is sent from client to SILI
    member private x.AppendProbeWithOffset(methodAddress : uint64, args : (OpCode * ilInstrOperand) list, offset, signature, afterInstr : ilInstr) =
        x.AppendProbe(methodAddress, List.append args [(OpCodes.Ldc_I4, offset |> int32 |> Arg32)], signature, afterInstr)

    member private x.PlaceEnterProbe (firstInstr : ilInstr byref) =
        let isSpontaneous = if Reflection.isExternalMethod x.m || Reflection.isStaticConstructor x.m then 1 else 0
        let locals, localsCount =
            match x.m.GetMethodBody() with
            | null -> null, 0
            | mb ->
                let locals = mb.LocalVariables
                locals, locals.Count
        let parameters = x.m.GetParameters()
        let hasThis = Reflection.hasThis x.m
        let argsCount = parameters.Length
        let totalArgsCount = if hasThis then argsCount + 1 else argsCount
        // TODO: MethodHandles are not equal, fix it
        let isMain = match entryPoint with
                        | None -> false
                        | Some e -> x.m.Name = e.Name
        if isMain then
            let args = [(OpCodes.Ldc_I4, Arg32 x.m.MetadataToken)
                        (OpCodes.Ldc_I4, Arg32 (Coverage.moduleToken x.m.Module))
                        (OpCodes.Ldc_I4, Arg32 totalArgsCount)
//                        (OpCodes.Ldc_I4, Arg32 1) // Arguments of entry point are concrete
                        (OpCodes.Ldc_I4, Arg32 0) // Arguments of entry point are symbolic
                        (OpCodes.Ldc_I4, x.rewriter.MaxStackSize |> int32 |> Arg32)
                        (OpCodes.Ldc_I4, Arg32 localsCount)]
            x.PrependProbe(probes.enterMain, args, x.tokens.void_token_u4_u2_bool_u4_u4_sig, &firstInstr) |> ignore
        else
            let args = [(OpCodes.Ldc_I4, Arg32 x.m.MetadataToken)
                        (OpCodes.Ldc_I4, Arg32 (Coverage.moduleToken x.m.Module))
                        (OpCodes.Ldc_I4, x.rewriter.MaxStackSize |> int32 |> Arg32)
                        (OpCodes.Ldc_I4, Arg32 totalArgsCount)
                        (OpCodes.Ldc_I4, Arg32 localsCount)
                        (OpCodes.Ldc_I4, Arg32 isSpontaneous)]
            x.PrependProbe(probes.enter, args, x.tokens.void_token_u4_u4_u4_u4_i1_sig, &firstInstr) |> ignore

    member private x.PrependValidLeaveMain(instr : ilInstr byref) =
        match instr.stackState with
        | _ when Reflection.hasNonVoidResult x.m |> not ->
            x.PrependProbeWithOffset(probes.leaveMain_0, [], x.tokens.void_offset_sig, &instr) |> ignore
        | UnOp evaluationStackCellType.I1
        | UnOp evaluationStackCellType.I2
        | UnOp evaluationStackCellType.I4 ->
            // TODO: 2Misha: Why mem value and then dup and pass it to probe?
            x.PrependDup &instr |> ignore
            x.PrependProbeWithOffset(probes.leaveMain_4, [], x.tokens.void_i4_offset_sig, &instr) |> ignore
        | UnOp evaluationStackCellType.I8 ->
            x.PrependDup &instr |> ignore
            x.PrependProbeWithOffset(probes.leaveMain_8, [], x.tokens.void_i8_offset_sig, &instr) |> ignore
        | UnOp evaluationStackCellType.R4 ->
            x.PrependDup &instr |> ignore
            x.PrependProbeWithOffset(probes.leaveMain_f4, [], x.tokens.void_r4_offset_sig, &instr) |> ignore
        | UnOp evaluationStackCellType.R8 ->
            x.PrependDup &instr |> ignore
            x.PrependProbeWithOffset(probes.leaveMain_f8, [], x.tokens.void_r8_offset_sig, &instr) |> ignore
        | UnOp evaluationStackCellType.I ->
            x.PrependDup &instr |> ignore
            x.PrependProbeWithOffset(probes.leaveMain_p, [], x.tokens.void_i_offset_sig, &instr) |> ignore
        | UnOp evaluationStackCellType.Ref ->
            x.PrependDup &instr |> ignore
            x.PrependInstr(OpCodes.Conv_I, NoArg, &instr) |> ignore
            x.PrependProbeWithOffset(probes.leaveMain_p, [], x.tokens.void_i_offset_sig, &instr) |> ignore
        | UnOp evaluationStackCellType.Struct
        | UnOp evaluationStackCellType.RefLikeStruct ->
            x.PrependDup &instr |> ignore
            let returnType = Reflection.getMethodReturnType x.m
            let returnTypeToken = x.AcceptReturnTypeToken returnType
            x.PrependInstr(OpCodes.Box, Arg32 returnTypeToken, &instr) |> ignore
            x.PrependInstr(OpCodes.Conv_I, NoArg, &instr) |> ignore
            x.PrependProbeWithOffset(probes.leaveMain_p, [], x.tokens.void_i_offset_sig, &instr) |> ignore
        | _ -> internalfailf "PrependValidLeaveMain: unexpected stack state! %O" instr.stackState

    member private x.PlaceLeaveProbe(instr : ilInstr byref) =
        let isMain = match entryPoint with
                        | None -> false
                        | Some e -> x.m.MethodHandle = e.MethodHandle
        if isMain then
            x.PrependValidLeaveMain(&instr)
        else
            let returnsSomething = Reflection.hasNonVoidResult x.m
            let args = [(OpCodes.Ldc_I4, (if returnsSomething then 1 else 0) |> Arg32)]
            x.PrependProbeWithOffset(probes.leave, args, x.tokens.void_u1_offset_sig, &instr) |> ignore

    member x.MethodName with get() = x.m.Name

    member private x.PrependLdcDefault(t : System.Type, instr : ilInstr byref) =
        match t with
        | _ when not t.IsValueType -> x.PrependInstr(OpCodes.Ldnull, NoArg, &instr)
        | _ when t = typeof<bool> -> x.PrependInstr(OpCodes.Ldc_I4_0, NoArg, &instr)
        | _ when t = typeof<int8> -> x.PrependInstr(OpCodes.Ldc_I4_0, NoArg, &instr)
        | _ when t = typeof<uint8> -> x.PrependInstr(OpCodes.Ldc_I4_0,NoArg, &instr)
        | _ when t = typeof<int16> -> x.PrependInstr(OpCodes.Ldc_I4_0, NoArg, &instr)
        | _ when t = typeof<uint16> -> x.PrependInstr(OpCodes.Ldc_I4_0, NoArg, &instr)
        | _ when t = typeof<int> -> x.PrependInstr(OpCodes.Ldc_I4_0, NoArg, &instr)
        | _ when t = typeof<uint> -> x.PrependInstr(OpCodes.Ldc_I4_0, NoArg, &instr)
        | _ when t = typeof<int64> -> x.PrependInstr(OpCodes.Ldc_I8, (Arg64 0L), &instr)
        | _ when t = typeof<uint64> -> x.PrependInstr(OpCodes.Ldc_I8, (Arg64 0L), &instr)
        | _ when t = typeof<single> -> x.PrependInstr(OpCodes.Ldc_R4, (Arg32 0), &instr)
        | _ when t = typeof<double> -> x.PrependInstr(OpCodes.Ldc_R8, (Arg64 0L), &instr)
        | _ -> __unreachable__()

    member private x.SizeOfIndirection = function
        | OpCodeValues.Ldind_I1
        | OpCodeValues.Ldind_U1
        | OpCodeValues.Stind_I1 -> 1
        | OpCodeValues.Ldind_I2
        | OpCodeValues.Ldind_U2
        | OpCodeValues.Stind_I2 -> 2
        | OpCodeValues.Ldind_I4
        | OpCodeValues.Ldind_U4
        | OpCodeValues.Ldind_R4
        | OpCodeValues.Stind_I4
        | OpCodeValues.Stind_R4 -> 4
        | OpCodeValues.Ldind_I8
        | OpCodeValues.Ldind_R8
        | OpCodeValues.Stind_I8
        | OpCodeValues.Stind_R8 -> 8
        | OpCodeValues.Ldind_I
        | OpCodeValues.Ldind_Ref
        | OpCodeValues.Stind_I
        | OpCodeValues.Stind_Ref -> System.IntPtr.Size
        | _ -> __unreachable__()

    member private x.AcceptTypeToken (t : System.Type) accept =
        if t.Module = x.m.Module && t.IsTypeDefinition && not (t.IsGenericType || t.IsGenericTypeDefinition) then
            t.MetadataToken
        else accept()

    member private x.AcceptFieldTypeToken (f : FieldInfo) =
        if f.Module = x.m.Module then
            x.AcceptTypeToken f.DeclaringType (fun () -> x.AcceptFieldDefTypeToken f.MetadataToken)
        else
            x.AcceptFieldRefTypeToken f.MetadataToken

    member private x.AcceptFieldRefTypeToken (memberRef : int) =
        __notImplemented__()
        // InteropCalls.FieldRefTypeToken (memberRef |> uint) |> int

    member private x.AcceptFieldDefTypeToken (fieldDef : int) =
        __notImplemented__()
        // InteropCalls.FieldDefTypeToken (fieldDef |> uint) |> int

    member private x.AcceptArgTypeToken (t : System.Type) idx =
        x.AcceptTypeToken t (fun () ->
            let methodDef = x.m.MetadataToken
            __notImplemented__())
            // InteropCalls.ArgTypeToken (methodDef |> uint, idx |> uint) |> int)

    member private x.AcceptLocVarTypeToken (t : System.Type) idx =
        __notImplemented__()
        // x.AcceptTypeToken t (fun () -> InteropCalls.LocalTypeToken idx |> int)

    member private x.AcceptReturnTypeToken (t : System.Type) =
        __notImplemented__()
        // x.AcceptTypeToken t (InteropCalls.ReturnTypeToken >> int)

    member private x.AcceptDeclaringTypeToken (m : MethodBase) (methodToken : int) =
        __notImplemented__()
        // x.AcceptTypeToken m.DeclaringType (fun () -> InteropCalls.DeclaringTypeToken (methodToken |> uint) |> int)

    member private x.TypeSizeInstr (t : System.Type) getToken =
        if t.IsByRef || t.IsArray || (t.IsConstructedGenericType && t.GetGenericTypeDefinition().FullName = "System.ByReference`1") then
            OpCodes.Ldc_I4, Arg32 System.IntPtr.Size
        elif TypeUtils.isGround t then
            let size = TypeUtils.internalSizeOf t
            OpCodes.Ldc_I4, Arg32 (int size)
        else
            let typeToken = getToken()
            OpCodes.Sizeof, Arg32 typeToken

    member x.PlaceProbes() =
        let instructions = x.rewriter.CopyInstructions()
        Logger.error "PlaceProbes : 1"
        let method = Application.getMethod x.m
        let cfg =
            match method.CFG with
            | Some cfg -> cfg
            | None -> internalfailf $"Getting CFG of method {x} without body (extern or abstract)"
        let basicBlocks = cfg.SortedOffsets
        let mutable currentBasicBlockIndex = 0
        assert(not <| Array.isEmpty instructions)
        let mutable atLeastOneReturnFound = false
        let mutable hasPrefix = false
        let mutable prefixCell = instructions.[0]
        let mutable prefix : ilInstr byref = &prefixCell
        x.PlaceEnterProbe(&instructions.[0])
        for i in 0 .. instructions.Length - 1 do
            let instr = &instructions.[i]
            if not hasPrefix then prefix <- instr
            match instr.opcode with
            | OpCode op ->
                let prependTarget = if hasPrefix then &prefix else &instr
                if not hasPrefix && uint32 basicBlocks[currentBasicBlockIndex] = instr.offset then
                    x.PrependProbeWithOffset(probes.trackCoverage, [], x.tokens.void_offset_sig, &instr) |> ignore
                    currentBasicBlockIndex <- currentBasicBlockIndex + 1

                let opcodeValue = LanguagePrimitives.EnumOfValue op.Value
                match opcodeValue with
                // Prefixes
                | OpCodeValues.Unaligned_
                | OpCodeValues.Volatile_
                | OpCodeValues.Tail_
                | OpCodeValues.Constrained_
                | OpCodeValues.Readonly_  ->
                    hasPrefix <- true

                // Concrete instructions
                | OpCodeValues.Ldarga_S
                | OpCodeValues.Ldloca_S
                | OpCodeValues.Ldarga
                | OpCodeValues.Ldloca
                | OpCodeValues.Ldnull
                | OpCodeValues.Ldc_I4_M1
                | OpCodeValues.Ldc_I4_0
                | OpCodeValues.Ldc_I4_1
                | OpCodeValues.Ldc_I4_2
                | OpCodeValues.Ldc_I4_3
                | OpCodeValues.Ldc_I4_4
                | OpCodeValues.Ldc_I4_5
                | OpCodeValues.Ldc_I4_6
                | OpCodeValues.Ldc_I4_7
                | OpCodeValues.Ldc_I4_8
                | OpCodeValues.Ldc_I4_S
                | OpCodeValues.Ldc_I4
                | OpCodeValues.Ldc_I8
                | OpCodeValues.Ldc_R4
                | OpCodeValues.Ldc_R8
                | OpCodeValues.Pop
                | OpCodeValues.Ldtoken
                | OpCodeValues.Arglist
                | OpCodeValues.Ldftn
                | OpCodeValues.Sizeof

                // Branchings
                | OpCodeValues.Brfalse_S
                | OpCodeValues.Brfalse -> x.PrependProbeWithOffset(probes.brfalse, [], x.tokens.void_offset_sig, &prependTarget) |> ignore
                | OpCodeValues.Brtrue_S
                | OpCodeValues.Brtrue -> x.PrependProbeWithOffset(probes.brtrue, [], x.tokens.void_offset_sig, &prependTarget) |> ignore
                | OpCodeValues.Switch -> x.PrependProbeWithOffset(probes.switch, [], x.tokens.void_offset_sig, &prependTarget) |> ignore

                // Symbolic stack instructions
                | OpCodeValues.Ldarg_0
                | OpCodeValues.Ldarg_1
                | OpCodeValues.Ldarg_2
                | OpCodeValues.Ldarg_3
                | OpCodeValues.Ldloc_0
                | OpCodeValues.Ldloc_1
                | OpCodeValues.Ldloc_2
                | OpCodeValues.Ldloc_3
                | OpCodeValues.Stloc_0
                | OpCodeValues.Stloc_1
                | OpCodeValues.Stloc_2
                | OpCodeValues.Stloc_3
                | OpCodeValues.Ldarg_S
                | OpCodeValues.Starg_S
                | OpCodeValues.Ldloc_S
                | OpCodeValues.Stloc_S
                | OpCodeValues.Ldarg
                | OpCodeValues.Starg
                | OpCodeValues.Ldloc
                | OpCodeValues.Stloc
                | OpCodeValues.Dup

                | OpCodeValues.Add
                | OpCodeValues.Sub
                | OpCodeValues.Mul
                | OpCodeValues.Div
                | OpCodeValues.Div_Un
                | OpCodeValues.Rem
                | OpCodeValues.Rem_Un
                | OpCodeValues.And
                | OpCodeValues.Or
                | OpCodeValues.Xor
                | OpCodeValues.Shl
                | OpCodeValues.Shr
                | OpCodeValues.Shr_Un
                | OpCodeValues.Add_Ovf
                | OpCodeValues.Add_Ovf_Un
                | OpCodeValues.Mul_Ovf
                | OpCodeValues.Mul_Ovf_Un
                | OpCodeValues.Sub_Ovf
                | OpCodeValues.Sub_Ovf_Un
                | OpCodeValues.Ceq
                | OpCodeValues.Cgt
                | OpCodeValues.Cgt_Un
                | OpCodeValues.Clt
                | OpCodeValues.Clt_Un
                | OpCodeValues.Neg
                | OpCodeValues.Not

                | OpCodeValues.Conv_I1
                | OpCodeValues.Conv_I2
                | OpCodeValues.Conv_I4
                | OpCodeValues.Conv_I8
                | OpCodeValues.Conv_R4
                | OpCodeValues.Conv_R8
                | OpCodeValues.Conv_U4
                | OpCodeValues.Conv_U8
                | OpCodeValues.Conv_R_Un
                | OpCodeValues.Conv_U2
                | OpCodeValues.Conv_U1
                | OpCodeValues.Conv_I
                | OpCodeValues.Conv_U
                | OpCodeValues.Conv_Ovf_I1_Un
                | OpCodeValues.Conv_Ovf_I2_Un
                | OpCodeValues.Conv_Ovf_I4_Un
                | OpCodeValues.Conv_Ovf_I8_Un
                | OpCodeValues.Conv_Ovf_U1_Un
                | OpCodeValues.Conv_Ovf_U2_Un
                | OpCodeValues.Conv_Ovf_U4_Un
                | OpCodeValues.Conv_Ovf_U8_Un
                | OpCodeValues.Conv_Ovf_I_Un
                | OpCodeValues.Conv_Ovf_U_Un
                | OpCodeValues.Conv_Ovf_I1
                | OpCodeValues.Conv_Ovf_U1
                | OpCodeValues.Conv_Ovf_I2
                | OpCodeValues.Conv_Ovf_U2
                | OpCodeValues.Conv_Ovf_I4
                | OpCodeValues.Conv_Ovf_U4
                | OpCodeValues.Conv_Ovf_I8
                | OpCodeValues.Conv_Ovf_U8
                | OpCodeValues.Conv_Ovf_I
                | OpCodeValues.Conv_Ovf_U

                | OpCodeValues.Ldind_I1
                | OpCodeValues.Ldind_U1
                | OpCodeValues.Ldind_I2
                | OpCodeValues.Ldind_U2
                | OpCodeValues.Ldind_I4
                | OpCodeValues.Ldind_U4
                | OpCodeValues.Ldind_I8
                | OpCodeValues.Ldind_I
                | OpCodeValues.Ldind_R4
                | OpCodeValues.Ldind_R8
                | OpCodeValues.Ldind_Ref

                | OpCodeValues.Stind_Ref
                | OpCodeValues.Stind_I1
                | OpCodeValues.Stind_I2
                | OpCodeValues.Stind_I4
                | OpCodeValues.Stind_I8
                | OpCodeValues.Stind_R4
                | OpCodeValues.Stind_R8
                | OpCodeValues.Stind_I

                | OpCodeValues.Mkrefany
                | OpCodeValues.Newarr
                | OpCodeValues.Localloc
                | OpCodeValues.Cpobj
                | OpCodeValues.Ldobj
                | OpCodeValues.Ldstr
                | OpCodeValues.Castclass
                | OpCodeValues.Isinst
                | OpCodeValues.Unbox
                | OpCodeValues.Unbox_Any
                | OpCodeValues.Ldfld
                | OpCodeValues.Ldflda
                | OpCodeValues.Stfld
                | OpCodeValues.Ldsfld
                | OpCodeValues.Ldsflda
                | OpCodeValues.Stsfld
                | OpCodeValues.Stobj
                | OpCodeValues.Box
                | OpCodeValues.Ldlen
                | OpCodeValues.Ldelema
                | OpCodeValues.Ldelem_I1
                | OpCodeValues.Ldelem_U1
                | OpCodeValues.Ldelem_I2
                | OpCodeValues.Ldelem_U2
                | OpCodeValues.Ldelem_I4
                | OpCodeValues.Ldelem_U4
                | OpCodeValues.Ldelem_I8
                | OpCodeValues.Ldelem_I
                | OpCodeValues.Ldelem_R4
                | OpCodeValues.Ldelem_R8
                | OpCodeValues.Ldelem_Ref
                | OpCodeValues.Ldelem
                | OpCodeValues.Stelem_I
                | OpCodeValues.Stelem_I1
                | OpCodeValues.Stelem_I2
                | OpCodeValues.Stelem_I4
                | OpCodeValues.Stelem_I8
                | OpCodeValues.Stelem_R4
                | OpCodeValues.Stelem_R8
                | OpCodeValues.Stelem_Ref
                | OpCodeValues.Stelem
                | OpCodeValues.Ckfinite
                | OpCodeValues.Ldvirtftn
                | OpCodeValues.Initobj
                | OpCodeValues.Cpblk
                | OpCodeValues.Initblk
                | OpCodeValues.Rethrow

                | OpCodeValues.Call
                | OpCodeValues.Callvirt
                | OpCodeValues.Newobj
                | OpCodeValues.Calli -> ()

                | OpCodeValues.Ret ->
                    assert (not hasPrefix)
                    atLeastOneReturnFound <- true
                    x.PlaceLeaveProbe &instr
                | OpCodeValues.Throw

                // Ignored instructions
                | OpCodeValues.Nop
                | OpCodeValues.Break
                | OpCodeValues.Jmp
                | OpCodeValues.Refanyval
                | OpCodeValues.Refanytype
                | OpCodeValues.Endfinally
                | OpCodeValues.Br_S
                | OpCodeValues.Br
                | OpCodeValues.Leave
                | OpCodeValues.Leave_S
                | OpCodeValues.Endfilter -> ()
                | opcode -> internalfail $"opcode = {opcode}"

                if hasPrefix && op.OpCodeType <> OpCodeType.Prefix then
                    hasPrefix <- false
                instructions.[i] <- instr
            | SwitchArg -> ()
        assert atLeastOneReturnFound

    member x.Skip (body : rawMethodBody) =
        { properties = {ilCodeSize = body.properties.ilCodeSize; maxStackSize = body.properties.maxStackSize}; il = body.il; ehs = body.ehs}

    member private x.ShouldInstrument = not (Application.getMethod x.m).IsInternalCall

    member x.Instrument(body : rawMethodBody) =
        assert(x.rewriter = null)
        x.tokens <- body.tokens
        Logger.error "Instrument : start"
        // TODO: call Application.getMethod and take ILRewriter there!
        x.rewriter <- ILRewriter(body)
        Logger.error "Instrument : rewriter"
        x.m <- x.rewriter.Method
        let t = x.m.DeclaringType
        if t = typeof<System.InvalidProgramException> || t = typeof<System.TypeLoadException> || t = typeof<System.BadImageFormatException> then
            internalfailf "Incorrect instrumentation: exception %O is thrown!" t
        let result =
            Logger.error "Instrument : 1"
            if InstrumenterCoverage.instrumentedFunctions.Add x.m then
                Logger.trace "Instrumenting %s (token = %u)" (Reflection.methodToString x.m) body.properties.token
                try
                    Logger.error "Instrument : 2"
                    x.rewriter.Import()
                    // x.rewriter.PrintInstructions "before instrumentation" probes
                    Logger.error "Instrument : 3"
                    x.PlaceProbes()
                    Logger.error "Instrument : 4"
                    // x.rewriter.PrintInstructions "after instrumentation" probes
                    x.rewriter.Export()
                with e ->
                    Logger.error "Instrumentation failed: in method %O got exception %O" x.m e
                    x.Skip body
            else
                Logger.trace "Duplicate JITting of %s" x.MethodName
                x.Skip body

        x.rewriter <- null
        result
