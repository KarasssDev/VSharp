namespace VSharp.Core

open FSharpx.Collections
open VSharp

module public SolverInteraction =

    type unsatCore() = class end

    type encodingContext =
        { addressOrder : Map<concreteHeapAddress, int>}

    type satInfo = { mdl : model }
    type unsatInfo = { core : term[] }

    type smtResult =
        | SmtSat of satInfo
        | SmtUnsat of unsatInfo
        | SmtUnknown of string

    type ISolver =
        abstract CheckSat : encodingContext -> term -> smtResult
        abstract Assert : encodingContext -> term -> unit

    type IIncrementalSolver =
        abstract Check: unit -> smtResult
        abstract Assert: term -> encodingContext -> bool
        abstract Pop: unit -> unit
        abstract Push : unit -> unit

    type ISimplifier =
        abstract Simplify: term -> term -> encodingContext -> term

    let mutable private solver : ISolver option = None
    let mutable private simplifier: ISimplifier option = None

    let configureSolver s = solver <- Some s
    let configureSimplifier s = simplifier <- Some s

    let getEncodingContext (state : state) =
        let addresses = PersistentDict.keys state.allocatedTypes
        let sortedAddresses = Seq.sortWith VectorTime.compare addresses
        let order = Seq.fold (fun (map, i) address -> Map.add address i map, i + 1) (Map.empty, 1) sortedAddresses |> fst
        let orderWithNull = Map.add VectorTime.zero 0 order
        { addressOrder = orderWithNull }

    let checkSat state = // TODO: need to solve types here? #do
        let ctx = getEncodingContext state
        let formula = PC.toSeq state.pc |> conjunction
        match solver with
        | Some s -> s.CheckSat ctx formula
        | None -> SmtUnknown ""

    let rec simplify state condition =
        let ctx = getEncodingContext state
        let assump = (PC.makeTerm state.pc)
        match simplifier with
        | Some simplifier' -> simplifier'.Simplify assump condition ctx
        | None -> condition


