namespace VSharp.Solver

open System.Collections.Generic
open FSharpx.Collections
open VSharp
open VSharp.Core.SolverInteraction
open VSharp.Core

module private Simplification =
    let (>>=) (m: ('a -> 'b) -> 'b) (f: 'a -> ('c -> 'b) -> 'b) = (fun k -> m (fun x -> f x k))
    let return' x = (fun k -> k x)
    let (>=>) m f = m >>= fun x k -> f x |> k
    type ContinuationBuilder() =
          member this.Return(x) = (fun k -> k x)
          member this.ReturnFrom(x) = x
          member this.Bind(m: ('a -> 'b) -> 'b, f) = m >>= f
          member this.Delay(f) = (fun k -> f () k)
    let cps = ContinuationBuilder()
    let private (|Connective|_|) = function
        | Conjunction ts -> Some ts
        | Disjunction ts -> Some ts
        | _ -> None
    let private (|Leaf|_|) (t: term) =
        match t with
        | Connective _ -> None
        | _ -> Some t
    type private Redundancy =
        | NonConstraining
        | NonRelaxing
        | NotRedundant
    type private SATResult =
        | SAT
        | UNSAT

    exception UnknownSolverResult
    exception AssertionFailed

    let private toSATResult r =
        match r with
        | SmtSat _ -> SAT
        | SmtUnsat _ -> UNSAT
        | SmtUnknown _ -> raise UnknownSolverResult

    let mkConjunction ts =
        match ts with
        | [t] -> t
        | _ -> Expression (Operator OperationType.LogicalAnd) ts Bool
    let mkDisjunction ts = Expression (Operator OperationType.LogicalOr) (Seq.toList ts) Bool
    let mkNegation t = Expression (Operator OperationType.LogicalNot) [t] Bool
    let rec transformXor (t: term) =

        let unwrapXor x y = cps {
            let! x' = transformXor x
            let! y' = transformXor y
            return mkDisjunction [
                    mkConjunction [mkNegation x'; y'];
                    mkConjunction [x'; mkNegation y']
            ]
        }

        match t with
        | Xor(x, y) -> unwrapXor x y
        | Conjunction xs -> Cps.List.mapk transformXor xs >=> mkConjunction
        | Disjunction xs -> Cps.List.mapk transformXor xs >=> mkDisjunction
        | Negation x -> transformXor x >=> mkNegation
        | _ -> fun f -> f t

    let rec toNNF (t: term) =
        match t with
        | Negation t' ->
            match t' with
            | Conjunction ts -> Cps.List.mapk toNNF ts >=> List.map mkNegation >=> mkDisjunction
            | Disjunction ts -> Cps.List.mapk toNNF ts >=> List.map mkNegation >=> mkConjunction
            | Negation nt -> return' nt
            | _ -> return' t
        | Conjunction ts -> Cps.List.mapk toNNF ts >=> mkConjunction
        | Disjunction ts -> Cps.List.mapk toNNF ts >=> mkDisjunction
        | _ -> return' t

    let rec syntaxSimplify formula =

        let isTrue t =
            match t with
            | True -> true
            | _ -> false

        let isFalse t =
            match t with
            | False -> true
            | _ -> false

        let hasTrue ts = (List.filter isTrue ts).Length > 0
        let hasFalse ts = (List.filter isFalse ts).Length > 0

        cps {
            match formula with
            | Conjunction ts ->
                let! simplifiedTerms = Cps.List.mapk syntaxSimplify ts
                return
                    if hasFalse simplifiedTerms then False
                    else
                        match List.filter (not << isTrue) simplifiedTerms with
                        | [] -> True
                        | [t] -> t
                        | ts -> mkConjunction ts

            | Disjunction ts ->
                let! simplifiedTerms = Cps.List.mapk syntaxSimplify ts
                return
                    if hasTrue simplifiedTerms then True
                    else
                        match List.filter (not << isFalse) simplifiedTerms with
                        | [] -> False
                        | [t] -> t
                        | ts -> mkDisjunction ts
            | _ -> return formula
        }
    type public Simplifier(solver: IIncrementalSolver) =
        let check() = toSATResult <| solver.Check()
        let push() = solver.Push()
        let pop() = solver.Pop()
        let solverAssert encCtx (formula: term) = if solver.Assert formula encCtx then () else raise AssertionFailed
        let withAssert encCtx formula f =
            push()
            solverAssert encCtx formula
            let result = f()
            pop()
            result
        let mutable cache = Dictionary<term * term, term>()
        let handleLeaf encCtx t  =
            let checkRedundancy (leaf: term) =
                let result = withAssert encCtx (mkNegation leaf) check
                match result with
                | UNSAT -> NonConstraining
                | SAT ->
                    let result = withAssert encCtx leaf check
                    match result with
                    | UNSAT -> NonRelaxing
                    | SAT -> NotRedundant

            match checkRedundancy t with
            | NonConstraining -> True
            | NonRelaxing -> False
            | NotRedundant -> t
        let rec simplifyRec encCtx formula = cps {
            match formula with
            | Conjunction ts -> return! handleConnective encCtx ts true
            | Disjunction ts -> return! handleConnective encCtx ts false
            | Leaf t -> return handleLeaf encCtx t
            | _ -> return __unreachable__()
        }

        and handleConnective encCtx ts isConjunction =
            let rec updateChildren children =
                let updateChild oldChild i =
                    let ts =
                        VSharp.List.foldi (fun acc j x ->
                            if i = j then acc else (if isConjunction then x else mkNegation x)::acc
                        ) List.empty children
                    withAssert encCtx (mkConjunction ts) (fun () -> simplifyRec encCtx oldChild)
                cps {
                    let! children' = Cps.List.mapik updateChild children
                    if List.forall2 (=) children' children then
                        if isConjunction then
                            return mkConjunction children'
                        else
                            return mkDisjunction children'
                    else
                        return! updateChildren children'
                }
            updateChildren ts
        let simplify
            (assumptions: term)
            (formula: term)
            (encCtx: encodingContext): term =
            try
                match formula with
                | Leaf t -> t
                | _ ->
                    withAssert encCtx assumptions (fun () ->
                        (transformXor formula >>= toNNF >>= simplifyRec encCtx >>= syntaxSimplify) id
                    )
            with
                | :? UnknownSolverResult -> formula
                | :? AssertionFailed -> formula

        interface ISimplifier with
            member x.Simplify assumptions condition ctx =
                Dict.getValueOrUpdate cache (assumptions, condition) (
                    fun () -> simplify assumptions condition ctx
                )
