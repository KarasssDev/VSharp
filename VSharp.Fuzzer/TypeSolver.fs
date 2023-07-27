module internal VSharp.Fuzzer.TypeSolver

open System.Reflection
open VSharp
open VSharp.Core


type SolvingResult = {
    concreteClassParams: System.Type[]
    mockedClassParams: Mocking.Type option[]
    concreteMethodParams: System.Type[]
    mockedMethodParams: Mocking.Type option[]
}

type TypeSolver() =
    let dynamicTypeBuilder = Mocking.Mocker()
    let mockCache = System.Collections.Generic.Dictionary<System.Type list, ITypeMock>()
    let mockTypeCache = System.Collections.Generic.Dictionary<ITypeMock, Mocking.Type>()
    let systemTypeCache = System.Collections.Generic.Dictionary<Mocking.Type, System.Type>()

    let mockMethod (freshMock: Mocking.Type) (generate: System.Type -> obj) (method: Mocking.Method) =
        let implementation = Array.init Options.options.MaxTestsCount (fun _ -> generate method.BaseMethod.ReturnType)
        freshMock.AddMethod(method.BaseMethod, implementation)

    let encodeMock (mock: ITypeMock) (generate: System.Type -> obj) =
        match mockTypeCache.TryGetValue(mock) with
        | true, value -> value
        | _ ->
            Logger.error $"encode {mock.Name}"
            let freshMock = Mocking.Type(mock.Name)
            mock.SuperTypes |> Seq.iter freshMock.AddSuperType
            freshMock.MethodMocks |> Seq.iter (mockMethod freshMock generate)
            mockTypeCache.Add(mock, freshMock)
            freshMock

    let mockToType (mock: Mocking.Type) =
        match systemTypeCache.TryGetValue(mock) with
        | true, value -> value
        | _ ->
            let dynamicType = dynamicTypeBuilder.BuildDynamicType mock
            systemTypeCache.Add(mock, dynamicType)
            dynamicType

    member this.MockType (t: System.Type) (generate: System.Type -> obj) =
        let mock =
            match mockCache.TryGetValue [t] with
            | true, v -> v
            | false, _ ->
                let mock = TypeMock([t])
                mockCache.Add([t], mock)
                mock
        let encodedMock = encodeMock mock generate
        let typ = mockToType encodedMock
        mock, typ

    member this.GetMocks () = mockTypeCache

    member this.SolveGenericMethodParameters (method: Method) (generate: System.Type -> obj) =

        let substituteGenerics classParams methodParams =
            let getConcreteType =
                function
                | ConcreteType t -> t
                | MockType m ->
                    mockCache.Add (m.SuperTypes |> Seq.toList, m)
                    encodeMock m generate |> mockToType

            let methodBase = (method :> IMethod).MethodBase
            let classParams = classParams |> Array.map getConcreteType
            let methodParams = methodParams |> Array.map getConcreteType
            let declaringType = Reflection.concretizeTypeParameters methodBase.DeclaringType classParams
            let method = Reflection.concretizeMethodParameters declaringType methodBase methodParams
            method

        let typeStorage = typeStorage()

        match SolveGenericMethodParameters typeStorage method with
        | Some(classParams, methodParams) ->
            let method = substituteGenerics classParams methodParams
            Some (method, typeStorage)
        | _ -> None
