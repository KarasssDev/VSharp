module internal VSharp.Fuzzer.Options

type internal Options = {
    MaxTestsCount: int
    ArrayMaxSize: int
    StringMaxSize: int
}

let mutable options = {
    MaxTestsCount = 10
    ArrayMaxSize = 10
    StringMaxSize = 10
}
