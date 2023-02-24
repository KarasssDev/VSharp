module VSharp.Fuzzer.FuzzerInfo

type FuzzerConfig = {
    MaxTest: int
    Timeout: int
    MaxClauses: int
}

let defaultFuzzerConfig = {
    MaxTest = 10
    Timeout = 1000
    MaxClauses = 10
}
