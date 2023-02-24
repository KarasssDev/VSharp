module VSharp.Fuzzer.Coverage

type CoverageLocation = {
    assemblyName: string
    moduleName: string
    methodToken: int
    offset: int
} with
        static member serialize x =
            $"%s{x.assemblyName}|%s{x.moduleName}|%d{x.methodToken}|%d{x.offset}"

        static member deserialize (x: string) =
            let parts = x.Split "|"
            {
                assemblyName = parts[0]
                moduleName = parts[1]
                methodToken = int parts[2]
                offset = int parts[3]
            }
