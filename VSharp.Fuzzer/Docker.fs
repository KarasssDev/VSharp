module VSharp.Fuzzer.Docker

open System.Diagnostics
open System.IO
open System.Runtime.InteropServices
open System.Text
open VSharp


type private MountMode =
    | Readonly
    | ReadWrite

type private DockerOptions =
    | Mount of string * string * MountMode
    | EnvVar of string * string
    | User of uint * uint

let private buildOptions (options: DockerOptions seq) =
    let args = StringBuilder()
    for option in options do
        match option with
        | Mount (source, target, mountMode) ->
            match mountMode with
            | Readonly -> args.Append $" --mount type=bind,source={source},target={target}" |> ignore
            | ReadWrite -> args.Append $" --mount type=bind,source={source},target={target}" |> ignore
        | EnvVar (name, value) -> args.Append $""" -e {name}="{value}" """ |> ignore
        | User (uid, gid) -> args.Append $" --user {uid}:{gid}" |> ignore
    args.ToString ()

let private executeDockerCommand args =
    Logger.error $"Args: {args}"
    let info = ProcessStartInfo()
    info.WorkingDirectory <- Directory.GetCurrentDirectory()
    info.FileName <- "docker"
    info.Arguments <- args
    info.UseShellExecute <- false
    info.RedirectStandardOutput <- false
    info.RedirectStandardError <- false
    Process.Start info

let private runContainer (name: string) (options: DockerOptions seq) =
    let options = buildOptions options
    $" run {options} {name} " |> executeDockerCommand

let private stopContainer (name: string) =
    $" stop {name}" |> executeDockerCommand
    
let private fuzzerContainerName = "karasss/fuzzer:latest"

let private getPipePath (serverName: string) (pipeName: string): string =
    let pipeStreamType = typeof<System.IO.Pipes.PipeStream>
    let getPathMethod = pipeStreamType.GetMethod ("GetPipePath", System.Reflection.BindingFlags.NonPublic ||| System.Reflection.BindingFlags.Static)
    let result = getPathMethod.Invoke (null, [| serverName; pipeName |])
    result.ToString ()

let startFuzzer dllsPath outputPath =

    let options =
        let pipePath = getPipePath "." "FuzzerPipe"

        let baseOptions = [
            Mount(dllsPath, dllsPath, Readonly)
            Mount(outputPath, outputPath, ReadWrite)
            Mount(pipePath, pipePath, ReadWrite)

            EnvVar("CORECLR_PROFILER", "{2800fea6-9667-4b42-a2b6-45dc98e77e9e}")
            EnvVar("CORECLR_ENABLE_PROFILING", "1")
            EnvVar("CORECLR_PROFILER_PATH", "/app/libvsharpConcolic.so")
        ]

        let linuxOptions = [
            Mount("/etc/passwd", "/etc/passwd", Readonly) 
            Mount("/etc/group", "/etc/group", Readonly)
            Interop.LinuxCalls.getCurrentUserInfo () |> User
        ]

        if (RuntimeInformation.IsOSPlatform OSPlatform.Linux) then List.concat [baseOptions; linuxOptions]
        else baseOptions

    runContainer fuzzerContainerName options

let stopFuzzer () = stopContainer fuzzerContainerName
