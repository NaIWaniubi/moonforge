// wasmcheck: `moonforge-wasmcheck <module.wasm>`

///|
fn main {
  let argv = @env.args()
  if argv.length() < 2 {
    println("usage: moonforge-wasmcheck <module.wasm>")
    @sys.exit(2)
  }
  let data = @fs.read_file_to_bytes(argv[1]) catch {
    @fs.IOError(message) => {
      println("wasmcheck: cannot read input: " + message)
      @sys.exit(2)
      b""
    }
  }
  match @wasmcheck_lib.wasm_report(data) {
    Ok(sections) => println(@wasmcheck_lib.sections_to_json(sections))
    Err(error) => {
      println("wasmcheck: " + error)
      @sys.exit(2)
    }
  }
}
