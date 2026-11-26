// bundle: `moonforge-bundle <macho> [Info.plist]`
fn main {
  let argv = @env.args()
  if argv.length() < 2 {
    println("usage: moonforge-bundle <macho> [Info.plist]")
    @sys.exit(2)
  }
  let macho = @fs.read_file_to_bytes(argv[1]) catch {
    @fs.IOError(message) => {
      println("bundle: cannot read Mach-O: " + message)
      @sys.exit(2)
      b""
    }
  }
  let plist = if argv.length() >= 3 {
    Some(@fs.read_file_to_bytes(argv[2]) catch {
      @fs.IOError(message) => {
        println("bundle: cannot read plist: " + message)
        @sys.exit(2)
        b""
      }
    })
  } else {
    None
  }
  println(@bundle_lib.bundle_profile(macho, plist).to_json())
}
