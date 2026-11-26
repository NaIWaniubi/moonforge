// moonforge wasm runtime: the MoonBit wasm host protocol.
//
// Two call shapes are supported:
//   runtime.run(Uint8Array, argv)                 legacy single-file protocol
//   runtime.run({ "name.bin": Uint8Array, ... }, argv)  v2 multi-artifact protocol
//
// The virtual filesystem is per-run, so browser and Node tests share exactly
// the same host glue and cannot leak state between analyses.

export function createRuntime(module) {
  function importsFor(state) {
    const memory = () => state.instance.exports.memory;
    return {
      wasi_snapshot_preview1: {
        fd_write(fd, iovs, iovsLen, nwrittenPtr) {
          const buf = memory().buffer;
          const dv = new DataView(buf);
          const sink = fd === 2 ? state.stderr : state.stdout;
          let total = 0;
          for (let i = 0; i < iovsLen; i++) {
            const ptr = dv.getUint32(iovs + i * 8, true);
            const len = dv.getUint32(iovs + i * 8 + 4, true);
            const view = new Uint8Array(buf, ptr, len);
            for (let j = 0; j < len; j++) sink.push(view[j]);
            total += len;
          }
          dv.setUint32(nwrittenPtr, total, true);
          return 0;
        },
      },
      __moonbit_sys_unstable: {
        exit(code) {
          state.exitCode = code;
          throw { __moonforge_exit: code };
        },
      },
      __moonbit_fs_unstable: {
        begin_create_string() {
          return { chars: [] };
        },
        string_append_char(h, ch) {
          h.chars.push(ch);
        },
        finish_create_string(h) {
          let s = "";
          for (let i = 0; i < h.chars.length; i++) s += String.fromCharCode(h.chars[i]);
          return s;
        },
        begin_read_string(s) {
          return { s: s, i: 0 };
        },
        string_read_char(h) {
          return h.i < h.s.length ? h.s.charCodeAt(h.i++) : -1;
        },
        finish_read_string(_h) {},
        begin_read_byte_array(u8) {
          return { u8: u8, i: 0 };
        },
        byte_array_read_byte(h) {
          return h.i < h.u8.length ? h.u8[h.i++] : -1;
        },
        finish_read_byte_array(_h) {},
        begin_read_string_array(arr) {
          return { arr: arr, i: 0 };
        },
        string_array_read_string(h) {
          return h.i < h.arr.length ? h.arr[h.i++] : "ffi_end_of_/string_array";
        },
        finish_read_string_array(_h) {},
        args_get() {
          return state.argv;
        },
        read_file_to_bytes_new(path) {
          const bytes = state.files[path];
          if (!bytes) {
            state.error = "no such file: " + path;
            return -1;
          }
          state.currentPath = path;
          state.currentInput = bytes;
          return 0;
        },
        get_file_content() {
          return state.currentInput || new Uint8Array();
        },
        get_error_message() {
          return state.error;
        },
      },
    };
  }

  return {
    run(input, argv) {
      const files = input instanceof Uint8Array ? { "input.bin": input } : input || {};
      const names = Object.keys(files);
      const state = {
        files,
        currentPath: names[0] || "input.bin",
        currentInput: files[names[0]] || new Uint8Array(),
        argv: argv || ["moonforge-web", "input.bin"],
        error: "",
        stdout: [],
        stderr: [],
        exitCode: null,
        instance: null,
      };
      state.instance = new WebAssembly.Instance(module, importsFor(state));
      try {
        state.instance.exports._start();
      } catch (e) {
        if (!e || e.__moonforge_exit === undefined) throw e;
      }
      const dec = new TextDecoder();
      return {
        stdout: dec.decode(Uint8Array.from(state.stdout)),
        stderr: dec.decode(Uint8Array.from(state.stderr)),
        exitCode: state.exitCode,
      };
    },
  };
}
