# CS2 Dumper

A read-only Windows x86-64 tool for collecting Counter-Strike 2 PE module data, Source 2 SchemaSystem classes and enums, interface registrations, input buttons, and configured signature results. It writes one normalized data set as JSON, C++, C#, Rust, and Zig source files.

The tool reads a running `cs2.exe` with `PROCESS_VM_READ` and `PROCESS_QUERY_LIMITED_INFORMATION`. It does not inject code, call functions inside the game, or modify game files. An offline mode parses local PE files and resolves module-relative signatures; SchemaSystem, interfaces, and buttons require a live process.

## Build

Requirements: Windows x86-64, CMake 3.25+, a C++20 compiler, and Ninja or another CMake generator. The single-header [nlohmann/json 3.11.3](https://github.com/nlohmann/json/releases/tag/v3.11.3) dependency and its MIT license are vendored under `external/nlohmann`.

```powershell
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
```

Run from the project root so the default `config/` directory is found:

```powershell
./build/cs2-dumper.exe --game-dir "E:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive" --output output --validate
```

If CS2 is running, the program finds `cs2.exe`, opens it read-only, and enumerates its loaded modules. `--pid` selects a process explicitly. The game directory can be the CS2 root or `game/bin/win64`; modules under `game/csgo/bin/win64` are located automatically. If the game is not running, use `--offline --game-dir ...` to export PE data and signatures without live schema or interface data.

## CLI

```text
--output DIR             Output directory (default: output)
--game-dir DIR           CS2 root or game/bin/win64
--config-dir DIR         Configuration directory (default: config)
--pid ID                 Explicit cs2.exe process ID
--offline                Do not attach to the game
--format all|json|cpp|csharp|rust|zig  Repeatable (default: all)
--module NAME            Export one requested module
--schema-only            Collect schema data and its discovery signature
--interfaces-only        Collect interfaces
--offsets-only           Collect public signature offsets
--no-signatures          Disable pattern scanning
--verbose                Include detailed diagnostics
--validate               Print every validation issue
--help                   Show usage
```

The output directory contains `client_dll.*`, `engine2_dll.*`, and other module files, plus `interfaces.*`, `offsets.*`, `buttons.*`, and `info.json`. Each module gets files for all selected formats even when its binary is unavailable; its JSON `status` and `available` fields make that explicit. Modules known only through schema metadata are marked `schema_only`. JSON offsets are numeric with optional hexadecimal display strings. Public source files contain module-relative values only.

## What is collected

The PE parser checks DOS, NT, PE32+ optional, section, and export bounds. Loaded modules are discovered with Windows Toolhelp. The scanner compiles byte patterns with `?` or `??` wildcards, scans a named section, rejects ambiguous matches, and resolves RIP-relative, relative call, relative jump, or immediate operands with explicit instruction metadata. A configured pointer dereference uses the read-only process reader.

SchemaSystem is Source 2's runtime type metadata, not the Source 1 `RecvTable`/`RecvProp` netvar system. The collector locates the schema object through a signature or a validated `SchemaSystem_...` interface factory, walks type scopes and class/enum hash bindings, and reads field names, types, offsets, sizes when derivable, arrays, metadata, base relationships, and enum values. Names are kept module and type-scope qualified internally. A field is marked `networked` only when explicit `MNetwork...` metadata or `MNetworkVarNames` names it. A zero networked count means none was exposed through this profile; it does not mean the game has no replication. Base offsets remain `null` when the metadata layout does not expose a verified offset. The database API can resolve inherited fields when base offsets are known.

The interface collector resolves each module's exported `CreateInterface` registry head and walks validated `InterfaceReg` nodes. It records interface names, version suffixes, and module-relative factory addresses. Instance RVAs are reported only for simple validated factory stubs. When an instance's first pointer leads into that module's `.rdata` section, its vtable RVA is reported too; no vtable slot count is inferred. The button collector walks the `KeyButton` list from a configured, validated signature and writes state RVAs. No button names or offsets are hardcoded.

Collection fills `DumpDatabase` before validators and all five generators run. Failed signatures and unavailable modules remain visible in `offsets.json` and `info.json`; a failed pattern does not stop unrelated output. Ordering is deterministic. `info.json` includes the one intentionally changing value, `dump_timestamp`, along with module sizes, PE timestamps, a Steam manifest build ID when found, and counts.

## Configuration and updates

- `config/modules.json` lists the 18 requested modules to attempt. Additional schema owner names found at runtime are exported automatically.
- `config/signatures.json` contains patterns, target sections, resolver rules, and optional pointer dereferences. Its initial signatures were checked for unique matches against the local game binaries used during development. Game updates may invalidate them. A result is emitted only after a unique match and a valid module-relative target (or a validated live collector target).
- `config/layouts.json` holds the observed Source 2 structure profile used by the schema and button collectors. These are **metadata layout offsets**, separate from generated game field offsets. The collector validates scope counts, class sizes, field bounds, names, and traversal limits. Update this profile when SchemaSystem internals change. Its starting point is the [upstream cs2-dumper Source 2 structures](https://github.com/a2x/cs2-dumper/tree/master/src/source2), corrected against the local runtime.

To update a signature after a game update, confirm its instruction sequence against the installed DLL, use wildcards for unstable displacements, specify `.text` or another section, set the resolver's displacement offset and instruction length, then run with `--validate`. Ambiguous or missing matches are reported and are never replaced with old offsets. To troubleshoot empty schema output, first check `offsets.json` for `SchemaSystem`, then inspect `info.json` issues for a profile validation failure. To troubleshoot empty interfaces, check that `CreateInterface` is exported and that the module is loaded. To troubleshoot empty buttons, check `button_list` and the live process attachment.

Offsets and structure layouts are build dependent. Keep a generated dump together with its `info.json`; do not treat values from one game build as permanent.

## Tests

`ctest --test-dir build --output-on-failure` runs deterministic tests for the pattern parser and ambiguity handling, RIP/call/jump math, a synthetic PE image and export directory, raw PE mapping, JSON and all language formatting, identifier sanitization, inheritance traversal, and duplicate handling. A live run is needed to verify the installed game's current metadata. The generated source can also be checked with a C++ compiler, `dotnet build`, `rustc --crate-type lib`, and `zig test`.

## License

The vendored JSON library retains its MIT license at `external/nlohmann/LICENSE.MIT`.
