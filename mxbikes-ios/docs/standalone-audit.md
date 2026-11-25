## Publisher standalone target audit

MX Bikes has a publisher-sold standalone Windows edition. That is a possible
**legitimate** route for removing a *Steam-client dependency* from the port,
but it is neither automatically licensed by a Steam purchase nor a native iOS
build. We must inspect the actual owned standalone executable first.

From the public repository root on your own computer, with the original
standalone executable **outside the checkout**:

```sh
python mxbikes-ios/scripts/mxbikes_standalone_import_audit.py \
  --standalone-exe /path/to/publisher-licensed/standalone/mxbikes.exe \
  --out /tmp/mxb-standalone-audit
```

The output `standalone-candidate-imports.json` includes an independent SHA,
entry point, exception record count, and Steam/graphics/Windows import
inventory. It does not copy the EXE, assets, original code, keys, or game
memory. It never executes the candidate.

A report with zero `steam_symbol_count` only means **no static imported
Steam API symbols were found**. It does *not* prove that the original program
will initialize without Steam, that its licensing is valid, or that it has
a functioning engine/renderer. A new SHA needs its own original-code trace,
CFG map, and independent native ARM64 validation: the Steam EXE's pinned RVAs
must NOT be reused as if they were the standalone layout.

See [authenticated original game execution](run-original-locally.md) for
the *Steam* target. Those tests still stop at the unsupported Steam API.

## Public beta21e demo research target (November 24, 2026)

The publisher's publicly distributed beta21e demo was downloaded and
extracted transiently on a standard public GitHub runner. Its observed
executable SHA-256 is
`b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742`.
The import audit identified 11 DLLs, 310 imported symbols and **zero static
Steam imports**. This is a distinct executable from the private Steam build.

The separate `mxbikes_public_demo_entry.py` reference runner starts at the
PE's real entry, maps original sections with bounded permissions and
models only basic Win32 clock and process identity calls. It stops at any
unsupported import, fault or execution budget. It never supplies a licensing
success result or changes demo restrictions.

No private repository workflows, credentials, commercial assets or owned
Steam binaries are needed for this public demo experiment. The workflow
downloads the public installer directly from its publisher, verifies the
extracted executable's pinned SHA before execution, and deletes the temporary
files. Only aggregate diagnostic metadata is emitted. It is still x64
reference execution, not native ARM64 translation or a booted game.
