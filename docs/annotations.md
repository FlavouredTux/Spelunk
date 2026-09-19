# Annotations

Record names, notes and C-style signatures directly through the CLI:

```sh
spelunk --annotate 0x401234 --set-name update_player \
  --set-signature "int update_player(Player* player, float dt)" \
  --set-note "state transition owner" \
  --confidence 0.95 --source hand --evidence "unique log and callers" \
  --annotations project.annotations ./target
```

Add `--dry-run` to print the proposed file without writing it.
The destination is selected in this order: explicit `--annotations PATH`,
existing `<binary>.spelunk-annotations` sidecar, then the annotation cache.

```sh
spelunk --list-annotations --annotations project.annotations ./target
spelunk --export-annotations exported.annotations ./target
spelunk -p --show-provenance --annotations project.annotations \
  -s update_player ./target
```

The signature parser handles plain C declarations; function-pointer parameters
and templated types are not supported. Field records use a zero-based
parameter index and a byte offset.

## On-disk format

`Annotations::save` produces a flat line-per-record file. Most
records are self-describing:

```
rename <hex-addr>  <new-name>
sig    <hex-addr>  <return-type>|<param-type>|<param-name>|...
note   <hex-addr>  <text>
const  <hex-value> <name>
field  <hex-addr>  <param-index>|<hex-offset>|<field-name>
meta   <kind> <hex-addr> conf=<float>|src=<tag>|ev=<text>
```

`meta` carries provenance for one of the records above; `<kind>` is
`rename`, `note`, or `sig`. Pipes are the field separator inside the
`meta` tail; embedded `|` is `\|`. `\n` / `\r` / `\\` also escape
themselves. Unknown record kinds and unknown meta subkinds are
silently skipped, so an older spelunk reading a newer file pulls the
names through cleanly and just loses the metadata.
