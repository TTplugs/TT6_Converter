# TT6_Converter

Standalone DX7 (`.syx`) to TT6 preset converter.

This repository contains the converter previously embedded in `TT6`.

## Scope

- Input: DX7 SysEx voice data (`.syx`)
- Output: TT6 parameter JSON and/or FXP preset file
- Compatible with the TT6 LV2 control order (ports 3..33)

## Files

- `dx7_to_tt6.py`: main converter script
- `LICENSE`: GPL-2.0-only

## Usage

```bash
python3 dx7_to_tt6.py INPUT.syx --patch-index 0 --print
python3 dx7_to_tt6.py INPUT.syx --patch-index 0 \
  --output-json tt6_patch.json \
  --output-fxp TT6_patch.fxp
```

Using a reference FXP template (for host header compatibility):

```bash
python3 dx7_to_tt6.py INPUT.syx --patch-index 0 \
  --template-fxp kick01.FXP \
  --output-fxp TT6_patch.fxp \
  --output-json TT6_patch.json
```

## Reproducible Release Workflow

Use this workflow to produce deterministic example outputs from a fixed input set.

1. Create a release workspace:

```bash
VERSION=v0.1.0
mkdir -p releases/$VERSION
```

2. Convert canonical inputs in deterministic order:

```bash
for syx in $(ls examples/input/*.syx | LC_ALL=C sort); do
  base=$(basename "${syx%.syx}")
  python3 dx7_to_tt6.py "$syx" --patch-index 0 \
    --output-json "releases/$VERSION/${base}.json" \
    --output-fxp "releases/$VERSION/${base}.fxp"
done
```

3. Generate a checksum manifest:

```bash
cd releases/$VERSION
sha256sum *.json *.fxp | LC_ALL=C sort > SHA256SUMS
```

4. Commit and tag:

```bash
git add releases/$VERSION
git commit -m "Release $VERSION example preset exports"
git tag -a $VERSION -m "TT6_Converter $VERSION"
```

5. Verify reproducibility on another machine:

```bash
sha256sum -c releases/$VERSION/SHA256SUMS
```

## Notes

- The DX7 -> TT6 mapping is heuristic and tuned for musical starting points.
- It is not a bit-identical emulation of DX7 synthesis.
- FXP defaults can be overridden with `--fxid` and `--fx-version`.

## License

GPL-2.0-only.