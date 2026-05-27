#!/usr/bin/env python3
"""
DX7 -> TT6 preset converter.

Reads DX7 SysEx voice data (single voice or 32-voice bank) and converts one
voice to TT6 control values. Can export:
  - JSON with TT6 parameters
  - FXP (VST program format) following the layout seen in S2400-saved presets
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


TT6_SYMBOLS = [
    "algo",
    "op1_ratio",
    "op1_level",
    "op1_decay",
    "op2_ratio",
    "op2_level",
    "op2_decay",
    "op3_ratio",
    "op3_level",
    "op3_decay",
    "op4_ratio",
    "op4_level",
    "op4_decay",
    "op5_ratio",
    "op5_level",
    "op5_decay",
    "op6_ratio",
    "op6_level",
    "op6_decay",
    "attack",
    "sustain",
    "release",
    "feedback",
    "op_mode",
    "filter_cutoff",
    "filter_res",
    "lfo_rate",
    "lfo_depth",
    "drive",
    "gain",
    "vel_amount",
]

DX7_TO_TT6_ALGO = [
    0, 0, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 5, 6, 6, 7, 7,
    8, 8, 9, 9, 10, 10, 11, 11,
    12, 12, 13, 13, 14, 14, 15, 15,
]


def clamp(x: float, lo: float, hi: float) -> float:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def exp_map_01(x01: float, out_min: float, out_max: float) -> float:
    x01 = clamp(x01, 0.0, 1.0)
    if out_min <= 0.0 or out_max <= 0.0:
        return out_min + (out_max - out_min) * x01
    return out_min * ((out_max / out_min) ** x01)


def sanitize_name(name: str, size: int = 28) -> bytes:
    ascii_bytes = bytearray()
    for ch in name:
        c = ord(ch)
        if 32 <= c <= 126:
            ascii_bytes.append(c)
        else:
            ascii_bytes.append(ord("_"))
        if len(ascii_bytes) >= size:
            break
    while len(ascii_bytes) < size:
        ascii_bytes.append(0)
    return bytes(ascii_bytes[:size])


@dataclass
class Dx7Op:
    r1: int
    r2: int
    r3: int
    r4: int
    l1: int
    l2: int
    l3: int
    l4: int
    rate_scale: int
    ams: int
    kvs: int
    output: int
    mode: int
    coarse: int
    fine: int
    detune: int


@dataclass
class Dx7Voice:
    ops: List[Dx7Op]   # op1..op6 order (index 0 = op1)
    algorithm: int
    feedback: int
    lfo_speed: int
    lfo_pmd: int
    pmod_sensitivity: int
    name: str


def parse_sysex_messages(raw: bytes) -> List[bytes]:
    msgs: List[bytes] = []
    i = 0
    n = len(raw)
    while i < n:
        if raw[i] != 0xF0:
            i += 1
            continue
        j = raw.find(b"\xF7", i + 1)
        if j < 0:
            break
        msgs.append(raw[i : j + 1])
        i = j + 1
    return msgs


def decode_name(name_bytes: bytes) -> str:
    chars = []
    for b in name_bytes:
        if 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append(" ")
    return "".join(chars).strip() or "DX7_PATCH"


def parse_unpacked_voice(v155: bytes) -> Dx7Voice:
    if len(v155) < 155:
        raise ValueError(f"Expected 155 bytes, got {len(v155)}")

    ops: List[Dx7Op] = [None] * 6  # type: ignore
    for slot in range(6):
        base = slot * 21
        op_index = 5 - slot  # slot0=OP6 ... slot5=OP1
        ops[op_index] = Dx7Op(
            r1=v155[base + 0],
            r2=v155[base + 1],
            r3=v155[base + 2],
            r4=v155[base + 3],
            l1=v155[base + 4],
            l2=v155[base + 5],
            l3=v155[base + 6],
            l4=v155[base + 7],
            rate_scale=v155[base + 13],
            ams=v155[base + 14],
            kvs=v155[base + 15],
            output=v155[base + 16],
            mode=v155[base + 17] & 0x01,
            coarse=v155[base + 18] & 0x1F,
            fine=v155[base + 19],
            detune=v155[base + 20] & 0x0F,
        )

    return Dx7Voice(
        ops=ops,
        algorithm=v155[134] & 0x1F,
        feedback=v155[135] & 0x07,
        lfo_speed=v155[137],
        lfo_pmd=v155[139],
        pmod_sensitivity=v155[143] & 0x07,
        name=decode_name(v155[145:155]),
    )


def unpack_packed_voice(v128: bytes) -> Dx7Voice:
    if len(v128) < 128:
        raise ValueError(f"Expected 128 bytes, got {len(v128)}")

    ops: List[Dx7Op] = [None] * 6  # type: ignore
    for slot in range(6):
        base = slot * 17
        op_index = 5 - slot  # slot0=OP6 ... slot5=OP1

        b12 = v128[base + 12]
        b13 = v128[base + 13]
        b15 = v128[base + 15]

        ops[op_index] = Dx7Op(
            r1=v128[base + 0],
            r2=v128[base + 1],
            r3=v128[base + 2],
            r4=v128[base + 3],
            l1=v128[base + 4],
            l2=v128[base + 5],
            l3=v128[base + 6],
            l4=v128[base + 7],
            rate_scale=b12 & 0x07,
            ams=b13 & 0x03,
            kvs=(b13 >> 2) & 0x07,
            output=v128[base + 14],
            mode=b15 & 0x01,
            coarse=(b15 >> 1) & 0x1F,
            fine=v128[base + 16],
            detune=(b12 >> 3) & 0x0F,
        )

    return Dx7Voice(
        ops=ops,
        algorithm=v128[110] & 0x1F,
        feedback=v128[111] & 0x07,
        lfo_speed=v128[112],
        lfo_pmd=v128[114],
        pmod_sensitivity=(v128[116] >> 4) & 0x07,
        name=decode_name(v128[118:128]),
    )


def extract_voices(raw: bytes) -> List[Dx7Voice]:
    voices: List[Dx7Voice] = []
    msgs = parse_sysex_messages(raw)

    if not msgs:
        # raw payload without F0/F7 wrapper
        if len(raw) == 155:
            return [parse_unpacked_voice(raw)]
        if len(raw) == 128:
            return [unpack_packed_voice(raw)]
        if len(raw) == 4096:
            return [unpack_packed_voice(raw[i * 128 : (i + 1) * 128]) for i in range(32)]
        raise ValueError("No SysEx messages found and raw length is not a known DX7 voice size.")

    for msg in msgs:
        if len(msg) < 8 or msg[0] != 0xF0 or msg[-1] != 0xF7:
            continue
        # common Yamaha bulk headers are 6 bytes before payload and 1 checksum byte before F7
        payload = msg[6:-2] if len(msg) >= 9 else b""
        if len(payload) == 155:
            voices.append(parse_unpacked_voice(payload))
        elif len(payload) == 128:
            voices.append(unpack_packed_voice(payload))
        elif len(payload) == 4096:
            for i in range(32):
                voices.append(unpack_packed_voice(payload[i * 128 : (i + 1) * 128]))

    if not voices:
        raise ValueError("Could not parse DX7 voices from SysEx data.")
    return voices


def op_ratio_from_dx7(op: Dx7Op) -> float:
    mode = op.mode & 0x01
    coarse = clamp(float(op.coarse), 0.0, 31.0)
    fine = clamp(float(op.fine), 0.0, 99.0)
    detune = clamp(float(op.detune), 0.0, 14.0)
    detune_mul = 2.0 ** ((detune - 7.0) / 96.0)

    if mode == 0:
        if coarse <= 0.0:
            ratio = 0.5 * (1.0 + fine / 99.0)
        else:
            ratio = coarse * (1.0 + fine / 100.0)
        return clamp(ratio * detune_mul, 0.25, 32.0)

    # fixed frequency mode -> approximate ratio around A4 reference (440Hz)
    fixed_hz = (10.0 ** (coarse / 8.0)) * (1.0 + fine / 100.0)
    ratio = (fixed_hz / 440.0) * detune_mul
    return clamp(ratio, 0.25, 32.0)


def op_level_from_dx7(output_0_99: int) -> float:
    x = clamp(float(output_0_99), 0.0, 99.0)
    db = (x - 99.0) * 0.75
    lin = 10.0 ** (db / 20.0)
    if lin < 0.001:
        return 0.0
    return clamp(lin, 0.0, 1.0)


def op_decay_ms_from_dx7(op: Dx7Op) -> float:
    # Maps a blend of R2/R3 to TT6 decay in milliseconds.
    rate = clamp((op.r2 + op.r3) * 0.5, 0.0, 99.0)
    decay01 = ((99.0 - rate) / 99.0) ** 1.8
    ms = 1.0 + decay01 * 7999.0
    return clamp(ms, 1.0, 8000.0)


def build_tt6_params(voice: Dx7Voice) -> Tuple[List[float], Dict[str, float]]:
    algo = DX7_TO_TT6_ALGO[clamp(float(voice.algorithm), 0.0, 31.0).__int__()]
    feedback = clamp(voice.feedback / 7.0, 0.0, 1.0)

    params: List[float] = [0.0] * len(TT6_SYMBOLS)
    params[0] = float(algo)

    brightness_acc = 0.0
    attack_rate_acc = 0.0
    release_rate_acc = 0.0
    sustain_acc = 0.0

    for i, op in enumerate(voice.ops):
        ratio = op_ratio_from_dx7(op)
        level = op_level_from_dx7(op.output)
        decay = op_decay_ms_from_dx7(op)

        params[1 + i * 3 + 0] = ratio
        params[1 + i * 3 + 1] = level
        params[1 + i * 3 + 2] = decay

        brightness_acc += level * clamp(ratio / 8.0, 0.0, 1.0)
        attack_rate_acc += clamp(float(op.r1), 0.0, 99.0)
        release_rate_acc += clamp(float(op.r4), 0.0, 99.0)
        sustain_acc += clamp(float(op.l3), 0.0, 99.0) / 99.0

    brightness = clamp(brightness_acc / 6.0, 0.0, 1.0)
    avg_attack_rate = attack_rate_acc / 6.0
    avg_release_rate = release_rate_acc / 6.0
    avg_sustain = sustain_acc / 6.0

    attack_ms = 0.1 + (((99.0 - avg_attack_rate) / 99.0) ** 2.2) * 1999.9
    sustain = clamp(avg_sustain * 0.8, 0.0, 1.0)
    release_ms = 1.0 + (((99.0 - avg_release_rate) / 99.0) ** 1.7) * 7999.0

    lfo_rate = exp_map_01(clamp(voice.lfo_speed / 99.0, 0.0, 1.0), 0.05, 30.0)
    lfo_depth = clamp((voice.lfo_pmd / 99.0) * (0.5 + 0.5 * (voice.pmod_sensitivity / 7.0)), 0.0, 1.0)

    cutoff = 300.0 + (brightness**1.2) * 19700.0
    drive = clamp(0.35 * feedback + 0.15 * brightness, 0.0, 1.0)

    params[19] = clamp(attack_ms, 0.1, 2000.0)
    params[20] = sustain
    params[21] = clamp(release_ms, 1.0, 8000.0)
    params[22] = feedback
    params[23] = 0.0             # FM mode
    params[24] = clamp(cutoff, 20.0, 20000.0)
    params[25] = 0.10
    params[26] = lfo_rate
    params[27] = lfo_depth
    params[28] = drive
    params[29] = -6.0
    params[30] = 0.70

    params_by_symbol = {k: float(v) for k, v in zip(TT6_SYMBOLS, params)}
    return params, params_by_symbol


def read_fxp_header(path: Path) -> Dict[str, int]:
    data = path.read_bytes()
    if len(data) < 52:
        raise ValueError(f"{path} is too small to be a valid FXP file.")
    if data[0:4] != b"CcnK" or data[8:12] != b"FxCk":
        raise ValueError(f"{path} does not look like an FXP file (CcnK/FxCk header missing).")
    return {
        "chunk_size": struct.unpack("<I", data[4:8])[0],
        "version": struct.unpack("<I", data[12:16])[0],
        "fx_id": struct.unpack("<I", data[16:20])[0],
        "fx_version": struct.unpack("<I", data[20:24])[0],
        "num_params": struct.unpack("<I", data[24:28])[0],
    }


def write_fxp(path: Path, fx_id: int, fx_version: int, name: str, params: List[float]) -> None:
    num_params = len(params)
    chunk_size = 4 + 4 + 4 + 4 + 4 + 28 + (4 * num_params)

    header = struct.pack(
        "<4sI4sIIII28s",
        b"CcnK",
        chunk_size,
        b"FxCk",
        1,            # file format version
        fx_id & 0xFFFFFFFF,
        fx_version & 0xFFFFFFFF,
        num_params,
        sanitize_name(name, 28),
    )
    body = b"".join(struct.pack("<f", float(p)) for p in params)
    path.write_bytes(header + body)


def parse_int_auto(s: str) -> int:
    return int(s, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert DX7 SysEx to TT6 parameters / FXP preset.")
    parser.add_argument("input", type=Path, help="DX7 .syx file (or raw 155/128/4096 bytes)")
    parser.add_argument("--patch-index", type=int, default=0, help="Voice index to convert (default: 0)")
    parser.add_argument("--output-json", type=Path, default=None, help="Write TT6 parameters as JSON")
    parser.add_argument("--output-fxp", type=Path, default=None, help="Write TT6 preset as FXP")
    parser.add_argument("--name", type=str, default=None, help="Program name for output (default: DX7 voice name)")
    parser.add_argument("--template-fxp", type=Path, default=None, help="Use FXP header values from template")
    parser.add_argument("--fxid", type=parse_int_auto, default=0x743C7CA6, help="FXP plugin ID (hex/int)")
    parser.add_argument("--fx-version", type=int, default=1, help="FXP plugin version (default: 1)")
    parser.add_argument("--print", action="store_true", dest="print_params", help="Print parameter table")
    args = parser.parse_args()

    raw = args.input.read_bytes()
    voices = extract_voices(raw)
    if not voices:
        raise ValueError("No DX7 voices decoded.")

    patch_index = args.patch_index
    if patch_index < 0 or patch_index >= len(voices):
        raise ValueError(f"patch-index out of range: {patch_index} (decoded voices: {len(voices)})")

    voice = voices[patch_index]
    params, params_by_symbol = build_tt6_params(voice)
    out_name = args.name or voice.name or f"TT6_DX7_{patch_index:02d}"

    if args.template_fxp is not None:
        hdr = read_fxp_header(args.template_fxp)
        fx_id = hdr["fx_id"]
        fx_version = hdr["fx_version"]
    else:
        fx_id = args.fxid
        fx_version = args.fx_version

    if args.output_json is not None:
        payload = {
            "converter": "dx7_to_tt6",
            "source_file": str(args.input),
            "decoded_voices": len(voices),
            "patch_index": patch_index,
            "voice_name": voice.name,
            "tt6_name": out_name,
            "tt6_uri": "urn:asier:lv2:tt6",
            "tt6_params_ordered": params,
            "tt6_params_by_symbol": params_by_symbol,
            "fxp_hint": {
                "fx_id": fx_id,
                "fx_version": fx_version,
                "num_params": len(params),
            },
        }
        args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.output_fxp is not None:
        write_fxp(args.output_fxp, fx_id=fx_id, fx_version=fx_version, name=out_name, params=params)

    if args.print_params or (args.output_json is None and args.output_fxp is None):
        print(f"DX7 voice: {voice.name!r} -> TT6 name: {out_name!r}")
        print(f"Decoded voices: {len(voices)} | selected index: {patch_index}")
        for i, sym in enumerate(TT6_SYMBOLS):
            print(f"{i:02d} {sym:14s} = {params[i]:.6f}")

    if args.output_json is not None:
        print(f"Wrote JSON: {args.output_json}")
    if args.output_fxp is not None:
        print(f"Wrote FXP : {args.output_fxp} (fx_id=0x{fx_id:08X}, fx_version={fx_version})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
