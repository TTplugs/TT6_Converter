const TT6_SYMBOLS = [
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
];

const DX7_TO_TT6_ALGO = [
  0, 0, 1, 1, 2, 2, 3, 3,
  4, 4, 5, 5, 6, 6, 7, 7,
  8, 8, 9, 9, 10, 10, 11, 11,
  12, 12, 13, 13, 14, 14, 15, 15,
];

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let j = 0; j < 8; j += 1) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

const TEXT_ENCODER = new TextEncoder();

const state = {
  jsonText: "",
  fxpBytes: null,
  batchZipBytes: null,
  outputBaseName: "tt6_patch",
  params: [],
  batchMode: false,
  batchCount: 0,
};

const els = {
  themeToggle: document.getElementById("themeToggle"),
  syxFile: document.getElementById("syxFile"),
  patchIndex: document.getElementById("patchIndex"),
  programName: document.getElementById("programName"),
  batchMode: document.getElementById("batchMode"),
  templateFxp: document.getElementById("templateFxp"),
  fxid: document.getElementById("fxid"),
  fxVersion: document.getElementById("fxVersion"),
  convertBtn: document.getElementById("convertBtn"),
  downloadJsonBtn: document.getElementById("downloadJsonBtn"),
  downloadFxpBtn: document.getElementById("downloadFxpBtn"),
  downloadBatchBtn: document.getElementById("downloadBatchBtn"),
  statusText: document.getElementById("statusText"),
  metaBox: document.getElementById("metaBox"),
  paramsBody: document.getElementById("paramsBody"),
};

function clamp(x, lo, hi) {
  if (x < lo) return lo;
  if (x > hi) return hi;
  return x;
}

function expMap01(x01, outMin, outMax) {
  const x = clamp(x01, 0, 1);
  if (outMin <= 0 || outMax <= 0) {
    return outMin + (outMax - outMin) * x;
  }
  return outMin * ((outMax / outMin) ** x);
}

function parseIntAuto(text) {
  const t = text.trim();
  if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  if (/^-?\d+$/.test(t)) return parseInt(t, 10);
  throw new Error(`Invalid integer value: ${text}`);
}

function parseNonNegativeInt(text, fieldName) {
  const value = parseInt(text, 10);
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${fieldName} must be a non-negative integer.`);
  }
  return value;
}

function sanitizeName(name, size = 28) {
  const out = new Uint8Array(size);
  const source = (name || "").slice(0, size);
  for (let i = 0; i < source.length; i += 1) {
    const code = source.charCodeAt(i);
    out[i] = code >= 32 && code <= 126 ? code : 95;
  }
  return out;
}

function decodeName(bytes) {
  const chars = [];
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i];
    chars.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : " ");
  }
  const name = chars.join("").trim();
  return name || "DX7_PATCH";
}

function parseSysexMessages(raw) {
  const messages = [];
  let i = 0;
  while (i < raw.length) {
    if (raw[i] !== 0xf0) {
      i += 1;
      continue;
    }
    let j = i + 1;
    while (j < raw.length && raw[j] !== 0xf7) {
      j += 1;
    }
    if (j >= raw.length) break;
    messages.push(raw.slice(i, j + 1));
    i = j + 1;
  }
  return messages;
}

function parseUnpackedVoice(v155) {
  if (v155.length < 155) {
    throw new Error(`Expected 155 bytes, got ${v155.length}`);
  }
  const ops = new Array(6);
  for (let slot = 0; slot < 6; slot += 1) {
    const base = slot * 21;
    const opIndex = 5 - slot;
    ops[opIndex] = {
      r1: v155[base + 0],
      r2: v155[base + 1],
      r3: v155[base + 2],
      r4: v155[base + 3],
      l1: v155[base + 4],
      l2: v155[base + 5],
      l3: v155[base + 6],
      l4: v155[base + 7],
      rate_scale: v155[base + 13],
      ams: v155[base + 14],
      kvs: v155[base + 15],
      output: v155[base + 16],
      mode: v155[base + 17] & 0x01,
      coarse: v155[base + 18] & 0x1f,
      fine: v155[base + 19],
      detune: v155[base + 20] & 0x0f,
    };
  }
  return {
    ops,
    algorithm: v155[134] & 0x1f,
    feedback: v155[135] & 0x07,
    lfo_speed: v155[137],
    lfo_pmd: v155[139],
    pmod_sensitivity: v155[143] & 0x07,
    name: decodeName(v155.slice(145, 155)),
  };
}

function unpackPackedVoice(v128) {
  if (v128.length < 128) {
    throw new Error(`Expected 128 bytes, got ${v128.length}`);
  }
  const ops = new Array(6);
  for (let slot = 0; slot < 6; slot += 1) {
    const base = slot * 17;
    const opIndex = 5 - slot;
    const b12 = v128[base + 12];
    const b13 = v128[base + 13];
    const b15 = v128[base + 15];
    ops[opIndex] = {
      r1: v128[base + 0],
      r2: v128[base + 1],
      r3: v128[base + 2],
      r4: v128[base + 3],
      l1: v128[base + 4],
      l2: v128[base + 5],
      l3: v128[base + 6],
      l4: v128[base + 7],
      rate_scale: b12 & 0x07,
      ams: b13 & 0x03,
      kvs: (b13 >> 2) & 0x07,
      output: v128[base + 14],
      mode: b15 & 0x01,
      coarse: (b15 >> 1) & 0x1f,
      fine: v128[base + 16],
      detune: (b12 >> 3) & 0x0f,
    };
  }
  return {
    ops,
    algorithm: v128[110] & 0x1f,
    feedback: v128[111] & 0x07,
    lfo_speed: v128[112],
    lfo_pmd: v128[114],
    pmod_sensitivity: (v128[116] >> 4) & 0x07,
    name: decodeName(v128.slice(118, 128)),
  };
}

function extractVoices(raw) {
  const voices = [];
  const messages = parseSysexMessages(raw);

  if (messages.length === 0) {
    if (raw.length === 155) return [parseUnpackedVoice(raw)];
    if (raw.length === 128) return [unpackPackedVoice(raw)];
    if (raw.length === 4096) {
      const out = [];
      for (let i = 0; i < 32; i += 1) {
        out.push(unpackPackedVoice(raw.slice(i * 128, (i + 1) * 128)));
      }
      return out;
    }
    throw new Error("No SysEx messages found and raw length is not recognized.");
  }

  for (const msg of messages) {
    if (msg.length < 8 || msg[0] !== 0xf0 || msg[msg.length - 1] !== 0xf7) continue;
    const payload = msg.length >= 9 ? msg.slice(6, msg.length - 2) : new Uint8Array();
    if (payload.length === 155) voices.push(parseUnpackedVoice(payload));
    else if (payload.length === 128) voices.push(unpackPackedVoice(payload));
    else if (payload.length === 4096) {
      for (let i = 0; i < 32; i += 1) {
        voices.push(unpackPackedVoice(payload.slice(i * 128, (i + 1) * 128)));
      }
    }
  }

  if (!voices.length) {
    throw new Error("Could not parse DX7 voices from SysEx data.");
  }
  return voices;
}

function opRatioFromDx7(op) {
  const mode = op.mode & 0x01;
  const coarse = clamp(op.coarse, 0, 31);
  const fine = clamp(op.fine, 0, 99);
  const detune = clamp(op.detune, 0, 14);
  const detuneMul = 2 ** ((detune - 7) / 96);

  if (mode === 0) {
    const ratio = coarse <= 0 ? 0.5 * (1 + fine / 99) : coarse * (1 + fine / 100);
    return clamp(ratio * detuneMul, 0.25, 32);
  }

  const fixedHz = (10 ** (coarse / 8)) * (1 + fine / 100);
  const ratio = (fixedHz / 440) * detuneMul;
  return clamp(ratio, 0.25, 32);
}

function opLevelFromDx7(output099) {
  const x = clamp(output099, 0, 99);
  const db = (x - 99) * 0.75;
  const lin = 10 ** (db / 20);
  if (lin < 0.001) return 0;
  return clamp(lin, 0, 1);
}

function opDecayMsFromDx7(op) {
  const rate = clamp((op.r2 + op.r3) * 0.5, 0, 99);
  const decay01 = ((99 - rate) / 99) ** 1.8;
  return clamp(1 + decay01 * 7999, 1, 8000);
}

function buildTt6Params(voice) {
  const algo = DX7_TO_TT6_ALGO[Math.trunc(clamp(voice.algorithm, 0, 31))];
  const feedback = clamp(voice.feedback / 7, 0, 1);
  const params = new Array(TT6_SYMBOLS.length).fill(0);
  params[0] = algo;

  let brightnessAcc = 0;
  let attackRateAcc = 0;
  let releaseRateAcc = 0;
  let sustainAcc = 0;

  voice.ops.forEach((op, i) => {
    const ratio = opRatioFromDx7(op);
    const level = opLevelFromDx7(op.output);
    const decay = opDecayMsFromDx7(op);
    params[1 + i * 3 + 0] = ratio;
    params[1 + i * 3 + 1] = level;
    params[1 + i * 3 + 2] = decay;
    brightnessAcc += level * clamp(ratio / 8, 0, 1);
    attackRateAcc += clamp(op.r1, 0, 99);
    releaseRateAcc += clamp(op.r4, 0, 99);
    sustainAcc += clamp(op.l3, 0, 99) / 99;
  });

  const brightness = clamp(brightnessAcc / 6, 0, 1);
  const avgAttackRate = attackRateAcc / 6;
  const avgReleaseRate = releaseRateAcc / 6;
  const avgSustain = sustainAcc / 6;

  const attackMs = 0.1 + (((99 - avgAttackRate) / 99) ** 2.2) * 1999.9;
  const sustain = clamp(avgSustain * 0.8, 0, 1);
  const releaseMs = 1 + (((99 - avgReleaseRate) / 99) ** 1.7) * 7999;
  const lfoRate = expMap01(clamp(voice.lfo_speed / 99, 0, 1), 0.05, 30);
  const lfoDepth = clamp((voice.lfo_pmd / 99) * (0.5 + 0.5 * (voice.pmod_sensitivity / 7)), 0, 1);
  const cutoff = 300 + (brightness ** 1.2) * 19700;
  const drive = clamp(0.35 * feedback + 0.15 * brightness, 0, 1);

  params[19] = clamp(attackMs, 0.1, 2000);
  params[20] = sustain;
  params[21] = clamp(releaseMs, 1, 8000);
  params[22] = feedback;
  params[23] = 0;
  params[24] = clamp(cutoff, 20, 20000);
  params[25] = 0.1;
  params[26] = lfoRate;
  params[27] = lfoDepth;
  params[28] = drive;
  params[29] = -6;
  params[30] = 0.7;

  const bySymbol = {};
  TT6_SYMBOLS.forEach((symbol, i) => {
    bySymbol[symbol] = Number(params[i]);
  });
  return { params, bySymbol };
}

function readFxpHeader(bytes) {
  if (bytes.length < 52) {
    throw new Error("Template FXP is too small.");
  }
  const sig1 = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
  const sig2 = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
  if (sig1 !== "CcnK" || sig2 !== "FxCk") {
    throw new Error("Template FXP missing CcnK/FxCk header.");
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    chunk_size: dv.getUint32(4, true),
    version: dv.getUint32(12, true),
    fx_id: dv.getUint32(16, true),
    fx_version: dv.getUint32(20, true),
    num_params: dv.getUint32(24, true),
  };
}

function writeFxpBuffer(fxId, fxVersion, name, params) {
  const numParams = params.length;
  const chunkSize = 4 + 4 + 4 + 4 + 4 + 28 + (4 * numParams);
  const total = 4 + 4 + 4 + 4 + 4 + 4 + 4 + 28 + (4 * numParams);
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);

  out.set(TEXT_ENCODER.encode("CcnK"), 0);
  dv.setUint32(4, chunkSize, true);
  out.set(TEXT_ENCODER.encode("FxCk"), 8);
  dv.setUint32(12, 1, true);
  dv.setUint32(16, fxId >>> 0, true);
  dv.setUint32(20, fxVersion >>> 0, true);
  dv.setUint32(24, numParams, true);
  out.set(sanitizeName(name, 28), 28);

  let offset = 56;
  for (let i = 0; i < numParams; i += 1) {
    dv.setFloat32(offset, Number(params[i]), true);
    offset += 4;
  }
  return out;
}

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    c = CRC32_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function concatUint8(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function createStoredZip(files) {
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;

  for (const file of files) {
    const nameBytes = TEXT_ENCODER.encode(file.name);
    const data = file.data;
    const crc = crc32(data);

    const localHeader = new Uint8Array(30 + nameBytes.length + data.length);
    const ldv = new DataView(localHeader.buffer);
    ldv.setUint32(0, 0x04034b50, true);
    ldv.setUint16(4, 20, true);
    ldv.setUint16(6, 0, true);
    ldv.setUint16(8, 0, true);
    ldv.setUint16(10, 0, true);
    ldv.setUint16(12, 0, true);
    ldv.setUint32(14, crc, true);
    ldv.setUint32(18, data.length, true);
    ldv.setUint32(22, data.length, true);
    ldv.setUint16(26, nameBytes.length, true);
    ldv.setUint16(28, 0, true);
    localHeader.set(nameBytes, 30);
    localHeader.set(data, 30 + nameBytes.length);
    localParts.push(localHeader);

    const centralHeader = new Uint8Array(46 + nameBytes.length);
    const cdv = new DataView(centralHeader.buffer);
    cdv.setUint32(0, 0x02014b50, true);
    cdv.setUint16(4, 20, true);
    cdv.setUint16(6, 20, true);
    cdv.setUint16(8, 0, true);
    cdv.setUint16(10, 0, true);
    cdv.setUint16(12, 0, true);
    cdv.setUint16(14, 0, true);
    cdv.setUint32(16, crc, true);
    cdv.setUint32(20, data.length, true);
    cdv.setUint32(24, data.length, true);
    cdv.setUint16(28, nameBytes.length, true);
    cdv.setUint16(30, 0, true);
    cdv.setUint16(32, 0, true);
    cdv.setUint16(34, 0, true);
    cdv.setUint16(36, 0, true);
    cdv.setUint32(38, 0, true);
    cdv.setUint32(42, localOffset, true);
    centralHeader.set(nameBytes, 46);
    centralParts.push(centralHeader);

    localOffset += localHeader.length;
  }

  const localData = concatUint8(localParts);
  const centralData = concatUint8(centralParts);
  const eocd = new Uint8Array(22);
  const edv = new DataView(eocd.buffer);
  edv.setUint32(0, 0x06054b50, true);
  edv.setUint16(4, 0, true);
  edv.setUint16(6, 0, true);
  edv.setUint16(8, files.length, true);
  edv.setUint16(10, files.length, true);
  edv.setUint32(12, centralData.length, true);
  edv.setUint32(16, localData.length, true);
  edv.setUint16(20, 0, true);

  return concatUint8([localData, centralData, eocd]);
}

function updateStatus(message, isError = false) {
  els.statusText.textContent = message;
  els.statusText.style.color = isError ? "#ffbcc3" : "";
}

function toFileNameBase(rawName) {
  const n = (rawName || "TT6_PATCH").trim();
  return n.replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "") || "TT6_PATCH";
}

function renderMeta(meta) {
  els.metaBox.classList.remove("hidden");
  if (meta.mode === "batch") {
    els.metaBox.innerHTML = [
      "<strong>Mode:</strong> Batch",
      `<strong>Decoded voices:</strong> ${meta.decodedVoices}`,
      `<strong>Extracted patches:</strong> ${meta.batchCount}`,
      `<strong>Name source:</strong> ${meta.programName}`,
      `<strong>FXP ID:</strong> 0x${meta.fxId.toString(16).toUpperCase().padStart(8, "0")}`,
      `<strong>FXP version:</strong> ${meta.fxVersion}`,
    ].join("<br>");
    return;
  }
  els.metaBox.innerHTML = [
    "<strong>Mode:</strong> Single patch",
    `<strong>Voice:</strong> ${meta.voiceName}`,
    `<strong>Decoded voices:</strong> ${meta.decodedVoices}`,
    `<strong>Patch index:</strong> ${meta.patchIndex}`,
    `<strong>Program name:</strong> ${meta.programName}`,
    `<strong>FXP ID:</strong> 0x${meta.fxId.toString(16).toUpperCase().padStart(8, "0")}`,
    `<strong>FXP version:</strong> ${meta.fxVersion}`,
  ].join("<br>");
}

function renderParams(params) {
  if (!params || !params.length) {
    els.paramsBody.innerHTML = '<tr><td colspan="3" class="empty">No conversion yet.</td></tr>';
    return;
  }
  const rows = params.map((value, i) => (
    `<tr><td>${i}</td><td>${TT6_SYMBOLS[i]}</td><td>${Number(value).toFixed(6)}</td></tr>`
  ));
  els.paramsBody.innerHTML = rows.join("");
}

function downloadBlob(filename, mime, data) {
  const blob = data instanceof Uint8Array ? new Blob([data], { type: mime }) : new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function setDownloadButtons(jsonEnabled, fxpEnabled, batchEnabled) {
  els.downloadJsonBtn.disabled = !jsonEnabled;
  els.downloadFxpBtn.disabled = !fxpEnabled;
  if (els.downloadBatchBtn) {
    els.downloadBatchBtn.disabled = !batchEnabled;
  }
}

function setBatchUiState() {
  const enabled = Boolean(els.batchMode?.checked);
  if (els.patchIndex) els.patchIndex.disabled = enabled;
}

function makePayload(sourceFile, voicesCount, patchIndex, voiceName, programName, params, bySymbol, fxId, fxVersion) {
  return {
    converter: "dx7_to_tt6_web",
    source_file: sourceFile,
    decoded_voices: voicesCount,
    patch_index: patchIndex,
    voice_name: voiceName,
    tt6_name: programName,
    tt6_uri: "urn:asier:lv2:tt6",
    tt6_params_ordered: params,
    tt6_params_by_symbol: bySymbol,
    fxp_hint: {
      fx_id: fxId,
      fx_version: fxVersion,
      num_params: params.length,
    },
  };
}

async function convertNow() {
  const syx = els.syxFile.files[0];
  if (!syx) {
    throw new Error("Please select a DX7 SysEx file.");
  }

  const fxVersion = parseNonNegativeInt(els.fxVersion.value, "FXP version");
  let fxId = parseIntAuto(els.fxid.value || "0x743C7CA6");

  const raw = new Uint8Array(await syx.arrayBuffer());
  const voices = extractVoices(raw);

  const template = els.templateFxp.files[0];
  let finalFxVersion = fxVersion;
  if (template) {
    const hdr = readFxpHeader(new Uint8Array(await template.arrayBuffer()));
    fxId = hdr.fx_id;
    finalFxVersion = hdr.fx_version;
  }

  const userProgramName = (els.programName.value || "").trim();
  const isBatch = Boolean(els.batchMode?.checked);

  if (!isBatch) {
    const patchIndex = parseNonNegativeInt(els.patchIndex.value, "Patch index");
    if (patchIndex >= voices.length) {
      throw new Error(`Patch index out of range: ${patchIndex} (decoded voices: ${voices.length}).`);
    }

    const voice = voices[patchIndex];
    const { params, bySymbol } = buildTt6Params(voice);
    const programName = userProgramName || voice.name || `TT6_DX7_${String(patchIndex).padStart(2, "0")}`;
    const fxpBytes = writeFxpBuffer(fxId, finalFxVersion, programName, params);
    const payload = makePayload(
      syx.name,
      voices.length,
      patchIndex,
      voice.name,
      programName,
      params,
      bySymbol,
      fxId,
      finalFxVersion,
    );

    state.jsonText = JSON.stringify(payload, null, 2);
    state.fxpBytes = fxpBytes;
    state.batchZipBytes = null;
    state.outputBaseName = toFileNameBase(programName);
    state.params = params;
    state.batchMode = false;
    state.batchCount = 0;

    renderMeta({
      mode: "single",
      voiceName: voice.name,
      decodedVoices: voices.length,
      patchIndex,
      programName,
      fxId,
      fxVersion: finalFxVersion,
    });
    renderParams(params);
    setDownloadButtons(true, true, false);
    return;
  }

  const requestedStart = 0;
  const actualEnd = voices.length - 1;
  const files = [];
  const manifestPatches = [];
  let previewParams = null;

  for (let index = requestedStart; index <= actualEnd; index += 1) {
    const voice = voices[index];
    const { params } = buildTt6Params(voice);
    const patchTag = String(index).padStart(2, "0");
    const programName = userProgramName
      ? `${userProgramName}_${patchTag}`
      : (voice.name || `TT6_DX7_${patchTag}`);
    const fileBase = `${patchTag}_${toFileNameBase(programName)}`;
    const fxpBytes = writeFxpBuffer(fxId, finalFxVersion, programName, params);
    files.push({
      name: `${fileBase}.fxp`,
      data: fxpBytes,
    });

    manifestPatches.push({
      patch_index: index,
      voice_name: voice.name,
      tt6_name: programName,
      fxp_file: `${fileBase}.fxp`,
    });

    if (!previewParams) {
      previewParams = params;
    }
  }

  const manifest = {
    converter: "dx7_to_tt6_fxp_extract",
    source_file: syx.name,
    decoded_voices: voices.length,
    extracted_range: [requestedStart, actualEnd],
    extracted_patches: manifestPatches.length,
    fxp_hint: {
      fx_id: fxId,
      fx_version: finalFxVersion,
      num_params: TT6_SYMBOLS.length,
    },
    patches: manifestPatches,
  };

  files.unshift({
    name: "TT6_BATCH_manifest.json",
    data: TEXT_ENCODER.encode(JSON.stringify(manifest, null, 2)),
  });

  state.jsonText = "";
  state.fxpBytes = null;
  state.batchZipBytes = createStoredZip(files);
  state.outputBaseName = `tt6_batch_${String(requestedStart).padStart(2, "0")}_${String(actualEnd).padStart(2, "0")}`;
  state.params = previewParams || [];
  state.batchMode = true;
  state.batchCount = manifestPatches.length;

  renderMeta({
    mode: "batch",
    decodedVoices: voices.length,
    batchCount: manifestPatches.length,
    programName: userProgramName || "DX7 voice names",
    fxId,
    fxVersion: finalFxVersion,
  });
  renderParams(state.params);
  setDownloadButtons(false, false, true);
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("tt6_theme", theme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  setTheme(current === "dark" ? "light" : "dark");
}

async function onConvertClick() {
  try {
    updateStatus("Converting...");
    els.convertBtn.disabled = true;
    await convertNow();
    if (state.batchMode) {
      updateStatus(`FXP extraction complete (${state.batchCount} patches). Download FXP ZIP.`);
    } else {
      updateStatus("Conversion complete. Download JSON and/or FXP.");
    }
  } catch (error) {
    state.jsonText = "";
    state.fxpBytes = null;
    state.batchZipBytes = null;
    state.params = [];
    state.batchMode = false;
    state.batchCount = 0;
    setDownloadButtons(false, false, false);
    renderParams([]);
    els.metaBox.classList.add("hidden");
    updateStatus(error instanceof Error ? error.message : String(error), true);
  } finally {
    els.convertBtn.disabled = false;
  }
}

function setupEvents() {
  els.themeToggle.addEventListener("click", toggleTheme);
  els.convertBtn.addEventListener("click", onConvertClick);
  els.batchMode?.addEventListener("change", () => {
    setBatchUiState();
    setDownloadButtons(false, false, false);
    updateStatus("Ready.");
  });
  els.downloadJsonBtn.addEventListener("click", () => {
    if (!state.jsonText) return;
    downloadBlob(`${state.outputBaseName}.json`, "application/json;charset=utf-8", state.jsonText);
  });
  els.downloadFxpBtn.addEventListener("click", () => {
    if (!state.fxpBytes) return;
    downloadBlob(`${state.outputBaseName}.fxp`, "application/octet-stream", state.fxpBytes);
  });
  els.downloadBatchBtn?.addEventListener("click", () => {
    if (!state.batchZipBytes) return;
    downloadBlob(`${state.outputBaseName}.zip`, "application/zip", state.batchZipBytes);
  });
}

function initTheme() {
  const saved = localStorage.getItem("tt6_theme");
  if (saved === "dark" || saved === "light") {
    setTheme(saved);
    return;
  }
  setTheme("dark");
}

function init() {
  initTheme();
  setupEvents();
  setBatchUiState();
  setDownloadButtons(false, false, false);
}

init();
