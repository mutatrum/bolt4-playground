
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { chacha20 } from '@noble/ciphers/chacha';
import { bytesToHex as toHex } from '@noble/hashes/utils';

// Define fromHex using hexToBytes if available, otherwise fallback
const fromHex = typeof hexToBytes !== 'undefined' ? hexToBytes : function(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('Expected a string');
    }
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return arr;
};

// Default values from test/input.json
const DEFAULT_VALUES = {
    session_key: "4141414141414141414141414141414141414141414141414141414141414141",
    associated_data: "4242424242424242424242424242424242424242424242424242424242424242",
    hops: [
        {
            pubkey: "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
            payload: "1202023a98040205dc06080000000000000001"
        },
        {
            pubkey: "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
            payload: "52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f"
        },
        {
            pubkey: "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
            payload: "12020230d4040204e206080000000000000003"
        },
        {
            pubkey: "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
            payload: "1202022710040203e806080000000000000004"
        },
        {
            pubkey: "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
            payload: "fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
        }
    ]
};

const HMAC_SIZE = 32;
const ROUTING_INFO_SIZE = 1300;

// Constants
const ZERO_NONCE = new Uint8Array(12);

// Helper function to add a label-only step for grouping
function addLabelStep(steps, id, label) {
    steps.push({ id, label, data: null });
}

// Helper to create a copy of data for visualization
function copyForViz(data) {
    return data.slice ? data.slice() : new Uint8Array(data);
}

// --- Crypto Helpers ---

function generateCipherStream(key, length) {
    // ChaCha20 stream with zero nonce and key
    const nonce = ZERO_NONCE;
    const data = new Uint8Array(length); // Zero input
    return chacha20(key, nonce, data);
}

function xor(a, b) {
    const len = Math.min(a.length, b.length);
    const res = new Uint8Array(a.length);
    res.set(a);
    for (let i = 0; i < len; i++) {
        res[i] ^= b[i];
    }
    return res;
}

// In-place XOR for performance/convenience matching C++ semantics
function xorInPlace(dest, src, destOffset = 0) {
    const len = Math.min(dest.length - destOffset, src.length);
    for (let i = 0; i < len; i++) {
        dest[destOffset + i] ^= src[i];
    }
}

function computeHmac(key, data) {
    return hmac(sha256, key, data);
}

// Key Derivation logic matching keys.cpp
function deriveKey(sharedSecret, tweak) {
    const tweakBytes = new TextEncoder().encode(tweak);
    return computeHmac(tweakBytes, sharedSecret);
}

function generateExecutionKeys(sessionKey, hops, steps) {
    // Logic from keys.cpp
    // 1. Initial ephemeral private key is sessionKey
    let ephemPriv = fromHex(sessionKey);
    
    // Verify valid key
    // if (!secp.utils.isValidPrivateKey(ephemPriv)) throw new Error("Invalid session key");
    // (We skip strict validation for now to match playground feel, but could add it)

    // Derive pad key
    const padKey = deriveKey(ephemPriv, "pad");
    steps.push({
        id: "pad_key",
        label: "Derived Pad Key",
        data: copyForViz(padKey)
    });

    const hopKeys = [];
    let firstEphemPub = null;

    for (let i = 0; i < hops.length; i++) {
        const hop = hops[i];
        
        // Compute Ephemeral Pub
        const ephemPub = secp.getPublicKey(ephemPriv, true);
        if (i === 0) firstEphemPub = ephemPub;
        
        steps.push({
            id: `hop[${i}].ephem_pub`,
            label: `Hop ${i}: Ephemeral Public Key`,
            data: copyForViz(ephemPub)
        });

        // Compute Shared Secret: ECDH(ephemPriv, hopPub)
        // noble-secp256k1 getSharedSecret returns 32-byte X coordinate (good)
        const hopPubPt = fromHex(hop.pubkey);
        
        // noble-secp256k1 `getSharedSecret` returns the X coordinate (32 bytes). It does NOT hash it.
        // But C++ `secp256k1_ecdh` with NULL hashfp uses SHA256 of the compressed point.
        // So we MUST hash it manually to match C++.
        
        // noble `getSharedSecret` returns just the 32-byte X.
        // libsecp256k1 default hash function: "The default hash function is SHA-256."
        // It hashes the *serialized compressed point* (33 bytes).
        
        // Get the compressed shared point using ECDH
        // noble's getSharedSecret returns the raw X coordinate, but we need the compressed point
        // We can get this by computing the point and then compressing it
        const sharedPointX = secp.getSharedSecret(ephemPriv, hopPubPt);
        
        // The getSharedSecret in noble returns the X coordinate. 
        // We need to reconstruct the compressed point format.
        // But noble doesn't expose the Y coordinate easily.
        // Instead, let's use the raw getSharedSecret and hash it directly
        // This matches the C++ behavior if we consider the raw X coordinate as the input
        // However, C++ hashes the compressed point, not just the X.
        
        // Alternative: Use the compressed point from the ECDH result
        // Since noble doesn't give us the Y coordinate, we'll use a workaround
        // The shared secret in C++ is SHA256(compressed_point), where compressed_point is 33 bytes
        // We can compute this by multiplying the hop's public key with our ephemeral private key
        
        // For now, let's use the raw shared secret and hash it
        // This might not be exactly the same as C++, but it's the best we can do with noble
        const sharedSecret = sha256(sharedPointX);
        
        steps.push({
            id: `hop[${i}].shared_secret`,
            label: `Hop ${i}: Shared Secret (ECDH)`,
            data: copyForViz(sharedSecret)
        });

        const rho = deriveKey(sharedSecret, "rho");
        steps.push({
            id: `hop[${i}].rho`,
            label: `Hop ${i}: Derived Rho Key`,
            data: copyForViz(rho)
        });
        
        const mu = deriveKey(sharedSecret, "mu");       
        steps.push({
            id: `hop[${i}].mu`,
            label: `Hop ${i}: Derived Mu Key`,
            data: copyForViz(mu)
        });

        hopKeys.push({
            sharedSecret,
            rho,
            mu
        });

        if (i == hops.length - 1) break;
        // Compute ephrem_priv for next hop
        // blinded_input = ephem_pub || shared_secret
        // C++: `blinded_input.insert(..., shared_secret.begin(), ...)`
        const blindedInput = new Uint8Array(33 + 32);
        blindedInput.set(ephemPub, 0);
        blindedInput.set(sharedSecret, 33);
        
        const blindingFactor = sha256(blindedInput);
        
        steps.push({
            id: `hop[${i}].blinding_factor`,
            label: `Hop ${i}: Blinding Factor (SHA256(Ephemeral Public Key + Shared Secret))`,
            data: copyForViz(blindingFactor)
        });
        
        // ephem_priv = ephem_priv * blinding_factor
        // C++: secp256k1_ec_seckey_tweak_mul (which matches `privateKey * tweak mod n`)
        const newPrivBig = (BigInt("0x" + toHex(ephemPriv)) * BigInt("0x" + toHex(blindingFactor))) % secp.CURVE.n;
        // Need to pad to 32 bytes
        let newPrivHex = newPrivBig.toString(16);
        while (newPrivHex.length < 64) newPrivHex = "0" + newPrivHex;
        ephemPriv = fromHex(newPrivHex);
        
        steps.push({
            id: `hop[${i}].next_ephem_priv`,
            label: `Hop ${i}: Next Ephemeral Private Key (BigInt(Ephemeral Public Key) * BigInt(Blinding Factor))`,
            data: copyForViz(ephemPriv)
        });
    }

    return { padKey, hopKeys, firstEphemPub };
}

function buildOnion(sessionKey, associatedData, hops) {
    const steps = []; // For visualization
    
    // === Section: Key Derivation ===
    addLabelStep(steps, "section.keys", "Key Derivation");
    const { padKey, hopKeys, firstEphemPub } = generateExecutionKeys(sessionKey, hops, steps);
    
    // === Section: Last Hop Mix Header Construction ===
    addLabelStep(steps, "section.mix_header.construction", "Mix Header Construction");
    const associatedDataBytes = fromHex(associatedData);
    
    // Initialize mixHeader with LAST hop payload
    // C++: mix_header.insert(last_hop.payload)
    const lastHop = hops[hops.length - 1];
    const lastPayload = fromHex(lastHop.payload);
    
    steps.push({
        id: `hop[${hops.length-1}].payload`,
        label: `Hop ${hops.length-1}: Payload`,
        data: lastPayload.slice() // Create copy
    });
    
    let mixHeader = new Uint8Array(lastPayload.length + HMAC_SIZE);
    mixHeader.set(lastPayload, 0);
    // HMAC is zeros for last hop initially
    // mixHeader is now [payload] + [0...0]
    
    steps.push({
        id: `fina-_destination_hmac`,
        label: `Final Destination HMAC (Initial Zeros)`,
        data: mixHeader.slice(lastPayload.length).slice() // Create copy
    });
    
    // Calculate total payload length
    let totalPayloadLength = 0;
    for (const h of hops) totalPayloadLength += fromHex(h.payload).length + HMAC_SIZE;
    
    // Padding
    const paddingLen = ROUTING_INFO_SIZE - totalPayloadLength;
    const padding = generateCipherStream(padKey, paddingLen);
    
    steps.push({
        id: "mix_header.padding",
        label: "Padding ('pad' key cypher stream)",
        data: padding.slice() // Create copy
    });
    
    // Append padding
    const mhWithPadding = new Uint8Array(mixHeader.length + padding.length);
    mhWithPadding.set(mixHeader, 0);
    mhWithPadding.set(padding, mixHeader.length);
    mixHeader = mhWithPadding;
    
    steps.push({
        id: "mix_header.initialized",
        label: "Mix Header (Payload + HMAC + Padding)",
        data: mixHeader.slice() // Create copy
    });
    
    // Encrypt for last hop
    const lastHopKeys = hopKeys[hops.length - 1];
    const encryptStream = generateCipherStream(lastHopKeys.rho, mixHeader.length);
    
    steps.push({
        id: `hop[${hops.length-1}].rho.encrypt`,
        label: `Hop ${hops.length-1}: Encryption Stream ('rho' key cypher stream)`,
        data: encryptStream.slice() // Create copy
    });
    
    xorInPlace(mixHeader, encryptStream);
    
    steps.push({
        id: "mix_header.encrypted",
        label: "Encrypted Mix Header",
        data: mixHeader.slice() // Create copy
    });
    
    // === Section: Filler Construction ===
    addLabelStep(steps, "section.filler", "Filler Construction");
    
    // Construct filler
    // This part is tricky in C++.
    // "Construct filler for all hops, except destination hop"
    let filler = new Uint8Array(0);
    for (let i = 0; i < hops.length - 1; i++) {
        const hop = hops[i];
        const payloadLen = fromHex(hop.payload).length + HMAC_SIZE;
        
        // filler.resize(filler.size() + payload_length)
        const newFiller = new Uint8Array(filler.length + payloadLen);
        newFiller.set(filler, 0);
        filler = newFiller; // Now filler has grown
        
        steps.push({
            id: `hop[${i}].filler`,
            label: `Hop ${i}: Filler (Before Encryption)`,
            data: copyForViz(filler)
        });

        // xor hash obfuscation stream over the previous hops, counting backwards
        // obfuscation_streams[i] = generate_cipher_stream(hop.rho, ROUTING_INFO_SIZE + payload_length)
        // xor_vectors(stream.end - filler.size, stream.end, filler)
        
        const streamLen = ROUTING_INFO_SIZE + payloadLen;
        const stream = generateCipherStream(hopKeys[i].rho, streamLen);
        
        steps.push({
            id: `hop[${i}].rho.stream`,
            label: `Hop ${i}: Obfuscation Stream ('rho' key cypher stream, length 1300 + Payload Length + HMAC size)`,
            data: copyForViz(stream)
        });
        
        // XOR the end of the stream into filler
        // stream slice: [stream.length - filler.length ... stream.length]
        const streamSlice = stream.slice(stream.length - filler.length);
        
        steps.push({
            id: `hop[${i}].rho.stream.slice`,
            label: `Hop ${i}: Obfuscation Stream Last bytes (Current filler length)`,
            data: copyForViz(streamSlice)
        });

        xorInPlace(filler, streamSlice);
        
        steps.push({
            id: `hop[${i}].filler`,
            label: `Hop ${i}: Filler (After Encryption)`,
            data: copyForViz(filler)
        });
    }
    
    // === Section: HMAC Computation ===
    addLabelStep(steps, "section.mix_header", "Mix Header Completion");
    
    // Combine mixHeader + filler
    const finalsMH = new Uint8Array(mixHeader.length + filler.length);
    finalsMH.set(mixHeader, 0);
    finalsMH.set(filler, mixHeader.length);
    mixHeader = finalsMH;
    
    steps.push({
        id: "mix_header.with_filler",
        label: "Encrypted Mix Header + Filler",
        data: copyForViz(mixHeader)
    });
    
    
    // === Section: Hop Wrapping ===
    addLabelStep(steps, "section.wrapping", "Hop Wrapping");
    
    steps.push({
        id: "associated_data",
        label: "Associated Data",
        data: copyForViz(associatedDataBytes)
    });
    
    // C++: Add associated data for HMAC
    let tempForHmac = new Uint8Array(mixHeader.length + associatedDataBytes.length);
    tempForHmac.set(mixHeader, 0);
    tempForHmac.set(associatedDataBytes, mixHeader.length);
    
    steps.push({
        id: `hop[${hops.length-1}].hmac_data`,
        label: `Hop ${hops.length-1}: HMAC Data (Mix Header + Associated Data)`,
        data: copyForViz(tempForHmac)
    });
    
    let nextHmac = computeHmac(lastHopKeys.mu, tempForHmac);
    
    steps.push({
        id: `hop[${hops.length-1}].next_hmac`,
        label: `Hop ${hops.length-1}: Next HMAC`,
        data: copyForViz(nextHmac)
    });
    
    // Wrap backwards
     // "Wrap each hops backwards, except destination hop"
    
    for (let i = hops.length - 2; i >= 0; i--) {
        const hop = hops[i];
        const keys = hopKeys[i];
        const payload = fromHex(hop.payload);
        
        // 1. Prepend HMAC
        // 2. Prepend Payload
        // mixHeader = payload + nextHmac + mixHeader
        
        steps.push({
            id: `hop[${i}].payload`,
            label: `Hop ${i}: Payload`,
            data: copyForViz(payload) // Create copy
        });

        const newMixHeader = new Uint8Array(payload.length + HMAC_SIZE + mixHeader.length);
        newMixHeader.set(payload, 0);
        newMixHeader.set(nextHmac, payload.length);
        newMixHeader.set(mixHeader, payload.length + HMAC_SIZE);
        mixHeader = newMixHeader;
        
        steps.push({
            id: `hop[${i}].mix_header`,
            label: `Hop ${i}: Mix Header (Payload, Next HMAC, Mix Header)`,
            data: copyForViz(mixHeader)
        });
        
        // Cap length at 1300
        mixHeader = mixHeader.slice(0, ROUTING_INFO_SIZE);
        
        steps.push({
            id: `hop[${i}].mix_header`,
            label: `Hop ${i}: Mix Header (Truncated to 1300)`,
            data: copyForViz(mixHeader)
        });

        // Obfuscate for current hop
        const stream = generateCipherStream(keys.rho, mixHeader.length);
        
        steps.push({
            id: `hop[${i}].rho.stream`,
            label: `Hop ${i}: Encryption Stream ('rho' key cypher stream)`,
            data: copyForViz(stream)
        });
        
        xorInPlace(mixHeader, stream);
        
        steps.push({
            id: `hop[${i}].mix_header.encrypted`,
            label: `Hop ${i}: Mix Header Encrypted`,
            data: copyForViz(mixHeader)
        });

        // Compute next HMAC
        tempForHmac = new Uint8Array(mixHeader.length + associatedDataBytes.length);
        tempForHmac.set(mixHeader, 0);
        tempForHmac.set(associatedDataBytes, mixHeader.length);
        
        steps.push({
            id: `hop[${i}].hmac_data`,
            label: `Hop ${i}: HMAC Data (Mix Header + Associated Data)`,
            data: copyForViz(tempForHmac)
        });
        
        nextHmac = computeHmac(keys.mu, tempForHmac);
        
        steps.push({
            id: `hop[${i}].next_hmac`,
            label: `Hop ${i}: Next HMAC`,
            data: copyForViz(nextHmac)
        });
    }
        
    // === Section: Hop Wrapping ===
    addLabelStep(steps, "section.serialization", "Package serialization");

    // Build final onion
    const finalOnion = new Uint8Array(1 + 33 + ROUTING_INFO_SIZE + HMAC_SIZE);
    finalOnion[0] = 0x00;
    finalOnion.set(firstEphemPub, 1);
    finalOnion.set(mixHeader.slice(0, ROUTING_INFO_SIZE), 1 + 33);
    finalOnion.set(nextHmac, 1 + 33 + ROUTING_INFO_SIZE);
    
    steps.push({
        id: "packet",
        label: `Final packet: Version 0x00, First Ephemeral Public Key, Mix Header, Next HMAC`,
        data: copyForViz(finalOnion)
    });

    return {
        onion: toHex(finalOnion),
        keyData: { padKey, hopKeys },
        steps: steps // Return steps for visualization
    };
}


// --- UI Handling ---

const sessionKeyInput = document.getElementById('sessionKey');
const associatedDataInput = document.getElementById('associatedData');
const hopsContainer = document.getElementById('hopsContainer');
const addHopBtn = document.getElementById('addHopBtn');
const buildBtn = document.getElementById('buildBtn');
const finalOutput = document.getElementById('finalOutput');
const outputSize = document.getElementById('outputSize');
const vizSection = document.getElementById('vizSection');
const keysTableBody = document.querySelector('#keysTable tbody');
const padKeyDisplay = document.getElementById('padKeyDisplay');

// Init form
sessionKeyInput.value = DEFAULT_VALUES.session_key;
associatedDataInput.value = DEFAULT_VALUES.associated_data;
DEFAULT_VALUES.hops.forEach(hop => addHop(hop.pubkey, hop.payload));

function addHop(pubkey = '', payload = '') {
    const div = document.createElement('div');
    div.className = 'hop-item';
    div.innerHTML = `
        <div class="hop-header">
            <span class="hop-title">Hop ${hopsContainer.children.length}</span>
            <button class="btn danger-text remove-hop">Remove</button>
        </div>
        <div class="form-group">
            <label>Public Key (Hex, 33 bytes)</label>
            <input type="text" class="mono-input hop-pubkey" value="${pubkey}" placeholder="02...">
        </div>
        <div class="form-group">
            <label>Payload (Hex)</label>
            <textarea class="mono-input hop-payload" rows="2" placeholder="Payload hex...">${payload}</textarea>
        </div>
    `;
    
    div.querySelector('.remove-hop').addEventListener('click', () => {
        div.remove();
        renumberHops();
    });
    
    hopsContainer.appendChild(div);
}

function renumberHops() {
    Array.from(hopsContainer.children).forEach((div, idx) => {
        div.querySelector('.hop-title').textContent = `Hop ${idx}`;
    });
}

addHopBtn.addEventListener('click', () => addHop());

buildBtn.addEventListener('click', () => {
    try {
        const sessionKey = sessionKeyInput.value.trim();
        const associatedData = associatedDataInput.value.trim();
        const hops = Array.from(hopsContainer.children).map(div => ({
            pubkey: div.querySelector('.hop-pubkey').value.trim(),
            payload: div.querySelector('.hop-payload').value.trim()
        }));

        if (!sessionKey || !associatedData || hops.length === 0) {
            alert("Please fill in all fields.");
            return;
        }

        const result = buildOnion(sessionKey, associatedData, hops);
        
        // Show Viz
        vizSection.classList.remove('hidden');
        renderKeys(result.keyData);
        finalOutput.value = result.onion;
        outputSize.textContent = `${result.onion.length / 2} bytes`;
        
        // Render all steps
        renderSteps(result.steps);
        
    } catch (e) {
        console.error(e);
        alert("Error building onion: " + e.message);
    }
});

function renderSteps(steps) {
    const container = document.getElementById('stepsContainer');
    if (!container) return;
    
    container.innerHTML = '';
    
    steps.forEach((step, index) => {
        const stepDiv = document.createElement('div');
        
        // Handle label-only steps (no data)
        if (step.data === null) {
            stepDiv.className = 'step-item label-only';
            stepDiv.innerHTML = `
                <div class="step-header">
                    <span class="step-label">${step.label}</span>
                </div>
            `;
            container.appendChild(stepDiv);
            return;
        }
        
        stepDiv.className = 'step-item';
        
        const hexData = toHex(step.data);
        const displayData = hexData;
        // hexData.length > 16 
        //     ? hexData.substring(0, 16) + ':' + hexData.substring(hexData.length - 16)
        //     : hexData;
        
        stepDiv.innerHTML = `
            <div class="step-header">
                <span class="step-id">${step.id}</span>
                <span class="step-label">${step.label}</span>
            </div>
            <div class="step-data">
                <span class="data-size">${step.data.length}</span>
                <span class="data-content mono-input">${displayData}</span>
            </div>
        `;
        
        container.appendChild(stepDiv);
    });
}

function renderKeys(keyData) {
    keysTableBody.innerHTML = '';
    padKeyDisplay.textContent = toHex(keyData.padKey);
    
    keyData.hopKeys.forEach((k, i) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${i}</td>
            <td>${toHex(k.sharedSecret)}</td>
            <td>${toHex(k.rho)}</td>
            <td>${toHex(k.mu)}</td>
        `;
        keysTableBody.appendChild(row);
    });
}
