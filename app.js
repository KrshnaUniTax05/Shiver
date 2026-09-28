const nacl = window.nacl;
const util = window.nacl.util;
const socket = io();

// App State
const state = {
    code: null,
    keys: null,
    chats: {}, // peerCode -> [{ id, sender, text, ts }]
    activeChat: null,
    processedMsgIds: new Set(),
    peerKeyCache: {}
};

// UI Elements
const els = {
    screens: {
        unlock: document.getElementById('screen-unlock'),
        home: document.getElementById('screen-home'),
        chat: document.getElementById('screen-chat'),
        settings: document.getElementById('screen-settings')
    },
    unlockBtn: document.getElementById('btn-unlock'),
    passphraseInput: document.getElementById('passphrase'),
    ackCheck: document.getElementById('ack-checkbox'),
    myCodeDisplay: document.getElementById('my-code-display'),
    btnCopy: document.getElementById('btn-copy'),
    searchForm: document.getElementById('search-form'),
    searchInput: document.getElementById('search-input'),
    chatList: document.getElementById('chat-list'),
    btnSettings: document.getElementById('btn-settings'),
    btnBack: document.getElementById('btn-back'),
    btnBackSettings: document.getElementById('btn-back-settings'),
    btnLock: document.getElementById('btn-lock'),
    chatPeerCode: document.getElementById('chat-peer-code'),
    msgContainer: document.getElementById('messages-container'),
    msgForm: document.getElementById('msg-form'),
    msgInput: document.getElementById('msg-input')
};

// Cryptography & Identity Core
async function deriveIdentity(passphrase) {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(passphrase));
    const seed = new Uint8Array(hashBuffer);
    
    const signKeyPair = nacl.sign.keyPair.fromSeed(seed);
    const boxKeyPair = nacl.box.keyPair.fromSecretKey(seed);

    const signPubBase64 = util.encodeBase64(signKeyPair.publicKey);
    const boxPubBase64 = util.encodeBase64(boxKeyPair.publicKey);

    // Deterministic 10-char code generation
    const strForHash = `sign:${signPubBase64}|box:${boxPubBase64}`;
    const hash2 = await crypto.subtle.digest('SHA-256', encoder.encode(strForHash));
    const hashArray = new Uint8Array(hash2);
    
    let num = 0n;
    for (let i = 0; i < 8; i++) num = (num << 8n) | BigInt(hashArray[i]);
    
    let code = num.toString(36).toUpperCase().padStart(10, '0').slice(0, 10);

    return {
        code,
        keys: {
            signKeyPair, boxKeyPair,
            signPub: signPubBase64, boxPub: boxPubBase64
        }
    };
}

async function verifyPeerKeys(code, signPub, boxPub) {
    const strForHash = `sign:${signPub}|box:${boxPub}`;
    const hash2 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(strForHash));
    const hashArray = new Uint8Array(hash2);
    let num = 0n;
    for (let i = 0; i < 8; i++) num = (num << 8n) | BigInt(hashArray[i]);
    const derivedCode = num.toString(36).toUpperCase().padStart(10, '0').slice(0, 10);
    return derivedCode === code;
}

async function getPeerKeys(code) {
    if (state.peerKeyCache[code]) return state.peerKeyCache[code];
    try {
        const res = await fetch(`/api/users/${code}`);
        if (!res.ok) return null;
        const data = await res.json();
        if (await verifyPeerKeys(code, data.signPub, data.boxPub)) {
            state.peerKeyCache[code] = data;
            return data;
        }
    } catch (e) { console.error(e); }
    return null;
}

// Networking & Flow
async function unlockApp() {
    const pass = els.passphraseInput.value.trim();
    if (!pass || !els.ackCheck.checked) return;
    
    els.unlockBtn.disabled = true;
    els.unlockBtn.innerText = 'Unlocking...';

    const identity = await deriveIdentity(pass);
    state.code = identity.code;
    state.keys = identity.keys;

    // Register with server
    await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: state.code, signPub: state.keys.signPub, boxPub: state.keys.boxPub })
    });

    els.myCodeDisplay.innerText = state.code.match(/.{1,5}/g).join('-');
    socket.emit('subscribe', state.code);

    await fetchAndProcessMessages();
    
    showScreen('home');
}

async function fetchAndProcessMessages() {
    try {
        const res = await fetch(`/api/messages/${state.code}`);
        const msgs = await res.json();
        await processRawMessages(msgs);
    } catch(e) { console.error('Fetch error:', e); }
}

socket.on('message', async (rawMsg) => {
    await processRawMessages([rawMsg]);
});

async function processRawMessages(rawMessages) {
    let newMsgAdded = false;

    for (const msg of rawMessages) {
        if (state.processedMsgIds.has(msg.id)) continue;
        state.processedMsgIds.add(msg.id);

        try {
            const box = util.decodeBase64(msg.ciphertext);
            const nonce = util.decodeBase64(msg.nonce);
            const ephPub = util.decodeBase64(msg.ephemeralPub);

            const innerUint8 = nacl.box.open(box, nonce, ephPub, state.keys.boxKeyPair.secretKey);
            if (!innerUint8) continue; // Not for us / corrupt

            const innerStr = new TextDecoder().decode(innerUint8);
            const { s, r, t, ts, sig } = JSON.parse(innerStr);

            const peerKeys = await getPeerKeys(s);
            if (!peerKeys) continue;

            const msgToVerify = s + r + t + ts;
            const isValid = nacl.sign.detached.verify(
                new TextEncoder().encode(msgToVerify),
                util.decodeBase64(sig),
                util.decodeBase64(peerKeys.signPub)
            );

            if (!isValid) continue;

            const peerCode = (s === state.code) ? r : s;
            if (!state.chats[peerCode]) state.chats[peerCode] = [];
            
            // Check for duplicates
            if (!state.chats[peerCode].find(m => m.id === msg.id)) {
                state.chats[peerCode].push({ id: msg.id, sender: s, text: t, ts: parseInt(ts) });
                newMsgAdded = true;
            }
        } catch (e) {
            console.error('Decryption fail', e);
        }
    }

    if (newMsgAdded) {
        for (let pc in state.chats) state.chats[pc].sort((a,b) => a.ts - b.ts);
        renderHome();
        if (state.activeChat) renderChatView(state.activeChat);
    }
}

async function sendMessage(peerCode, text) {
    const peerKeys = await getPeerKeys(peerCode);
    if (!peerKeys) { alert('User not found.'); return; }

    const ts = Date.now().toString();
    const msgToSign = state.code + peerCode + text + ts;
    const sig = nacl.sign.detached(new TextEncoder().encode(msgToSign), state.keys.signKeyPair.secretKey);
    
    const innerObj = { s: state.code, r: peerCode, t: text, ts, sig: util.encodeBase64(sig) };
    const innerUint8 = new TextEncoder().encode(JSON.stringify(innerObj));

    // 1. Encrypt for Recipient
    const eph1 = nacl.box.keyPair();
    const nonce1 = nacl.randomBytes(24);
    const box1 = nacl.box(innerUint8, nonce1, util.decodeBase64(peerKeys.boxPub), eph1.secretKey);
    
    // 2. Encrypt for Self (Sync)
    const eph2 = nacl.box.keyPair();
    const nonce2 = nacl.randomBytes(24);
    const box2 = nacl.box(innerUint8, nonce2, util.decodeBase64(state.keys.boxPub), eph2.secretKey);

    const postMsg = async (rc, eph, n, c) => fetch('/api/messages', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipientCode: rc, ephemeralPub: util.encodeBase64(eph), nonce: util.encodeBase64(n), ciphertext: util.encodeBase64(c) })
    });

    await Promise.all([
        postMsg(peerCode, eph1.publicKey, nonce1, box1),
        postMsg(state.code, eph2.publicKey, nonce2, box2)
    ]);
}

// UI Rendering & Navigation
function showScreen(id) {
    Object.values(els.screens).forEach(el => el.classList.add('hide'));
    els.screens[id].classList.remove('hide');
    if(id === 'home') renderHome();
}

function renderHome() {
    els.chatList.innerHTML = '';
    const sortedPeers = Object.keys(state.chats).sort((a, b) => {
        const lastA = state.chats[a][state.chats[a].length - 1].ts;
        const lastB = state.chats[b][state.chats[b].length - 1].ts;
        return lastB - lastA;
    });

    if(sortedPeers.length === 0) {
        els.chatList.innerHTML = `<div class="text-center text-slate-500 mt-10 text-sm">No chats yet.<br>Search a code to begin.</div>`;
    }

    sortedPeers.forEach(peerCode => {
        const msgs = state.chats[peerCode];
        const lastMsg = msgs[msgs.length - 1];
        
        const div = document.createElement('div');
        div.className = 'flex items-center space-x-4 p-3 bg-slate-800 rounded-lg cursor-pointer hover:bg-slate-700 transition-colors border border-slate-700';
        div.onclick = () => { state.activeChat = peerCode; showScreen('chat'); renderChatView(peerCode); };
        
        div.innerHTML = `
            <div class="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-bold text-sm shadow-inner shrink-0">
                ${peerCode.substring(0, 2)}
            </div>
            <div class="flex-1 overflow-hidden">
                <div class="font-mono text-cyan-400 font-semibold">${peerCode.match(/.{1,5}/g).join('-')}</div>
                <div class="text-xs text-slate-400 truncate">${lastMsg.sender === state.code ? 'You: ' : ''}${lastMsg.text}</div>
            </div>
        `;
        els.chatList.appendChild(div);
    });
}

function renderChatView(peerCode) {
    els.chatPeerCode.innerText = peerCode.match(/.{1,5}/g).join('-');
    els.msgContainer.innerHTML = '';
    const msgs = state.chats[peerCode] || [];

    msgs.forEach(m => {
        const isMine = m.sender === state.code;
        const div = document.createElement('div');
        div.className = `flex w-full ${isMine ? 'justify-end' : 'justify-start'}`;
        
        div.innerHTML = `
            <div class="msg-bubble p-3 rounded-2xl ${isMine ? 'bg-cyan-600 text-white rounded-tr-sm' : 'bg-slate-700 text-slate-100 rounded-tl-sm'} shadow-md text-sm">
                ${m.text.replace(/</g, "&lt;").replace(/>/g, "&gt;")}
                <div class="text-[10px] opacity-60 mt-1 text-right">${new Date(m.ts).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
            </div>
        `;
        els.msgContainer.appendChild(div);
    });
    els.msgContainer.scrollTop = els.msgContainer.scrollHeight;
}

// Event Listeners
els.passphraseInput.addEventListener('input', () => {
    const p = els.passphraseInput.value.trim();
    els.unlockBtn.disabled = p.length < 5 || !els.ackCheck.checked;
});
els.ackCheck.addEventListener('change', () => {
    const p = els.passphraseInput.value.trim();
    els.unlockBtn.disabled = p.length < 5 || !els.ackCheck.checked;
});

els.unlockBtn.addEventListener('click', unlockApp);

els.btnCopy.addEventListener('click', () => {
    navigator.clipboard.writeText(state.code);
    els.btnCopy.innerText = 'Copied!';
    setTimeout(() => els.btnCopy.innerText = 'Copy', 2000);
});

els.searchForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const raw = els.searchInput.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (raw.length !== 10) return alert('Code must be exactly 10 alphanumeric characters.');
    if (raw === state.code) return alert('You cannot chat with yourself.');

    const keys = await getPeerKeys(raw);
    if (!keys) return alert('No user found.');

    els.searchInput.value = '';
    state.activeChat = raw;
    showScreen('chat');
    renderChatView(raw);
});

els.msgForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = els.msgInput.value.trim();
    if (!text || !state.activeChat) return;
    els.msgInput.value = '';
    await sendMessage(state.activeChat, text);
});

els.btnSettings.addEventListener('click', () => showScreen('settings'));
els.btnBack.addEventListener('click', () => { state.activeChat = null; showScreen('home'); });
els.btnBackSettings.addEventListener('click', () => showScreen('home'));

els.btnLock.addEventListener('click', () => {
    window.location.reload();
});
