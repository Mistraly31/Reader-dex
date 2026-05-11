const editor = document.getElementById('editor');
const passwordInput = document.getElementById('password');
const status = document.getElementById('status');

// --- 1. AUTOGUARDADO LOCAL ---
// Cargar contenido al iniciar
window.onload = () => {
    const saved = localStorage.getItem('autosave_content');
    if (saved) editor.value = saved;
};

// Guardar en cada pulsación de tecla
editor.oninput = () => {
    localStorage.setItem('autosave_content', editor.value);
    status.innerText = "Estado: Guardado en el navegador...";
};

// --- 2. CIFRADO Y DESCARGA ---
async function downloadFile() {
    const text = editor.value;
    const password = passwordInput.value;

    if (!password) return alert("Introduce una contraseña para cifrar");

    try {
        const encryptedData = await encrypt(text, password);
        const blob = new Blob([JSON.stringify(encryptedData)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = "data_segura.json";
        a.click();
        status.innerText = "Estado: Archivo descargado con éxito";
    } catch (e) {
        alert("Error al cifrar el archivo");
    }
}

// --- 3. SUBIDA Y DESCIFRADO ---
document.getElementById('fileInput').onchange = async (e) => {
    const file = e.target.files[0];
    const password = passwordInput.value;

    if (!password) return alert("Introduce la contraseña para descifrar el archivo");

    const reader = new FileReader();
    reader.onload = async (ev) => {
        try {
            const encryptedData = JSON.parse(ev.target.result);
            const decryptedText = await decrypt(encryptedData, password);
            editor.value = decryptedText;
            localStorage.setItem('autosave_content', decryptedText);
            status.innerText = "Estado: Archivo cargado y descifrado";
        } catch (err) {
            alert("Contraseña incorrecta o archivo dañado");
        }
    };
    reader.readAsText(file);
};

// --- UTILIDADES DE CRIPTOGRAFÍA ---
async function encrypt(text, password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    
    const key = await deriveKey(password, salt);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

    return {
        cipherText: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
        salt: btoa(String.fromCharCode(...salt)),
        iv: btoa(String.fromCharCode(...iv))
    };
}

async function decrypt(data, password) {
    const salt = new Uint8Array(atob(data.salt).split("").map(c => c.charCodeAt(0)));
    const iv = new Uint8Array(atob(data.iv).split("").map(c => c.charCodeAt(0)));
    const cipherText = new Uint8Array(atob(data.cipherText).split("").map(c => c.charCodeAt(0)));

    const key = await deriveKey(password, salt);
    const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipherText);

    return new TextDecoder().decode(decrypted);
}

async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    return window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}
