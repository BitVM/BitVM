export const sha256 = async buffer => {
    let hash = await window.crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hash));
}