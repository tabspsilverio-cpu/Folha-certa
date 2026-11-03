/* Local vault unlock using WebAuthn PRF. No PIN, raw vault key or biometric
 * data is stored. The existing remote vault and PIN login remain unchanged. */
(() => {
  const storageKey = `folha-certa-passkey-v1:${APP_RECORD_ID}`;
  const login = document.getElementById('biometricLogin');
  const setup = document.getElementById('biometricSetup');
  const remove = document.getElementById('biometricRemove');
  const help = document.getElementById('biometricHelp');
  const encoder = new TextEncoder();
  const supported = Boolean(window.isSecureContext && window.PublicKeyCredential && navigator.credentials);
  let busy = false;
  const random = size => crypto.getRandomValues(new Uint8Array(size));
  const b64 = bytes => bytesToBase64(new Uint8Array(bytes));
  const bytes = value => base64ToBytes(value);
  const saved = () => {
    try { return JSON.parse(localStorage.getItem(storageKey) || 'null'); }
    catch { return null; }
  };
  const aad = salt => encoder.encode(`${location.origin}|${APP_RECORD_ID}|${salt}|passkey-v1`);
  const message = text => {
    const error = document.getElementById('authError');
    error.textContent = text;
    error.classList.remove('hidden');
  };
  window.refreshBiometricControls = () => {
    const enabled = supported && supabaseMode && accessConfigured;
    const hasSaved = Boolean(saved());
    login.classList.toggle('hidden', !enabled || !hasSaved);
    setup.classList.toggle('hidden', !enabled || hasSaved);
    remove.classList.toggle('hidden', !enabled || !hasSaved);
    help.classList.toggle('hidden', !enabled);
  };
  async function wrappingKey(secret, salt) {
    const material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'HKDF', hash:'SHA-256', salt:encoder.encode(salt), info:aad(salt)}, material,
      {name:'AES-GCM',length:256}, false, ['wrapKey','unwrapKey']);
  }
  async function evaluate(id, input) {
    const credential = await navigator.credentials.get({publicKey:{
      challenge:random(32), rpId:location.hostname,
      allowCredentials:[{type:'public-key',id:bytes(id)}],
      userVerification:'required', timeout:60000,
      extensions:{prf:{eval:{first:bytes(input)}}}
    }});
    const secret = credential?.getClientExtensionResults()?.prf?.results?.first;
    if (!secret) throw new Error('Este dispositivo não suporta o desbloqueio seguro dos dados. Continue a usar o PIN da Folha Certa.');
    return secret;
  }
  async function run(action) {
    if (busy) return;
    busy = true;
    [login,setup,remove,document.getElementById('authSubmit')].forEach(button => button.disabled = true);
    try { await action(); }
    catch (error) {
      message(error.name === 'NotAllowedError' || error.name === 'AbortError'
        ? 'Pedido cancelado ou não autorizado. Pode entrar com o PIN.'
        : error.name === 'NotSupportedError' ? 'Este dispositivo não suporta esta opção. Use o PIN.'
        : error.message || 'Não foi possível desbloquear. Use o PIN.');
    } finally {
      busy = false;
      [login,setup,remove,document.getElementById('authSubmit')].forEach(button => button.disabled = false);
      window.refreshBiometricControls();
    }
  }
  setup.addEventListener('click', () => run(async () => {
    const pinInput = document.getElementById('authPin');
    let pin = pinInput.value;
    pinInput.value = '';
    if (!pin || pin.length < 4) throw new Error('Preencha o PIN da Folha Certa antes de ativar.');
    let exportableKey;
    const record = await getVaultRecord();
    if (!record) throw new Error('Entre primeiro com o PIN para configurar a aplicação.');
    try {
      exportableKey = await deriveEncryptionKey(pin, record.salt, true);
      await decryptState(record, exportableKey);
    } catch { throw new Error('Não foi possível confirmar o PIN. Verifique-o e tente novamente.'); }
    finally { pin = ''; }
    const input = b64(random(32));
    const credential = await navigator.credentials.create({publicKey:{
      challenge:random(32), rp:{name:'Folha Certa',id:location.hostname},
      user:{id:random(32),name:'Folha Certa',displayName:'Acesso à Folha Certa'},
      pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
      authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'required',userVerification:'required'},
      attestation:'none',timeout:60000,extensions:{prf:{}}
    }});
    if (!credential?.getClientExtensionResults()?.prf?.enabled)
      throw new Error('A chave criada não permite proteger o acesso aos dados neste dispositivo. Continue a entrar com o PIN.');
    const id = b64(credential.rawId);
    // Require a successful assertion before persisting any unlock record.
    const secret = await evaluate(id, input);
    const key = await wrappingKey(secret, record.salt);
    const iv = random(12);
    const wrapped = await crypto.subtle.wrapKey('raw', exportableKey, key, {name:'AES-GCM',iv,additionalData:aad(record.salt)});
    exportableKey = null;
    localStorage.setItem(storageKey, JSON.stringify({version:1,id,input,iv:b64(iv),wrapped:b64(wrapped),salt:record.salt}));
    message('Acesso rápido ativado. Toque em Entrar com impressão digital. O PIN continua disponível.');
  }));
  login.addEventListener('click', () => run(async () => {
    const stored = saved();
    if (!stored || stored.version !== 1) throw new Error('Ative novamente o acesso rápido com o PIN.');
    const secret = await evaluate(stored.id, stored.input);
    const key = await wrappingKey(secret, stored.salt);
    const candidate = await crypto.subtle.unwrapKey('raw', bytes(stored.wrapped), key,
      {name:'AES-GCM',iv:bytes(stored.iv),additionalData:aad(stored.salt)},
      {name:'AES-GCM',length:256},false,['encrypt','decrypt']);
    const record = await getVaultRecord();
    if (!record || record.salt !== stored.salt) throw new Error('O acesso mudou. Entre com o PIN e volte a ativar esta opção.');
    const state = await decryptState(record, candidate);
    encryptionKey = candidate;
    encryptionSalt = record.salt;
    await openApplication(state);
    document.getElementById('authForm').reset();
  }));
  remove.addEventListener('click', () => {
    if (!confirm('Desativar o acesso rápido neste dispositivo? O PIN e os dados da aplicação mantêm-se.')) return;
    localStorage.removeItem(storageKey);
    window.refreshBiometricControls();
    message('Acesso rápido desativado neste dispositivo. Pode continuar com o PIN.');
  });
  window.refreshBiometricControls();
})();
