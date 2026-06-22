/* ============================================================
   CNK Central ERP — auth.js (v2 — Google Sign-In)
   Módulo centralizado de autenticación, sesión y roles.

   Cargar en TODAS las páginas, DESPUÉS del SDK de Google:
   <script src="https://accounts.google.com/gsi/client" async defer></script>
   <script src="https://cdn.jsdelivr.net/gh/CNKVIAL2026/CNK-VIAL@main/auth.js"></script>

   IMPORTANTE: jsDelivr cachea por ~12h. Para pruebas inmediatas
   durante desarrollo, usar la URL "raw":
   https://raw.githubusercontent.com/CNKVIAL2026/CNK-VIAL/main/auth.js

   ── ESTADO DEL PROYECTO OAuth (Google Cloud) ──
   Proyecto:      CNK-Central
   Client ID:     1059326059950-p9pb6pktta8hbdmjpe30en23pe3go5lk.apps.googleusercontent.com
   Origen autorizado: https://cnkvial2026.github.io
   Pantalla de consentimiento: Externo / modo Testing
   Usuarios de prueba autorizados: fernandosinaycnk@gmail.com (admin)
   → Mientras la app esté en modo Testing, SOLO los emails agregados
     como "test users" en Google Cloud Console pueden iniciar sesión,
     sin importar lo que diga la tabla de roles aquí abajo.

   ── PENDIENTE TÉCNICO CONOCIDO ──
   El ID token (JWT) de Google se decodifica aquí del lado del cliente
   SIN verificar su firma criptográfica. El SDK de Google garantiza en
   la práctica que el token viene de un login real, pero la verificación
   robusta (firma + claves públicas de Google) debe hacerse en un
   servidor. Cuando se construya el endpoint de Apps Script (roadmap),
   migrar la verificación de roles allá y validar la firma del JWT del
   lado del servidor. Por ahora esto es un nivel de seguridad superior
   a las contraseñas compartidas que reemplaza, pero no es robusto a
   nivel "producción con datos críticos".
   ============================================================ */

(function (global) {
  'use strict';

  // ── CONFIGURACIÓN GOOGLE OAUTH ──
  var GOOGLE_CLIENT_ID = '1059326059950-p9pb6kttta8hbdmjpe30en23pe3go5lk.apps.googleusercontent.com';

  // ── TABLA EMAIL → ROL ──
  // TEMPORAL: vive aquí mientras se construye el endpoint de Apps Script
  // que la leerá desde la hoja "Configuración". Ver roadmap del proyecto.
  // ⚠️ Estos emails quedan públicos al subir este archivo al repo de
  // GitHub (igual que ya ocurría con las contraseñas). Mantener la
  // lista solo con personal autorizado real.
  var CNK_USUARIOS = {
    'fernandosinaycnk@gmail.com': { rol: 'admin', label: 'Administrador', nivel: 4, nombre: 'Fernando Sinay' }
    // Agregar aquí más personas conforme se sumen como test users en
    // Google Cloud Console, ej:
    // 'tecnico.juan@gmail.com': { rol: 'tecnico', label: 'Técnico de campo', nivel: 1, nombre: 'Juan Pérez' },
  };

  // Contraseña única del candado "Administración" dentro de bitácoras
  // (independiente del login por Google — protege catálogo/personal)
  var ADMIN_PANEL_PW_DEFAULT = 'CNK2026';

  var SESSION_KEY   = 'cnk_session';
  var ADMIN_PW_KEY  = 'cnk_admin_panel_pw';
  var SESSION_HOURS = 12; // expira sesión tras 12h de inactividad

  // ── HELPERS INTERNOS ──
  function safeGet(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }
  function safeSet(key, val) {
    try { localStorage.setItem(key, val); return true; } catch (e) { return false; }
  }
  function safeRemove(key) {
    try { localStorage.removeItem(key); } catch (e) {}
  }
  function getAdminPanelPw() {
    return safeGet(ADMIN_PW_KEY) || ADMIN_PANEL_PW_DEFAULT;
  }

  /**
   * Decodifica un JWT sin verificar firma (ver nota de seguridad arriba).
   * @returns {object|null} payload decodificado o null si es inválido
   */
  function decodeJWT(token) {
    try {
      var base64Url = token.split('.')[1];
      var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      var jsonPayload = decodeURIComponent(
        atob(base64).split('').map(function (c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join('')
      );
      return JSON.parse(jsonPayload);
    } catch (e) {
      return null;
    }
  }

  /**
   * Busca el rol asignado a un email en la tabla local.
   * (Punto de extensión: reemplazar por fetch a Apps Script cuando
   * exista el endpoint de Sheets — la firma de la función no cambia.)
   */
  function resolverRol(email) {
    var def = CNK_USUARIOS[(email || '').toLowerCase()];
    return def || null;
  }

  // ── SESIÓN ──
  function cnkGetSession() {
    var raw = safeGet(SESSION_KEY);
    if (!raw) return null;
    var session;
    try { session = JSON.parse(raw); } catch (e) { return null; }
    if (!session || !session.ts) return null;

    var ageHours = (Date.now() - session.ts) / 36e5;
    if (ageHours > SESSION_HOURS) {
      safeRemove(SESSION_KEY);
      return null;
    }
    return session;
  }

  function cnkTouchSession() {
    var session = cnkGetSession();
    if (!session) return;
    session.ts = Date.now();
    safeSet(SESSION_KEY, JSON.stringify(session));
  }

  function cnkLogout() {
    safeRemove(SESSION_KEY);
    if (global.google && global.google.accounts && global.google.accounts.id) {
      global.google.accounts.id.disableAutoSelect();
    }
  }

  function cnkRequireAuth(rolesPermitidos) {
    var session = cnkGetSession();
    if (!session) {
      global.location.href = 'login.html';
      return null;
    }
    if (rolesPermitidos && rolesPermitidos.length &&
        rolesPermitidos.indexOf(session.rol) === -1) {
      global.location.href = 'index.html?error=acceso_denegado';
      return null;
    }
    cnkTouchSession();
    return session;
  }

  // ── GOOGLE SIGN-IN ──
  var _onLoginSuccess = null;
  var _onLoginError = null;

  /**
   * Callback invocado automáticamente por el SDK de Google tras el login.
   * Recibe { credential: <JWT> }.
   */
  function handleGoogleCredential(response) {
    var payload = decodeJWT(response.credential);
    if (!payload || !payload.email) {
      if (_onLoginError) _onLoginError('No se pudo leer la respuesta de Google.');
      return;
    }
    if (!payload.email_verified) {
      if (_onLoginError) _onLoginError('El correo de Google no está verificado.');
      return;
    }

    var def = resolverRol(payload.email);
    if (!def) {
      if (_onLoginError) _onLoginError(
        'Tu cuenta (' + payload.email + ') inició sesión con Google correctamente, ' +
        'pero no tiene un rol asignado en CNK Central ERP. Contacta al administrador.'
      );
      return;
    }

    var session = {
      email: payload.email,
      nombre: def.nombre || payload.name || payload.email,
      rol: def.rol,
      label: def.label,
      nivel: def.nivel,
      ts: Date.now()
    };
    safeSet(SESSION_KEY, JSON.stringify(session));
    if (_onLoginSuccess) _onLoginSuccess(session);
  }

  /**
   * Inicializa el SDK de Google Identity Services.
   * Llamar una vez que el script de Google (accounts.google.com/gsi/client)
   * ya esté cargado en la página (usar window.onload o defer).
   * @param {function} onSuccess - recibe la sesión creada
   * @param {function} onError - recibe un mensaje de error legible
   */
  function cnkInitGoogleSignIn(onSuccess, onError) {
    _onLoginSuccess = onSuccess || null;
    _onLoginError = onError || null;

    if (!global.google || !global.google.accounts || !global.google.accounts.id) {
      if (_onLoginError) _onLoginError('El SDK de Google no cargó. Verifica tu conexión a internet.');
      return false;
    }

    global.google.accounts.id.initialize({
      client_id: GOOGLE_CLIENT_ID,
      callback: handleGoogleCredential,
      auto_select: false
    });
    return true;
  }

  /**
   * Dibuja el botón oficial "Sign in with Google" dentro del elemento dado.
   * @param {string|HTMLElement} container - id del elemento o el elemento mismo
   * @param {object} [options] - opciones de estilo del botón de Google
   */
  function cnkRenderGoogleButton(container, options) {
    var el = typeof container === 'string' ? document.getElementById(container) : container;
    if (!el || !global.google || !global.google.accounts || !global.google.accounts.id) return false;

    global.google.accounts.id.renderButton(el, Object.assign({
      type: 'standard',
      theme: 'outline',
      size: 'large',
      text: 'signin_with',
      shape: 'rectangular',
      locale: 'es'
    }, options || {}));
    return true;
  }

  // ── CANDADO ADMIN DE PANEL (dentro de bitácoras) ──
  function cnkCheckAdminPw(password) {
    return password === getAdminPanelPw();
  }
  function cnkChangeAdminPw(nueva) {
    if (!nueva || nueva.length < 4) return false;
    return safeSet(ADMIN_PW_KEY, nueva);
  }

  // ── EXPORTAR API PÚBLICA ──
  global.CNKAuth = {
    initGoogleSignIn: cnkInitGoogleSignIn,
    renderGoogleButton: cnkRenderGoogleButton,
    logout: cnkLogout,
    getSession: cnkGetSession,
    touchSession: cnkTouchSession,
    requireAuth: cnkRequireAuth,
    checkAdminPw: cnkCheckAdminPw,
    changeAdminPw: cnkChangeAdminPw,
    _resolverRol: resolverRol // expuesto solo para pruebas/debug
  };

})(window);
