const path = require('path');

const MAX_SCAN_SIZE = 1024 * 1024;

const EXTENSION_PELIGROSA = /\.(exe|dll|scr|com|bat|cmd|ps1|jar|app|msi|vbs|jsx\.map)$/i;

const PATTERNS_SECRETOS = [
  { name: 'Token de GitHub clásico', re: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/i },
  { name: 'Token de GitHub fina (granulado)', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/i },
  { name: 'Clave AWS', re: /\b(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b/ },
  { name: 'Clave privada OpenSSH/RSA/PGP', re: /-----BEGIN (RSA |OPENSSH |PGP |EC )*PRIVATE KEY-----/i },
  { name: 'Clave privada DSA', re: /-----BEGIN DSA PRIVATE KEY-----/i },
  { name: 'Clave de Google API', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Token de Stripe', re: /\b[rs]k_live_[0-9A-Za-z]{16,}\b/ },
  { name: 'JWT (posible)', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: 'Cadena de conexión a BD', re: /\b(mongodb|postgres(ql)?|mysql|redis):\/\/[^\s'"]*(:\S+)?@/i },
  { name: 'Contraseña o clave en variable', re: /(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|token)\s*[:=]\s*['"][^'"]{8,}['"]/i }
];

const NOMBRES_NO_SEGUROS = /\.env$|\.env\b|secrets?\b|credentials?\b|\.pem$|\.p12$|\.pfx$|\.key$/i;

function esBinario(buf) {
  if (!buf || buf.length === 0) return false;
  const sample = buf.subarray(0, Math.min(buf.length, 8000));
  for (let i = 0; i < sample.length; i++) {
    const b = sample[i];
    if (b === 0) return true;
  }
  return false;
}

function decodificarTexto(buf) {
  return buf.toString('utf8').replace(/^\uFEFF/, '');
}

function scanFile(nombreArchivo, buffer) {
  const problemas = [];
  const lower = nombreArchivo.toLowerCase().split('/').pop();

  if (EXTENSION_PELIGROSA.test(lower)) {
    problemas.push({
      tipo: 'extension',
      severidad: 'aviso',
      mensaje: `Extensión potencialmente peligrosa: ${path.extname(lower)}`
    });
  }

  if (NOMBRES_NO_SEGUROS.test(lower) && !lower.includes('.example') && !lower.includes('.sample')) {
    problemas.push({
      tipo: 'nombre',
      severidad: 'aviso',
      mensaje: 'Nombre de archivo relacionado con secretos o credenciales'
    });
  }

  if (!buffer || buffer.length === 0 || buffer.length > MAX_SCAN_SIZE || esBinario(buffer)) {
    return problemas;
  }

  const text = decodificarTexto(buffer);
  for (const pat of PATTERNS_SECRETOS) {
    const m = text.match(pat.re);
    if (m) {
      const secreto = m[0].length > 14 ? m[0].slice(0, 6) + '…' + m[0].slice(-6) : '[valor corto]';
      problemas.push({
        tipo: 'secreto',
        severidad: 'bloqueo',
        mensaje: `Posible ${pat.name} encontrado (${secreto})`
      });
    }
  }

  const ofuscacion = (text.match(/eval\(\s*(function\(|atob\(|JSON\.parse\()/gi) || []).length;
  const base64Largo = (text.match(/[A-Za-z0-9+/]{200,}={0,2}/g) || []).filter(s => !s.includes('\n')).length;
  if (ofuscacion > 0 || base64Largo > 2) {
    problemas.push({
      tipo: 'ofuscacion',
      severidad: 'aviso',
      mensaje: 'Código posiblemente ofuscado o sospechoso (eval/base64)'
    });
  }

  return problemas;
}

function scanAll(items) {
  const resultados = [];
  const bloqueos = [];
  const avisos = [];
  for (const it of items) {
    const archivo = typeof it.path === 'string' ? it.path : it.name;
    if (!it.buffer) continue;
    const issues = scanFile(archivo, it.buffer);
    for (const issue of issues) {
      if (issue.severidad === 'bloqueo') {
        bloqueos.push({ archivo, ...issue });
      } else {
        avisos.push({ archivo, ...issue });
      }
    }
    if (issues.length) resultados.push({ archivo, issues });
  }
  return { resultados, bloqueos, avisos };
}

module.exports = { scanFile, scanAll, esBinario };