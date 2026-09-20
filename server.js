const express = require('express');
const session = require('express-session');
const { Octokit } = require('octokit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const scanner = require('./scanner');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false
}));

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Demasiados intentos de inicio de sesión. Espera 10 minutos.'
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Has alcanzado el límite de subidas por hora. Vuelve más tarde.'
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Demasiadas peticiones. Un momento.'
});
app.use(globalLimiter);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));

const upload = multer({ dest: 'uploads/' });

function requireAuth(req, res, next) {
  if (!req.session.token) {
    return res.redirect('/login');
  }
  next();
}

app.get('/', (req, res) => {
  if (!req.session.token) return res.redirect('/login');
  res.render('index', { user: req.session.user, repos: req.session.repos || [], error: null });
});

app.get('/login', (req, res) => {
  if (req.session.token) return res.redirect('/');
  res.render('login', { error: null });
});

app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).render('login', { error: 'Escribe tu usuario y tu contraseña/token.' });
  }

  const blocked = db.isBlocked(username.trim());
  if (blocked) {
    console.warn(`Intento de acceso de usuario bloqueado: ${username}`);
    return res.status(403).render('login', { error: `Cuenta suspendida${blocked.block_reason ? ': ' + blocked.block_reason : '.'}` });
  }

  const token = password.trim();
  const octokit = new Octokit({ auth: token });

  try {
    const { data: user } = await octokit.rest.users.getAuthenticated();
    const userExpected = username.trim().toLowerCase();
    const userReal = user.login.toLowerCase();
    if (userExpected && userExpected !== userReal) {
      return res.status(401).render('login', { error: `El usuario "${username}" no coincide con el usuario del token (${user.login}).` });
    }

    db.upsertUser(user.login);

    const { data: repos } = await octokit.rest.repos.listForAuthenticatedUser({
      sort: 'updated',
      per_page: 100,
      affiliation: 'owner,collaborator'
    });

    req.session.token = token;
    req.session.user = user;
    req.session.repos = repos.map(r => ({
      full_name: r.full_name,
      name: r.name,
      private: r.private,
      default_branch: r.default_branch
    }));

    res.redirect('/');
  } catch (err) {
    console.error('Error login:', err.message);
    const m = (err && err.status === 401)
      ? 'Credenciales inválidas: el token no existe, expiró o no tiene permiso. Crea un token clásico marcando la casilla "repo".'
      : 'No se pudo conectar con GitHub. Revisa tu conexión y vuelve a intentar.';
    res.status(401).render('login', { error: m });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

function cleanRepoName(name) {
  return String(name || '').trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9._-]/g, '');
}

function safeJoin(base, name) {
  const segments = String(name || '').split(/[\\/]+/).filter(Boolean);
  const safe = segments.map(seg => seg.replace(/\.\.+/g, '_')).join('/');
  const baseClean = String(base || '').replace(/^\/+|\/+$/g, '').split(/[\\/]+/).filter(Boolean).map(seg => seg.replace(/\.\.+/g, '_')).join('/');
  return baseClean ? `${baseClean}/${safe}` : safe;
}

function friendlyError(err, action) {
  const m = String(err && err.message || '');
  if (err && err.status === 403) return `Tu token no tiene permiso para ${action}. Usa un token clásico con el permiso "repo", o permítele "Contents: Read and write".`;
  if (err && err.status === 404) return `No se encontró el recurso al ${action}. Revisa que el repositorio exista o que tu token tenga acceso a él.`;
  if (err && err.status === 409) return `Conflicto al ${action}: el repositorio ya existe o la referencia está bloqueada.`;
  return `Error al ${action}: ${m}`;
}

function parseIgnore(raw) {
  return String(raw || '')
    .split(/[\s,;]+/)
    .map(s => s.trim().toLowerCase().replace(/^\/+|\/+$/g, ''))
    .filter(Boolean);
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function makeIsIgnored(ignoreList) {
  return (filePath) => {
    if (!ignoreList.length) return false;
    const segs = filePath.toLowerCase().split('/');
    return ignoreList.some(k => {
      if (!k) return false;
      if (k.startsWith('*.')) return segs.some(s => s.endsWith(k.slice(1)));
      if (k.includes('*')) {
        const re = new RegExp('^' + k.split('*').map(escapeRe).join('.*') + '$');
        return segs.some(s => re.test(s));
      }
      return segs.some(s => s === k);
    });
  };
}

const HOME = os.homedir();

function rutaDentroDe(raiz, p) {
  const rel = path.relative(raiz, p);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function rutaSegura(pIn) {
  if (!pIn) return null;
  const abs = path.resolve(String(pIn));
  if (!fs.existsSync(abs)) return null;
  const real = fs.realpathSync(abs);
  if (real !== HOME && !rutaDentroDe(HOME, real)) return null;
  return real;
}

function esDirectorio(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}

async function pushArbol({ octokit, owner, repo, user, treeItems, skipped, commitMessage, totalCount }) {
  const { data: repoData } = await octokit.rest.repos.get({ owner, repo });
  const defaultBranch = repoData.default_branch || 'main';

  let latestCommitSha = null;
  let baseTreeSha = null;
  let repoHasCommits = true;
  try {
    const { data: refData } = await octokit.rest.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`
    });
    latestCommitSha = refData.object.sha;
    const { data: commitData } = await octokit.rest.git.getCommit({
      owner,
      repo,
      commit_sha: latestCommitSha
    });
    baseTreeSha = commitData.tree.sha;
  } catch (err) {
    if (err.status === 404 || err.status === 409) {
      repoHasCommits = false;
    } else {
      throw err;
    }
  }

  const commitMessageFull = commitMessage || `Subir ${totalCount} archivo(s)`;
  let headSha;

  if (!repoHasCommits) {
    for (const item of treeItems) {
      await octokit.rest.repos.createOrUpdateFileContents({
        owner,
        repo,
        path: item.path,
        message: `${commitMessageFull} — ${item.path}`,
        content: item.content,
        committer: {
          name: user.login,
          email: `${user.id}+${user.login}@users.noreply.github.com`
        }
      });
    }
    const { data: refData } = await octokit.rest.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`
    });
    headSha = refData.object.sha;
  } else {
    const { data: newTree } = await octokit.rest.git.createTree({
      owner,
      repo,
      base_tree: baseTreeSha,
      tree: treeItems.map(t => ({ ...t, mode: '100644', type: 'blob' }))
    });
    const { data: newCommit } = await octokit.rest.git.createCommit({
      owner,
      repo,
      message: commitMessageFull,
      tree: newTree.sha,
      parents: [latestCommitSha],
      author: {
        name: user.login,
        email: `${user.id}+${user.login}@users.noreply.github.com`
      }
    });
    await octokit.rest.git.updateRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`,
      sha: newCommit.sha
    });
    headSha = newCommit.sha;
  }

  const expectedPaths = treeItems.map(t => t.path);

  let verified = false;
  try {
    const { data: checkRef } = await octokit.rest.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`
    });
    const { data: treeData } = await octokit.rest.git.getTree({
      owner,
      repo,
      tree_sha: checkRef.object.sha,
      recursive: '1'
    });
    const actualPaths = new Set((treeData.tree || []).map(t => t.path));
    verified = checkRef.object.sha === headSha && expectedPaths.every(p => actualPaths.has(p));
  } catch (err) {
    console.error('Error verificando subida:', err.message);
    verified = false;
  }

  try {
    db.logUpload(user.login, owner, repo, treeItems.length, skipped.length, headSha || null, !repoData.private);
  } catch (dbErr) {
    console.error('Error guardando en BD:', dbErr.message);
  }

  return {
    files: treeItems.map(t => t.name),
    skippedCount: skipped.length,
    commitSha: (headSha || '').slice(0, 7),
    branch: defaultBranch,
    verified,
    githubUrl: `https://github.com/${owner}/${repo}`,
    githubTreeUrl: `https://github.com/${owner}/${repo}/tree/${defaultBranch}`
  };
}

app.post('/api/scan', requireAuth, (req, res) => {
  const items = Array.isArray(req.body.files) ? req.body.files : [];
  const resultados = [];
  for (const f of items) {
    if (!f || !f.content) continue;
    const buf = Buffer.from(String(f.content), 'base64');
    if (buf.length > 1.5 * 1024 * 1024) {
      resultados.push({ archivo: f.name || '?', issues: [{ severidad: 'aviso', mensaje: 'Archivo demasiado grande para revisar (límite 1.5MB)' }] });
      continue;
    }
    const issues = scanner.scanFile(f.name || '?', buf);
    if (issues.length) resultados.push({ archivo: f.name, issues });
  }
  res.json({ resultados });
});

app.use((req, res, next) => {
  if (req.session.user && db.isBlocked(req.session.user.login)) {
    return req.session.destroy(() => res.redirect('/login'));
  }
  next();
});

app.get('/historial', requireAuth, (req, res) => {
  const username = req.session.user.login;
  const stats = db.userStats(username) || { upload_count: 0 };
  const uploads = db.recentUploads(username);
  res.render('historial', {
    user: req.session.user,
    stats,
    uploads,
    totalUploads: db.totalUploads(),
    totalUsers: db.totalUsers()
  });
});

app.post('/repo/create', requireAuth, async (req, res) => {
  const { name, description, visibility, big } = req.body;
  const repoName = cleanRepoName(name);

  if (!repoName) {
    return res.status(400).send('Escribe un nombre para el repositorio. Solo letras, números, guiones y puntos (sin espacios).');
  }

  const octokit = new Octokit({ auth: req.session.token });
  try {
    const { data: repo } = await octokit.rest.repos.createForAuthenticatedUser({
      name: repoName,
      description: (description || '').trim(),
      private: visibility !== 'public',
      auto_init: true
    });

    const repoShort = {
      full_name: repo.full_name,
      name: repo.name,
      private: repo.private,
      default_branch: repo.default_branch || 'main'
    };
    req.session.repos = [repoShort, ...(req.session.repos || []).filter(r => r.full_name !== repo.full_name)];

    res.redirect(`/repo/${repo.owner.login}/${repo.name}/upload?${big ? 'big=1&' : ''}pc=1`);
  } catch (err) {
    console.error('Error creando repo:', err.message);
    res.status(500).render('error', { message: friendlyError(err, 'creando el repositorio') });
  }
});

app.get('/repo/:owner/:repo', requireAuth, async (req, res) => {
  const { owner, repo } = req.params;
  const octokit = new Octokit({ auth: req.session.token });

  try {
    const { data: repoData } = await octokit.rest.repos.get({ owner, repo });
    const { data: contents } = await octokit.rest.repos.getContent({ owner, repo, path: '' });
    res.render('repo', {
      user: req.session.user,
      repo: { owner, name: repo, default_branch: repoData.default_branch },
      files: Array.isArray(contents) ? contents : [contents],
      success: req.query.uploaded === '1'
    });
  } catch (err) {
    res.status(404).render('error', { message: friendlyError(err, 'abrir el repositorio') });
  }
});

app.get('/repo/:owner/:repo/upload', requireAuth, (req, res) => {
  const { owner, repo } = req.params;
  res.render('upload', { user: req.session.user, repo: { owner, name: repo }, big: req.query.big === '1' });
});

app.get('/api/folders', requireAuth, (req, res) => {
  try {
    const pIn = req.query.path || HOME;
    const dir = rutaSegura(pIn);
    if (!dir) {
      return res.status(404).json({ error: 'Carpeta no accesible. Elige dentro de tu usuario de Windows.' });
    }
    if (!esDirectorio(dir)) {
      return res.status(400).json({ error: 'No es una carpeta.' });
    }
    const entries = fs.readdirSync(dir, { withFileTypes: true })
      .map(d => {
        const abs = path.join(dir, d.name);
        let isDir;
        let size = null;
        try {
          isDir = d.isDirectory();
          if (!isDir) size = fs.statSync(abs).size;
        } catch { return null; }
        return { name: d.name, path: abs, isDir, size };
      })
      .filter(Boolean)
      .sort((a, b) => (a.isDir === b.isDir) ? a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }) : (a.isDir ? -1 : 1));

    const esHome = dir === HOME;
    const parent = esHome || !rutaDentroDe(HOME, path.dirname(dir)) ? null : path.dirname(dir);

    const desktop = path.join(HOME, 'Desktop');
    const documentos = path.join(HOME, 'Documents');
    const descargas = path.join(HOME, 'Downloads');
    res.json({
      path: dir,
      name: path.basename(dir) || dir,
      parent,
      quick: [
        { label: 'Escritorio', path: desktop },
        { label: 'Documentos', path: documentos },
        { label: 'Descargas', path: descargas },
        { label: 'Inicio', path: HOME }
      ].filter(q => esDirectorio(q.path)),
      entries
    });
  } catch (err) {
    console.error('Error listando carpeta:', err.message);
    res.status(500).json({ error: 'No se pudo leer la carpeta: ' + err.message });
  }
});

app.post('/repo/:owner/:repo/upload/folder', requireAuth, uploadLimiter, async (req, res) => {
  const { owner, repo } = req.params;
  const { folderPath, ignore, targetPath, commitMessage } = req.body || {};

  try {
    const dir = rutaSegura(folderPath);
    if (!dir) {
      return res.status(400).send('Carpeta no accesible. Elige dentro de tu usuario de Windows.');
    }
    if (!esDirectorio(dir)) {
      return res.status(400).send('La ruta elegida no es una carpeta.');
    }

    const ignoreList = parseIgnore(ignore);
    const isIgnored = makeIsIgnored(ignoreList);
    const maxFileSize = 95 * 1024 * 1024;

    const treeItems = [];
    const skipped = [];

    function walk(subdir) {
      let entries;
      try {
        entries = fs.readdirSync(subdir, { withFileTypes: true });
      } catch { return; }
      for (const ent of entries) {
        if (ent.name === '.git') continue;
        const abs = path.join(subdir, ent.name);
        let st;
        try { st = fs.lstatSync(abs); } catch { continue; }
        if (st.isSymbolicLink()) continue;

        const rel = path.relative(dir, abs).split(path.sep).join('/');

        if (ent.isDirectory()) {
          if (isIgnored(rel)) { skipped.push(rel + '/'); continue; }
          walk(abs);
          continue;
        }
        if (!st.isFile()) continue;
        if (st.size > maxFileSize) { skipped.push(rel); continue; }

        let content;
        try { content = fs.readFileSync(abs, 'base64'); } catch { skipped.push(rel); continue; }
        const buffer = Buffer.from(content, 'base64');

        if (isIgnored(rel)) { skipped.push(rel); continue; }

        const scan = scanner.scanFile(ent.name, buffer);
        const bloqueo = scan.find(s => s.severidad === 'bloqueo');
        if (bloqueo) {
          console.warn(`🛡️ Descartado por el guardia de seguridad: ${abs} — ${bloqueo.mensaje}`);
          skipped.push(rel);
          continue;
        }

        treeItems.push({
          path: safeJoin(targetPath, rel),
          name: ent.name,
          content
        });
      }
    }

    walk(dir);

    if (treeItems.length === 0) {
      const causa = skipped.length
        ? 'Todos los archivos quedaron descartados (carpetas excluidas, demasiado grandes o bloqueados por el guardia de seguridad).'
        : 'No se encontraron archivos en la carpeta.';
      return res.status(400).send(causa);
    }

    const data = await pushArbol({
      octokit: new Octokit({ auth: req.session.token }),
      owner,
      repo,
      user: req.session.user,
      treeItems,
      skipped,
      commitMessage,
      totalCount: treeItems.length + skipped.length
    });

    res.render('success', {
      user: req.session.user,
      repo: { owner, name: repo },
      ...data
    });
  } catch (err) {
    console.error('Error subiendo carpeta:', err.message);
    if (!res.headersSent) res.status(500).render('error', { message: friendlyError(err, 'subir la carpeta') });
  }
});

app.post('/repo/:owner/:repo/upload', requireAuth, uploadLimiter, upload.array('files'), async (req, res) => {
  const { owner, repo } = req.params;
  const { commitMessage, targetPath } = req.body;
  const files = req.files;

  if (!files || files.length === 0) {
    return res.status(400).send('No se subieron archivos.');
  }

  const ignoreList = parseIgnore(req.body.ignore);
  const isIgnored = makeIsIgnored(ignoreList);

  const octokit = new Octokit({ auth: req.session.token });
  const cleanedFiles = [];

  const treeItems = [];
  const skipped = [];
  const maxFileSize = 95 * 1024 * 1024;
  try {
    for (const file of files) {
      cleanedFiles.push(file);
      if (file.size > maxFileSize) {
        for (const of of cleanedFiles) if (fs.existsSync(of.path)) fs.unlinkSync(of.path);
        return res.status(413).send(`El archivo ${file.originalname} supera el límite de 95MB.`);
      }
      const content = fs.readFileSync(file.path, 'base64');
      const filePath = safeJoin(targetPath, file.originalname);
      if (isIgnored(filePath)) {
        skipped.push(filePath);
        fs.unlinkSync(file.path);
        continue;
      }
      const buffer = Buffer.from(content, 'base64');
      const scan = scanner.scanFile(file.originalname, buffer);
      const bloqueos = scan.filter(s => s.severidad === 'bloqueo');
      if (bloqueos.length) {
        for (const of of cleanedFiles) if (fs.existsSync(of.path)) fs.unlinkSync(of.path);
        return res.status(400).send(
          `🛡️ Subida bloqueada por el guardia de seguridad.\n\n` +
          bloqueos.map(b => `- ${file.originalname}: ${b.mensaje}`).join('\n')
        );
      }
      treeItems.push({
        path: filePath,
        name: file.originalname,
        content: content
      });
    }

    if (treeItems.length === 0 && skipped.length > 0) {
      res.status(400).send('Todos los archivos seleccionados fueron ignorados (carpetas excluidas). Ajusta la lista de carpetas a ignorar.');
      return;
    }
    if (treeItems.length === 0) {
      return res.status(400).send('No se subieron archivos.');
    }

    const data = await pushArbol({
      octokit,
      owner,
      repo,
      user: req.session.user,
      treeItems,
      skipped,
      commitMessage,
      totalCount: files.length
    });

    res.render('success', {
      user: req.session.user,
      repo: { owner, name: repo },
      ...data
    });
  } catch (err) {
    console.error('Error subiendo:', err.message);
    for (const file of cleanedFiles) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
    }
    res.status(500).render('error', { message: friendlyError(err, 'subir los archivos') });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log('   Abre esa dirección en tu navegador y escribe tu usuario de GitHub y tu token.');
});