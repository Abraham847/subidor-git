const express = require('express');
const session = require('express-session');
const { Octokit } = require('octokit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
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

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Escribe tu usuario y tu contraseña/token.');
  }

  const token = password.trim();
  const octokit = new Octokit({ auth: token });

  try {
    const { data: user } = await octokit.rest.users.getAuthenticated();
    const userExpected = username.trim().toLowerCase();
    const userReal = user.login.toLowerCase();
    if (userExpected && userExpected !== userReal) {
      return res.status(401).send(`El usuario "${username}" no coincide con el usuario del token (${user.login}).`);
    }

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
    res.status(401).send('No se pudo conectar. Revisa tu usuario y token. Error: ' + err.message);
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

app.post('/repo/create', requireAuth, async (req, res) => {
  const { name, description, visibility } = req.body;
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

    res.redirect(`/repo/${repo.owner.login}/${repo.name}/upload`);
  } catch (err) {
    console.error('Error creando repo:', err.message);
    res.status(500).send('Error creando repositorio: ' + err.message);
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
    res.status(404).send('No se pudo abrir el repositorio: ' + err.message);
  }
});

app.get('/repo/:owner/:repo/upload', requireAuth, (req, res) => {
  const { owner, repo } = req.params;
  res.render('upload', { user: req.session.user, repo: { owner, name: repo } });
});

app.post('/repo/:owner/:repo/upload', requireAuth, upload.array('files'), async (req, res) => {
  const { owner, repo } = req.params;
  const { commitMessage, targetPath } = req.body;
  const files = req.files;

  if (!files || files.length === 0) {
    return res.status(400).send('No se subieron archivos.');
  }

  const octokit = new Octokit({ auth: req.session.token });
  const cleanedFiles = [];

  try {
    const { data: repoData } = await octokit.rest.repos.get({ owner, repo });
    const defaultBranch = repoData.default_branch || 'main';

    const { data: refData } = await octokit.rest.git.getRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`
    });

    const latestCommitSha = refData.object.sha;
    const { data: commitData } = await octokit.rest.git.getCommit({
      owner,
      repo,
      commit_sha: latestCommitSha
    });
    const baseTreeSha = commitData.tree.sha;

    const treeItems = [];
    const maxFileSize = 95 * 1024 * 1024;
    for (const file of files) {
      cleanedFiles.push(file);
      if (file.size > maxFileSize) {
        for (const of of cleanedFiles) if (fs.existsSync(of.path)) fs.unlinkSync(of.path);
        return res.status(413).send(`El archivo ${file.originalname} supera el límite de 95MB.`);
      }
      const content = fs.readFileSync(file.path, 'base64');
      const filePath = safeJoin(targetPath, file.originalname);
      treeItems.push({
        path: filePath,
        mode: '100644',
        type: 'blob',
        content: content,
        encoding: 'base64'
      });
    }

    const { data: newTree } = await octokit.rest.git.createTree({
      owner,
      repo,
      base_tree: baseTreeSha,
      tree: treeItems
    });

    const { data: newCommit } = await octokit.rest.git.createCommit({
      owner,
      repo,
      message: commitMessage || `Subir ${files.length} archivo(s)`,
      tree: newTree.sha,
      parents: [latestCommitSha],
      author: {
        name: req.session.user.login,
        email: `${req.session.user.id}+${req.session.user.login}@users.noreply.github.com`
      }
    });

    await octokit.rest.git.updateRef({
      owner,
      repo,
      ref: `heads/${defaultBranch}`,
      sha: newCommit.sha
    });

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
        tree_sha: newCommit.sha,
        recursive: '1'
      });
      const actualPaths = new Set((treeData.tree || []).map(t => t.path));
      verified = checkRef.object.sha === newCommit.sha && expectedPaths.every(p => actualPaths.has(p));
    } catch (err) {
      console.error('Error verificando subida:', err.message);
      verified = false;
    }

    res.render('success', {
      user: req.session.user,
      repo: { owner, name: repo },
      files: files.map(f => f.originalname),
      commitSha: newCommit.sha.slice(0, 7),
      branch: defaultBranch,
      verified,
      githubUrl: `https://github.com/${owner}/${repo}`,
      githubTreeUrl: `https://github.com/${owner}/${repo}/tree/${defaultBranch}`
    });
  } catch (err) {
    console.error('Error subiendo:', err.message);
    for (const file of cleanedFiles) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
    }
    res.status(500).send('Error subiendo archivos: ' + err.message);
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log('   Abre esa dirección en tu navegador y escribe tu usuario de GitHub y tu token.');
});