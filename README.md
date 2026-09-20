# Subidor Git

Web sencilla para subir archivos y proyectos a GitHub escribiendo tu **usuario** y tu **token/contraseña**. Sin registrar apps OAuth, sin configuraciones complicadas.

## 🚀 Cómo usarla

```bash
npm install
node server.js
```

Abre `http://localhost:3000` y:

1. Escribe tu **usuario de GitHub**.
2. En el campo contraseña pega tu **token de acceso**:
   - Ves a https://github.com/settings/tokens/new?scopes=repo,user
   - Marca la casilla `repo`, pulsa "Generate token" y copia el código `ghp_...`
   - (Si no ves esa casilla, usa: Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token → marca `repo`)

3. Pulsa **Conectar** → se abren tus repositorios.
4. Elige un repositorio → **Subir archivos** (puedes arrastrar varios) y pulsa subir.

## ✨ Características

- Login simple: usuario + token (sin OAuth ni ngrok)
- Subida múltiple con arrastrar y soltar
- Carpeta de destino opcional y mensaje de commit
- Detecta la rama por defecto (main/master)
- Lista tus repositorios públicos y privados
- Tu token se guarda solo en la sesión de tu navegador (se borra al cerrarla)

## 📁 Estructura

```
├── server.js          # Backend Express (Express + Octokit)
├── views/             # Plantillas
│   ├── login.ejs      # Login con usuario + token
│   ├── index.ejs      # Lista de repositorios
│   ├── repo.ejs       # Ver archivos del repositorio
│   ├── upload.ejs     # Subir archivos (drag & drop)
│   └── success.ejs    # Confirmación
└── uploads/           # Temporal (se borra solo)
```

## ⚠️ Notas

- GitHub ya NO acepta la contraseña normal en conexiones de código; por eso se usa un token de acceso con permiso `repo`.
- Límite por archivo: 95MB (GitHub no permite más de 100MB por archivo vía API).