require('dotenv').config();

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const DATA_DIR = path.join(ROOT, 'data');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, 'groupdrive.db'));

const run = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    })
  );

const get = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.get(sql, params, (err, row) =>
      err ? reject(err) : resolve(row)
    )
  );

const all = (sql, params = []) =>
  new Promise((resolve, reject) =>
    db.all(sql, params, (err, rows) =>
      err ? reject(err) : resolve(rows)
    )
  );

const makeToken = () => crypto.randomBytes(32).toString('hex');

const baseUrl = () =>
  (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'groupdrive.sid',
  secret: process.env.SESSION_SECRET || 'CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT',
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: DATA_DIR
  }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 12 * 60 * 60 * 1000
  }
}));

// ===================== EMAIL: UNISENDER GO =====================

async function sendMail(to, subject, text, html) {
  const apiKey = process.env.UNISENDER_GO_API_KEY;
  const from = process.env.MAIL_FROM;

  if (!apiKey || !from) {
    console.error(
      'Почта не настроена. Проверь UNISENDER_GO_API_KEY и MAIL_FROM.'
    );
    throw new Error('Не настроена отправка писем через Unisender Go.');
  }

  const endpoint =
    process.env.UNISENDER_GO_API_URL ||
    'https://goapi.unisender.ru/ru/transactional/api/v1/email/send.json';

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'X-API-KEY': apiKey.trim(),
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      message: {
        recipients: [{ email: to }],
        subject,
        from_email: from.trim(),
        from_name: process.env.MAIL_FROM_NAME || 'GroupDrive',
        body: {
          html,
          plaintext: text
        },
        skip_unsubscribe: 1
      }
    })
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok || result.status === 'error') {
    console.error('Ошибка Unisender Go:', response.status, result);
    throw new Error(
      'Unisender Go не отправил письмо. Проверь API-ключ и отправителя.'
    );
  }
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Необходимо войти в аккаунт' });
  }
  next();
}

async function currentUser(req) {
  if (!req.session.userId) return null;

  return get(
    `SELECT id,name,email,role,confirmed,created_at
     FROM users WHERE id=?`,
    [req.session.userId]
  );
}

function requireTeacher(req, res, next) {
  currentUser(req)
    .then(user => {
      if (!user || !['teacher', 'admin'].includes(user.role)) {
        return res.status(403).json({
          error: 'Доступ разрешён только преподавателям'
        });
      }

      req.user = user;
      next();
    })
    .catch(next);
}

function requireAdmin(req, res, next) {
  currentUser(req)
    .then(user => {
      if (!user || user.role !== 'admin') {
        return res.status(403).json({
          error: 'Это действие доступно только администратору'
        });
      }

      req.user = user;
      next();
    })
    .catch(next);
}

function asyncRoute(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

// ===================== FILE UPLOADS =====================

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).slice(0, 15);
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: Number(process.env.MAX_FILE_MB || 500) * 1024 * 1024,
    files: 1
  },
  fileFilter: (_req, file, cb) => {
    const blocked = /\.(exe|bat|cmd|com|msi|ps1|sh|php|js|html?)$/i
      .test(file.originalname);

    if (blocked) {
      return cb(new Error('Этот тип файла запрещён'));
    }

    cb(null, true);
  }
});

// ===================== DATABASE =====================

async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      confirmed INTEGER NOT NULL DEFAULT 0,
      confirm_token TEXT,
      confirm_expires INTEGER,
      reset_token TEXT,
      reset_expires INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      owner_id INTEGER NOT NULL,
      parent_id INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      folder_id INTEGER,
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT,
      size INTEGER NOT NULL DEFAULT 0,
      can_download INTEGER NOT NULL DEFAULT 1,
      is_public INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_by INTEGER NOT NULL,
      allow_download INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS assignments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      due_at TEXT,
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS file_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL UNIQUE,
      teacher_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      comment TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const columns = await all('PRAGMA table_info(files)');

  if (!columns.some(c => c.name === 'can_download')) {
    await run(
      'ALTER TABLE files ADD COLUMN can_download INTEGER NOT NULL DEFAULT 1'
    );
  }

  if (!columns.some(c => c.name === 'is_public')) {
    await run(
      'ALTER TABLE files ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0'
    );
  }

  // Создаём администратора при первом запуске.
  if (process.env.SEED_ADMIN_EMAIL && process.env.SEED_ADMIN_PASSWORD) {
    const email = process.env.SEED_ADMIN_EMAIL.trim().toLowerCase();
    const existing = await get(
      'SELECT id FROM users WHERE email=?',
      [email]
    );

    if (existing) {
      await run(
        "UPDATE users SET role='admin', confirmed=1 WHERE id=?",
        [existing.id]
      );
    } else {
      const hash = await bcrypt.hash(
        process.env.SEED_ADMIN_PASSWORD,
        12
      );

      await run(
        `INSERT INTO users
         (name,email,password_hash,role,confirmed)
         VALUES(?,?,?,'admin',1)`,
        [
          process.env.SEED_ADMIN_NAME || 'Администратор',
          email,
          hash
        ]
      );
    }
  }
}

// ===================== HEALTH CHECK =====================

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, app: 'GroupDrive' });
});

// ===================== REGISTRATION =====================

app.post('/api/register', asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2 || name.length > 100) {
    return res.status(400).json({
      error: 'Укажи имя и фамилию'
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      error: 'Проверь адрес электронной почты'
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: 'Пароль должен содержать не менее 8 символов'
    });
  }

  const existing = await get(
    'SELECT id FROM users WHERE email=?',
    [email]
  );

  if (existing) {
    return res.status(409).json({
      error: 'Аккаунт с такой почтой уже существует'
    });
  }

  const confirmToken = makeToken();
  const expires = Date.now() + 24 * 60 * 60 * 1000;
  const hash = await bcrypt.hash(password, 12);

  await run(
    `INSERT INTO users
     (name,email,password_hash,role,confirmed,confirm_token,confirm_expires)
     VALUES(?,?,?,'student',0,?,?)`,
    [name, email, hash, confirmToken, expires]
  );

  const link =
    `${baseUrl()}/api/confirm?token=${encodeURIComponent(confirmToken)}`;

  try {
    await sendMail(
      email,
      'Подтверждение почты GroupDrive',
      `Чтобы подтвердить почту, открой ссылку: ${link}`,
      `<h2>Добро пожаловать в GroupDrive!</h2>
       <p>Подтверди свой адрес электронной почты:</p>
       <p><a href="${link}">Подтвердить почту</a></p>
       <p>Ссылка действует 24 часа.</p>`
    );
  } catch (error) {
    await run(
      'DELETE FROM users WHERE email=? AND confirm_token=?',
      [email, confirmToken]
    );
    throw error;
  }

  res.status(201).json({
    message: 'Письмо отправлено. Проверь почту и папку «Спам».'
  });
}));

app.get('/api/confirm', asyncRoute(async (req, res) => {
  const token = String(req.query.token || '');

  const user = await get(
    'SELECT id,confirm_expires FROM users WHERE confirm_token=?',
    [token]
  );

  if (!user || !user.confirm_expires || user.confirm_expires < Date.now()) {
    return res.status(400).send(
      'Ссылка подтверждения недействительна или истекла.'
    );
  }

  await run(
    `UPDATE users
     SET confirmed=1,confirm_token=NULL,confirm_expires=NULL
     WHERE id=?`,
    [user.id]
  );

  res.redirect('/login.html?confirmed=1');
}));

// ===================== LOGIN / LOGOUT =====================

app.post('/api/login', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const requestedRole = String(req.body.role || 'student');

  const user = await get(
    'SELECT * FROM users WHERE email=?',
    [email]
  );

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'еверная почта или пароль' });
  }

  if (!user.confirmed) {
    return res.status(403).json({ error: 'Сначала подтверди электронную почту' });
  }

  if (requestedRole !== user.role) {
    return res.status(403).json({ error: 'ыбери правильную роль для входа' });
  }

  req.session.regenerate((err) => {
    if (err) {
      console.error('шибка создания сессии:', err);
      return res.status(500).json({ error: 'е удалось создать сессию' });
    }

    req.session.userId = user.id;

    req.session.save((saveErr) => {
      if (saveErr) {
        console.error('шибка сохранения сессии:', saveErr);
        return res.status(500).json({ error: 'е удалось сохранить сессию' });
      }

      res.json({
        ok: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      });
    });
  });
}));

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('groupdrive.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });
  res.json(user);
}));

// ===================== PASSWORD RECOVERY =====================

app.post('/api/forgot', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();

  const user = await get(
    'SELECT id,email FROM users WHERE email=?',
    [email]
  );

  if (user) {
    const resetToken = makeToken();
    const expires = Date.now() + 60 * 60 * 1000;

    await run(
      'UPDATE users SET reset_token=?,reset_expires=? WHERE id=?',
      [resetToken, expires, user.id]
    );

    const link =
      `${baseUrl()}/reset.html?token=${encodeURIComponent(resetToken)}`;

    await sendMail(
      email,
      'Восстановление пароля GroupDrive',
      `Ссылка для смены пароля: ${link}`,
      `<h2>Восстановление пароля</h2>
       <p>Чтобы создать новый пароль, перейди по ссылке:</p>
       <p><a href="${link}">Изменить пароль</a></p>
       <p>Ссылка действует 1 час.</p>`
    );
  }

  res.json({
    message: 'Если аккаунт существует, письмо отправлено.'
  });
}));

app.post('/api/reset', asyncRoute(async (req, res) => {
  const token = String(req.body.token || '');
  const password = String(req.body.password || '');

  if (password.length < 8) {
    return res.status(400).json({
      error: 'Пароль должен содержать не менее 8 символов'
    });
  }

  const user = await get(
    'SELECT id,reset_expires FROM users WHERE reset_token=?',
    [token]
  );

  if (!user || !user.reset_expires || user.reset_expires < Date.now()) {
    return res.status(400).json({
      error: 'Ссылка недействительна или истекла'
    });
  }

  const hash = await bcrypt.hash(password, 12);

  await run(
    `UPDATE users
     SET password_hash=?,reset_token=NULL,reset_expires=NULL
     WHERE id=?`,
    [hash, user.id]
  );

  res.json({ message: 'Пароль изменён. Теперь можно войти.' });
}));

// ===================== FOLDERS =====================

app.get('/api/folders', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const parent = req.query.parent ? Number(req.query.parent) : null;

  const rows = parent
    ? await all(
        'SELECT * FROM folders WHERE owner_id=? AND parent_id=? ORDER BY name',
        [me.id, parent]
      )
    : await all(
        'SELECT * FROM folders WHERE owner_id=? AND parent_id IS NULL ORDER BY name',
        [me.id]
      );

  res.json(rows);
}));

app.post('/api/folders', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const name = String(req.body.name || '').trim();
  const parentId = req.body.parent_id ? Number(req.body.parent_id) : null;

  if (!name || name.length > 120) {
    return res.status(400).json({ error: 'Неверное название папки' });
  }

  if (parentId) {
    const parent = await get(
      'SELECT id,owner_id FROM folders WHERE id=?',
      [parentId]
    );

    if (!parent || parent.owner_id !== me.id) {
      return res.status(403).json({ error: 'Нет доступа к папке' });
    }
  }

  const result = await run(
    'INSERT INTO folders(name,owner_id,parent_id) VALUES(?,?,?)',
    [name, me.id, parentId]
  );

  res.status(201).json({
    id: result.id,
    name,
    owner_id: me.id,
    parent_id: parentId
  });
}));

app.delete('/api/folders/:id', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const id = Number(req.params.id);

  const folder = await get(
    'SELECT * FROM folders WHERE id=?',
    [id]
  );

  if (!folder) return res.status(404).json({ error: 'Папка не найдена' });
  if (folder.owner_id !== me.id) {
    return res.status(403).json({ error: 'Нет доступа' });
  }

  const child = await get(
    'SELECT id FROM folders WHERE parent_id=? LIMIT 1',
    [id]
  );

  const file = await get(
    'SELECT id FROM files WHERE folder_id=? LIMIT 1',
    [id]
  );

  if (child || file) {
    return res.status(409).json({
      error: 'Сначала удали вложенные папки и файлы'
    });
  }

  await run('DELETE FROM folders WHERE id=?', [id]);
  res.json({ ok: true });
}));

// ===================== FILES =====================

app.get('/api/files', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const folder = req.query.folder ? Number(req.query.folder) : null;

  const rows = folder
    ? await all(
        `SELECT id,owner_id,folder_id,original_name,mime_type,size,
                can_download,is_public,created_at
         FROM files WHERE owner_id=? AND folder_id=?
         ORDER BY created_at DESC`,
        [me.id, folder]
      )
    : await all(
        `SELECT id,owner_id,folder_id,original_name,mime_type,size,
                can_download,is_public,created_at
         FROM files WHERE owner_id=? AND folder_id IS NULL
         ORDER BY created_at DESC`,
        [me.id]
      );

  res.json(rows);
}));

app.post(
  '/api/upload',
  requireAuth,
  upload.single('file'),
  asyncRoute(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'Выбери файл' });
    }

    const me = await currentUser(req);
    const folderId = req.body.folder_id
      ? Number(req.body.folder_id)
      : null;

    if (folderId) {
      const folder = await get(
        'SELECT id,owner_id FROM folders WHERE id=?',
        [folderId]
      );

      if (!folder || folder.owner_id !== me.id) {
        fs.unlink(req.file.path, () => {});
        return res.status(403).json({ error: 'Нет доступа к папке' });
      }
    }

    const originalName = Buffer.from(
      req.file.originalname,
      'latin1'
    ).toString('utf8');

    const result = await run(
      `INSERT INTO files
       (owner_id,folder_id,original_name,stored_name,mime_type,size)
       VALUES(?,?,?,?,?,?)`,
      [
        me.id,
        folderId,
        originalName,
        req.file.filename,
        req.file.mimetype,
        req.file.size
      ]
    );

    res.status(201).json({
      id: result.id,
      original_name: originalName,
      size: req.file.size
    });
  })
);

async function accessibleFile(req, id) {
  const me = await currentUser(req);

  const file = await get(
    'SELECT * FROM files WHERE id=?',
    [id]
  );

  if (!file) return { error: 404 };

  if (
    file.owner_id !== me.id &&
    !['teacher', 'admin'].includes(me.role) &&
    !file.is_public
  ) {
    return { error: 403 };
  }

  return { file, me };
}

app.get(
  '/api/files/:id/download',
  requireAuth,
  asyncRoute(async (req, res) => {
    const result = await accessibleFile(req, Number(req.params.id));

    if (result.error) {
      return res.status(result.error).json({ error: 'Нет доступа к файлу' });
    }

    const { file, me } = result;

    if (
      req.query.inline !== '1' &&
      !['teacher', 'admin'].includes(me.role) &&
      !file.can_download
    ) {
      return res.status(403).json({
        error: 'Преподаватель запретил скачивание'
      });
    }

    const filePath = path.join(
      UPLOAD_DIR,
      path.basename(file.stored_name)
    );

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Файл отсутствует на сервере' });
    }

    res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');

    if (req.query.inline === '1') {
      res.setHeader(
        'Content-Disposition',
        `inline; filename*=UTF-8''${encodeURIComponent(file.original_name)}`
      );
      return res.sendFile(filePath);
    }

    res.download(filePath, file.original_name);
  })
);

// Преподаватель управляет разрешением на скачивание.
app.patch(
  '/api/files/:id/permissions',
  requireAuth,
  requireTeacher,
  asyncRoute(async (req, res) => {
    const id = Number(req.params.id);
    const allow = req.body.can_download === true ||
      req.body.can_download === 1;

    const file = await get('SELECT id FROM files WHERE id=?', [id]);

    if (!file) return res.status(404).json({ error: 'Файл не найден' });

    await run(
      'UPDATE files SET can_download=? WHERE id=?',
      [allow ? 1 : 0, id]
    );

    res.json({ ok: true, can_download: allow });
  })
);

app.delete('/api/files/:id', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const id = Number(req.params.id);

  const file = await get('SELECT * FROM files WHERE id=?', [id]);

  if (!file) return res.status(404).json({ error: 'Файл не найден' });
  if (file.owner_id !== me.id) {
    return res.status(403).json({ error: 'Нет доступа' });
  }

  await run('DELETE FROM shares WHERE file_id=?', [id]);
  await run('DELETE FROM file_reviews WHERE file_id=?', [id]);
  await run('DELETE FROM files WHERE id=?', [id]);

  fs.unlink(path.join(UPLOAD_DIR, path.basename(file.stored_name)), () => {});
  res.json({ ok: true });
}));

// ===================== SHARING =====================

app.post('/api/share/:fileId', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const fileId = Number(req.params.fileId);

  const file = await get(
    'SELECT id,owner_id,can_download FROM files WHERE id=?',
    [fileId]
  );

  if (!file) return res.status(404).json({ error: 'Файл не найден' });

  if (file.owner_id !== me.id) {
    return res.status(403).json({
      error: 'Можно делиться только своими файлами'
    });
  }

  const allow = req.body.allow_download === true &&
    file.can_download === 1 ? 1 : 0;

  const expiresDays = Math.max(
    0,
    Math.min(Number(req.body.expires_days || 0), 365)
  );

  const expiresAt = expiresDays
    ? Date.now() + expiresDays * 86400000
    : null;

  const shareToken = makeToken();

  await run(
    `INSERT INTO shares
     (file_id,token,created_by,allow_download,expires_at)
     VALUES(?,?,?,?,?)`,
    [fileId, shareToken, me.id, allow, expiresAt]
  );

  res.json({
    url: `${baseUrl()}/share/${shareToken}`,
    allow_download: Boolean(allow)
  });
}));

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

app.get('/share/:token', asyncRoute(async (req, res) => {
  const share = await get(
    `SELECT s.*,f.original_name,f.stored_name,f.mime_type,f.can_download
     FROM shares s JOIN files f ON f.id=s.file_id
     WHERE s.token=?`,
    [req.params.token]
  );

  if (!share || (share.expires_at && share.expires_at < Date.now())) {
    return res.status(404).send('Ссылка не найдена или истекла');
  }

  const canDownload = share.allow_download === 1 &&
    share.can_download === 1;

  res.type('html').send(`
    <!doctype html>
    <html lang="ru">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>${escapeHtml(share.original_name)}</title>
    <body style="font-family:Arial;background:#101827;color:white;padding:24px">
      <h2>${escapeHtml(share.original_name)}</h2>
      <div id="preview"></div>
      ${canDownload
        ? `<p><a style="color:#80eaff"
             href="/share/${encodeURIComponent(req.params.token)}/download">
             Скачать файл</a></p>`
        : '<p>Скачивание запрещено владельцем файла или преподавателем.</p>'}
      <script>
        const url = '/share/${encodeURIComponent(req.params.token)}/content';
        const ext = ${JSON.stringify(path.extname(share.original_name).toLowerCase())};
        const box = document.getElementById('preview');

        if (['.png','.jpg','.jpeg','.gif','.webp'].includes(ext)) {
          box.innerHTML = '<img style="max-width:95%;max-height:80vh" src="' + url + '">';
        } else if (['.pdf'].includes(ext)) {
          box.innerHTML = '<iframe style="width:95%;height:80vh;border:0" src="' + url + '"></iframe>';
        } else if (['.mp4','.webm','.ogg'].includes(ext)) {
          box.innerHTML = '<video controls style="max-width:95%;max-height:80vh" src="' + url + '"></video>';
        } else {
          box.textContent = 'Предпросмотр этого формата не поддерживается.';
        }
      </script>
    </body>
    </html>
  `);
}));

app.get('/share/:token/content', asyncRoute(async (req, res) => {
  const share = await get(
    `SELECT s.expires_at,f.* FROM shares s
     JOIN files f ON f.id=s.file_id WHERE s.token=?`,
    [req.params.token]
  );

  if (!share || (share.expires_at && share.expires_at < Date.now())) {
    return res.status(404).end();
  }

  const filePath = path.join(
    UPLOAD_DIR,
    path.basename(share.stored_name)
  );

  if (!fs.existsSync(filePath)) return res.status(404).end();

  res.setHeader('Content-Type', share.mime_type || 'application/octet-stream');
  res.setHeader(
    'Content-Disposition',
    `inline; filename*=UTF-8''${encodeURIComponent(share.original_name)}`
  );

  res.sendFile(filePath);
}));

app.get('/share/:token/download', asyncRoute(async (req, res) => {
  const share = await get(
    `SELECT s.allow_download,s.expires_at,f.*
     FROM shares s JOIN files f ON f.id=s.file_id WHERE s.token=?`,
    [req.params.token]
  );

  if (
    !share ||
    share.allow_download !== 1 ||
    share.can_download !== 1 ||
    (share.expires_at && share.expires_at < Date.now())
  ) {
    return res.status(403).send('Скачивание запрещено или ссылка истекла');
  }

  const filePath = path.join(UPLOAD_DIR, path.basename(share.stored_name));

  if (!fs.existsSync(filePath)) return res.status(404).end();

  res.download(filePath, share.original_name);
}));

// ===================== ADMIN: STUDENTS AND TEACHERS =====================

// Список людей для админ-панели: показываем имена, роли и число работ.
app.get(
  '/api/admin/users',
  requireAuth,
  requireAdmin,
  asyncRoute(async (_req, res) => {
    const users = await all(`
      SELECT u.id,u.name,u.email,u.role,u.created_at,
        (SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS files_count
      FROM users u
      WHERE u.role IN ('student','teacher')
      ORDER BY CASE u.role WHEN 'student' THEN 0 ELSE 1 END,
               u.name COLLATE NOCASE
    `);

    res.json(users);
  })
);

// Только администратор создаёт преподавателей.
app.post(
  '/api/admin/teachers',
  requireAuth,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (name.length < 2) {
      return res.status(400).json({ error: 'Укажи имя и фамилию' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Неверный адрес почты' });
    }

    if (password.length < 12) {
      return res.status(400).json({
        error: 'Временный пароль должен содержать минимум 12 символов'
      });
    }

    if (await get('SELECT id FROM users WHERE email=?', [email])) {
      return res.status(409).json({
        error: 'Пользователь с такой почтой уже существует'
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await run(
      `INSERT INTO users(name,email,password_hash,role,confirmed)
       VALUES(?,?,?,'teacher',1)`,
      [name, email, hash]
    );

    res.status(201).json({
      id: result.id,
      name,
      email,
      role: 'teacher'
    });
  })
);

// Снять роль преподавателя может только администратор.
app.delete(
  '/api/admin/teachers/:id',
  requireAuth,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const teacher = await get(
      "SELECT id FROM users WHERE id=? AND role='teacher'",
      [Number(req.params.id)]
    );

    if (!teacher) {
      return res.status(404).json({ error: 'Преподаватель не найден' });
    }

    await run(
      "UPDATE users SET role='student' WHERE id=?",
      [teacher.id]
    );

    res.json({ ok: true });
  })
);

// ===================== STUDENT LIST / WORK REVIEW =====================

app.get(
  '/api/students',
  requireAuth,
  requireTeacher,
  asyncRoute(async (_req, res) => {
    res.json(await all(`
      SELECT u.id,u.name,u.email,u.created_at,
        (SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS files_count
      FROM users u
      WHERE u.role='student'
      ORDER BY u.name COLLATE NOCASE
    `));
  })
);

app.get('/api/reviews', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);

  if (['teacher', 'admin'].includes(me.role)) {
    const studentId = req.query.student_id
      ? Number(req.query.student_id)
      : null;

    const params = [];
    let where = "WHERE u.role='student'";

    if (studentId) {
      where += ' AND u.id=?';
      params.push(studentId);
    }

    const rows = await all(`
      SELECT f.id AS file_id,f.owner_id,f.original_name,f.size,
        f.created_at,f.can_download,
        u.id AS student_id,u.name AS student_name,u.email AS student_email,
        r.status,r.comment,r.updated_at AS reviewed_at,t.name AS reviewed_by
      FROM files f
      JOIN users u ON u.id=f.owner_id
      LEFT JOIN file_reviews r ON r.file_id=f.id
      LEFT JOIN users t ON t.id=r.teacher_id
      ${where}
      ORDER BY f.created_at DESC
    `, params);

    return res.json(rows);
  }

  res.json(await all(`
    SELECT f.id AS file_id,f.owner_id,f.original_name,f.size,
      f.created_at,f.can_download,r.status,r.comment,
      r.updated_at AS reviewed_at,t.name AS reviewed_by
    FROM files f
    LEFT JOIN file_reviews r ON r.file_id=f.id
    LEFT JOIN users t ON t.id=r.teacher_id
    WHERE f.owner_id=?
    ORDER BY f.created_at DESC
  `, [me.id]));
}));

app.patch(
  '/api/files/:id/review',
  requireAuth,
  requireTeacher,
  asyncRoute(async (req, res) => {
    const fileId = Number(req.params.id);
    const status = String(req.body.status || 'pending');
    const comment = String(req.body.comment || '').trim().slice(0, 5000);

    if (!['pending', 'accepted', 'revision'].includes(status)) {
      return res.status(400).json({ error: 'Неверный статус проверки' });
    }

    const file = await get(`
      SELECT f.id FROM files f
      JOIN users u ON u.id=f.owner_id
      WHERE f.id=? AND u.role='student'
    `, [fileId]);

    if (!file) {
      return res.status(404).json({ error: 'Работа ученика не найдена' });
    }

    await run(`
      INSERT INTO file_reviews(file_id,teacher_id,status,comment,updated_at)
      VALUES(?,?,?,?,CURRENT_TIMESTAMP)
      ON CONFLICT(file_id) DO UPDATE SET
        teacher_id=excluded.teacher_id,
        status=excluded.status,
        comment=excluded.comment,
        updated_at=CURRENT_TIMESTAMP
    `, [fileId, req.session.userId, status, comment]);

    res.json({ ok: true, status, comment });
  })
);

// ===================== ASSIGNMENTS =====================

app.get('/api/assignments', requireAuth, asyncRoute(async (_req, res) => {
  res.json(await all(`
    SELECT a.*,u.name AS teacher_name
    FROM assignments a JOIN users u ON u.id=a.created_by
    ORDER BY a.created_at DESC
  `));
}));

app.post(
  '/api/assignments',
  requireAuth,
  requireTeacher,
  asyncRoute(async (req, res) => {
    const title = String(req.body.title || '').trim();
    const description = String(req.body.description || '').trim();

    if (!title) {
      return res.status(400).json({ error: 'Укажи название задания' });
    }

    const result = await run(
      `INSERT INTO assignments(title,description,due_at,created_by)
       VALUES(?,?,?,?)`,
      [title, description, req.body.due_at || null, req.session.userId]
    );

    res.status(201).json({ id: result.id, title, description });
  })
);

app.delete(
  '/api/assignments/:id',
  requireAuth,
  requireTeacher,
  asyncRoute(async (req, res) => {
    await run(
      'DELETE FROM assignments WHERE id=?',
      [Number(req.params.id)]
    );
    res.json({ ok: true });
  })
);

// ===================== STATIC PAGES / ERRORS =====================

app.use(express.static(PUBLIC_DIR));

app.get('/', (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

app.use((err, _req, res, _next) => {
  console.error('Ошибка сервера:', err);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: err.code === 'LIMIT_FILE_SIZE'
        ? `Файл слишком большой. Лимит ${process.env.MAX_FILE_MB || 500} МБ`
        : 'Ошибка загрузки файла'
    });
  }

  res.status(500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'Внутренняя ошибка сервера'
      : err.message || 'Внутренняя ошибка сервера'
  });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`GroupDrive запущен на порту ${PORT}`);
      console.log('Почта: Unisender Go API');
    });
  })
  .catch(err => {
    console.error('Не удалось запустить GroupDrive:', err);
    process.exit(1);
  });