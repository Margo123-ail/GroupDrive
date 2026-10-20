require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const DATA_DIR = path.join(ROOT, 'data');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, 'groupdrive.db'));
const run = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function (err) { err ? reject(err) : resolve({ id: this.lastID, changes: this.changes }); }));
const get = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)));
const all = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
const token = () => crypto.randomBytes(32).toString('hex');
const safeEqual = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  name: 'groupdrive.sid',
  secret: process.env.SESSION_SECRET || 'CHANGE_THIS_SESSION_SECRET_BEFORE_DEPLOYMENT',
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 12 }
}));

const transporter = (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS)
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    }) : null;

async function sendMail(to, subject, text, html) {
  // Preferred: transactional-email API. It uses a dedicated API key, not your personal mailbox password.
  if (process.env.BREVO_API_KEY && process.env.MAIL_FROM) {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'accept': 'application/json', 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json' },
      body: JSON.stringify({
        sender: { name: process.env.MAIL_FROM_NAME || 'GroupDrive', email: process.env.MAIL_FROM },
        to: [{ email: to }], subject, textContent: text, htmlContent: html
      })
    });
    if (!response.ok) {
      const details = await response.text().catch(() => '');
      console.error('Brevo email error:', response.status, details);
      throw new Error('Почтовый сервис не принял письмо. Проверь API-ключ и подтверждённый адрес отправителя в Brevo.');
    }
    return;
  }
  if (transporter && String(process.env.MAIL_MODE || '').toLowerCase() !== 'local') {
    await transporter.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to, subject, text, html });
    return;
  }
  console.log('\n--- GROUPDRIVE MAIL (LOCAL TEST MODE — NOT SENT) ---\nTo:', to, '\nSubject:', subject, '\n', text, '\n----------------------------------------\n');
}
const mailConfigured = () => Boolean((process.env.BREVO_API_KEY && process.env.MAIL_FROM) || (transporter && String(process.env.MAIL_MODE || '').toLowerCase() !== 'local'));
const baseUrl = () => (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}
async function currentUser(req) {
  if (!req.session.userId) return null;
  return get('SELECT id,name,email,role,confirmed,created_at FROM users WHERE id=?', [req.session.userId]);
}
async function requireTeacher(req, res, next) {
  try {
    const user = await currentUser(req);
    if (!user || !['teacher', 'admin'].includes(user.role)) return res.status(403).json({ error: 'Доступ только для преподавателя или администратора' });
    req.user = user; next();
  } catch (e) { next(e); }
}
function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname).slice(0, 15)}`)
});
const upload = multer({
  storage,
  limits: { fileSize: Number(process.env.MAX_FILE_MB || 500) * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const blocked = /\.(exe|bat|cmd|com|msi|ps1|sh|php|js|html?)$/i.test(file.originalname);
    cb(blocked ? new Error('Этот тип файла запрещён для загрузки') : null, !blocked);
  }
});

async function initDb() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student',
    confirmed INTEGER NOT NULL DEFAULT 0, confirm_token TEXT, confirm_expires INTEGER,
    reset_token TEXT, reset_expires INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, owner_id INTEGER NOT NULL,
    parent_id INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id), FOREIGN KEY(parent_id) REFERENCES folders(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, folder_id INTEGER,
    original_name TEXT NOT NULL, stored_name TEXT NOT NULL, mime_type TEXT, size INTEGER NOT NULL DEFAULT 0,
    can_download INTEGER NOT NULL DEFAULT 1, is_public INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(owner_id) REFERENCES users(id), FOREIGN KEY(folder_id) REFERENCES folders(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT DEFAULT '',
    due_at TEXT, created_by INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL, token TEXT NOT NULL UNIQUE,
    created_by INTEGER NOT NULL, allow_download INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  // Safe migrations for databases created by earlier versions.
  const columns = await all('PRAGMA table_info(files)');
  if (!columns.some(c => c.name === 'can_download')) await run('ALTER TABLE files ADD COLUMN can_download INTEGER NOT NULL DEFAULT 1');
  if (!columns.some(c => c.name === 'is_public')) await run('ALTER TABLE files ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0');

  // Bootstrap admin. If that email already exists, promote that account; its current password stays unchanged.
  if (process.env.SEED_ADMIN_EMAIL && process.env.SEED_ADMIN_PASSWORD) {
    const email = process.env.SEED_ADMIN_EMAIL.trim().toLowerCase();
    const existing = await get('SELECT id FROM users WHERE email=?', [email]);
    if (existing) {
      await run("UPDATE users SET role='admin',confirmed=1 WHERE id=?", [existing.id]);
      console.log('Учетная запись назначена администратором:', email);
    } else {
      const hash = await bcrypt.hash(process.env.SEED_ADMIN_PASSWORD, 12);
      await run('INSERT INTO users(name,email,password_hash,role,confirmed) VALUES(?,?,?,?,1)',
        [process.env.SEED_ADMIN_NAME || 'Администратор', email, hash, 'admin']);
      console.log('Создан начальный аккаунт администратора:', email);
    }
  } else if (process.env.SEED_TEACHER_EMAIL && process.env.SEED_TEACHER_PASSWORD) {
    // Backward compatibility with the first project archive.
    const email = process.env.SEED_TEACHER_EMAIL.trim().toLowerCase();
    const existing = await get('SELECT id FROM users WHERE email=?', [email]);
    if (!existing) {
      const hash = await bcrypt.hash(process.env.SEED_TEACHER_PASSWORD, 12);
      await run('INSERT INTO users(name,email,password_hash,role,confirmed) VALUES(?,?,?,?,1)',
        [process.env.SEED_TEACHER_NAME || 'Преподаватель', email, hash, 'teacher']);
      console.log('Создан начальный аккаунт преподавателя:', email);
    }
  }

  await run(`CREATE TABLE IF NOT EXISTS file_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL UNIQUE,
    teacher_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    comment TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(file_id) REFERENCES files(id), FOREIGN KEY(teacher_id) REFERENCES users(id)
  )`);
}
app.get('/api/health', (_req, res) => res.json({ ok: true, app: 'GroupDrive' }));

app.post('/api/register', asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'Укажи имя длиной от 2 до 100 символов' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Проверь адрес электронной почты' });
  if (password.length < 8 || password.length > 200) return res.status(400).json({ error: 'Пароль должен содержать от 8 символов' });
  if (await get('SELECT id FROM users WHERE email=?', [email])) return res.status(409).json({ error: 'Аккаунт с такой почтой уже существует' });
  const confirmToken = token();
  const expires = Date.now() + 24 * 60 * 60 * 1000;
  const hash = await bcrypt.hash(password, 12);
  await run('INSERT INTO users(name,email,password_hash,role,confirmed,confirm_token,confirm_expires) VALUES(?,?,?,?,0,?,?)',
    [name, email, hash, 'student', confirmToken, expires]);
  const link = `${baseUrl()}/api/confirm?token=${confirmToken}`;
  try {
    await sendMail(email, 'Подтверждение GroupDrive', `Чтобы подтвердить почту, открой ссылку (действует 24 часа): ${link}`,
      `<p>Подтверди почту GroupDrive:</p><p><a href="${link}">Подтвердить адрес</a></p><p>Ссылка действует 24 часа.</p>`);
  } catch (err) {
    // Let the user retry registration if the delivery provider failed.
    await run('DELETE FROM users WHERE email=? AND confirm_token=?', [email, confirmToken]);
    throw err;
  }
  res.status(201).json({ message: mailConfigured()
    ? 'Регистрация почти завершена. Проверь почту и перейди по ссылке подтверждения.'
    : 'Аккаунт создан, но реальная отправка пока не настроена. Тестовая ссылка напечатана в консоли сервера.' });
}));
app.get('/api/confirm', asyncRoute(async (req, res) => {
  const t = String(req.query.token || '');
  const user = await get('SELECT id,confirm_expires FROM users WHERE confirm_token=?', [t]);
  if (!user || user.confirm_expires < Date.now()) return res.status(400).send('Ссылка подтверждения недействительна или истекла. Запроси регистрацию повторно.');
  await run('UPDATE users SET confirmed=1,confirm_token=NULL,confirm_expires=NULL WHERE id=?', [user.id]);
  res.redirect('/login.html?confirmed=1');
}));
app.post('/api/login', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const requestedRole = String(req.body.role || 'student');
  const user = await get('SELECT * FROM users WHERE email=?', [email]);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Неверная почта или пароль' });
  if (!user.confirmed) return res.status(403).json({ error: 'Сначала подтверди электронную почту. В тестовом режиме ссылка находится в консоли сервера.' });
  if (requestedRole !== user.role) return res.status(403).json({ error: user.role === 'admin' ? 'Выбери вход «Администратор»' : user.role === 'teacher' ? 'Выбери вход «Преподаватель»' : 'Выбери вход «Студент»' });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Не удалось создать сессию' });
    req.session.userId = user.id;
    res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  });
}));
app.post('/api/logout', (req, res) => req.session.destroy(() => { res.clearCookie('groupdrive.sid'); res.json({ ok: true }); }));
app.get('/api/me', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);
  if (!user) return res.status(401).json({ error: 'Не авторизован' });
  res.json(user);
}));
app.post('/api/forgot', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = await get('SELECT id,email FROM users WHERE email=?', [email]);
  // Keep response generic to avoid exposing registered addresses.
  if (user) {
    const resetToken = token(), expires = Date.now() + 60 * 60 * 1000;
    await run('UPDATE users SET reset_token=?,reset_expires=? WHERE id=?', [resetToken, expires, user.id]);
    const link = `${baseUrl()}/reset.html?token=${resetToken}`;
    await sendMail(email, 'Восстановление пароля GroupDrive', `Ссылка для смены пароля (действует 1 час): ${link}`,
      `<p>Чтобы сменить пароль, перейди по ссылке:</p><p><a href="${link}">Сбросить пароль</a></p><p>Ссылка действует 1 час.</p>`);
  }
  res.json({ message: 'Если аккаунт с такой почтой существует, инструкция для восстановления отправлена. В локальном режиме проверь консоль сервера.' });
}));
app.post('/api/reset', asyncRoute(async (req, res) => {
  const t = String(req.body.token || '');
  const password = String(req.body.password || '');
  if (password.length < 8) return res.status(400).json({ error: 'Новый пароль должен содержать не менее 8 символов' });
  const user = await get('SELECT id,reset_expires FROM users WHERE reset_token=?', [t]);
  if (!user || user.reset_expires < Date.now()) return res.status(400).json({ error: 'Ссылка недействительна или истекла' });
  const hash = await bcrypt.hash(password, 12);
  await run('UPDATE users SET password_hash=?,reset_token=NULL,reset_expires=NULL WHERE id=?', [hash, user.id]);
  res.json({ message: 'Пароль изменён. Теперь можно войти.' });
}));

app.get('/api/folders', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const parent = req.query.parent ? Number(req.query.parent) : null;
  let rows;
  if (['teacher','admin'].includes(me.role)) {
    rows = parent
      ? await all(`SELECT f.*,u.name AS owner_name,u.email AS owner_email FROM folders f JOIN users u ON u.id=f.owner_id WHERE f.parent_id=? ORDER BY f.name`, [parent])
      : await all(`SELECT f.*,u.name AS owner_name,u.email AS owner_email FROM folders f JOIN users u ON u.id=f.owner_id WHERE f.parent_id IS NULL ORDER BY f.name`, []);
  } else {
    rows = parent
      ? await all('SELECT * FROM folders WHERE owner_id=? AND parent_id=? ORDER BY name', [me.id, parent])
      : await all('SELECT * FROM folders WHERE owner_id=? AND parent_id IS NULL ORDER BY name', [me.id]);
  }
  res.json(rows);
}));
app.post('/api/folders', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req), name = String(req.body.name || '').trim();
  const parentId = req.body.parent_id ? Number(req.body.parent_id) : null;
  if (!name || name.length > 120) return res.status(400).json({ error: 'Название папки должно содержать от 1 до 120 символов' });
  if (parentId) {
    const parent = await get('SELECT id,owner_id FROM folders WHERE id=?', [parentId]);
    if (!parent || (!['teacher','admin'].includes(me.role) && parent.owner_id !== me.id)) return res.status(403).json({ error: 'Нет доступа к родительской папке' });
  }
  const r = await run('INSERT INTO folders(name,owner_id,parent_id) VALUES(?,?,?)', [name, me.id, parentId]);
  res.status(201).json({ id: r.id, name, owner_id: me.id, parent_id: parentId });
}));
app.delete('/api/folders/:id', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req), id = Number(req.params.id);
  const folder = await get('SELECT * FROM folders WHERE id=?', [id]);
  if (!folder) return res.status(404).json({ error: 'Папка не найдена' });
  if (!['teacher','admin'].includes(me.role) && folder.owner_id !== me.id) return res.status(403).json({ error: 'Нет доступа' });
  const child = await get('SELECT id FROM folders WHERE parent_id=? LIMIT 1', [id]);
  const file = await get('SELECT id FROM files WHERE folder_id=? LIMIT 1', [id]);
  if (child || file) return res.status(409).json({ error: 'Сначала удали файлы и вложенные папки' });
  await run('DELETE FROM folders WHERE id=?', [id]); res.json({ ok: true });
}));
app.get('/api/files', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req), folder = req.query.folder ? Number(req.query.folder) : null;
  let rows;
  if (['teacher','admin'].includes(me.role)) {
    rows = folder
      ? await all(`SELECT f.id,f.owner_id,f.folder_id,f.original_name,f.mime_type,f.size,f.can_download,f.is_public,f.created_at,u.name AS owner_name,u.email AS owner_email FROM files f JOIN users u ON u.id=f.owner_id WHERE f.folder_id=? ORDER BY f.created_at DESC`, [folder])
      : await all(`SELECT f.id,f.owner_id,f.folder_id,f.original_name,f.mime_type,f.size,f.can_download,f.is_public,f.created_at,u.name AS owner_name,u.email AS owner_email FROM files f JOIN users u ON u.id=f.owner_id WHERE f.folder_id IS NULL ORDER BY f.created_at DESC`, []);
  } else {
    rows = folder
      ? await all('SELECT id,owner_id,folder_id,original_name,mime_type,size,can_download,is_public,created_at FROM files WHERE owner_id=? AND folder_id=? ORDER BY created_at DESC', [me.id, folder])
      : await all('SELECT id,owner_id,folder_id,original_name,mime_type,size,can_download,is_public,created_at FROM files WHERE owner_id=? AND folder_id IS NULL ORDER BY created_at DESC', [me.id]);
  }
  res.json(rows);
}));
app.post('/api/upload', requireAuth, upload.single('file'), asyncRoute(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Выбери файл для загрузки' });
  const me = await currentUser(req), folderId = req.body.folder_id ? Number(req.body.folder_id) : null;
  if (folderId) {
    const folder = await get('SELECT id,owner_id FROM folders WHERE id=?', [folderId]);
    if (!folder || (!['teacher','admin'].includes(me.role) && folder.owner_id !== me.id)) {
      fs.unlink(req.file.path, () => {});
      return res.status(403).json({ error: 'Нет доступа к папке' });
    }
  }
  const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
  const result = await run('INSERT INTO files(owner_id,folder_id,original_name,stored_name,mime_type,size,can_download) VALUES(?,?,?,?,?,?,?)',
    [me.id, folderId, originalName, req.file.filename, req.file.mimetype, req.file.size, 1]);
  res.status(201).json({ id: result.id, original_name: originalName, size: req.file.size });
}));
async function accessibleFile(req, id) {
  const me = await currentUser(req);
  const file = await get('SELECT f.*,u.role AS owner_role FROM files f JOIN users u ON u.id=f.owner_id WHERE f.id=?', [id]);
  if (!file) return { error: 404 };
  if (!['teacher','admin'].includes(me.role) && file.owner_id !== me.id && !file.is_public) return { error: 403 };
  return { file, me };
}
app.get('/api/files/:id/download', requireAuth, asyncRoute(async (req, res) => {
  const result = await accessibleFile(req, Number(req.params.id));
  if (result.error) return res.status(result.error).json({ error: result.error === 404 ? 'Файл не найден' : 'Нет доступа' });
  const { file, me } = result;
  if (req.query.inline !== '1' && !['teacher','admin'].includes(me.role) && !file.can_download) return res.status(403).json({ error: 'Преподаватель запретил скачивание этого файла' });
  const filePath = path.join(UPLOAD_DIR, path.basename(file.stored_name));
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Файл отсутствует на сервере' });
  res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');
  if (req.query.inline === '1') {
    res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(file.original_name)}`);
    return res.sendFile(filePath);
  }
  res.download(filePath, file.original_name);
}));
app.patch('/api/files/:id/permissions', requireAuth, requireTeacher, asyncRoute(async (req, res) => {
  const id = Number(req.params.id), allow = req.body.can_download === true || req.body.can_download === 1;
  const file = await get('SELECT id FROM files WHERE id=?', [id]);
  if (!file) return res.status(404).json({ error: 'Файл не найден' });
  await run('UPDATE files SET can_download=? WHERE id=?', [allow ? 1 : 0, id]);
  res.json({ ok: true, can_download: allow });
}));
app.delete('/api/files/:id', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req), id = Number(req.params.id);
  const file = await get('SELECT * FROM files WHERE id=?', [id]);
  if (!file) return res.status(404).json({ error: 'Файл не найден' });
  if (!['teacher','admin'].includes(me.role) && file.owner_id !== me.id) return res.status(403).json({ error: 'Нет доступа' });
  await run('DELETE FROM shares WHERE file_id=?', [id]);
  await run('DELETE FROM files WHERE id=?', [id]);
  fs.unlink(path.join(UPLOAD_DIR, path.basename(file.stored_name)), () => {});
  res.json({ ok: true });
}));
app.post('/api/share/:fileId', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req), fileId = Number(req.params.fileId);
  const file = await get('SELECT id,owner_id,can_download FROM files WHERE id=?', [fileId]);
  if (!file) return res.status(404).json({ error: 'Файл не найден' });
  if (!['teacher','admin'].includes(me.role) && file.owner_id !== me.id) return res.status(403).json({ error: 'Создавать ссылку можно только на свои файлы' });
  // A public share never bypasses a teacher/admin download restriction.
  const allow = req.body.allow_download === true && file.can_download === 1 ? 1 : 0;
  const expiresDays = Number(req.body.expires_days || 0);
  const expiresAt = expiresDays > 0 ? Date.now() + Math.min(expiresDays, 365) * 86400000 : null;
  const shareToken = token();
  await run('INSERT INTO shares(file_id,token,created_by,allow_download,expires_at) VALUES(?,?,?,?,?)', [fileId, shareToken, req.session.userId, allow, expiresAt]);
  res.json({ url: `${baseUrl()}/share/${shareToken}`, token: shareToken, allow_download: !!allow });
}));
app.get('/share/:token', asyncRoute(async (req, res) => {
  const share = await get('SELECT s.*,f.original_name,f.stored_name,f.mime_type,f.size FROM shares s JOIN files f ON f.id=s.file_id WHERE s.token=?', [req.params.token]);
  if (!share || (share.expires_at && share.expires_at < Date.now())) return res.status(404).send('Ссылка не найдена или истекла');
  const filePath = path.join(UPLOAD_DIR, path.basename(share.stored_name));
  if (!fs.existsSync(filePath)) return res.status(404).send('Файл отсутствует');
  const canDownload = share.allow_download === 1;
  res.type('html').send(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(share.original_name)}</title><body style="margin:0;background:#0b1224;color:#eef3ff;font:16px Arial;padding:24px"><h2>${escapeHtml(share.original_name)}</h2><p>${canDownload ? 'Скачивание разрешено' : 'Просмотр без кнопки скачивания'}</p><div id="view"></div>${canDownload ? `<p><a style="color:#83e6f4" href="/share/${encodeURIComponent(req.params.token)}/download">Скачать файл</a></p>` : ''}<script>const name=${JSON.stringify(share.original_name)},url='/share/${encodeURIComponent(req.params.token)}/content';const e=name.split('.').pop().toLowerCase(),v=document.getElementById('view');if(['pdf'].includes(e))v.innerHTML='<iframe style="width:95vw;height:80vh;border:0" src="'+url+'"></iframe>';else if(['png','jpg','jpeg','gif','webp'].includes(e))v.innerHTML='<img style="max-width:95%;max-height:80vh" src="'+url+'">';else if(['mp4','webm','ogg'].includes(e))v.innerHTML='<video controls playsinline style="max-width:95%;max-height:80vh" src="'+url+'"></video>';else v.textContent='Предпросмотр этого формата не поддерживается в браузере.';</script></body></html>`);
}));
app.get('/share/:token/content', asyncRoute(async (req, res) => {
  const share = await get('SELECT s.expires_at,f.* FROM shares s JOIN files f ON f.id=s.file_id WHERE s.token=?', [req.params.token]);
  if (!share || (share.expires_at && share.expires_at < Date.now())) return res.status(404).end();
  const p = path.join(UPLOAD_DIR, path.basename(share.stored_name));
  if (!fs.existsSync(p)) return res.status(404).end();
  res.setHeader('Content-Type', share.mime_type || 'application/octet-stream');
  res.setHeader('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(share.original_name)}`);
  res.sendFile(p);
}));
app.get('/share/:token/download', asyncRoute(async (req, res) => {
  const share = await get('SELECT s.allow_download,s.expires_at,f.* FROM shares s JOIN files f ON f.id=s.file_id WHERE s.token=?', [req.params.token]);
  if (!share || share.allow_download !== 1 || share.can_download !== 1 || (share.expires_at && share.expires_at < Date.now())) return res.status(403).send('Скачивание запрещено или ссылка истекла');
  res.download(path.join(UPLOAD_DIR, path.basename(share.stored_name)), share.original_name);
}));
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// ADMIN: only administrators may create staff accounts. Regular registration remains student-only.
app.get('/api/admin/teachers', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Доступ только для администратора' });
  res.json(await all("SELECT id,name,email,created_at FROM users WHERE role='teacher' ORDER BY name"));
}));
app.post('/api/admin/teachers', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Добавлять преподавателей может только администратор' });
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'Имя должно содержать от 2 до 100 символов' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Проверь адрес электронной почты' });
  if (password.length < 12 || password.length > 200) return res.status(400).json({ error: 'Временный пароль должен содержать минимум 12 символов' });
  if (await get('SELECT id FROM users WHERE email=?', [email])) return res.status(409).json({ error: 'Аккаунт с такой почтой уже существует' });
  const hash = await bcrypt.hash(password, 12);
  const result = await run("INSERT INTO users(name,email,password_hash,role,confirmed) VALUES(?,?,?,'teacher',1)", [name,email,hash]);
  res.status(201).json({ id: result.id, name, email, role: 'teacher', message: 'Преподаватель создан. Передай ему временный пароль безопасным способом.' });
}));
app.delete('/api/admin/teachers/:id', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Доступ только для администратора' });
  const id = Number(req.params.id), teacher = await get("SELECT id FROM users WHERE id=? AND role='teacher'", [id]);
  if (!teacher) return res.status(404).json({ error: 'Преподаватель не найден' });
  await run("UPDATE users SET role='student' WHERE id=?", [id]);
  await run('DELETE FROM sessions WHERE sess LIKE ?', [`%"userId":${id}%`]).catch(()=>{});
  res.json({ ok: true, message: 'Роль преподавателя снята; аккаунт и файлы сохранены как аккаунт ученика.' });
}));

// Review queue for teachers/admins; students can read their own feedback only.
app.get('/api/reviews', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  if (!me) return res.status(401).json({ error: 'Не авторизован' });
  if (['teacher','admin'].includes(me.role)) {
    res.json(await all(`SELECT f.id AS file_id,f.original_name,f.size,f.created_at,f.can_download,
      u.id AS student_id,u.name AS student_name,u.email AS student_email,
      r.status,r.comment,r.updated_at AS reviewed_at,t.name AS reviewed_by
      FROM files f JOIN users u ON u.id=f.owner_id
      LEFT JOIN file_reviews r ON r.file_id=f.id LEFT JOIN users t ON t.id=r.teacher_id
      WHERE u.role='student' ORDER BY CASE WHEN r.status IS NULL OR r.status='pending' THEN 0 ELSE 1 END, f.created_at DESC`));
  } else {
    res.json(await all(`SELECT f.id AS file_id,f.original_name,f.size,f.created_at,r.status,r.comment,r.updated_at AS reviewed_at,t.name AS reviewed_by
      FROM files f LEFT JOIN file_reviews r ON r.file_id=f.id LEFT JOIN users t ON t.id=r.teacher_id
      WHERE f.owner_id=? ORDER BY f.created_at DESC`, [me.id]));
  }
}));
app.patch('/api/files/:id/review', requireAuth, requireTeacher, asyncRoute(async (req, res) => {
  const fileId = Number(req.params.id), status = String(req.body.status || 'pending');
  const comment = String(req.body.comment || '').trim().slice(0, 5000);
  if (!['pending','accepted','revision'].includes(status)) return res.status(400).json({ error: 'Неизвестный статус проверки' });
  const file = await get("SELECT f.id FROM files f JOIN users u ON u.id=f.owner_id WHERE f.id=? AND u.role='student'", [fileId]);
  if (!file) return res.status(404).json({ error: 'Работа ученика не найдена' });
  await run(`INSERT INTO file_reviews(file_id,teacher_id,status,comment,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)
    ON CONFLICT(file_id) DO UPDATE SET teacher_id=excluded.teacher_id,status=excluded.status,comment=excluded.comment,updated_at=CURRENT_TIMESTAMP`,
    [fileId, req.session.userId, status, comment]);
  res.json({ ok: true, status, comment });
}));

app.get('/api/students', requireAuth, requireTeacher, asyncRoute(async (_req, res) => {
  res.json(await all(`SELECT u.id,u.name,u.email,u.created_at,
    (SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS files_count
    FROM users u WHERE u.role='student' ORDER BY u.name`));
}));
app.get('/api/assignments', requireAuth, asyncRoute(async (_req, res) => {
  res.json(await all('SELECT a.*,u.name AS teacher_name FROM assignments a JOIN users u ON u.id=a.created_by ORDER BY a.created_at DESC'));
}));
app.post('/api/assignments', requireAuth, requireTeacher, asyncRoute(async (req, res) => {
  const title = String(req.body.title || '').trim(), description = String(req.body.description || '').trim();
  if (!title) return res.status(400).json({ error: 'Укажи название задания' });
  const r = await run('INSERT INTO assignments(title,description,due_at,created_by) VALUES(?,?,?,?)',
    [title, description, req.body.due_at || null, req.session.userId]);
  res.status(201).json({ id: r.id, title, description, due_at: req.body.due_at || null });
}));
app.delete('/api/assignments/:id', requireAuth, requireTeacher, asyncRoute(async (req, res) => {
  await run('DELETE FROM assignments WHERE id=?', [Number(req.params.id)]); res.json({ ok: true });
}));

app.use(express.static(path.join(ROOT, 'public')));
app.get('/', (_req, res) => res.sendFile(path.join(ROOT, 'public', 'login.html')));
app.use((err, _req, res, _next) => {
  console.error(err);
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? `Файл слишком большой. Лимит: ${process.env.MAX_FILE_MB || 500} МБ` : 'Ошибка загрузки файла' });
  res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Внутренняя ошибка сервера' : (err.message || 'Внутренняя ошибка сервера') });
});

initDb().then(() => app.listen(PORT, () => console.log(`GroupDrive запущен: ${baseUrl()}\nРежим почты: ${mailConfigured() ? (process.env.BREVO_API_KEY ? 'Brevo API' : 'SMTP') : 'локальный (ссылки в консоли)'}\n`)))
  .catch(err => { console.error('Не удалось инициализировать БД:', err); process.exit(1); });
