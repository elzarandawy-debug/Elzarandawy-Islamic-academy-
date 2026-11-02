/*
 * Elzarandawy Islamic Academy - website server (Netlify Function, stores data in Netlify Blobs).
 * Everything is open for visitors; only the admin signs in.
 * First admin: elzarandawy@gmail.com / Alishehu@723  (set the ADMIN_PASSWORD variable in Netlify to choose your own).
 */
import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';

var SESSION_DAYS = 14;
var nowIso = function () { return new Date().toISOString(); };
var TOKEN_OUT = undefined;
var SECRET = '';
var BACKUP_NOW = false;

function hashPw(pw) { var salt = crypto.randomBytes(16).toString('hex'); return 'n$' + salt + '$' + crypto.scryptSync(pw, salt, 32, { N: 16384, r: 8, p: 1 }).toString('hex'); }
function checkPw(pw, st) { try { var p = String(st).split('$'); var h = crypto.scryptSync(pw, p[1], 32, { N: 16384, r: 8, p: 1 }); var w = Buffer.from(p[2], 'hex'); return w.length === h.length && crypto.timingSafeEqual(w, h); } catch (e) { return false; } }
function signToken_(payload) { var body = Buffer.from(JSON.stringify(payload)).toString('base64url'); return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url'); }
function readToken_(t) {
  if (!t || typeof t !== 'string') return null; var a = t.split('.'); if (a.length !== 2) return null;
  var want = crypto.createHmac('sha256', SECRET).update(a[0]).digest('base64url'); var x = Buffer.from(a[1]), y = Buffer.from(want);
  if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) return null;
  try { var p = JSON.parse(Buffer.from(a[0], 'base64url').toString('utf8')); if (!p.exp || p.exp < Date.now() / 1000) return null; return p; } catch (e) { return null; }
}

  class HttpError extends Error { constructor(status, msg, extra) { super(msg); this.status = status; this.extra = extra || {}; } }
  const bad = (m, extra) => new HttpError(400, m, extra);
  const U = {
    now: nowIso, pad: (n, w = 6) => String(n).padStart(w, '0'),
    str(v, { max = 500, min = 0, name = 'Field', required = false } = {}) {
      if (v === undefined || v === null) v = ''; v = String(v).trim();
      if (required && !v) throw bad(`${name} is required`);
      if (v && v.length < min) throw bad(`${name} must be at least ${min} characters`);
      if (v.length > max) throw bad(`${name} is too long (max ${max} characters)`);
      return v;
    },
    num(v, { min = -Infinity, max = Infinity, name = 'Number', def } = {}) {
      if (v === undefined || v === null || v === '') { if (def !== undefined) return def; throw bad(`${name} is required`); }
      const n = Number(v); if (!Number.isFinite(n)) throw bad(`${name} must be a number`);
      if (n < min || n > max) throw bad(`${name} must be between ${min} and ${max}`); return n;
    },
    int(v, o = {}) { return Math.trunc(U.num(v, o)); },
    bool: (v) => v === true || v === 1 || v === '1' || v === 'true' || v === 'on',
    url(v, { name = 'URL', required = false, max = 1000 } = {}) {
      v = U.str(v, { max, name, required }); if (!v) return '';
      let u; try { u = new URL(v); } catch (_) { throw bad(`${name} is not a valid link`); }
      if (u.protocol !== 'https:' && u.protocol !== 'http:') throw bad(`${name} must start with http:// or https://`);
      return u.toString();
    },
    email(v) { v = U.str(v, { max: 200, name: 'Email', required: true }).toLowerCase(); if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) throw bad('Please enter a valid email address'); return v; },
    oneOf(v, list, name = 'Value') { if (!list.includes(v)) throw bad(`${name} must be one of: ${list.join(', ')}`); return v; },
    publicUser: (u) => u && ({ id: u.id, email: u.email, fullName: u.full_name, regNumber: u.reg_number, role: u.role, status: u.status, phone: u.phone, country: u.country, language: u.language, createdAt: u.created_at }),
    finalPrice: (c) => (c.type === 'PAID' ? Math.max(0, Math.round(c.price * (1 - (c.discount_pct || 0) / 100) * 100) / 100) : 0),
    gradeLabel: (p) => (p === null || p === undefined ? null : p >= 85 ? 'Distinction' : p >= 70 ? 'Merit' : 'Pass'),
  };
  const CURRENCIES = ['NGN', 'USD', 'GHS', 'GBP', 'EUR', 'SAR', 'AED'];

  // ---------- storage (Netlify Blobs) ----------
  var TABLES = ['users', 'courses', 'modules', 'lessons', 'enrollments', 'progress', 'exams', 'questions', 'attempts', 'payments', 'donations', 'certificates', 'messages'];
  var db = null, loadedSig = '', pendingFiles = [], preloaded = {};
  var D0 = function () { var d = { seq: {}, counters: {}, settings: {} }; TABLES.forEach(function (t) { d[t] = []; d.seq[t] = 0; }); return d; };
  const store = () => getStore({ name: 'academy', consistency: 'strong' });
  async function ensureSecret() {
    if (SECRET) return; if (process.env.SECRET) { SECRET = process.env.SECRET; return; }
    var st = store(), s = await st.get('secret'); if (!s) { s = crypto.randomBytes(32).toString('hex'); await st.set('secret', s); } SECRET = s;
  }
  async function loadDb() {
    var raw = await store().get('db', { type: 'json' }); pendingFiles = []; preloaded = {};
    if (raw) { db = raw; TABLES.forEach(function (t) { db[t] = db[t] || []; db.seq[t] = db.seq[t] || 0; }); loadedSig = JSON.stringify(db); }
    else { db = D0(); seed(); await store().setJSON('db', db); loadedSig = JSON.stringify(db); }
  }
  async function saveDb() {
    for (const f of pendingFiles) await store().set((f.pub ? 'pub/' : 'priv/') + f.id, f.bytes, { metadata: { mime: f.mime } });
    pendingFiles = []; var sig = JSON.stringify(db); if (sig === loadedSig) return;
    await store().setJSON('db', db); loadedSig = sig;
  }
  const ins = (t, row) => { row.id = ++db.seq[t]; db[t].push(row); return row; };
  const find = (t, fn) => db[t].find(fn);
  const filt = (t, fn) => db[t].filter(fn);
  const rm = (t, fn) => { const before = db[t].length; db[t] = db[t].filter((r) => !fn(r)); return before - db[t].length; };
  const next = (name) => { db.counters[name] = (db.counters[name] || 0) + 1; return db.counters[name]; };
  const cp = (o) => JSON.parse(JSON.stringify(o));

  // ---------- files ----------
  function storeFile_(file, pub) {
    var m = /^data:([^;,]+);base64,(.*)$/.exec(file.dataUrl || ''); if (!m) throw bad('Invalid file');
    var mime = m[1]; if (!/^image\/(png|jpe?g|webp|gif)$/.test(mime) && !(mime === 'application/pdf' && !pub)) throw bad(pub ? 'Only images (PNG, JPG, WEBP, GIF) are allowed' : 'Only images (PNG, JPG, WEBP, GIF) or PDF files are allowed');
    var bytes = Buffer.from(m[2], 'base64'); if (bytes.length > 2000000) throw new HttpError(413, 'File too large (max 1.5MB).');
    var id = crypto.randomBytes(12).toString('hex'); pendingFiles.push({ id, bytes, mime, pub }); return id;
  }
  const pubUrl_ = (id) => '/api/file/' + id;
  function readFile_(id) { var f = preloaded[id]; if (!f) throw new HttpError(404, 'File missing'); return 'data:' + f.mime + ';base64,' + f.bytes.toString('base64'); }

  function delLesson(id) { rm('progress', (p) => p.lesson_id === id); rm('lessons', (l) => l.id === id); }
  function delExam(id) { rm('questions', (q) => q.exam_id === id); rm('attempts', (a) => a.exam_id === id); rm('exams', (e) => e.id === id); }
  function delModule(id) { filt('lessons', (l) => l.module_id === id).forEach((l) => delLesson(l.id)); db.exams.forEach((e) => { if (e.module_id === id) e.module_id = null; }); rm('modules', (m) => m.id === id); }
  function delCourse(id) {
    filt('modules', (m) => m.course_id === id).forEach((m) => delModule(m.id));
    filt('exams', (e) => e.course_id === id).forEach((e) => delExam(e.id));
    rm('enrollments', (e) => e.course_id === id); rm('payments', (p) => p.course_id === id); rm('certificates', (c) => c.course_id === id); rm('courses', (c) => c.id === id);
  }
  function delUser(id) {
    rm('enrollments', (e) => e.user_id === id); rm('progress', (e) => e.user_id === id); rm('attempts', (e) => e.user_id === id);
    rm('payments', (e) => e.user_id === id); rm('certificates', (e) => e.user_id === id); rm('users', (u) => u.id === id);
  }

  // ---------- settings ----------
  const DEFAULT_SETTINGS = {
    siteName: 'Elzarandawy Islamic Academy', siteNameAr: 'أكاديمية الظرنداي الإسلامية',
    tagline: 'Seeking knowledge, illuminating minds', taglineAr: 'الحث عن العلم، وإضاءة العقول',
    logo: '/img/logo.png', seal: '/img/seal.png', signature: '', founderPhoto: '/img/founder.jpg',
    founderName: 'Shaykh Ali Shehu Zaranda', founderTitle: 'Founder & Director, Elzarandawy Islamic Academy',
    founderBio: 'Shaykh Ali Shehu Zaranda is the founder of Elzarandawy Islamic Academy, established to make authentic Islamic knowledge, Quranic studies and the Arabic language accessible to sincere students everywhere, in a structured and affordable way.',
    email: 'elzarandawy@gmail.com', phone: '+2349135610001', whatsapp: '2349135610001',
    social: { facebook: 'https://www.facebook.com/profile.php?id=61572532125321', youtube: '', telegram: '', tiktok: 'https://www.tiktok.com/@elzarandawy' },
    announcement: 'Welcome! All courses are free. Start learning today.',
    maintenance: { on: false, message: 'The academy is temporarily undergoing scheduled upgrades. Please check back shortly.' },
    defaultVideoUrl: 'https://www.facebook.com/share/v/19fxULSncQ/', defaultCurrency: 'NGN',
    bank: { provider: 'OPay', accountNumber: '09135610001', accountName: 'ELZARANDAWY ACADEMY', international: 'International students: contact elzarandawy@gmail.com or WhatsApp +2349135610001 for payment options.' },
    donation: { title: 'Support the Academy', message: 'Your sadaqah supports free courses, scholarships for needy students and the running costs of the academy. May Allah reward you abundantly.', presets: [1000, 2000, 5000, 10000, 20000, 50000] },
    cert: { signatoryName: 'Shaykh Ali Shehu Zaranda', signatoryTitle: 'Founder & Director', language: 'English', extraLogos: [], autoIssue: false },
    categories: ['Arabic Language', 'Quran & Tajweed', 'Islamic Studies', 'Hadith Studies', 'Fiqh', 'Aqeedah'],
  };
  const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
  function getSettings() {
    const out = cp(DEFAULT_SETTINGS);
    for (const [k, v] of Object.entries(db.settings)) { if (isObj(v) && isObj(out[k])) out[k] = { ...out[k], ...v }; else out[k] = v; }
    return out;
  }
  const setSetting = (k, v) => { db.settings[k] = v; };
  const DEFAULT_IMG = { logo: DEFAULT_SETTINGS.logo, seal: DEFAULT_SETTINGS.seal, signature: '', founderPhoto: DEFAULT_SETTINGS.founderPhoto };
  function publicSettings(s) {
    return {
      siteName: s.siteName, siteNameAr: s.siteNameAr, tagline: s.tagline, taglineAr: s.taglineAr, logo: s.logo, seal: s.seal, signature: s.signature,
      founder: { name: s.founderName, title: s.founderTitle, bio: s.founderBio, photo: s.founderPhoto },
      email: s.email, phone: s.phone, whatsapp: s.whatsapp, social: s.social, announcement: s.announcement, maintenance: s.maintenance,
      defaultVideoUrl: s.defaultVideoUrl, defaultCurrency: s.defaultCurrency, bank: s.bank, donation: s.donation, categories: s.categories,
      cert: { signatoryName: s.cert.signatoryName, signatoryTitle: s.cert.signatoryTitle, language: s.cert.language, extraLogos: s.cert.extraLogos },
    };
  }

  // ---------- seed ----------
  function seed() {
    ins('users', { email: 'elzarandawy@gmail.com', password_hash: hashPw(process.env.ADMIN_PASSWORD || 'Alishehu@723'), full_name: 'Shaykh Ali Shehu Zaranda', reg_number: null, role: 'SUPER_ADMIN', status: 'APPROVED', phone: '+2349135610001', country: 'Nigeria', language: 'English', token_version: 0, created_at: nowIso(), last_login_at: null });
    const c = ins('courses', { title: 'Arabic for Beginners (Sample Course)', category: 'Arabic Language', type: 'FREE', price: 0, currency: 'NGN', discount_pct: 0, instructor: 'Shaykh Ali Shehu Zaranda', description: 'A sample course with a short exam. The admin can edit or delete it and create new courses.', image: '', published: 1, created_by: 1, created_at: nowIso(), updated_at: nowIso() });
    const m1 = ins('modules', { course_id: c.id, title: 'Module 1: The Arabic Alphabet', description: 'Letters and sounds', position: 0 });
    const m2 = ins('modules', { course_id: c.id, title: 'Module 2: First Words', description: '', position: 1 });
    [[m1, 'Lesson 1: Introduction'], [m1, 'Lesson 2: Letters Alif to Thaa'], [m2, 'Lesson 3: Greetings']].forEach(([m, t], i) => ins('lessons', { module_id: m.id, course_id: c.id, title: t, description: 'Sample lesson. Admins can paste a Google Drive, YouTube or Facebook link here. If left empty, the default academy video plays.', video_url: '', audio_url: '', attachments: [], position: i }));
    const e = ins('exams', { course_id: c.id, module_id: null, title: 'Final Exam', instructions: 'Answer all questions. Good luck.', duration_minutes: 30, start_at: null, end_at: null, pass_mark: 50, max_attempts: 0, shuffle: 1, required: 1, published: 1, created_by: 1, created_at: nowIso() });
    [['How many letters are in the Arabic alphabet?', ['26', '28', '30', '32'], 1], ['Arabic is written from…', ['Left to right', 'Right to left', 'Top to bottom'], 1], ['"As-salamu alaykum" means…', ['Good morning', 'Peace be upon you', 'Thank you'], 1]].forEach(([text, options, correct], i) => ins('questions', { exam_id: e.id, text, type: 'MCQ', options, correct, points: 1, explanation: '', position: i }));
  }

  // ---------- services ----------
  const isStaff = (u) => u && (u.role === 'ADMIN' || u.role === 'SUPER_ADMIN');
  const isEnrolled = (uid, cid) => !!find('enrollments', (e) => e.user_id === uid && e.course_id === cid);
  const canAccess = (u, cid) => !!u && (isStaff(u) || (u.status === 'APPROVED' && isEnrolled(u.id, cid)));
  const enroll = (uid, cid, source) => { if (!isEnrolled(uid, cid)) db.enrollments.push({ user_id: uid, course_id: cid, source, created_at: nowIso() }); };
  function examWindow(exam, at = Date.now()) {
    const s = exam.start_at ? Date.parse(exam.start_at) : null, e = exam.end_at ? Date.parse(exam.end_at) : null;
    if (s && at < s) return 'UPCOMING'; if (e && at > e) return 'CLOSED'; return 'OPEN';
  }
  function gradeAttempt(a) {
    const qs = filt('questions', (q) => q.exam_id === a.exam_id); let score = 0, max = 0;
    for (const q of qs) { max += q.points; if (a.answers[q.id] !== undefined && Number(a.answers[q.id]) === q.correct) score += q.points; }
    const exam = find('exams', (e) => e.id === a.exam_id); const percent = max > 0 ? Math.round((score / max) * 1000) / 10 : 0;
    return { score, max, percent, passed: percent >= (exam ? exam.pass_mark : 50) ? 1 : 0 };
  }
  function finalizeAttempt(id, status = 'SUBMITTED') {
    const a = find('attempts', (x) => x.id === id); if (!a || a.status !== 'IN_PROGRESS') return a;
    const g = gradeAttempt(a); Object.assign(a, { status, submitted_at: nowIso(), score: g.score, max_score: g.max, percent: g.percent, passed: g.passed }); if (g.passed) issueForAttempt(a); return a;
  }
  const expireAttempts = (uid) => filt('attempts', (a) => a.status === 'IN_PROGRESS' && a.deadline < nowIso() && (uid === undefined || a.user_id === uid)).forEach((a) => finalizeAttempt(a.id, 'EXPIRED'));
  function issueForAttempt(a) {
    if (find('certificates', (x) => x.attempt_key === a.key)) return;
    const exam = find('exams', (e) => e.id === a.exam_id); if (!exam) return; const y = new Date().getUTCFullYear();
    ins('certificates', { cert_no: `CERT-${y}-${U.pad(next('cert-' + y))}`, attempt_key: a.key, student_name: a.student_name, user_id: null, course_id: exam.course_id, status: 'ISSUED', final_percent: a.percent, requested_at: nowIso(), issued_at: nowIso(), issued_by: null });
  }
  function eligibility(uid, cid) {
    const lessons = filt('lessons', (l) => l.course_id === cid); const ids = new Set(lessons.map((l) => l.id));
    const done = filt('progress', (p) => p.user_id === uid && ids.has(p.lesson_id)).length; expireAttempts(uid);
    const exams = filt('exams', (e) => e.course_id === cid && e.published).map((e) => {
      const fin = filt('attempts', (a) => a.exam_id === e.id && a.user_id === uid && a.status !== 'IN_PROGRESS');
      return { id: e.id, title: e.title, required: !!e.required, passed: fin.some((a) => a.passed), bestPercent: fin.length ? Math.max(...fin.map((a) => a.percent)) : null };
    });
    const req = exams.filter((e) => e.required); const lessonsOk = lessons.length > 0 && done >= lessons.length; const examsOk = req.every((e) => e.passed);
    const finalPercent = req.length ? Math.round((req.reduce((s, e) => s + (e.bestPercent || 0), 0) / req.length) * 10) / 10 : null;
    return { lessonsTotal: lessons.length, lessonsDone: done, lessonsOk, exams, examsOk, eligible: lessonsOk && examsOk, finalPercent };
  }
  function issueCert(id, by) {
    const c = find('certificates', (x) => x.id === id); if (!c) throw new HttpError(404, 'Certificate not found'); if (c.status === 'ISSUED') return c;
    const y = new Date().getUTCFullYear(); Object.assign(c, { status: 'ISSUED', cert_no: `CERT-${y}-${U.pad(next('cert-' + y))}`, issued_at: nowIso(), issued_by: by ?? null }); return c;
  }
  function certView(no) {
    const c = find('certificates', (x) => x.cert_no === no && x.status === 'ISSUED'); if (!c) return null;
    const u = c.user_id ? find('users', (x) => x.id === c.user_id) : null, co = find('courses', (x) => x.id === c.course_id); if (!co) return null;
    return { certNo: c.cert_no, studentName: c.student_name || (u && u.full_name) || '', regNumber: u ? u.reg_number : '', courseTitle: co.title, instructor: co.instructor, category: co.category, issuedAt: c.issued_at, finalPercent: c.final_percent, grade: U.gradeLabel(c.final_percent) };
  }
  const courseProgress = (uid, cid) => { const ls = filt('lessons', (l) => l.course_id === cid), ids = new Set(ls.map((l) => l.id)); const done = filt('progress', (p) => p.user_id === uid && ids.has(p.lesson_id)).length; return { total: ls.length, done, percent: ls.length ? Math.round((done / ls.length) * 100) : 0 }; };
  function courseCard(c) {
    return { id: c.id, title: c.title, category: c.category, type: c.type, price: c.price, currency: c.currency, discountPct: c.discount_pct, finalPrice: U.finalPrice(c), instructor: c.instructor, description: c.description, image: c.image,
      modules: filt('modules', (m) => m.course_id === c.id).length, lessons: filt('lessons', (l) => l.course_id === c.id).length, students: filt('enrollments', (e) => e.course_id === c.id).length };
  }
  function examStatusForUser(exam, uid) {
    const attempts = filt('attempts', (a) => a.exam_id === exam.id && a.user_id === uid).sort((a, b) => b.id - a.id);
    const fin = attempts.filter((a) => a.status !== 'IN_PROGRESS'); const inp = attempts.find((a) => a.status === 'IN_PROGRESS') || null;
    const best = fin.reduce((m, a) => (a.percent > (m ?? -1) ? a.percent : m), null); const used = attempts.length;
    return { id: exam.id, title: exam.title, courseId: exam.course_id, moduleId: exam.module_id, instructions: exam.instructions, durationMinutes: exam.duration_minutes, startAt: exam.start_at, endAt: exam.end_at, passMark: exam.pass_mark, maxAttempts: exam.max_attempts, required: !!exam.required, window: examWindow(exam),
      questionCount: filt('questions', (q) => q.exam_id === exam.id).length, attemptsUsed: used, attemptsLeft: exam.max_attempts === 0 ? null : Math.max(0, exam.max_attempts - used), bestPercent: best, passed: fin.some((a) => a.passed), inProgressId: inp ? inp.id : null, lastAttemptId: fin[0] ? fin[0].id : null };
  }
  const byPos = (a, b) => a.position - b.position || a.id - b.id;

  // ---------- router ----------
  const routes = [];
  const GUARD = {
    user: (c) => { if (!c.user) throw new HttpError(401, 'Please sign in to continue'); },
    approved: (c) => { GUARD.user(c); if (c.user.status !== 'APPROVED') throw new HttpError(403, 'Your account is awaiting approval by the academy administration.'); },
    student: (c) => { GUARD.approved(c); if (c.user.role !== 'STUDENT') throw new HttpError(403, 'This action is for student accounts'); },
    staff: (c) => { GUARD.user(c); if (!isStaff(c.user)) throw new HttpError(403, 'Administrator access required'); },
    super: (c) => { GUARD.user(c); if (c.user.role !== 'SUPER_ADMIN') throw new HttpError(403, 'Super Admin access required'); },
  };
  const R = (method, path, guard, fn) => { const keys = []; const re = new RegExp('^' + path.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$'); routes.push({ method, re, keys, guard, fn }); };
  const now = U.now;
  const sess = {
    set(u) { TOKEN_OUT = signToken_({ uid: u.id, v: u.token_version, exp: Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400 }); },
    clear() { TOKEN_OUT = ''; },
  };

  // ======= public =======
  R('GET', '/api/public/bootstrap', null, () => {
    const s = getSettings();
    return { settings: publicSettings(s), stats: { students: filt('users', (u) => u.role === 'STUDENT' && u.status === 'APPROVED').length, courses: filt('courses', (c) => c.published).length, lessons: filt('lessons', (l) => (find('courses', (c) => c.id === l.course_id) || {}).published).length, certificates: filt('certificates', (c) => c.status === 'ISSUED').length }, paystack: false, baseUrl: '' };
  });
  R('POST', '/api/auth/register', null, (c) => {
    throw new HttpError(403, 'Registration is not needed. The courses are open to everyone.');
    const b = c.body; const full = U.str(b.fullName, { name: 'Full name', min: 3, max: 120, required: true }); const email = U.email(b.email);
    const pw = U.str(b.password, { name: 'Password', min: 8, max: 200, required: true }); const phone = U.str(b.phone, { name: 'Phone', max: 40, required: true, min: 6 });
    const country = U.str(b.country, { name: 'Country', max: 80, required: true }); const language = U.oneOf(b.language || 'English', ['English', 'Arabic', 'Hausa'], 'Language');
    if (find('users', (u) => u.email === email)) throw bad('An account with this email already exists. Please sign in.');
    const y = new Date().getUTCFullYear();
    // Demo mode: new students are approved immediately so you can try everything on one phone.
    const u = ins('users', { email, password_hash: hashPw(pw), full_name: full, reg_number: `EZA-${y}-${U.pad(next('reg-' + y))}`, role: 'STUDENT', status: 'APPROVED', phone, country, language, token_version: 0, created_at: now(), last_login_at: null });
    sess.set(u); return { user: U.publicUser(u) };
  });
  R('POST', '/api/auth/login', null, (c) => {
    const email = String(c.body.email || '').trim().toLowerCase(); const u = find('users', (x) => x.email === email);
    if (!u || !checkPw(String(c.body.password || ''), u.password_hash)) throw new HttpError(401, 'Incorrect email or password');
    if (u.status === 'SUSPENDED') throw new HttpError(403, 'This account has been suspended. Please contact the academy.');
    if (u.status === 'REJECTED') throw new HttpError(403, 'This registration was not approved. Please contact the academy.');
    u.last_login_at = now(); sess.set(u); return { user: U.publicUser(u) };
  });
  R('POST', '/api/auth/logout', null, () => { sess.clear(); return { ok: true }; });
  R('GET', '/api/auth/me', null, (c) => ({ user: U.publicUser(c.user) }));
  R('PUT', '/api/auth/profile', 'user', (c) => {
    const b = c.body; Object.assign(c.user, { full_name: U.str(b.fullName, { name: 'Full name', min: 3, max: 120, required: true }), phone: U.str(b.phone, { max: 40 }), country: U.str(b.country, { max: 80 }), language: U.oneOf(b.language || 'English', ['English', 'Arabic', 'Hausa'], 'Language') });
    return { user: U.publicUser(c.user) };
  });
  R('POST', '/api/auth/change-password', 'user', (c) => {
    if (!checkPw(String(c.body.currentPassword || ''), c.user.password_hash)) throw new HttpError(400, 'Current password is incorrect');
    c.user.password_hash = hashPw(U.str(c.body.newPassword, { name: 'New password', min: 8, max: 200, required: true })); c.user.token_version++; sess.set(c.user); return { ok: true };
  });
  R('GET', '/api/public/courses', null, () => ({ courses: filt('courses', (c) => c.published).sort((a, b) => b.id - a.id).map(courseCard) }));
  R('GET', '/api/public/courses/:id', null, (c) => {
    const co = find('courses', (x) => x.id === Number(c.params.id)); if (!co || (!co.published && !isStaff(c.user))) throw new HttpError(404, 'Course not found');
    const modules = filt('modules', (m) => m.course_id === co.id).sort(byPos).map((m) => ({ id: m.id, title: m.title, description: m.description, lessons: filt('lessons', (l) => l.module_id === m.id).sort(byPos).map((l) => ({ id: l.id, title: l.title })) }));
    const exams = filt('exams', (e) => e.course_id === co.id && e.published).map((e) => ({ id: e.id, title: e.title, duration_minutes: e.duration_minutes, start_at: e.start_at, end_at: e.end_at, pass_mark: e.pass_mark, module_id: e.module_id }));
    let access = null; if (c.user) { access = { enrolled: canAccess(c.user, co.id) }; const p = filt('payments', (x) => x.user_id === c.user.id && x.course_id === co.id).sort((a, b) => b.id - a.id)[0]; access.lastPayment = p ? p.status : null; }
    return { course: courseCard(co), modules, exams, access };
  });
  R('GET', '/api/public/verify/:q', null, (c) => {
    const q = decodeURIComponent(c.params.q).trim().toUpperCase().slice(0, 40); const s = publicSettings(getSettings()); const cert = certView(q);
    if (cert) return { type: 'certificate', certificate: cert, brand: { siteName: s.siteName, siteNameAr: s.siteNameAr, logo: s.logo, seal: s.seal, signature: s.signature, cert: s.cert, tagline: s.tagline, taglineAr: s.taglineAr } };
    const st = find('users', (u) => u.reg_number === q && u.role === 'STUDENT');
    if (st) return { type: 'student', student: { fullName: st.full_name, regNumber: st.reg_number, status: st.status, since: st.created_at }, certificates: filt('certificates', (x) => x.user_id === st.id && x.status === 'ISSUED').map((x) => ({ cert_no: x.cert_no, issued_at: x.issued_at, course_title: (find('courses', (k) => k.id === x.course_id) || {}).title })) };
    throw new HttpError(404, 'No certificate or student was found with that number');
  });
  R('POST', '/api/public/contact', null, (c) => { const b = c.body; ins('messages', { name: U.str(b.name, { name: 'Name', max: 120, required: true }), email: U.email(b.email), body: U.str(b.message, { name: 'Message', max: 3000, required: true, min: 5 }), is_read: 0, created_at: now() }); return { ok: true }; });
  R('POST', '/api/public/donations', null, (c) => {
    const f = c.body; const name = f.anonymous === '1' && !f.name ? 'Anonymous' : U.str(f.name, { name: 'Name', max: 120, required: true });
    const amount = U.num(f.amount, { name: 'Amount', min: 1, max: 1e9 }); const currency = U.oneOf(String(f.currency || 'NGN').toUpperCase(), CURRENCIES, 'Currency');
    const reference = U.str(f.reference, { name: 'Transaction reference', max: 100, required: true, min: 3 });
    if (find('donations', (d) => d.method === 'MANUAL' && d.reference === reference)) throw bad('This transaction reference was already submitted');
    const file = c.files[0]; const d = ins('donations', { donor_name: name, email: f.email ? U.email(f.email) : null, phone: U.str(f.phone, { max: 40 }), amount, currency, note: U.str(f.note, { max: 500 }), method: 'MANUAL', reference, proof_file: file ? storeFile_(file, false) : null, proof_name: file ? file.filename.slice(0, 120) : null, status: 'PENDING', admin_notes: '', created_at: now(), reviewed_at: null });
    return { ok: true, id: d.id };
  });
  R('POST', '/api/public/donations/paystack', null, () => { throw new HttpError(503, 'Online card payment is not enabled. Please use bank transfer.'); });
  R('POST', '/api/courses/:id/pay/paystack', 'student', () => { throw new HttpError(503, 'Online card payment is not enabled. Please use bank transfer.'); });

  // ======= student =======
  R('POST', '/api/courses/:id/enroll', 'student', (c) => { const co = find('courses', (x) => x.id === Number(c.params.id) && x.published); if (!co) throw new HttpError(404, 'Course not found'); if (co.type !== 'FREE') throw bad('This is a paid course. Please complete payment to enrol.'); enroll(c.user.id, co.id, 'FREE'); return { ok: true }; });
  R('GET', '/api/me/courses', 'approved', (c) => ({ courses: isStaff(c.user) ? [] : filt('enrollments', (e) => e.user_id === c.user.id).sort((a, b) => b.created_at.localeCompare(a.created_at)).map((e) => { const co = find('courses', (x) => x.id === e.course_id); if (!co) return null; const ce = find('certificates', (x) => x.user_id === c.user.id && x.course_id === co.id); return { id: co.id, title: co.title, category: co.category, type: co.type, instructor: co.instructor, image: co.image, enrolledAt: e.created_at, progress: courseProgress(c.user.id, co.id), certificate: ce ? { certNo: ce.cert_no, status: ce.status } : null }; }).filter(Boolean) }));
  R('GET', '/api/courses/:id/learn', null, (c) => {
    const id = Number(c.params.id); const co = find('courses', (x) => x.id === id); if (!co || (!co.published && !isStaff(c.user))) throw new HttpError(404, 'Course not found');
    const s = getSettings();
    const modules = filt('modules', (m) => m.course_id === id).sort(byPos).map((m) => ({ id: m.id, title: m.title, description: m.description, lessons: filt('lessons', (l) => l.module_id === m.id).sort(byPos).map((l) => ({ id: l.id, title: l.title, description: l.description, videoUrl: l.video_url || (l.audio_url ? '' : s.defaultVideoUrl), audioUrl: l.audio_url, isDefaultVideo: !l.video_url && !l.audio_url, attachments: l.attachments || [], completed: false })) }));
    return { course: { id: co.id, title: co.title, instructor: co.instructor, description: co.description, category: co.category }, modules, exams: filt('exams', (e) => e.course_id === id && e.published).map(examSummary), progress: { total: 0, done: 0, percent: 0 }, certificate: null, eligibility: null };
  });
  R('POST', '/api/lessons/:id/complete', 'student', (c) => {
    const l = find('lessons', (x) => x.id === Number(c.params.id)); if (!l || !canAccess(c.user, l.course_id)) throw new HttpError(403, 'Not allowed');
    if (c.body.completed === false) rm('progress', (p) => p.user_id === c.user.id && p.lesson_id === l.id); else if (!find('progress', (p) => p.user_id === c.user.id && p.lesson_id === l.id)) db.progress.push({ user_id: c.user.id, lesson_id: l.id, completed_at: now() });
    return { progress: courseProgress(c.user.id, l.course_id) };
  });
  R('POST', '/api/payments', 'student', (c) => {
    const f = c.body; const co = find('courses', (x) => x.id === Number(f.courseId) && x.published); if (!co || co.type !== 'PAID') throw bad('Course not found or not a paid course');
    if (isEnrolled(c.user.id, co.id)) throw bad('You are already enrolled in this course');
    if (find('payments', (p) => p.user_id === c.user.id && p.course_id === co.id && p.status === 'PENDING')) throw bad('You already have a payment awaiting review for this course');
    const reference = U.str(f.reference, { name: 'Transaction reference', max: 100, min: 3, required: true }); if (find('payments', (p) => p.method === 'MANUAL' && p.reference === reference)) throw bad('This transaction reference has already been submitted');
    const amount = U.num(f.amount, { name: 'Amount paid', min: 1, max: 1e9 }); const currency = U.oneOf(String(f.currency || 'NGN').toUpperCase(), CURRENCIES, 'Currency'); const file = c.files[0]; if (!file) throw bad('Please attach your proof of payment (screenshot or PDF)');
    const p = ins('payments', { user_id: c.user.id, course_id: co.id, method: 'MANUAL', reference, amount, currency, proof_file: storeFile_(file, false), proof_name: file.filename.slice(0, 120), status: 'PENDING', admin_notes: '', reviewed_by: null, created_at: now(), reviewed_at: null }); return { ok: true, id: p.id };
  });
  R('GET', '/api/me/payments', 'user', (c) => ({ payments: filt('payments', (p) => p.user_id === c.user.id).sort((a, b) => b.id - a.id).map((p) => { const co = find('courses', (x) => x.id === p.course_id) || {}; return { id: p.id, method: p.method, reference: p.reference, amount: p.amount, currency: p.currency, status: p.status, notes: p.admin_notes, createdAt: p.created_at, proofName: p.proof_name, courseTitle: co.title, courseId: co.id }; }) }));
  R('GET', '/api/me/exams', 'approved', (c) => { if (isStaff(c.user)) return { exams: [] }; expireAttempts(c.user.id); return { exams: filt('exams', (e) => e.published && isEnrolled(c.user.id, e.course_id)).sort((a, b) => b.id - a.id).map((e) => ({ ...examStatusForUser(e, c.user.id), courseTitle: (find('courses', (x) => x.id === e.course_id) || {}).title })) }; });
  const examSummary = (e) => ({ id: e.id, title: e.title, courseId: e.course_id, moduleId: e.module_id, instructions: e.instructions, durationMinutes: e.duration_minutes, startAt: e.start_at, endAt: e.end_at, passMark: e.pass_mark, maxAttempts: 0, required: !!e.required, window: examWindow(e), questionCount: filt('questions', (q) => q.exam_id === e.id).length, attemptsUsed: 0, attemptsLeft: null, bestPercent: null, passed: false, inProgressId: null, lastAttemptId: null });
  const questionsFor = (a) => { const qs = filt('questions', (q) => q.exam_id === a.exam_id); const m = new Map(qs.map((q) => [q.id, q])); return a.question_order.map((id) => m.get(id)).filter(Boolean).map((q) => ({ id: q.id, text: q.text, type: q.type, options: q.options, points: q.points })); };
  R('POST', '/api/exams/:id/start', null, (c) => {
    const exam = find('exams', (x) => x.id === Number(c.params.id) && x.published); if (!exam) throw new HttpError(404, 'This exam is not available');
    const name = U.str(c.body.name, { name: 'Your full name', min: 3, max: 120, required: true });
    const w = examWindow(exam); if (w === 'UPCOMING') throw bad(`This exam opens on ${new Date(exam.start_at).toUTCString()}`); if (w === 'CLOSED') throw bad('This exam is closed');
    const ids = filt('questions', (q) => q.exam_id === exam.id).sort(byPos).map((q) => q.id); if (!ids.length) throw bad('This exam has no questions yet');
    if (exam.shuffle) for (let i = ids.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [ids[i], ids[j]] = [ids[j], ids[i]]; }
    rm('attempts', (a) => Date.now() - Date.parse(a.started_at) > 120 * 86400000);
    const st = Date.now(); let dl = st + exam.duration_minutes * 60000; if (exam.end_at) dl = Math.min(dl, Date.parse(exam.end_at));
    const key = crypto.randomBytes(9).toString('hex');
    ins('attempts', { key, exam_id: exam.id, user_id: null, student_name: name, started_at: new Date(st).toISOString(), deadline: new Date(dl).toISOString(), submitted_at: null, status: 'IN_PROGRESS', score: null, max_score: null, percent: null, passed: null, answers: {}, question_order: ids });
    return { attemptId: key };
  });
  function loadAttempt(c) { const a = find('attempts', (x) => x.key === String(c.params.id)); if (!a) throw new HttpError(404, 'Attempt not found'); if (a.status === 'IN_PROGRESS' && Date.parse(a.deadline) < Date.now()) return finalizeAttempt(a.id, 'EXPIRED'); return a; }
  const mergeAnswers = (a, ans) => { const valid = new Set(a.question_order); for (const [k, v] of Object.entries(ans || {})) if (valid.has(Number(k)) && Number.isInteger(v) && v >= 0 && v < 10) a.answers[k] = v; };
  R('GET', '/api/attempts/:id', null, (c) => {
    const a = loadAttempt(c); const exam = find('exams', (x) => x.id === a.exam_id);
    const base = { id: a.key, status: a.status, startedAt: a.started_at, deadline: a.deadline, serverNow: now(), exam: { id: exam.id, title: exam.title, courseId: exam.course_id, instructions: exam.instructions, passMark: exam.pass_mark, durationMinutes: exam.duration_minutes } };
    if (a.status === 'IN_PROGRESS') return { ...base, questions: questionsFor(a), answers: a.answers };
    const result = { score: a.score, maxScore: a.max_score, percent: a.percent, passed: !!a.passed, submittedAt: a.submitted_at, attemptsLeft: null }; let review = null;
    if (a.passed) review = filt('questions', (q) => q.exam_id === exam.id).sort(byPos).map((q) => ({ id: q.id, text: q.text, options: q.options, correct: q.correct, explanation: q.explanation, yourAnswer: a.answers[q.id] ?? null }));
    const ce = find('certificates', (x) => x.attempt_key === a.key && x.status === 'ISSUED');
    return { ...base, result, review, certificate: ce ? certView(ce.cert_no) : null };
  });
  R('PUT', '/api/attempts/:id/answers', null, (c) => { const a = loadAttempt(c); if (a.status !== 'IN_PROGRESS') throw bad('This attempt is already finished', { finished: true }); mergeAnswers(a, c.body.answers); return { saved: true }; });
  R('POST', '/api/attempts/:id/submit', null, (c) => { const a = loadAttempt(c); if (a.status === 'IN_PROGRESS') { mergeAnswers(a, c.body.answers); finalizeAttempt(a.id, 'SUBMITTED'); } return { attemptId: a.key }; });

  // ======= admin: courses / modules / lessons =======
  const courseBody = (b, s) => { const type = 'FREE'; return { title: U.str(b.title, { name: 'Course title', max: 200, required: true }), category: U.str(b.category, { name: 'Category', max: 80 }) || 'Islamic Studies', type, price: type === 'PAID' ? U.num(b.price, { name: 'Price', min: 0, max: 1e9 }) : 0, currency: U.oneOf(String(b.currency || s.defaultCurrency || 'NGN').toUpperCase(), CURRENCIES, 'Currency'), discount_pct: type === 'PAID' ? U.num(b.discountPct, { name: 'Discount', min: 0, max: 100, def: 0 }) : 0, instructor: U.str(b.instructor, { name: 'Instructor', max: 120 }) || s.founderName, description: U.str(b.description, { name: 'Description', max: 6000 }), image: U.str(b.image, { max: 2000000, name: 'Cover image' }), published: U.bool(b.published) ? 1 : 0 }; };
  const touch = (id) => { const c = find('courses', (x) => x.id === id); if (c) c.updated_at = now(); };
  R('GET', '/api/admin/courses', 'staff', () => ({ courses: db.courses.slice().sort((a, b) => b.id - a.id).map((c) => ({ ...c, modules: filt('modules', (m) => m.course_id === c.id).length, lessons: filt('lessons', (l) => l.course_id === c.id).length, exams: filt('exams', (e) => e.course_id === c.id).length, students: filt('enrollments', (e) => e.course_id === c.id).length, finalPrice: U.finalPrice(c) })) }));
  R('GET', '/api/admin/courses/:id', 'staff', (c) => {
    const co = find('courses', (x) => x.id === Number(c.params.id)); if (!co) throw new HttpError(404, 'Course not found');
    return { course: co, modules: filt('modules', (m) => m.course_id === co.id).sort(byPos).map((m) => ({ ...m, lessons: filt('lessons', (l) => l.module_id === m.id).sort(byPos).map((l) => ({ ...l, attachments: l.attachments || [] })) })), exams: filt('exams', (e) => e.course_id === co.id).map((e) => ({ ...e, question_count: filt('questions', (q) => q.exam_id === e.id).length })), defaultVideoUrl: getSettings().defaultVideoUrl };
  });
  R('POST', '/api/admin/courses', 'staff', (c) => { const b = courseBody(c.body, getSettings()); const co = ins('courses', { ...b, created_by: c.user.id, created_at: now(), updated_at: now() }); ins('modules', { course_id: co.id, title: 'Module 1', description: '', position: 0 }); return { id: co.id }; });
  R('PUT', '/api/admin/courses/:id', 'staff', (c) => { const co = find('courses', (x) => x.id === Number(c.params.id)); if (!co) throw new HttpError(404, 'Course not found'); Object.assign(co, courseBody(c.body, getSettings()), { updated_at: now() }); return { ok: true }; });
  R('DELETE', '/api/admin/courses/:id', 'staff', (c) => {
    const id = Number(c.params.id); const enrolled = filt('enrollments', (e) => e.course_id === id).length, certs = filt('certificates', (x) => x.course_id === id).length;
    if ((enrolled || certs) && c.query.get('force') !== '1') throw new HttpError(409, `This course has ${enrolled} enrolled student(s) and ${certs} certificate(s). Deleting it removes all of that data.`, { needsForce: true, enrolled, certs });
    if (c.query.get('force') === '1' && c.user.role !== 'SUPER_ADMIN' && (enrolled || certs)) throw new HttpError(403, 'Only the Super Admin can delete a course that has students or certificates');
    delCourse(id); return { ok: true };
  });
  R('POST', '/api/admin/courses/:id/modules', 'staff', (c) => { const cid = Number(c.params.id); if (!find('courses', (x) => x.id === cid)) throw new HttpError(404, 'Course not found'); const pos = filt('modules', (m) => m.course_id === cid).reduce((m, x) => Math.max(m, x.position), -1) + 1; const m = ins('modules', { course_id: cid, title: U.str(c.body.title, { name: 'Module title', max: 200, required: true }), description: U.str(c.body.description, { max: 1000 }), position: pos }); touch(cid); return { id: m.id }; });
  R('PUT', '/api/admin/modules/:id', 'staff', (c) => { const m = find('modules', (x) => x.id === Number(c.params.id)); if (!m) throw new HttpError(404, 'Module not found'); m.title = U.str(c.body.title, { name: 'Module title', max: 200, required: true }); m.description = U.str(c.body.description, { max: 1000 }); touch(m.course_id); return { ok: true }; });
  R('DELETE', '/api/admin/modules/:id', 'staff', (c) => { const m = find('modules', (x) => x.id === Number(c.params.id)); if (!m) throw new HttpError(404, 'Module not found'); delModule(m.id); touch(m.course_id); return { ok: true }; });
  const lessonBody = (b) => ({ title: U.str(b.title, { name: 'Lesson title', max: 200, required: true }), description: U.str(b.description, { max: 5000 }), video_url: U.url(b.videoUrl, { name: 'Video link' }), audio_url: U.url(b.audioUrl, { name: 'Audio link' }), attachments: (Array.isArray(b.attachments) ? b.attachments.slice(0, 20) : []).filter((a) => a && a.url).map((a) => ({ name: U.str(a.name, { max: 120 }) || 'Download', url: U.url(a.url, { name: 'Attachment link' }) })) });
  R('POST', '/api/admin/modules/:id/lessons', 'staff', (c) => { const m = find('modules', (x) => x.id === Number(c.params.id)); if (!m) throw new HttpError(404, 'Module not found'); const b = lessonBody(c.body); const pos = filt('lessons', (l) => l.module_id === m.id).reduce((a, x) => Math.max(a, x.position), -1) + 1; const l = ins('lessons', { module_id: m.id, course_id: m.course_id, ...b, position: pos }); touch(m.course_id); return { id: l.id }; });
  R('PUT', '/api/admin/lessons/:id', 'staff', (c) => { const l = find('lessons', (x) => x.id === Number(c.params.id)); if (!l) throw new HttpError(404, 'Lesson not found'); Object.assign(l, lessonBody(c.body)); touch(l.course_id); return { ok: true }; });
  R('DELETE', '/api/admin/lessons/:id', 'staff', (c) => { const l = find('lessons', (x) => x.id === Number(c.params.id)); if (!l) throw new HttpError(404, 'Lesson not found'); delLesson(l.id); touch(l.course_id); return { ok: true }; });
  R('POST', '/api/admin/reorder', 'staff', (c) => {
    const ids = (Array.isArray(c.body.ids) ? c.body.ids : []).map(Number).filter(Number.isInteger);
    if (c.body.type === 'modules') ids.forEach((id, i) => { const m = find('modules', (x) => x.id === id); if (m) m.position = i; });
    else if (c.body.type === 'lessons') { const m = find('modules', (x) => x.id === Number(c.body.moduleId)); if (!m) throw bad('Module not found'); ids.forEach((id, i) => { const l = find('lessons', (x) => x.id === id); if (l) { l.position = i; l.module_id = m.id; l.course_id = m.course_id; } }); } else throw bad('Unknown reorder type');
    return { ok: true };
  });

  // ======= admin: exams =======
  const isoOrNull = (v, name) => { if (!v) return null; const t = Date.parse(v); if (Number.isNaN(t)) throw bad(`${name} is not a valid date`); return new Date(t).toISOString(); };
  const examBody = (b) => {
    const co = find('courses', (x) => x.id === Number(b.courseId)); if (!co) throw bad('Please choose a course for this exam'); let moduleId = null;
    if (b.moduleId) { const m = find('modules', (x) => x.id === Number(b.moduleId) && x.course_id === co.id); if (!m) throw bad('That module does not belong to the chosen course'); moduleId = m.id; }
    const start = isoOrNull(b.startAt, 'Start date'), end = isoOrNull(b.endAt, 'End date'); if (start && end && Date.parse(end) <= Date.parse(start)) throw bad('The end date must be after the start date');
    return { course_id: co.id, module_id: moduleId, title: U.str(b.title, { name: 'Exam title', max: 200, required: true }), instructions: U.str(b.instructions, { max: 3000 }), duration_minutes: U.int(b.durationMinutes, { name: 'Duration', min: 1, max: 600, def: 30 }), start_at: start, end_at: end, pass_mark: U.num(b.passMark, { name: 'Pass mark', min: 0, max: 100, def: 50 }), max_attempts: U.int(b.maxAttempts, { name: 'Maximum attempts', min: 0, max: 50, def: 0 }), shuffle: U.bool(b.shuffle) ? 1 : 0, required: U.bool(b.required) ? 1 : 0, published: U.bool(b.published) ? 1 : 0 };
  };
  R('GET', '/api/admin/exams', 'staff', () => ({ exams: db.exams.slice().sort((a, b) => b.id - a.id).map((e) => { const co = find('courses', (x) => x.id === e.course_id) || {}, m = find('modules', (x) => x.id === e.module_id); return { ...e, course_title: co.title, module_title: m ? m.title : null, question_count: filt('questions', (q) => q.exam_id === e.id).length, attempt_count: filt('attempts', (a) => a.exam_id === e.id && a.status !== 'IN_PROGRESS').length }; }) }));
  R('GET', '/api/admin/exams/:id', 'staff', (c) => { const e = find('exams', (x) => x.id === Number(c.params.id)); if (!e) throw new HttpError(404, 'Exam not found'); return { exam: e, questions: filt('questions', (q) => q.exam_id === e.id).sort(byPos) }; });
  R('POST', '/api/admin/exams', 'staff', (c) => { const b = examBody(c.body); if (b.published) throw bad('Add questions first, then publish the exam.'); const e = ins('exams', { ...b, published: 0, created_by: c.user.id, created_at: now() }); return { id: e.id }; });
  R('PUT', '/api/admin/exams/:id', 'staff', (c) => { const e = find('exams', (x) => x.id === Number(c.params.id)); if (!e) throw new HttpError(404, 'Exam not found'); const b = examBody(c.body); if (b.published && !find('questions', (q) => q.exam_id === e.id)) throw bad('Add at least one question before publishing'); Object.assign(e, b); return { ok: true }; });
  R('DELETE', '/api/admin/exams/:id', 'staff', (c) => { delExam(Number(c.params.id)); return { ok: true }; });
  const questionBody = (b) => {
    const type = U.oneOf(b.type || 'MCQ', ['MCQ', 'TF'], 'Question type'); let options;
    if (type === 'TF') options = ['True', 'False']; else { options = (Array.isArray(b.options) ? b.options : []).map((o) => U.str(o, { max: 300 })).filter(Boolean); if (options.length < 2 || options.length > 6) throw bad('A multiple-choice question needs between 2 and 6 options'); }
    return { text: U.str(b.text, { name: 'Question', max: 1500, required: true }), type, options, correct: U.int(b.correct, { name: 'Correct answer', min: 0, max: options.length - 1 }), points: U.num(b.points, { name: 'Points', min: 0.5, max: 100, def: 1 }), explanation: U.str(b.explanation, { max: 1000 }) };
  };
  R('POST', '/api/admin/exams/:id/questions', 'staff', (c) => { const id = Number(c.params.id); if (!find('exams', (x) => x.id === id)) throw new HttpError(404, 'Exam not found'); const q = questionBody(c.body); const pos = filt('questions', (x) => x.exam_id === id).reduce((a, x) => Math.max(a, x.position), -1) + 1; return { id: ins('questions', { exam_id: id, ...q, position: pos }).id }; });
  R('PUT', '/api/admin/questions/:id', 'staff', (c) => { const q = find('questions', (x) => x.id === Number(c.params.id)); if (!q) throw new HttpError(404, 'Question not found'); Object.assign(q, questionBody(c.body)); return { ok: true }; });
  R('DELETE', '/api/admin/questions/:id', 'staff', (c) => { const q = find('questions', (x) => x.id === Number(c.params.id)); if (!q) throw new HttpError(404, 'Question not found'); rm('questions', (x) => x.id === q.id); if (!find('questions', (x) => x.exam_id === q.exam_id)) { const e = find('exams', (x) => x.id === q.exam_id); if (e) e.published = 0; } return { ok: true }; });
  R('GET', '/api/admin/exams/:id/attempts', 'staff', (c) => { expireAttempts(); return { attempts: filt('attempts', (a) => a.exam_id === Number(c.params.id)).sort((a, b) => b.id - a.id).map((a) => ({ id: a.id, status: a.status, percent: a.percent, score: a.score, maxScore: a.max_score, passed: a.passed, startedAt: a.started_at, submittedAt: a.submitted_at, studentName: a.student_name, regNumber: '' })) }; });

  // ======= admin: uploads (images are stored on this phone) =======
  R('POST', '/api/admin/upload-image', 'staff', (c) => { const f = c.files[0]; if (!f) throw bad('No file uploaded'); return { url: pubUrl_(storeFile_(f, true)) }; });
  const SLOTS = { logo: 'logo', seal: 'seal', signature: 'signature', founderPhoto: 'founderPhoto', certLogo0: 0, certLogo1: 1, certLogo2: 2 };
  R('POST', '/api/admin/upload/:slot', 'super', (c) => {
    const slot = c.params.slot; if (!(slot in SLOTS)) throw bad('Unknown image slot'); const f = c.files[0]; if (!f) throw bad('No file uploaded'); const s = getSettings(); const furl = pubUrl_(storeFile_(f, true));
    if (typeof SLOTS[slot] === 'string') setSetting(SLOTS[slot], furl); else { const arr = [...(s.cert.extraLogos || [])]; arr[SLOTS[slot]] = furl; setSetting('cert', { ...s.cert, extraLogos: arr.filter((x) => x !== undefined) }); }
    return { url: furl };
  });
  R('DELETE', '/api/admin/upload/:slot', 'super', (c) => {
    const slot = c.params.slot; if (!(slot in SLOTS)) throw bad('Unknown image slot'); const s = getSettings();
    if (typeof SLOTS[slot] === 'string') setSetting(SLOTS[slot], DEFAULT_IMG[slot]); else { const arr = [...(s.cert.extraLogos || [])]; arr.splice(SLOTS[slot], 1); setSetting('cert', { ...s.cert, extraLogos: arr }); }
    return { ok: true };
  });

  // ======= admin: stats / students =======
  R('GET', '/api/admin/stats', 'staff', (c) => {
    const base = { courses: db.courses.length, lessons: db.lessons.length, exams: db.exams.length }; if (c.user.role !== 'SUPER_ADMIN') return base;
    const sum = (arr) => arr.reduce((s, x) => s + x.amount, 0);
    return { ...base, students: filt('users', (u) => u.role === 'STUDENT').length, pendingStudents: filt('users', (u) => u.role === 'STUDENT' && u.status === 'PENDING').length, pendingPayments: filt('payments', (p) => p.status === 'PENDING').length, pendingCerts: filt('certificates', (x) => x.status === 'REQUESTED').length, issuedCerts: filt('certificates', (x) => x.status === 'ISSUED').length, pendingDonations: filt('donations', (d) => d.status === 'PENDING').length, donationsNgn: sum(filt('donations', (d) => d.status === 'CONFIRMED' && d.currency === 'NGN')), revenueNgn: sum(filt('payments', (p) => p.status === 'APPROVED' && p.currency === 'NGN')), unreadMessages: filt('messages', (m) => !m.is_read).length };
  });
  R('GET', '/api/admin/students', 'super', (c) => {
    const q = String(c.query.get('q') || '').trim().toLowerCase(), st = String(c.query.get('status') || '');
    return { students: filt('users', (u) => u.role === 'STUDENT' && (!st || u.status === st) && (!q || [u.full_name, u.email, u.reg_number].some((v) => String(v || '').toLowerCase().includes(q)))).sort((a, b) => b.id - a.id).slice(0, 500).map((u) => ({ id: u.id, email: u.email, full_name: u.full_name, reg_number: u.reg_number, status: u.status, phone: u.phone, country: u.country, language: u.language, created_at: u.created_at, last_login_at: u.last_login_at, courses: filt('enrollments', (e) => e.user_id === u.id).length })) };
  });
  R('GET', '/api/admin/students/:id', 'super', (c) => {
    const id = Number(c.params.id); const u = find('users', (x) => x.id === id && x.role === 'STUDENT'); if (!u) throw new HttpError(404, 'Student not found');
    const courses = filt('enrollments', (e) => e.user_id === id).map((e) => { const co = find('courses', (x) => x.id === e.course_id); if (!co) return null; const ls = filt('lessons', (l) => l.course_id === co.id), ids = new Set(ls.map((l) => l.id)); return { id: co.id, title: co.title, source: e.source, enrolledAt: e.created_at, lessonsTotal: ls.length, lessonsDone: filt('progress', (p) => p.user_id === id && ids.has(p.lesson_id)).length }; }).filter(Boolean);
    const attempts = filt('attempts', (a) => a.user_id === id).sort((a, b) => b.id - a.id).map((a) => ({ id: a.id, percent: a.percent, passed: a.passed, status: a.status, submittedAt: a.submitted_at, examTitle: (find('exams', (e) => e.id === a.exam_id) || {}).title }));
    return { student: U.publicUser(u), lastLoginAt: u.last_login_at, courses, attempts };
  });
  R('PUT', '/api/admin/students/:id', 'super', (c) => { const st = U.oneOf(c.body.status, ['PENDING', 'APPROVED', 'REJECTED', 'SUSPENDED'], 'Status'); const u = find('users', (x) => x.id === Number(c.params.id) && x.role === 'STUDENT'); if (!u) throw new HttpError(404, 'Student not found'); u.status = st; if (st === 'SUSPENDED' || st === 'REJECTED') u.token_version++; return { ok: true }; });
  R('DELETE', '/api/admin/students/:id', 'super', (c) => { const u = find('users', (x) => x.id === Number(c.params.id) && x.role === 'STUDENT'); if (!u) throw new HttpError(404, 'Student not found'); delUser(u.id); return { ok: true }; });
  R('POST', '/api/admin/students/:id/enroll', 'super', (c) => { const u = find('users', (x) => x.id === Number(c.params.id) && x.role === 'STUDENT'), co = find('courses', (x) => x.id === Number(c.body.courseId)); if (!u || !co) throw new HttpError(404, 'Student or course not found'); enroll(u.id, co.id, 'ADMIN'); return { ok: true }; });
  R('DELETE', '/api/admin/students/:id/enroll/:courseId', 'super', (c) => { rm('enrollments', (e) => e.user_id === Number(c.params.id) && e.course_id === Number(c.params.courseId)); return { ok: true }; });
  R('POST', '/api/admin/users/:id/reset-password', 'super', (c) => { const pw = U.str(c.body.password, { name: 'New password', min: 8, max: 200, required: true }); const u = find('users', (x) => x.id === Number(c.params.id) && x.id !== c.user.id); if (!u) throw new HttpError(404, 'User not found (you cannot reset your own password here — use Change Password)'); u.password_hash = hashPw(pw); u.token_version++; return { ok: true }; });

  // ======= admin: payments / donations / certificates / messages =======
  R('GET', '/api/admin/payments', 'super', (c) => { const st = String(c.query.get('status') || ''); return { payments: filt('payments', (p) => !st || p.status === st).sort((a, b) => (b.status === 'PENDING') - (a.status === 'PENDING') || b.id - a.id).slice(0, 500).map((p) => { const u = find('users', (x) => x.id === p.user_id) || {}, co = find('courses', (x) => x.id === p.course_id) || {}; return { id: p.id, method: p.method, reference: p.reference, amount: p.amount, currency: p.currency, status: p.status, notes: p.admin_notes, createdAt: p.created_at, reviewedAt: p.reviewed_at, hasProof: !!p.proof_file, proofName: p.proof_name, studentName: u.full_name, regNumber: u.reg_number, email: u.email, courseTitle: co.title, coursePrice: co.price, courseCurrency: co.currency, discountPct: co.discount_pct, courseType: co.type, expected: U.finalPrice(co) }; }) }; });
  R('PUT', '/api/admin/payments/:id', 'super', (c) => {
    const decision = U.oneOf(c.body.decision, ['APPROVED', 'REJECTED'], 'Decision'); const notes = U.str(c.body.notes, { max: 500 }); const p = find('payments', (x) => x.id === Number(c.params.id));
    if (!p) throw new HttpError(404, 'Payment not found'); if (p.status !== 'PENDING') throw bad('This payment was already reviewed');
    Object.assign(p, { status: decision, admin_notes: notes, reviewed_by: c.user.id, reviewed_at: now() }); if (decision === 'APPROVED') enroll(p.user_id, p.course_id, 'PAID'); return { ok: true };
  });
  R('GET', '/api/admin/donations', 'super', () => ({ donations: db.donations.slice().sort((a, b) => (b.status === 'PENDING') - (a.status === 'PENDING') || b.id - a.id).slice(0, 500).map((d) => ({ id: d.id, donorName: d.donor_name, email: d.email, phone: d.phone, amount: d.amount, currency: d.currency, note: d.note, method: d.method, reference: d.reference, hasProof: !!d.proof_file, proofName: d.proof_name, status: d.status, notes: d.admin_notes, createdAt: d.created_at })) }));
  R('PUT', '/api/admin/donations/:id', 'super', (c) => { const decision = U.oneOf(c.body.decision, ['CONFIRMED', 'REJECTED'], 'Decision'); const d = find('donations', (x) => x.id === Number(c.params.id) && x.status === 'PENDING'); if (!d) throw bad('Donation not found or already reviewed'); Object.assign(d, { status: decision, admin_notes: U.str(c.body.notes, { max: 500 }), reviewed_at: now() }); return { ok: true }; });
  R('GET', '/api/admin/certificates', 'super', () => ({ certificates: db.certificates.slice().sort((a, b) => b.id - a.id).slice(0, 500).map((x) => { const u = x.user_id ? find('users', (k) => k.id === x.user_id) : null, co = find('courses', (k) => k.id === x.course_id) || {}; return { id: x.id, certNo: x.cert_no, status: x.status, finalPercent: x.final_percent, requestedAt: x.requested_at, issuedAt: x.issued_at, studentName: x.student_name || (u && u.full_name), regNumber: u ? u.reg_number : '', courseTitle: co.title }; }) }));
  R('POST', '/api/admin/certificates/:id/issue', 'super', (c) => ({ certNo: issueCert(Number(c.params.id), c.user.id).cert_no }));
  R('POST', '/api/admin/certificates/:id/revoke', 'super', (c) => { const x = find('certificates', (k) => k.id === Number(c.params.id)); if (!x) throw new HttpError(404, 'Certificate not found'); x.status = 'REVOKED'; return { ok: true }; });
  R('GET', '/api/admin/messages', 'super', () => ({ messages: db.messages.slice().sort((a, b) => b.id - a.id).slice(0, 300).map((m) => ({ id: m.id, name: m.name, email: m.email, body: m.body, isRead: m.is_read, createdAt: m.created_at })) }));
  R('PUT', '/api/admin/messages/:id', 'super', (c) => { const m = find('messages', (x) => x.id === Number(c.params.id)); if (m) m.is_read = 1; return { ok: true }; });
  R('DELETE', '/api/admin/messages/:id', 'super', (c) => { rm('messages', (x) => x.id === Number(c.params.id)); return { ok: true }; });

  // ======= admin: staff =======
  R('GET', '/api/admin/staff', 'super', () => ({ staff: filt('users', (u) => u.role === 'ADMIN').sort((a, b) => b.id - a.id).map((u) => ({ id: u.id, email: u.email, fullName: u.full_name, phone: u.phone, status: u.status, role: u.role, createdAt: u.created_at, lastLoginAt: u.last_login_at })) }));
  R('POST', '/api/admin/staff', 'super', (c) => { const b = c.body; const email = U.email(b.email); if (find('users', (u) => u.email === email)) throw bad('An account with this email already exists'); const pw = U.str(b.password, { name: 'Password', min: 8, max: 200, required: true }); const u = ins('users', { email, password_hash: hashPw(pw), full_name: U.str(b.fullName, { name: 'Full name', min: 3, max: 120, required: true }), reg_number: null, role: 'ADMIN', status: 'APPROVED', phone: U.str(b.phone, { max: 40 }), country: U.str(b.country, { max: 80 }), language: 'English', token_version: 0, created_at: now(), last_login_at: null }); return { id: u.id }; });
  R('PUT', '/api/admin/staff/:id', 'super', (c) => { const st = U.oneOf(c.body.status, ['APPROVED', 'SUSPENDED'], 'Status'); const u = find('users', (x) => x.id === Number(c.params.id) && x.role === 'ADMIN'); if (!u) throw new HttpError(404, 'Admin not found'); u.status = st; u.token_version++; return { ok: true }; });
  R('DELETE', '/api/admin/staff/:id', 'super', (c) => { const u = find('users', (x) => x.id === Number(c.params.id) && x.role === 'ADMIN'); if (!u) throw new HttpError(404, 'Admin not found'); delUser(u.id); return { ok: true }; });

  // ======= admin: receipts + backup =======
  R('GET', '/api/admin/payments/:id/proof', 'super', (c) => { const p = find('payments', (x) => x.id === Number(c.params.id)); if (!p || !p.proof_file) throw new HttpError(404, 'No proof file'); return { dataUrl: readFile_(p.proof_file) }; });
  R('GET', '/api/admin/donations/:id/proof', 'super', (c) => { const d = find('donations', (x) => x.id === Number(c.params.id)); if (!d || !d.proof_file) throw new HttpError(404, 'No proof file'); return { dataUrl: readFile_(d.proof_file) }; });
  R('GET', '/api/admin/backup', 'super', () => ({ telegram: false, last: db.settings._backup || null }));
  R('POST', '/api/admin/backup/run', 'super', () => { db.settings._backup = { at: now(), size: JSON.stringify(db).length, sent: false }; BACKUP_NOW = true; return { ok: true, sent: false, telegram: false }; });
  R('GET', '/api/admin/backup/export', 'super', () => ({ json: JSON.stringify(db) }));
  R('POST', '/api/admin/backup/restore', 'super', (c) => {
    const f = c.files[0]; if (!f) throw bad('Choose a backup file (.json)'); let d;
    try { d = JSON.parse(Buffer.from(f.dataUrl.split(',')[1], 'base64').toString('utf8')); if (!d.users || !d.seq) throw 0; } catch (_) { throw bad('This is not a valid backup file'); }
    TABLES.forEach((t) => { d[t] = d[t] || []; }); db = d; return { ok: true, message: 'Backup restored. Reloading…' };
  });
  R('GET', '/api/admin/settings', 'super', () => ({ settings: getSettings(), paystack: false }));
  R('PUT', '/api/admin/settings', 'super', (c) => {
    const b = c.body; const cur = getSettings(); const text = { siteName: 120, siteNameAr: 120, tagline: 200, taglineAr: 200, founderName: 120, founderTitle: 200, founderBio: 3000, announcement: 400, phone: 40, whatsapp: 20 };
    for (const [k, max] of Object.entries(text)) if (b[k] !== undefined) setSetting(k, U.str(b[k], { max, name: k }));
    if (b.email !== undefined) setSetting('email', U.email(b.email)); if (b.defaultVideoUrl !== undefined) setSetting('defaultVideoUrl', U.url(b.defaultVideoUrl, { name: 'Default video link' }));
    if (b.defaultCurrency !== undefined) setSetting('defaultCurrency', U.oneOf(String(b.defaultCurrency).toUpperCase(), CURRENCIES, 'Currency'));
    if (b.social) setSetting('social', Object.fromEntries(['facebook', 'youtube', 'telegram', 'tiktok'].map((k) => [k, U.url(b.social[k], { name: k })])));
    if (b.maintenance) setSetting('maintenance', { on: U.bool(b.maintenance.on), message: U.str(b.maintenance.message, { max: 500 }) });
    if (b.bank) setSetting('bank', { provider: U.str(b.bank.provider, { max: 80 }), accountNumber: U.str(b.bank.accountNumber, { max: 40 }), accountName: U.str(b.bank.accountName, { max: 120 }), international: U.str(b.bank.international, { max: 600 }) });
    if (b.donation) setSetting('donation', { title: U.str(b.donation.title, { max: 120 }), message: U.str(b.donation.message, { max: 1500 }), presets: (Array.isArray(b.donation.presets) ? b.donation.presets : cur.donation.presets).map(Number).filter((n) => n > 0 && n < 1e9).slice(0, 8) });
    if (b.cert) setSetting('cert', { ...cur.cert, signatoryName: U.str(b.cert.signatoryName, { max: 120 }), signatoryTitle: U.str(b.cert.signatoryTitle, { max: 160 }), language: U.oneOf(b.cert.language || 'English', ['English', 'Arabic', 'Hausa'], 'Certificate language'), autoIssue: U.bool(b.cert.autoIssue) });
    if (Array.isArray(b.categories)) setSetting('categories', b.categories.map((x) => U.str(x, { max: 80 })).filter(Boolean).slice(0, 30));
    return { ok: true };
  });

  // ---------- request handler ----------
  const loginFails = new Map();
  async function handleAsync(req) {
    const method = String(req.method || 'GET').toUpperCase(), path = String(req.path || '');
    const query = req.query || {}; const q = { get: (k) => (query[k] === undefined || query[k] === null ? null : String(query[k])) };
    const body = req.body && typeof req.body === 'object' ? req.body : {}; const files = Array.isArray(req.files) ? req.files : [];
    TOKEN_OUT = undefined; BACKUP_NOW = false;
    for (const r of routes) {
      if (r.method !== method) continue; const m = r.re.exec(path); if (!m) continue;
      const params = {}; r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
      let lkey = null;
      try {
        await ensureSecret(); await loadDb();
        const pm = /^\/api\/admin\/(payments|donations)\/(\d+)\/proof$/.exec(path);
        if (pm) { const rec = find(pm[1], (x) => x.id === Number(pm[2])); if (rec && rec.proof_file) { const g = await store().getWithMetadata('priv/' + rec.proof_file, { type: 'arrayBuffer' }); if (g) preloaded[rec.proof_file] = { bytes: Buffer.from(g.data), mime: (g.metadata && g.metadata.mime) || 'application/octet-stream' }; } }
        let user = null; const s = readToken_(req.token);
        if (s) { const u = find('users', (x) => x.id === s.uid); if (u && u.token_version === s.v && u.status !== 'SUSPENDED' && u.status !== 'REJECTED') user = u; }
        const ctx = { user, params, query: q, body, files };
        const open = ['/api/public/bootstrap', '/api/auth/login', '/api/auth/logout', '/api/auth/me'];
        if (!isStaff(user) && !open.includes(path)) { const mm = getSettings().maintenance; if (mm && mm.on) throw new HttpError(503, mm.message || 'Maintenance', { maintenance: true }); }
        if (path === '/api/auth/login') { lkey = String(body.email || '').toLowerCase().slice(0, 100); const f = loginFails.get(lkey); if (f && f.n >= 10 && f.t > Date.now()) throw new HttpError(429, 'Too many attempts. Please wait 15 minutes and try again.'); }
        if (r.guard) GUARD[r.guard](ctx);
        let out;
        try { out = r.fn(ctx); } catch (e) { if (lkey && e instanceof HttpError && e.status === 401) { const f = loginFails.get(lkey); loginFails.set(lkey, { n: (f && f.t > Date.now() ? f.n : 0) + 1, t: Date.now() + 900000 }); } throw e; }
        if (method !== 'GET') { const b = db.settings._backup; if (BACKUP_NOW || !b || Date.now() - Date.parse(b.at) > 86400000) { try { await makeBackup_(); } catch (e) {} } }
        await saveDb();
        out = out === undefined ? { ok: true } : out;
        if (TOKEN_OUT !== undefined) out.token = TOKEN_OUT;
        return { status: 200, data: out };
      } catch (e) {
        if (e instanceof HttpError) return { status: e.status, data: Object.assign({ error: e.message }, e.extra) };
        console.error(e); return { status: 500, data: { error: 'Something went wrong: ' + (e && e.message) } };
      }
    }
    return { status: 404, data: { error: 'Not found' } };
  }
  async function makeBackup_() {
    const day = new Date().toISOString().slice(0, 10), data = JSON.stringify(db);
    await store().set('backups/' + day + '.json', data); db.settings._backup = { at: now(), size: data.length, sent: false };
    const l = await store().list({ prefix: 'backups/' }); const keys = (l.blobs || []).map((b) => b.key).sort();
    for (const k of keys.slice(0, Math.max(0, keys.length - 7))) await store().delete(k);
  }

// ======================= Netlify Function entry =======================
const CORS = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
export default async (req) => {
  const url = new URL(req.url);
  const fid = url.searchParams.get('file');
  if (fid) {
    if (!/^[a-f0-9]{24}$/.test(fid)) return new Response('Not found', { status: 404 });
    const g = await getStore({ name: 'academy', consistency: 'strong' }).getWithMetadata('pub/' + fid, { type: 'arrayBuffer' });
    if (!g) return new Response('Not found', { status: 404 });
    return new Response(g.data, { status: 200, headers: { 'Content-Type': (g.metadata && g.metadata.mime) || 'application/octet-stream', 'Cache-Control': 'public, max-age=31536000, immutable' } });
  }
  if (req.method !== 'POST') return new Response(JSON.stringify({ ok: true, service: 'Elzarandawy Islamic Academy API' }), { status: 200, headers: CORS });
  let body; try { body = await req.json(); } catch (e) { return new Response(JSON.stringify({ status: 400, data: { error: 'Bad request' } }), { status: 200, headers: CORS }); }
  const out = await handleAsync(body);
  return new Response(JSON.stringify(out), { status: 200, headers: CORS });
};
