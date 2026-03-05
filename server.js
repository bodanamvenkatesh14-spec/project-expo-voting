/**
 * ExpoVote Live – Main Server (NeDB, no MongoDB needed)
 */
require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Datastore = require('@seald-io/nedb');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'expovote_secret_2024';
const DATA_DIR = path.join(__dirname, 'data');
const MAX_VOTES_PER_IP = 3;

const db = {
  admins: new Datastore({ filename: path.join(DATA_DIR, 'admins.db'), autoload: true }),
  projects: new Datastore({ filename: path.join(DATA_DIR, 'projects.db'), autoload: true }),
  votes: new Datastore({ filename: path.join(DATA_DIR, 'votes.db'), autoload: true }),
  settings: new Datastore({ filename: path.join(DATA_DIR, 'settings.db'), autoload: true }),
};

db.votes.ensureIndex({ fieldName: 'ip_address' });
db.settings.ensureIndex({ fieldName: 'key', unique: true });

function dbFind(store, query) { return new Promise((res, rej) => store.find(query, (e, d) => e ? rej(e) : res(d))); }
function dbFindOne(store, query) { return new Promise((res, rej) => store.findOne(query, (e, d) => e ? rej(e) : res(d))); }
function dbInsert(store, doc) { return new Promise((res, rej) => store.insert(doc, (e, d) => e ? rej(e) : res(d))); }
function dbUpdate(store, q, upd, opts) { return new Promise((res, rej) => store.update(q, upd, opts || {}, (e, n) => e ? rej(e) : res(n))); }
function dbRemove(store, q, opts) { return new Promise((res, rej) => store.remove(q, opts || {}, (e, n) => e ? rej(e) : res(n))); }
function dbCount(store, q) { return new Promise((res, rej) => store.count(q, (e, n) => e ? rej(e) : res(n))); }
function dbFindSorted(store, q, sort, limit) {
  return new Promise((res, rej) => {
    let c = store.find(q).sort(sort);
    if (limit) c = c.limit(limit);
    c.exec((e, d) => e ? rej(e) : res(d));
  });
}

async function seed() {
  // Remove old 'admin' account if it exists, replace with 'venky'
  const oldAdmin = await dbFindOne(db.admins, { username: 'admin' });
  if (oldAdmin) await dbRemove(db.admins, { username: 'admin' }, {});
  const existing = await dbFindOne(db.admins, { username: 'venky' });
  if (!existing) {
    const hash = await bcrypt.hash('Venky@14', 12);
    await dbInsert(db.admins, { username: 'venky', password: hash });
  }
  for (const [k, v] of [['voting_active', true], ['winner_declared', false], ['winner_project_id', null]]) {
    if (!await dbFindOne(db.settings, { key: k })) await dbInsert(db.settings, { key: k, value: v });
  }
}

async function setSetting(key, value) {
  if (await dbFindOne(db.settings, { key })) await dbUpdate(db.settings, { key }, { $set: { value } });
  else await dbInsert(db.settings, { key, value });
}

function getIP(req) {
  return ((req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket?.remoteAddress || '127.0.0.1';
}

function authMW(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Unauthorized.' });
  try { req.admin = jwt.verify(h.split(' ')[1], JWT_SECRET); next(); }
  catch { res.status(401).json({ success: false, message: 'Invalid token.' }); }
}

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  etag: false,
  lastModified: false,
  setHeaders: (res) => { res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate'); }
}));
app.set('trust proxy', 1);

// AUTH
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await dbFindOne(db.admins, { username });
    if (!admin || !await bcrypt.compare(password, admin.password)) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    const token = jwt.sign({ id: admin._id, username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ success: true, token, username });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.get('/api/auth/verify', (req, res) => {
  try {
    const h = req.headers.authorization;
    if (!h?.startsWith('Bearer ')) return res.status(401).json({ success: false });
    const decoded = jwt.verify(h.split(' ')[1], JWT_SECRET);
    res.json({ success: true, username: decoded.username });
  } catch { res.status(401).json({ success: false, message: 'Invalid token.' }); }
});

// PROJECTS
app.get('/api/projects', async (req, res) => {
  try { res.json({ success: true, projects: await dbFindSorted(db.projects, {}, { vote_count: -1 }) }); }
  catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/projects', authMW, async (req, res) => {
  try {
    const { project_name, team_name, description, category } = req.body;
    if (!project_name || !team_name || !description) return res.status(400).json({ success: false, message: 'All fields required.' });
    const project = await dbInsert(db.projects, { project_name, team_name, description, category: category || 'General', vote_count: 0, is_winner: false, created_at: new Date() });
    io.emit('project_added', project);
    res.status(201).json({ success: true, project });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.put('/api/projects/:id', authMW, async (req, res) => {
  try {
    const { project_name, team_name, description, category } = req.body;
    await dbUpdate(db.projects, { _id: req.params.id }, { $set: { project_name, team_name, description, category } });
    const project = await dbFindOne(db.projects, { _id: req.params.id });
    io.emit('project_updated', project);
    res.json({ success: true, project });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.delete('/api/projects/:id', authMW, async (req, res) => {
  try {
    await dbRemove(db.projects, { _id: req.params.id });
    await dbRemove(db.votes, { project_id: req.params.id }, { multi: true });
    io.emit('project_deleted', { id: req.params.id });
    res.json({ success: true, message: 'Deleted.' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// VOTES
const voteLimiter = rateLimit({ windowMs: 60000, max: 10, standardHeaders: true, legacyHeaders: false });

app.post('/api/votes', voteLimiter, async (req, res) => {
  try {
    const { project_id, fingerprint } = req.body;
    const ip = getIP(req);
    if (!project_id) return res.status(400).json({ success: false, message: 'Project ID required.' });
    const vs = await dbFindOne(db.settings, { key: 'voting_active' });
    if (!vs?.value) return res.status(403).json({ success: false, message: 'Voting is currently closed.' });
    const wd = await dbFindOne(db.settings, { key: 'winner_declared' });
    if (wd?.value) return res.status(403).json({ success: false, message: 'Voting has ended.' });
    const project = await dbFindOne(db.projects, { _id: project_id });
    if (!project) return res.status(404).json({ success: false, message: 'Project not found.' });
    const ipCount = await dbCount(db.votes, { ip_address: ip });
    if (ipCount >= MAX_VOTES_PER_IP) return res.status(429).json({ success: false, message: `You have reached the maximum ${MAX_VOTES_PER_IP} votes limit from this network.`, votes_used: ipCount, votes_remaining: 0 });
    if (fingerprint && await dbCount(db.votes, { fingerprint }) >= MAX_VOTES_PER_IP)
      return res.status(429).json({ success: false, message: 'Vote limit reached on this device.', votes_used: MAX_VOTES_PER_IP, votes_remaining: 0 });
    await dbInsert(db.votes, { project_id, ip_address: ip, fingerprint: fingerprint || null, timestamp: new Date() });
    await dbUpdate(db.projects, { _id: project_id }, { $inc: { vote_count: 1 } });
    const updatedProject = await dbFindOne(db.projects, { _id: project_id });
    const newCount = await dbCount(db.votes, { ip_address: ip });
    const allProjects = await dbFindSorted(db.projects, {}, { vote_count: -1 });
    io.emit('vote_update', { projects: allProjects, updated_project: updatedProject });
    res.json({ success: true, message: 'Vote recorded successfully!', votes_used: newCount, votes_remaining: MAX_VOTES_PER_IP - newCount, project: updatedProject });
  } catch (e) { console.error(e); res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.get('/api/votes/status', async (req, res) => {
  try {
    const ip = getIP(req);
    const { fingerprint } = req.query;
    const ipCount = await dbCount(db.votes, { ip_address: ip });
    const fpCount = fingerprint ? await dbCount(db.votes, { fingerprint }) : 0;
    const effective = Math.max(ipCount, fpCount);
    res.json({ success: true, votes_used: effective, votes_remaining: Math.max(0, MAX_VOTES_PER_IP - effective), max_votes: MAX_VOTES_PER_IP, can_vote: effective < MAX_VOTES_PER_IP });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.get('/api/votes/stats', authMW, async (req, res) => {
  try {
    const totalVotes = await dbCount(db.votes, {});
    const allVotes = await dbFind(db.votes, {});
    const uniqueIPs = new Set(allVotes.map(v => v.ip_address)).size;
    const projects = await dbFindSorted(db.projects, {}, { vote_count: -1 });
    const vs = await dbFindOne(db.settings, { key: 'voting_active' });
    const wd = await dbFindOne(db.settings, { key: 'winner_declared' });
    const recentVotes = await dbFindSorted(db.votes, {}, { timestamp: -1 }, 20);
    const enriched = await Promise.all(recentVotes.map(async v => {
      const p = await dbFindOne(db.projects, { _id: v.project_id });
      return { ...v, project_id: p ? { project_name: p.project_name, team_name: p.team_name } : null };
    }));
    res.json({ success: true, total_votes: totalVotes, unique_voters: uniqueIPs, projects, recent_votes: enriched, voting_active: vs?.value || false, winner_declared: wd?.value || false });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// ADMIN
app.get('/api/admin/status', async (req, res) => {
  try {
    const vs = await dbFindOne(db.settings, { key: 'voting_active' });
    const wd = await dbFindOne(db.settings, { key: 'winner_declared' });
    const wp = await dbFindOne(db.settings, { key: 'winner_project_id' });
    const winner = wp?.value ? await dbFindOne(db.projects, { _id: wp.value }) : null;
    res.json({ success: true, voting_active: vs?.value || false, winner_declared: wd?.value || false, winner });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/admin/voting/start', authMW, async (req, res) => {
  try {
    await setSetting('voting_active', true);
    await setSetting('winner_declared', false);
    await setSetting('winner_project_id', null);
    await dbUpdate(db.projects, {}, { $set: { is_winner: false } }, { multi: true });
    io.emit('voting_started');
    res.json({ success: true, message: 'Voting started!' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/admin/voting/stop', authMW, async (req, res) => {
  try {
    await setSetting('voting_active', false);
    io.emit('voting_stopped');
    res.json({ success: true, message: 'Voting stopped.' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/admin/voting/declare-winner', authMW, async (req, res) => {
  try {
    await setSetting('voting_active', false);
    await setSetting('winner_declared', true);
    const projs = await dbFindSorted(db.projects, {}, { vote_count: -1 }, 1);
    const winner = projs[0];
    if (!winner) return res.status(400).json({ success: false, message: 'No projects.' });
    await dbUpdate(db.projects, { _id: winner._id }, { $set: { is_winner: true } });
    await setSetting('winner_project_id', winner._id);
    io.emit('winner_declared', { winner: { ...winner, is_winner: true } });
    res.json({ success: true, message: 'Winner declared!', winner });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

app.post('/api/admin/reset', authMW, async (req, res) => {
  try {
    await dbRemove(db.votes, {}, { multi: true });
    await dbUpdate(db.projects, {}, { $set: { vote_count: 0, is_winner: false } }, { multi: true });
    await setSetting('voting_active', true);
    await setSetting('winner_declared', false);
    await setSetting('winner_project_id', null);
    const projects = await dbFindSorted(db.projects, {}, { vote_count: -1 });
    io.emit('system_reset', { projects });
    io.emit('voting_started');
    res.json({ success: true, message: 'System reset. All votes cleared. Voting is OPEN!' });
  } catch { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// PAGES
app.get('/', (req, res) => res.redirect('/vote'));
app.get('/vote', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vote.html')));
app.get('/leaderboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'leaderboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/thankyou', (req, res) => res.sendFile(path.join(__dirname, 'public', 'thankyou.html')));

io.on('connection', (socket) => {
  socket.on('request_leaderboard', async () => {
    try {
      const projects = await dbFindSorted(db.projects, {}, { vote_count: -1 });
      const vs = await dbFindOne(db.settings, { key: 'voting_active' });
      const wd = await dbFindOne(db.settings, { key: 'winner_declared' });
      socket.emit('leaderboard_data', { projects, voting_active: vs?.value || false, winner_declared: wd?.value || false });
    } catch { }
  });
});

(async () => {
  await seed();
  server.listen(PORT, () => {
    console.log('\n========================================');
    console.log('  ExpoVote Live is RUNNING!');
    console.log('  http://localhost:' + PORT);
    console.log('  Admin: venky / Venky@14');
    console.log('========================================\n');
  });
})();
