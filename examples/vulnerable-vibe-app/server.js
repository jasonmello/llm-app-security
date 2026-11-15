// Deliberately vulnerable demo server. DO NOT DEPLOY.
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const db = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

async function requireUser(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const { rows } = await db.query('select user_id from sessions where token = $1', [token]);
  if (!rows[0]) return res.status(401).end();
  req.userId = rows[0].user_id;
  next();
}

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await db.query('select * from users where email = $1', [email]);
  if (!rows[0] || rows[0].password !== password) return res.status(401).json({ error: 'bad credentials' });
  res.json({ token: rows[0].session_token });
});

app.get('/api/orders/:id', requireUser, async (req, res) => {
  const { rows } = await db.query('select * from orders where id = $1', [req.params.id]);
  res.json(rows[0]);
});

app.get('/api/search', requireUser, async (req, res) => {
  const { rows } = await db.query(`select id, name from products where name ilike '%${req.query.q}%'`);
  res.json(rows);
});

app.get('/api/admin/users', async (req, res) => {
  const { rows } = await db.query('select id, email, password from users');
  res.json(rows);
});

app.post('/api/checkout', requireUser, async (req, res) => {
  const { productId, amount } = req.body;
  await db.query('insert into payments (user_id, product_id, amount) values ($1, $2, $3)', [req.userId, productId, amount]);
  res.json({ ok: true });
});

app.use((err, req, res, next) => res.status(500).json({ error: err.message, stack: err.stack }));

app.listen(3000);
