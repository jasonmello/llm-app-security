// Shared database pool. DO NOT DEPLOY.
const { Pool } = require('pg');
module.exports = { db: new Pool({ connectionString: process.env.DATABASE_URL }) };
