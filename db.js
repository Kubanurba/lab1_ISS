const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'auth',
    password: '1234',
    port: '5432',
})

pool.on('error', (err) => {
    console.error('Error:', err)
})

module.exports = pool; 