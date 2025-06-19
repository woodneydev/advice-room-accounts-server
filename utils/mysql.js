import dotenv from "dotenv";
dotenv.config()
import mysql from 'mysql2';

const {
  MYSQL_HOST,
  MYSQL_USER,
  MYSQL_PASSWORD,
  MYSQL_DATABASE,
} = process.env;

export const pool = mysql.createPool({
  host: MYSQL_HOST,
  user: MYSQL_USER,
  password: MYSQL_PASSWORD,
  database: MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  maxIdle: 10,
  idleTimeout: 60000,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
});

export const escape = mysql.escape;

export const query = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    pool.query(sql, params, (err, rows) => {
      if (err) {
        console.error(err);
        return reject(err);
      }
      resolve(rows);
    });
  });
};