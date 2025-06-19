import mysql from "../utils/mysql.js";

const creatUserTable = async () => {

    const q = `CREATE TABLE user (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        is_verified BOOLEAN NOT NULL DEFAULT FALSE,
        verification_number VARCHAR(255) DEFAULT NULL,
        user_role VARCHAR(255) NOT NULL DEFAULT 'user',
        refresh_token VARCHAR(255) DEFAULT NULL,
        enable_2fa BOOLEAN NOT NULL DEFAULT FALSE,
        password VARCHAR(60) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX (id),
        INDEX (first_name),
        INDEX (last_name)
      );
    `

    try {
        const result = await mysql.query(q);
        console.log(result);
    } catch (error) {
        console.error(error);
    }
}


const dropUserTable = async () => {
    const q = 'DROP TABLE IF EXISTS user'

    try {
        const reqult = await mysql.query(q);
    } catch (error) {
        console.error(error)
    }
}



const runMigrations = () => {
    if (process.argv[2] === "migrate:down") return dropUserTable();
    if (process.argv[2] === "migrate:latest") return creatUserTable();
}

runMigrations();

