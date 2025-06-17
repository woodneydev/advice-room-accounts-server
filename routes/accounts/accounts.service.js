// const knex = require('knex')(require('../../knexfile.js'));
// const mysql = require('mysql2/promise');
const mysql = require("../../utils/mysql.js");

const findByEmail = async (email) => {
  // console.log("email ", email)
  const escapedEmail = mysql.escape(email);
  const q = `SELECT * FROM user WHERE email = ${escapedEmail}`

  try {
    const result = await mysql.query(q);
    // console.log("result => ", result)
    return result[0];
  } catch (error) {
    throw error;
  }
}

const findById = async (id) => {
  const escapedId = mysql.escape(id);
  const q = `SELECT * FROM user WHERE id = ${escapedId}`

  try {
    const result = await mysql.query(q);
    return result[0];
  } catch (error) {
    throw error;
  }
}

const insertUser = async ({ first_name, last_name, email, password, verification_number }) => {
  const escapedFirstName = mysql.escape(first_name);
  const escapedLastName = mysql.escape(last_name);
  const escapedEmail = mysql.escape(email);
  const escapedPassword = mysql.escape(password);
  const escapedVerificationNumber = mysql.escape(verification_number);

  const q = `INSERT INTO user (first_name, last_name, email, password, verification_number) VALUES (${escapedFirstName}, ${escapedLastName}, ${escapedEmail}, ${escapedPassword}, ${escapedVerificationNumber})`;

  try {
    const result = await mysql.query(q);

    if (result?.affectedRows > 0) {
       const newUser = await findByEmail(email); 
      return newUser
    } else {
      throw 'User was not added.'
    }
  } catch (error) {
    throw error
  }
}


const updateUserByEmail = async  (user, email) => {
  const escapedFirstName = mysql.escape(user.first_name);
  const escapedLastName = mysql.escape(user.last_name);
  const escapedPassword = mysql.escape(user.password);
  const escapedEmail = mysql.escape(user.email);
  const escapedVerification = mysql.escape(user.is_verified);
  const escapedVerificationNumber = mysql.escape(user.verification_number);
  const escapedWhereEmail = mysql.escape(email);
  
  const q = `
            UPDATE user SET first_name = ${escapedFirstName}, last_name = ${escapedLastName}, password = ${escapedPassword}, email = ${escapedEmail}, is_verified = ${escapedVerification}, verification_number = ${escapedVerificationNumber}
            Where email = ${escapedWhereEmail}
  `
  try {
    const result = await mysql.query(q);
    return result[0];
  } catch (error) {
    throw error;
  }
}

const updateRefreshToken = async (id, refresh_token) => {
  const escapedId = mysql.escape(id);
  const escapedRefreshToken = mysql.escape(refresh_token);

  const q = `UPDATE user SET refresh_token = ${escapedRefreshToken} WHERE id = ${escapedId}`;

  try {
    const result = await mysql.query(q);
    if (result.affectedRows > 0) {
      const record = await findById(id);
      return record;
    } else {
      throw new Error('No rows updated');
    }
  } catch (error) {
    throw error;
  }
}

module.exports = {
  insertUser,
  findByEmail,
  updateUserByEmail,
  updateRefreshToken
};
