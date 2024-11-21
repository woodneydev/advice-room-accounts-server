require("dotenv").config();
const https = require("https");
const fs = require("fs");
const express = require("express");
const app = express();
const { PORT, ENV, KEY_PATH, CERT_PATH, CA_PATH } = process.env;
const accounts = require("./routes/accounts/accounts");
const certificates = {
    key: fs.readFileSync(KEY_PATH),
    cert: fs.readFileSync(CERT_PATH),
    ca: CA_PATH ? fs.readFileSync(CA_PATH) : null
}


app.use("/accounts", accounts);

https.createServer(certificates, app).listen(PORT, () => {
    console.log("HTTPS Server running on port: ", PORT)
})
