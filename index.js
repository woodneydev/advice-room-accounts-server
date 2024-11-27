require("dotenv").config();
const https = require("https");
const fs = require("fs");
const express = require("express");
const app = express();
const { PORT, ENV, KEY_PATH, CERT_PATH, CA_PATH } = process.env;
const accounts = require("./routes/accounts/accounts");
const notFound = require("./errors/notFound");
const errorHandler = require("./errors/errorHandler");
const certificates = {
    key: fs.readFileSync(KEY_PATH),
    cert: fs.readFileSync(CERT_PATH),
    ca: CA_PATH ? fs.readFileSync(CA_PATH) : null
}

// add rate limiting to prevent brute force attacks

app.use("/accounts", accounts);

app.use(notFound);
app.use(errorHandler)

https.createServer(certificates, app).listen(PORT, () => {
    console.log("HTTPS Server running on port: ", PORT)
})
