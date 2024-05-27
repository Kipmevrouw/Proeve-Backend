const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");

dotenv.config();

const saltRounds = parseInt(process.env.SALT_ROUNDS, 10);

const app = express();
const corsOptions = {
  origin: "https://techyourtalentamsterdam.nl"
};

app.use(cors(corsOptions));
app.use(express.json());

const dbConfig = {
  host: process.env.MYSQL_ADDON_HOST,
  database: process.env.MYSQL_ADDON_DB,
  user: process.env.MYSQL_ADDON_USER,
  password: process.env.MYSQL_ADDON_PASSWORD
};

let db;

function handleDisconnect() {
  db = mysql.createConnection(dbConfig);

  db.connect((err) => {
    if (err) {
      console.error('Error connecting to the database:', err);
      setTimeout(handleDisconnect, 2000); // Probeer opnieuw te verbinden na 2 seconden
    } else {
      console.log('Verbonden met de database');
    }
  });

  db.on('error', (err) => {
    console.error('Database error:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
      handleDisconnect(); // Herstel de verbinding wanneer deze wordt verbroken
    } else {
      throw err;
    }
  });
}

handleDisconnect();

app.post("/signup", (req, res) => {
  console.log("Ontvangen gegevens:", req.body);
  const sql =
    "INSERT INTO gebruiker (`voornaam`, `achternaam`, `school`, `code`, `uitslag1`, `uitslag2`, `wachtwoord`, `akkoort_voorwaarden`) VALUES (?)";
  const wachtwoord = req.body.wachtwoord;
  bcrypt.hash(wachtwoord.toString(), saltRounds, (err, hash) => {
    console.log("bcrypt done");
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Interne serverfout" });
    }
    const values = [
      req.body.voornaam,
      req.body.achternaam,
      req.body.school,
      req.body.code,
      req.body.uitslag1,
      req.body.uitslag2,
      hash,
      req.body.akkoort_voorwaarden,
    ];
    console.log("Values gelezen")
    db.query(sql, [values], (err, data) => {
      if (err) return res.json(err);
      return res.json(data);
    });
  });
});

app.post("/login", (req, res) => {
  const sql =
    "SELECT * FROM gebruiker WHERE voornaam = ? AND achternaam = ? AND code = ?";
  db.query(
    sql,
    [req.body.voornaam, req.body.achternaam, req.body.code],
    (err, data) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Interne serverfout" });
      }

      if (data.length === 0) {
        return res.status(401).json({ error: "Gebruiker niet gevonden" });
      }

      const hashedPassword = data[0].wachtwoord;

      bcrypt.compare(req.body.wachtwoord, hashedPassword, (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Interne serverfout" });
        }
        if (result) {
          return res.json({ success: "Login succesvol" });
        } else {
          return res.status(401).json({ error: "Onjuiste inloggegevens" });
        }
      });
    }
  );
});

app.get("/", (req, res) => {
  res.send("Server is running!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server draait op poort ${PORT}`);
});
