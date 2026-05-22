const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const app = express();
app.use(express.json());

// Read private key from secret file
let PRIVATE_KEY;
try {
  PRIVATE_KEY = fs.readFileSync("/etc/secrets/private_key.pem", "utf8");
} catch(e) {
  PRIVATE_KEY = (process.env.PRIVATE_KEY || "").replace(/\\n/g, "\n");
}

app.post("/", (req, res) => {
  try {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = req.body;

    const decryptedAesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    const iv = Buffer.from(initial_vector, "base64");
    const encryptedData = Buffer.from(encrypted_flow_data, "base64");
    const TAG_LENGTH = 16;
    const encryptedBody = encryptedData.slice(0, -TAG_LENGTH);
    const authTag = encryptedData.slice(-TAG_LENGTH);

    const decipher = crypto.createDecipheriv("aes-128-gcm", decryptedAesKey, iv);
    decipher.setAuthTag(authTag);
    const decryptedBody = Buffer.concat([decipher.update(encryptedBody), decipher.final()]);
    const body = JSON.parse(decryptedBody.toString());

    console.log("Decrypted body:", JSON.stringify(body));

    const response = body.action === "ping"
      ? { version: body.version, data: { status: "active" } }
      : { version: body.version, screen: "WELCOME", data: {} };

    const cipher = crypto.createCipheriv("aes-128-gcm", decryptedAesKey, iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(response)), cipher.final()]);
    const tag = cipher.getAuthTag();
    res.send(Buffer.concat([encrypted, tag]).toString("base64"));

  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).send("Error");
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
