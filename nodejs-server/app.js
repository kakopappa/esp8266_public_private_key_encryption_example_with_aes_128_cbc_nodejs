const crypto = require('crypto');
const express = require('express')
const app = express()
const port = 80

app.use(express.json());

let cipher_iv;
let cipher_key;

const encrypt = (publicKey, text) => {
  const buffer = Buffer.from(text, "utf8");
  const encryptOptions = {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING
  }

  const encrypted = crypto.publicEncrypt(encryptOptions, buffer);
  return encrypted.toString("base64");
}
 
let aesEncrypt = function(text){
    const cipher = crypto.createCipheriv('aes-128-cbc',cipher_key,cipher_iv)
    text = new Buffer.from(text)
    var crypted = cipher.update(text,'utf-8','base64')
    crypted += cipher.final('base64');
    return crypted;
}

let aesDecrypt = function(text){
    const decipher = crypto.createDecipheriv('aes-128-cbc',cipher_key,cipher_iv)
    let dec = decipher.update(text,'base64','utf-8');
    dec += decipher.final();
    return dec;
}
 
app.post('/handshake', (req, res) => {
  cipher_iv = crypto.randomBytes(16); // IV
  cipher_key = crypto.randomBytes(16);
  
  console.log("cipher_iv:" , cipher_iv);
  console.log("cipher_key:" , cipher_key);

  const public_key = req.body.public_key;
  let data = Buffer.concat([cipher_key, cipher_iv]);
  const resp = encrypt(public_key, data);
  res.send(JSON.stringify({key: resp}));
})

app.post('/login', (req, res) => {  
    const request = aesDecrypt(req.body.request);
    console.log("Decrypted request from ESP: " , request);
    // Do the login here.  Prepare the response
    let data = JSON.stringify({account: { "name" : "Aruna" }});
    res.send(JSON.stringify({result: {response: aesEncrypt(data)}}));
})

app.listen(port, () => {
  console.log(`Listening at http://localhost:${port}`)
})

