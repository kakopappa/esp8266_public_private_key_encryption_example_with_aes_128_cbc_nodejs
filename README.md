# ESP8266 public/private key encryption example with NodeJS server

This example demonstrate how to communicate securely in an unsecure WiFi using public/private. Data is encryped with aes 128 cbc encryption.

https://www.preveil.com/blog/public-and-private-key/

1. Generate RSA keys.

openssl genrsa -out private.pem 1024
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

and update rsa_private_key and rsa_public_key in the sketch.

2. Start the NodeJS Server. by default the server starts on port 80
3. Update the Arduino sketch with IP of the server in _server_ip and change WIFI_SSID, WIFI_PASS
4. When when sketch starts, 
  1. Connect to WiFi
  2. Send the public key to server 
  3. The server generates a new AES KEY/IV and encrypt it using public key and send it back to ESP.
  4. ESP decrypt the message using private key and store the key/iv in memory
  5. ESP sends a login request with encrypted data (encryped using above key)
  6. The server decrypt the data and encrypt user account info and send it back to ESP
  7. ESP decrypts the account info


