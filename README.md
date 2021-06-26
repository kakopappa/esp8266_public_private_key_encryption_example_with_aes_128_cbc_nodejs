# ESP8266 public/private key encryption example with NodeJS server

This example demonstrate how to communicate securely in an unsecure WiFi using public/private key encryption. 

Data is encryped with aes 128 cbc encryption after the initial handshake.

![alt text](https://github.com/kakopappa/esp8266_public_private_key_encryption_example_with_aes_128_cbc_nodejs/blob/main/demo.png)

1. Generate RSA keys.

openssl genrsa -out private.pem 1024
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

and update rsa_private_key and rsa_public_key in the sketch.

2. Start the NodeJS Server. by default the server starts on port 80

4. Update the Arduino sketch with IP of the server in _server_ip and change WIFI_SSID, WIFI_PASS

6. When when sketch starts it connects to WiFi

7. Send the public key to server 

9. The server generates a new AES KEY/IV and encrypt it using public key and send it back to ESP.

10. ESP decrypt the message using private key and store the key/iv in memory

12. ESP sends a login request with encrypted data (encryped using above key)

14. The server decrypt the data and encrypt user account info and send it back to ESP

16. ESP decrypts the account info


More info:
https://www.preveil.com/blog/public-and-private-key/

