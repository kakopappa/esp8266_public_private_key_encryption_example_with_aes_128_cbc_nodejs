#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

#include "Base64.h"
#include "Hash.h"
#include <Arduino_JSON.h>

// WiFi config
const char WIFI_SSID[] = "";
const char WIFI_PASS[] = "";

uint8_t _cipher_key[16], _cipher_iv[16];
String _server_ip = "";


//openssl genrsa -out private.pem 1024
//openssl rsa -in private.pem -outform PEM -pubout -out public.pem

const char rsa_private_key[] = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
)EOF";

const char rsa_public_key[] = R"EOF(
-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----
)EOF";


HTTPClient http;

void setup()
{
  Serial.begin(115200);
  Serial.println("Starting...");  
 
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.print("Waiting for WiFi connection.");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(500);
  }
  Serial.println(" Finished !");

  delay(100);
  
  handshake(rsa_private_key, rsa_public_key);
  Serial.println("Handshake Finished !");
  
  login("xxxx@gmail.com", "this");
  Serial.println("Login Finished !");  
}
 
void loop()
{ 
}

void handshake(const char private_key[], const char public_key[]) {  
  http.begin("http://" + _server_ip + "/handshake");
  http.addHeader("Content-Type", "application/json");

  JSONVar payload;
  payload["public_key"] = public_key; 

  String payload_str = JSON.stringify(payload);

  Serial.print("POST:");
  Serial.println(payload_str);
  
  http.POST(payload_str);
  payload_str = http.getString();

  Serial.print("Response:");
  Serial.println(payload_str);
 
  payload = JSON.parse(payload_str);
  String key_str = (const char *)payload["key"];

  int input_len = key_str.length();
  char *key = const_cast<char*>(key_str.c_str());
  int len = base64_dec_len(key, input_len);
  uint8_t data[len];
  base64_decode((char *)data, key, input_len);

  int i;
//  for(i = 0; i < len; i++) {
//    Serial.printf("%02x", data[i]);
//  }
//  Serial.println();
 
  
  // RSA PKCS#1 V1.5 Padding Encryption
  BearSSL::PrivateKey *private_key_obj = new BearSSL::PrivateKey(private_key);
  
  (*br_rsa_private_get_default())(data, private_key_obj->getRSA());

  // In RSAES-PKCS1-v1_5, the data begins with 00 02 and ends with 00 eg: 00 02 <encryped> 00
  
  for(i = 2; i < len; i++){
    if(data[i] == 0) break;
  }
  i++;
  len -= i;

  uint8_t decoded_data[len];
  memcpy(decoded_data, &data[i], len);

//  for(i = 0; i < len; i++) {
//    Serial.printf("%02x", decoded_data[i]);
//  }
//  Serial.println();

  // set the Key & IV server generated

  uint8_t b_arr[16], b_arr2[16];
  memcpy(b_arr, decoded_data, 16);        //key
  memcpy(b_arr2, &decoded_data[16], 16);  //iv
  
  aes_128_cbc_init(b_arr, b_arr2);   
}


void login(String email, String password) {
  http.begin("http://" + _server_ip + "/login");
  http.addHeader("Content-Type", "application/json");
   
  JSONVar payload;
  payload["username"] = email;
  payload["password"] = password;   

  String payload_str = JSON.stringify(payload);
  String encrypted_payload = aes_128_cbc_encrypt(payload_str);

  payload = JSONVar();
  payload["request"] = encrypted_payload;
  
  payload_str = JSON.stringify(payload);
  http.POST(payload_str);
  payload_str = http.getString();
  Serial.println(payload_str);

  payload = JSON.parse(payload_str);
  String response = (const char *)payload["result"]["response"];
  String decrypted_response_str = aes_128_cbc_decrypt(response);
  Serial.println(decrypted_response_str);
}

void aes_128_cbc_init(uint8_t b_arr[], uint8_t b_arr2[]){
  memcpy(_cipher_key, b_arr, 16);
  memcpy(_cipher_iv, b_arr2, 16);
}


String aes_128_cbc_encrypt(String plain_data){
  int i;
  // PKCS#7 Padding (Encryption), Block Size : 16
  int len = plain_data.length();
  int n_blocks = len / 16 + 1;
  uint8_t n_padding = n_blocks * 16 - len;
  uint8_t data[n_blocks*16];
  memcpy(data, plain_data.c_str(), len);
  for(i = len; i < n_blocks * 16; i++){
    data[i] = n_padding;
  }

  // AES CBC Encryption
  uint8_t key[16], iv[16];
  memcpy(key, _cipher_key, 16);
  memcpy(iv, _cipher_iv, 16);

  // encryption context
  br_aes_big_cbcenc_keys encCtx;

  // reset the encryption context and encrypt the data
  br_aes_big_cbcenc_init(&encCtx, key, 16);
  br_aes_big_cbcenc_run( &encCtx, iv, data, n_blocks*16 );

  // Base64 Encode
  len = n_blocks*16;
  char encoded_data[ base64_enc_len(len) ];
  base64_encode(encoded_data, (char *)data, len);
  
  return String(encoded_data);
}


String aes_128_cbc_decrypt(String encoded_data_str){  
  // Base64 Decode
  int input_len = encoded_data_str.length();
  char *encoded_data = const_cast<char*>(encoded_data_str.c_str());
  int len = base64_dec_len(encoded_data, input_len);
  uint8_t data[ len ];
  base64_decode((char *)data, encoded_data, input_len);
  
  // AES CBC Decryption
  uint8_t key[16], iv[16];
  memcpy(key, _cipher_key, 16);
  memcpy(iv, _cipher_iv, 16);

  int n_blocks = len / 16;

  br_aes_big_cbcdec_keys decCtx;

  br_aes_big_cbcdec_init(&decCtx, key, 16);
  br_aes_big_cbcdec_run( &decCtx, iv, data, n_blocks*16 );  //Important ! iv mo swap.

  // PKCS#7 Padding (Decryption)
  uint8_t n_padding = data[n_blocks*16-1];
  len = n_blocks*16 - n_padding;
  char plain_data[len + 1];
  memcpy(plain_data, data, len);
  plain_data[len] = '\0';

  return String(plain_data);
}
 



 
