const fs = require('fs');
const crypto = require('crypto');
const publickey_path = 'C:/Users/Robbie/Documents/CSULB/CECS/478 Security/Project/ClientApplication/Ryan keys/public.pem';
const privatekey_path = 'C:/Users/Robbie/Documents/CSULB/CECS/478 Security/Project/ClientApplication/Ryan keys/private.pem';


// Outputs user input from text box to an area on the page.
function send(){
  // Get the value of the element with Id 'input'
  var messageString = document.getElementById('input').value;

  // Print our message to the element with Id 'print-output'
  document.getElementById('print-output').innerHTML = messageString;

  /*
  Encrypt message.
  Returns a JSON object.
   */
  var cipher = encrypt(messageString, publickey_path);

  // Display encrypted message on the page.
  document.getElementById('print-cipher').innerHTML = cipher;

  // Call decryption function to decrypt our encrypted message.
  var decryptedMessage = decrypt(cipher, privatekey_path);
  console.log(decryptedMessage);

  // Display decrypted message on the page.
  document.getElementById('print-plaintext').innerHTML = decryptedMessage;
}





// Input is a message string and an RSA public key file path (.pem file).
function encrypt(message, publickey_filepath){
  // Read file and get contents
  var publickeydata = fs.readFileSync(publickey_filepath);


  // Generate 256-bit key for AES
  var AES_key = crypto.randomBytes(32);
  // Convert key to a Buffer
  var aes_bufferkey = Buffer.from(AES_key);

  // Generate a 16-bit Initialization Vector
  var iv = crypto.randomBytes(16);
  // Initialize an AES object.
  var AES_cipher = crypto.createCipheriv('aes-256-cbc', aes_bufferkey, iv);

  // Encypt message with AES
  var AES_ciphertext = AES_cipher.update(message, 'utf8', 'hex');
  AES_ciphertext += AES_cipher.final('hex');
  AES_ciphertext = iv.toString('hex') + AES_ciphertext;


  // Generate 256-bit key for HMAC
  var HMAC_key = crypto.randomBytes(32);
  // Initialize HMAC object
  var hmac = crypto.createHmac('sha256', HMAC_key);
  // Compute integrity tag by encrypting ciphertext with our HMAC object
  var integrityTag = hmac.update(AES_ciphertext);
  integrityTag = hmac.digest('hex');


  var hmac_bufferkey = Buffer.from(HMAC_key);
  // Concatenate AES and HMAC keys
  var concatbuffers = Buffer.concat([aes_bufferkey, hmac_bufferkey]);

  // Encrypt concatenated keys with RSA object
  var encryptedkeys = crypto.publicEncrypt(
    {
      key: publickeydata,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, concatbuffers);


  // Creating an object to structure the JSON file
  var myObj = {
    "RSA_ciphertext": encryptedkeys,//.toString('hex'),
    "AES_ciphertext": AES_ciphertext,
    "HMAC_tag": integrityTag
  };
  // Convert from an object to a string
  var json_output = JSON.stringify(myObj);
  // Write to a file called 'encryption.json'
  fs.writeFileSync('encryption.json', json_output);

  return json_output;
}









function decrypt(json, privateKey_filepath){
  // Get contents of the private key file
  var privatekeydata = fs.readFileSync(privateKey_filepath);

  // Convert json from text to an object
  var json_input = JSON.parse(json);

  // Extract different ciphers from JSON
  var rsa_input = json_input.RSA_ciphertext;
  var aes_input = json_input.AES_ciphertext;
  var hmac_input = json_input.HMAC_tag;

  // Convert to Buffer for decryption
  var rsa_buffer = Buffer.from(rsa_input);
  var aes_input_buffer = Buffer.from(aes_input);

  // Decrypt rsa ciphertext to get concatenated keys
  var keys = crypto.privateDecrypt(privatekeydata, rsa_buffer);
  // Split keys
  var aes_key = keys.slice(0, 32);
  var hmac_key = keys.slice(32, 64);

  try {
    var hmac_decrypt = crypto.createHmac('sha256', hmac_key);
    var decrypted_integrityTag = hmac_decrypt.update(aes_input_buffer);
    decrypted_integrityTag = hmac_decrypt.digest('hex');

    if(decrypted_integrityTag == hmac_input) {
      console.log("Integrity tag verified!");
    }
    else {
      console.error("Integrity tag was not verified.");
    }
  } catch (e) {
    console.error(e.message);
  }

  var ivbuffer = aes_input_buffer.slice(0, 16);
  var aesbuffer = aes_input_buffer.slice(16, 64);
  var iv = aes_input.substr(0, 16);
  aes_input = aes_input.substr(16);


  try {
    var AES_decipher = crypto.createDecipheriv('aes-256-cbc', aes_key, ivbuffer);
    AES_decipher.setAutoPadding(false);

    var plaintext = AES_decipher.update(aesbuffer, 'hex', 'utf8');
    plaintext += AES_decipher.final('utf8');

  } catch (e) {
    console.error(e.message);
  }

  return plaintext;
}
