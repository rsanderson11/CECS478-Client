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

  // Generate a 16-bit Initialization Vector
  var iv = crypto.randomBytes(16);
  // Initialize an AES object.
  var AES_cipher = crypto.createCipheriv('aes-256-cbc', AES_key, iv);

  // Encypt message with AES
  var cipher_buffer = Buffer.concat([
    AES_cipher.update(message),
    AES_cipher.final()
  ]);

  // Generate 256-bit key for HMAC
  var HMAC_key = crypto.randomBytes(32);
  // Initialize HMAC object
  var hmac = crypto.createHmac('sha256', HMAC_key);
  // Compute integrity tag by encrypting ciphertext with our HMAC object
  var integrityTag = hmac.update(cipher_buffer);
  integrityTag = hmac.digest('hex');
  // Convert integrity tag to a buffer
  var integrityTag_buffer = Buffer.from(integrityTag);

  // Concatenate AES and HMAC keys
  var concatbuffers = Buffer.concat([AES_key, HMAC_key]);

  // Encrypt concatenated keys with RSA object
  var encryptedkeys = crypto.publicEncrypt(
    {
      key: publickeydata,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, concatbuffers);

  // Creating an object to structure the JSON file
  var myObj = {
    "RSA_ciphertext": encryptedkeys,
    "IV": iv,
    "AES_ciphertext": cipher_buffer,
    "HMAC_tag": integrityTag_buffer
  };

  // Convert from an object to a string
  var json_output = JSON.stringify(myObj);
  // Write to a file called 'encryption.json'
  fs.writeFileSync('encryption.json', json_output);
  // Return json output
  return json_output;
}



function decrypt(json, privateKey_filepath){
  // Get contents of the private key file
  var privatekeydata = fs.readFileSync(privateKey_filepath);

  // Convert json from text to an object
  var json_input = JSON.parse(json);

  // Extract different ciphers from JSON
  var rsa_input = Buffer.from(json_input.RSA_ciphertext);
  var iv_input = Buffer.from(json_input.IV);
  var aes_input = Buffer.from(json_input.AES_ciphertext);
  var hmac_input = Buffer.from(json_input.HMAC_tag);

  // Decrypt rsa ciphertext to get concatenated keys
  var keys = crypto.privateDecrypt(privatekeydata, rsa_input);
  // Split the two different keys
  var aes_key = keys.slice(0, 32);
  var hmac_key = keys.slice(32, 64);

  try {
    // Create hmac object with decrypted hmac key
    var hmac_decrypt = crypto.createHmac('sha256', hmac_key);
    // Decrypt integrity tag using hmac object and aes ciphertext
    var decrypted_integrityTag = hmac_decrypt.update(aes_input);
    decrypted_integrityTag = hmac_decrypt.digest('hex');

    // Verify if integrity tags match
    if(decrypted_integrityTag == hmac_input) {
      console.log("Integrity tag verified!");
    }
    else {
      console.error("Integrity tag was not verified.");
    }
  } catch (e) {
    console.error(e.message);
  }

  // Decrypt ciphertext
  try {
    var AES_decipher = crypto.createDecipheriv('aes-256-cbc', aes_key, iv_input);

    var decrypt_buffer = Buffer.concat([
      AES_decipher.update(aes_input),
      AES_decipher.final()
    ]);
  } catch (e) {
    console.error(e.message);
  }
  // Convert decrypted message back to utf8
  decrypt_buffer.toString('utf8');
  return decrypt_buffer;
}
