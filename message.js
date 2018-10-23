const fs = require('fs');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
// var Base64 = require('js-based64').Base64;
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
}





// Input is a message string and an RSA public key file path (.pem file).
function encrypt(message, publickey_filepath){

  // Generate RSA object
  const encryptRSA = new NodeRSA();
  // Read file and get contents
  var publickeydata = fs.readFileSync(publickey_filepath);
  // Load public key
  encryptRSA.importKey(publickeydata);


  // Generate 256-bit key for AES
  var AES_key = crypto.randomBytes(32);
  //console.log(AESkey.toString('hex'));

  // Generate a 16-bit Initialization Vector
  var iv = crypto.randomBytes(16);
  // Initialize an AES object.
  var AES_cipher = crypto.createCipheriv('aes-256-cbc', AES_key, iv);

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


  // Concatenate AES and HMAC keys
  var concatkeys = AES_key + HMAC_key;


  // Encrypt concatenated keys with RSA object
  var encryptedkeys = encryptRSA.encrypt(concatkeys);


  // console.log("RSA cipher text: " + encryptedkeys.toString('hex'));
  // console.log("AES cipher text: " + AES_ciphertext);
  // console.log("HMAC tag: " + integrityTag);

  // Creating an object to structure the JSON file
  var myObj = {
    "RSA_ciphertext": encryptedkeys.toString('hex'),
    "AES_ciphertext": AES_ciphertext,
    "HMAC_tag": integrityTag
  };
  // Convert from an object to a string
  var json_output = JSON.stringify(myObj);
  // Write to a file called 'encryption.json'
  fs.writeFileSync('encryption.json', json_output, 'utf8');

  return json_output;
}


function decrypt(json, privateKey_filepath){
  // Initialize an RSA object
  var decryptRSA = new NodeRSA();
  // Get contents of the private key file
  var privatekeydata = fs.readFileSync(privateKey_filepath);
  // Load private key into decryptRSA
  decryptRSA.importKey(privatekeydata, 'pkcs1');

  // Convert json from text to an object
  var json_input = JSON.parse(json);

  var rsa_input = json_input.RSA_ciphertext;
  var aes_input = json_input.AES_ciphertext;
  var hmac_input = json_input.HMAC_tag;
}
