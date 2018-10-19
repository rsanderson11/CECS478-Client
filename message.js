const fs = require('fs');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const pkfilepath = 'public.pem';


// Outputs user input from text box to another area on the page.
function send(){
  // Get the value of the element with Id 'input'
  var messageString = document.getElementById('input').value;

  // Print our message to the element with Id 'print-output'
  document.getElementById('print-output').innerHTML = messageString;

  // Encrypt message
  encrypt(messageString, pkfilepath);













  // TODO: Encrypter
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


    //console.log("RSA cipher text: " + encryptedkeys.toString('hex'));
    //console.log("AES cipher text: " + AES_ciphertext);
    //console.log("HMAC tag: " + integrityTag);

    // Creating an object to structure the JSON file
    var myObj = {
      "RSA_ciphertext": encryptedkeys.toString('hex'),
      "AES_ciphertext": AES_ciphertext,
      "HMAC_tag": integrityTag
    };
    // Convert from an object to a string
    var myJSON = JSON.stringify(myObj);
    // Write to a file called 'encryption.json'
    fs.writeFileSync('encryption.json', myJSON, 'utf8');
  }
}

function decrypt(json, privateKey_filepath){
}
