const fs = require('fs');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');
const utf8 = require('utf8');

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
  function encrypt(message, pkp){

    // Generate RSA object
    const encryptRSA = new NodeRSA();
    // Read file and get contents
    var publickeydata = fs.readFileSync(pkfilepath);
    // Load public key
    encryptRSA.importKey(publickeydata);


    // Generate 256-bit key for AES
    var AESkey = crypto.randomBytes(32);
    //console.log(AESkey.toString('hex'));

    // Generate a 16-bit Initialization Vector
    var iv = crypto.randomBytes(16);
    // Initialize an AES object.
    var AEScipher = crypto.createCipheriv('aes-256-cbc', AESkey, iv);

    // Encypt message with AES
    var AES_ciphertext = AEScipher.update(message, 'utf8', 'hex');
    AES_ciphertext += AEScipher.final('hex');
    AES_ciphertext = iv.toString('hex') + AES_ciphertext;


    // Generate 256-bit key for HMAC
    var HMACkey = crypto.randomBytes(32);
        //console.log(HMACkey.toString('hex'));
    // Initialize HMAC object
    var hmac = crypto.createHmac('sha256', HMACkey);
    // Compute integrity tag by encrypting ciphertext with our HMAC object
    var integrityTag = hmac.update(AES_ciphertext);
        //console.log(integrityTag);
    integrityTag = hmac.digest('hex');
        //console.log(integrityTag);

    // Concatenate AES and HMAC keys
    var concatKeys = AESkey.toString('hex') + HMACkey.toString('hex');
        //console.log(concatKeys);

    // Encrypt concatenated keys with RSA object
    var encryptedKeys = encryptRSA.encrypt(concatKeys);
        //console.log(encryptedKeys.toString('hex'));

    console.log("RSA cipher text: " + encryptedKeys.toString('hex'));
    console.log("AES cipher text: " + AES_ciphertext);
    console.log("HMAC tag: " + integrityTag);
  }
}
