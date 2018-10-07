// Outputs user input from text box to another area on the page.
function send(){
  // Get the value of the element with Id 'input'
  var textInput = document.getElementById("input").value;

  // Print our message to the element with Id 'print-output'
  document.getElementById("print-output").innerHTML = textInput;
}

// TODO: Encrypter
// Input is a message string and an RSA public key file path (.pem file).

// Initialize an RSA object (OAEP only).
// RSA object will load the public key.
// Initialize an AES object and generate a 256-bit AES key.
// Encrypt message with AES.
// Generate an HMAC 256-bit key.
// Run HMAC (SHA 256) on ciphertext to compute the inegrity tag.
// Concatenate the keys (AES and HMAC) and encrypt the keys with the RSA object.
// Output the RSA ciphertext, AES ciphertext and HMAC tag (JSON).


// Example of modular design
var Module = (function () {

  var privateMethod = function () {
    // private
  };

  var someMethod = function () {
    // public
  };

  var anotherMethod = function () {
    // public
  };

  return {
    someMethod: someMethod,
    anotherMethod: anotherMethod
  };

})();
// End example


// TODO: Decrypter
// Inputs: JSON object with keys as: RSA Ciphertext, AES ciphertext, HMAC tag, a file path to an RSA private keys

// Initialize an RSA object (OAEP only; 2048 bits key size).
// Load the private key into your RSA private key.
// Decrypt the RSA Ciphertext (from JSON) and recover a pair of 256-bit keys (one is AES, other is HMAC).
// Run HMAC (SHA 256 with HMAC key^) to regenerate tag.
// Compare this tag with input tag (from JSON).
// If no match, return failure.
// Otherwise, continue by Initializing an AES key (same as encrypter module) and decrypt the AES ciphertext (from JSON input).
// Return recovered plaintext (or failure at any step).
