function send(){
  var form, message, cipher;

  // Gets all info within the form 'messageForm'
  form = document.getElementById('messageForm');

  // Use this if extracting data from a textarea
  // message = form.elements["message_contents"].value;

  // Extract data from the text field 'message'
  message = form.elements["message"].value;

  // Print our message to the element 'print-output'
  document.getElementById("print-output").innerHTML = message;
}
