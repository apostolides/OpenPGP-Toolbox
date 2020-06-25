async function decrypt_armored_private_key(private_key_armored,passphrase){
  const { keys: [private_key] } = await openpgp.key.readArmored(private_key_armored);
  await private_key.decrypt(passphrase);
  return private_key;
}

var openpgp_wrapper = {
  encrypt : async function(private_key_armored,public_key_armored,passphrase,payload){
    const private_key = await decrypt_armored_private_key(private_key_armored,passphrase);
    const pd = payload;
    const { data: encrypted } = await openpgp.encrypt({
          message: openpgp.message.fromText(pd),
          publicKeys: (await openpgp.key.readArmored(public_key_armored)).keys,
          privateKeys: [private_key]
      });
    return encrypted;

  },
  decrypt : async function(encrypted_message,public_key_armored,private_key){
    const { data: decrypted } = await openpgp.decrypt({
            message: await openpgp.message.readArmored(encrypted_message),
            publicKeys: (await openpgp.key.readArmored(public_key_armored)).keys,
            privateKeys: [private_key]
        });
    return decrypted;
  },
  generate_keys : async function(user_id_name,passphrase){
		const keys = await openpgp.generateKey({
				userIds: [{name:user_id_name}],
				curve: 'curve25519',
				passphrase: passphrase
			  });
		return keys;
	},
  decrypt_armored_private_key : decrypt_armored_private_key
};

$().ready(()=>{
  $("#private-key-area").val("");
  $("#public-key-area").val("");
  $("#recipient-public-key-area").val("");
  $("#recipient-message-field").val("");
  $("#recipient-encrypted-message").val("");
  $("#decrypted-message-field").val("");
});

var private_key_armored;
var public_key_armored;
var userId;
var passphrase;

$("#generate-btn").on('click',
async ()=>{
  passphrase = $("#password-field").val();
  userId = $("#user-id-field").val();
  if(!passphrase || !userId){
    console.log("required");
    return;
  }
  var keys = await openpgp_wrapper.generate_keys(userId,passphrase);
  private_key_armored = keys.privateKeyArmored;
  public_key_armored = keys.publicKeyArmored;
  const private_key_area = $("#private-key-area");
  private_key_area.val("");
  private_key_area.val(private_key_armored);
  const public_key_area = $("#public-key-area");
  public_key_area.val("");
  public_key_area.val(public_key_armored);
});

$("#encrypt-btn").on('click',
async ()=>{
  var message = $("#recipient-message-field").val();
  var recipient_public_key = $("#recipient-public-key-area").val();
  private_key_armored = $("#private-key-area").val();
  passphrase = $("#password-field").val();
  userId = $("#user-id-field").val();
  if(!passphrase || !userId){
    console.log("required");
    return;
  }
  var encrypted = await openpgp_wrapper.encrypt(private_key_armored,recipient_public_key,passphrase,message);
  $("#recipient-encrypted-message").val(encrypted);
});

$("#decrypt-btn").on('click',
async ()=>{
  var recipient_public_key = $("#recipient-public-key-area").val();
  public_key_armored = $("#public-key-area").val();
  encrypted = $("#recipient-encrypted-message").val();
  private_key_armored = $("#private-key-area").val();
  passphrase = $("#password-field").val();
  if(!passphrase){
    console.log("required");
    return;
  }
  var decrypted = await openpgp_wrapper.decrypt(encrypted,public_key_armored,await openpgp_wrapper.decrypt_armored_private_key(private_key_armored,passphrase));
  $("#decrypted-message-field").val(decrypted);
});
