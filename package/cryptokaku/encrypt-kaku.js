module.exports = function (RED) {
	var CryptoJS = require("crypto-js");

	function EncryptKakuNode(config) {
		RED.nodes.createNode(this, config);

		var node = this;
		node.key = config.key;

		node.on('input', function (msg) {
			var key = node.key || msg.key;
            if (msg.key && node.key && (node.key !== msg.key)) {
                node.warn(RED._("common.errors.nooverride"));
            }
            if (!key) {
                node.error("Missing configuration, please check your secret key.", msg);
                return;
			}

			if(msg.payload) {
				//convert key
				key = CryptoJS.enc.Hex.parse(key);

				//generate iv
				var iv = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");

				//ecrypt
				var encrypted = CryptoJS.AES.encrypt(msg.payload, key, { iv: iv });

				//convert iv and ciphertext to base64
				iv.concat(encrypted.ciphertext);
				var base64 = CryptoJS.enc.Base64.stringify(iv);
				
				//return
				msg.payload = base64;
			}
			else {
				// debugging message
				node.trace('Nothing to encrypt: empty payload');
			}
			node.send(msg);
		});
	}
	RED.nodes.registerType("encrypt-kaku", EncryptKakuNode);
};