module.exports = function (RED) {
	var CryptoJS = require("crypto-js");
	
	function DecryptKakuNode(config) {
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
				//decode base64
				let buff = Buffer.from(msg.payload, 'base64');
				let hexiv = buff.toString('hex').slice(0,32);
				let hexpay = buff.toString('hex').slice(32);

				//split IV
				let iv = CryptoJS.enc.Hex.parse(hexiv);
				let ciphertext = CryptoJS.enc.Hex.parse(hexpay);

				//convert key					
				key = CryptoJS.enc.Hex.parse(key);

				//decrypt					
				var message = CryptoJS.AES.decrypt({ciphertext: ciphertext}, key, {iv: iv});
				msg.payload = message.toString(CryptoJS.enc.Utf8);
			} 
			else {
				// debugging message
				node.trace('Nothing to decrypt: empty payload');
			}
			node.send(msg);
		});
	}
	RED.nodes.registerType("decrypt-kaku", DecryptKakuNode);
};