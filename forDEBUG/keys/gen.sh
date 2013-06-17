openssl genrsa -out privateKey.pem 512
openssl rsa -in privateKey.pem -pubout -outform PEM -out publicKey.pem