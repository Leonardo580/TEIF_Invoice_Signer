$alias = "mykeyalias"
$key_store_file_name = "keystore.p12"
$storepass = "password"
$keypass = "password"

## genertae key pairs and store them in PCK#12 format
keytool -genkeypair -alias $alias -keyalg RSA -keysize 3072 `
        -sigalg SHA256withRSA -storetype PKCS12 -keystore $key_store_file_name `
        -storepass $storepass -keypass $keypass `
        -dname "CN=Your Company Name, OU=Your Unit, O=Your Org, L=Your City, ST=Your State, C=TN"
#Generate certificate request
keytool -certreq -alias $alias -keystore $key_store_file_name -storepass $storepass -file request.csr
#import that certificate to the keyfile
keytool -importcert -alias $alias -keystore $key_store_file_name -storepass $storepass -file .\request.csr -trustcacerts
