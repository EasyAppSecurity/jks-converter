## SSL server credentials to Java .keystore import ##

SSL .key and .crt to java keystore groovy script

### Using ###

[OpenSSL](http://slproweb.com/products/Win32OpenSSL.html) need to be installed 

Just try: `groovy import keyfile.key certfile.crt`<br/><br/>
<b>Change in source:</b><br/>
Target keystore name<br/>
`KEYSTORE_NAME = 'keystore.ImportKey'`<br/>
Target keystore password<br/>
`KEYPASS = 'importkey'`<br/>
Target keystore alias<br/>
`ALIAS = 'importkey'`

Target certificate name<br/>
`CERT_NAME = 'public.cer'`


### Get public keytore ###

For create public java keysore (without private key):<br/>
`keytool -importcert -file public.cer -keystore public -alias importkey -storepass importkey`
