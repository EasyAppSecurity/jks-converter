import java.security.*
import java.io.IOException
import java.io.InputStream
import java.io.FileInputStream
import java.io.DataInputStream
import java.io.ByteArrayInputStream
import java.io.FileOutputStream
import java.security.spec.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.Collection
import java.util.Iterator

KEYSTORE_NAME = 'keystore.ImportKey'
KEYPASS = 'importkey'
ALIAS = 'importkey'

CERT_NAME = 'public.cer'

def InputStream fullStream(String fname)
throws IOException {
    
    FileInputStream fis = new FileInputStream(fname)
    DataInputStream dis = new DataInputStream(fis)
    
    byte[] bytes = new byte[dis.available()]
    dis.readFully(bytes)
    
    ByteArrayInputStream bais = new ByteArrayInputStream(bytes)
    
    return bais;
}

copy = { File src, File dest->
    def input = src.newDataInputStream()
    def output = dest.newDataOutputStream()
    
    output << input
    
    input.close()
    output.close()
}

exec = { command->
    def proc = command.execute()
    proc.waitFor()
}

if (args.length==0 || args.length < 2 || args.length >= 3
    || !args[0].endsWith(".key") || !args[1].endsWith(".crt")) {
	  
    println("Usage: groovy import /pathto/keyfile.key /pathto/certfile.crt")
    System.exit(0)
}

def keypath = args[0]
def cerpath = args[1]

File keypemfile = File.createTempFile('key', '.pem')
keypemfile.deleteOnExit()

File cerpemfile = File.createTempFile('cert', '.pem')
cerpemfile.deleteOnExit()

copy(new File(keypath), keypemfile)
copy(new File(cerpath), cerpemfile)

println "Private key PEM -> DER"
	File keyderfile = File.createTempFile('key', '.der')
	keyderfile.deleteOnExit()
	exec("openssl pkcs8 -topk8 -nocrypt -in ${keypemfile.absolutePath} -inform PEM -out ${keyderfile.absolutePath} -outform DER")

println "Certificate PEM -> DER"
	File cerderfile = File.createTempFile('cert', '.der')
	cerderfile.deleteOnExit()
	exec("openssl x509 -in ${cerpemfile.absolutePath} -inform PEM -out ${cerderfile.absolutePath} -outform DER")

try {
    // initializing and clearing keystore
    KeyStore ks = KeyStore.getInstance("JKS", "SUN")
    ks.load( null , KEYPASS.toCharArray())
    println "Using keystore-file : ${KEYSTORE_NAME}"
    
    ks.store(new FileOutputStream(KEYSTORE_NAME), KEYPASS.toCharArray())
    ks.load(new FileInputStream(KEYSTORE_NAME), KEYPASS.toCharArray())
    
    // loading Key
    InputStream fl = fullStream(keyderfile.absolutePath)
    
    byte[] key = new byte[fl.available()]
    KeyFactory kf = KeyFactory.getInstance("RSA")
    fl.read ( key, 0, fl.available() )
    fl.close()
    
    PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec( key )
    PrivateKey ff = kf.generatePrivate(keysp)
    
    // loading CertificateChain
    CertificateFactory cf = CertificateFactory.getInstance("X.509")
    InputStream certstream = fullStream(cerderfile.absolutePath)
    
    Collection c = cf.generateCertificates(certstream)
    Certificate[] certs = new Certificate[c.toArray().length]
    
    if (c.size() == 1) {
			certstream = fullStream(cerderfile.absolutePath)
			println("One certificate, no chain.")
			Certificate cert = cf.generateCertificate(certstream)
			certs[0] = cert
        } else {
			println "Certificate chain length: ${c.size()}"
			certs = (Certificate[])c.toArray();
    }
    
    // storing keystore
    ks.setKeyEntry(ALIAS, ff, KEYPASS.toCharArray(), certs )
    println "Key and certificate stored."
    println "Alias: ${ALIAS} Password: ${KEYPASS}"
    
    ks.store(new FileOutputStream (KEYSTORE_NAME), KEYPASS.toCharArray())
    } catch (Exception ex) {
    ex.printStackTrace()
}

//import .cer from keystore
exec("keytool -export -keystore keystore.ImportKey -storepass ${KEYPASS} -alias ${ALIAS} -file ${CERT_NAME}")