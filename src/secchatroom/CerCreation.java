package secchatroom;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;


public class CerCreation {
	
	public static void main(String[] args) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, IOException {
		CreateCertificates();
		System.out.println("The certificates have been created successfully");
	}

	private static void CreateCertificates() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException {
		KeyStore kServer = KeyStore.getInstance(KeyStore.getDefaultType());
		KeyStore kClient1 = KeyStore.getInstance(KeyStore.getDefaultType());
		KeyStore kClient2 = KeyStore.getInstance(KeyStore.getDefaultType());
		
		KeyStore tServer = KeyStore.getInstance(KeyStore.getDefaultType());
		KeyStore tClient = KeyStore.getInstance(KeyStore.getDefaultType());


		char[] password = "access".toCharArray();
		
		kServer.load(null, password);
		kClient1.load(null, password);
		kClient2.load(null, password);
		
		tServer.load(null, password);
		tClient.load(null, password);


		// certificates and RSA keys for Server, Client1, Client2
		CertAndKeyGen certGServer = new CertAndKeyGen("RSA", "MD5WithRSA", null);
		CertAndKeyGen certGClient1 = new CertAndKeyGen("RSA", "MD5WithRSA", null);
		CertAndKeyGen certGClient2 = new CertAndKeyGen("RSA", "MD5WithRSA", null);
		// generate it with 2048 bits
		certGServer.generate(2048);
		certGClient1.generate(2048);
		certGClient2.generate(2048);
		
		// prepare the validity of the certificate
		long Seconds = (long) 365 * 24 * 60 * 60; // valid for one year
		
		// add the certificate information, currently only valid for one year.
		X509Certificate certServer = certGServer.getSelfCertificate(new X500Name("CN=Server"), Seconds);
		X509Certificate certClient1 = certGClient1.getSelfCertificate(new X500Name("CN=Client1"), Seconds);
		X509Certificate certClient2 = certGClient2.getSelfCertificate(new X500Name("CN=Client2"), Seconds);
		
		// set the certificate and the key in the keystore
		kServer.setKeyEntry("server", certGServer.getPrivateKey(), password, new X509Certificate[] {certServer} );
		kClient1.setKeyEntry("client1", certGClient1.getPrivateKey(), password, new X509Certificate[] { certClient1 });
		kClient2.setKeyEntry("client2", certGClient2.getPrivateKey(), password, new X509Certificate[] { certClient2 });
		
		// set the trusted certificates and the public keys in the keystore
		tServer.setCertificateEntry("client1", certClient1);
		tServer.setCertificateEntry("client2", certClient2);
		tClient.setCertificateEntry("server", certServer);

		// Store away the keystore.
		FileOutputStream fos;
		
		fos = new FileOutputStream("serverKeyStore");
		kServer.store(fos, password);
		fos.close();	
		
		fos = new FileOutputStream("client1KeyStore");
		kClient1.store(fos, password);
		fos.close();
		
		fos = new FileOutputStream("client2KeyStore");
		kClient2.store(fos, password);
		fos.close();
		
		fos = new FileOutputStream("serverTrustStore");
		tServer.store(fos, password);
		fos.close();	
		
		fos = new FileOutputStream("clientTrustStore");
		tClient.store(fos, password);
		fos.close();

	}
}
