package secchat;

/*
 * Source code from http://www.dreamincode.net/forums/topic/259777-a-simple-chat-program-with-clientserver-gui-optional/
 */
import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/*
 * The Client that can be run both as a console or a GUI
 */
public class Client  {

	// for I/O
	private ObjectInputStream sInput;		// to read from the socket
	private ObjectOutputStream sOutput;		// to write on the socket
	private SSLSocket socket;

	// if I use a GUI or not
	private ClientGUI cg;
	
	// the server, the port and the username
	private String server, username;
	private int port;

	private EncryptDecrypt encdec;
	
	static SSLContext ssl_ctx;
	private SSLSession session;
	private String clientN;
	/*
	 *  Constructor called by console mode
	 *  server: the server address
	 *  port: the port number
	 *  username: the username
	 */
	Client(String server, int port, String username) {
		// which calls the common constructor with the GUI set to null
		this(server, port, username, null);
	}

	/*
	 * Constructor call when used from a GUI
	 * in console mode the ClienGUI parameter is null
	 */
	Client(String server, int port, String username, ClientGUI cg) {
		this.server = server;
		this.port = port;
		this.username = username;
		// save if we are in GUI mode or not
		this.cg = cg;
	}
	
	/*
	 * To start the dialog
	 */
	public boolean start() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyManagementException {
		
		clientN = "client1";
		
		encdec = new EncryptDecrypt();
		
		//  truststore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        FileInputStream fis = new FileInputStream("clientTrustStore");
        trustStore.load(fis, "access".toCharArray());
        fis.close();
        trustManagerFactory.init(trustStore);

        //  keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        fis = new FileInputStream(clientN+"KeyStore");
        keyStore.load(fis, "access".toCharArray());
        fis.close();
        keyManagerFactory.init(keyStore, "access".toCharArray());

        // Setup the SSL context to use the truststore and keystore
        ssl_ctx = SSLContext.getInstance("TLS");
        ssl_ctx.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
		
		SSLSocketFactory SSLsf = (SSLSocketFactory) ssl_ctx.getSocketFactory();
		
		// try to connect to the server
		try {
			socket = (SSLSocket) SSLsf.createSocket(server, port);
			//socket.startHandshake();

			session = socket.getSession();

			//elegxos ths ypografis kai ths egkurothtas tou pistopoihtikou
			System.out.println();
			X509Certificate cert;
		    try {
		      cert = (X509Certificate) session.getPeerCertificates()[0];
		      cert.verify(cert.getPublicKey());
		      cert.checkValidity();
		      System.out.println("Certificate "+cert.getSubjectDN().getName()+" has been approved.");
		    } catch (SSLPeerUnverifiedException e) {
		      System.err.println(session.getPeerHost() + " failed verification.");
		    }
		    System.out.println();
		  
		} 
		// if it failed not much I can so
		catch(Exception e) {
			display("Error connectiong to server:" + e);
			return false;
		}
		
		String msg = "Connection accepted " + socket.getInetAddress() + ":" + socket.getPort();
		display(msg);
	
		/* Creating both Data Stream */
		try
		{
			sInput  = new ObjectInputStream(socket.getInputStream());
			sOutput = new ObjectOutputStream(socket.getOutputStream());
		}
		catch (IOException eIO) {
			display("Exception creating new Input/output Streams: " + eIO);
			return false;
		}

		// creates the Thread to listen from the server 
		new ListenFromServer().start();
		// Send our username to the server this is the only message that we
		// will send as a String. All other messages will be ChatMessage objects
		try
		{
			
			SecretKey senderSecretKey = EncryptDecrypt.getSecretkey();
			
			//Kruptografhsh tou mhnymatos
			byte[] EncryptedAes = encdec.encrypt(username.getBytes(), senderSecretKey, "AES");
			
			//kruptografhsh toy summetrikoy kleidioy
			PublicKey serverPublicKey = session.getPeerCertificates()[0].getPublicKey();
			byte[] EncryptedRSA = encdec.encrypt(senderSecretKey.getEncoded(), serverPublicKey, "RSA/ECB/PKCS1Padding");
			String AesKeyEncryptedRsa = new BASE64Encoder().encode(EncryptedRSA);
			
			//Dhmiourgia ths sunopshs kai ths ypografhs 
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(username.getBytes());
			byte[] byteMDChatMessage = md.digest();
			
			String MDChatMessage = new String();
			for (int i = 0; i < byteMDChatMessage.length; i++){
				MDChatMessage = MDChatMessage + Integer.toHexString((int)byteMDChatMessage[i] & 0xFF) ;
		    }
					
			String ChatMessageToSign = AesKeyEncryptedRsa + "|" + MDChatMessage;
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			char[] password = "access".toCharArray();
	        FileInputStream fis1 = new FileInputStream(clientN+"KeyStore");
	        ks.load(fis1, "access".toCharArray());
	        fis.close();   
			
			PrivateKey clientPrivateKey = (PrivateKey) ks.getKey(clientN, password);
			Signature clientSignature = Signature.getInstance("MD5withRSA");
			clientSignature.initSign(clientPrivateKey);
			clientSignature.update(ChatMessageToSign.getBytes());
			byte[] SignedChatMessage = clientSignature.sign();
			
			//mhnuma pros apostolh
			Message msgToSend = new Message(EncryptedAes, ChatMessageToSign, SignedChatMessage);	
			sOutput.writeObject(msgToSend);
		}
		catch (IOException eIO) {
			display("Exception doing login : " + eIO);
			disconnect();
			return false;
		}
		return true;
	}

	/*
	 * To send a message to the console or the GUI
	 */
	private void display(String msg) {
		if(cg == null)
			System.out.println(msg);      // println in console mode
		else
			cg.append(msg + "\n");		// append to the ClientGUI JTextArea (or whatever)
	}
	
	/*
	 * Apostolh mhnumatos sto server
	 */
	void sendMessage(ChatMessage msg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnrecoverableKeyException, SignatureException, KeyStoreException, IOException, CertificateException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
		
		SecretKey senderSecretKey = EncryptDecrypt.getSecretkey();
		
		//kryptografhsh toy mhnymatos
		byte[] EncryptedAes = encdec.encrypt(msg.getBytes(), senderSecretKey, "AES");
		
		//kruptografhsh toy summetrikoy kleidioy
		PublicKey serverPublicKey = session.getPeerCertificates()[0].getPublicKey();
		byte[] EncryptedRsa = encdec.encrypt(senderSecretKey.getEncoded(), serverPublicKey, "RSA/ECB/PKCS1Padding");
		String AesKeyEncryptedRsa = new BASE64Encoder().encode(EncryptedRsa);
		
		//Dhmiourgia ths sunopshs kai ths ypografhs 
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(msg.getBytes());
		byte[] byteMDChatMessage = md.digest();
		
		String MDChatMessage = new String();
		for (int i = 0; i < byteMDChatMessage.length; i++){
			MDChatMessage = MDChatMessage + Integer.toHexString((int)byteMDChatMessage[i] & 0xFF) ;
	    }
				
		String ChatMessageToSignature = AesKeyEncryptedRsa + "|" + MDChatMessage;
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] password = "access".toCharArray();
        FileInputStream fis = new FileInputStream(clientN+"KeyStore");
        ks.load(fis, "access".toCharArray());
        fis.close();   
		
		PrivateKey clientPrivateKey = (PrivateKey) ks.getKey(clientN, password);
		Signature clientSign = Signature.getInstance("MD5withRSA");
		clientSign.initSign(clientPrivateKey);
		clientSign.update(ChatMessageToSignature.getBytes());
		byte[] byteSignedChatMessage = clientSign.sign();
		
		//mhnuma pros apostolh
		Message msgToSend = new Message(EncryptedAes, ChatMessageToSignature, byteSignedChatMessage);
			
		try {
			sOutput.writeObject(msgToSend);
		}
		catch(IOException e) {
			display("Exception writing to server: " + e);
		}
	}

	/*
	 * if something goes wrong close input/output and diconnect 
	 * 
	 */
	private void disconnect() {
		try { 
			if(sInput != null) sInput.close();
		}
		catch(Exception e) {} // not much else I can do
		try {
			if(sOutput != null) sOutput.close();
		}
		catch(Exception e) {} // not much else I can do
        try{
			if(socket != null) socket.close();
		}
		catch(Exception e) {} // not much else I can do
		
		if(cg != null)
			cg.connectionFailed();
			
	}
	/*
	 * To start the Client in console mode use one of the following command
	 * > java Client
	 * > java Client username
	 * > java Client username portNumber
	 * > java Client username portNumber serverAddress
	 * at the console prompt
	 * If the portNumber is not specified 1500 is used
	 * If the serverAddress is not specified "localHost" is used
	 * If the username is not specified "Anonymous" is used
	 * > java Client 
	 * is equivalent to
	 * > java Client Anonymous 1500 localhost 
	 * are eqquivalent
	 * 
	 * In console mode, if an error occurs the program simply stops
	 * when a GUI id used, the GUI is informed of the disconnection
	 */
	public static void main(String[] args) throws UnrecoverableKeyException, KeyManagementException {
		// default values
		int portNumber = 1500;
		String serverAddress = "localhost";
		String userName = "Anonymous";

		// depending of the number of arguments provided we fall through
		switch(args.length) {
			// > javac Client username portNumber serverAddr
			case 3:
				serverAddress = args[2];
			// > javac Client username portNumber
			case 2:
				try {
					portNumber = Integer.parseInt(args[1]);
				}
				catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Client [username] [portNumber] [serverAddress]");
					return;
				}
			// > javac Client username
			case 1: 
				userName = args[0];
			// > java Client
			case 0:
				break;
			// wrong input
			default:
				System.out.println("Usage is: > java Client [username] [portNumber] {serverAddress]");
			return;
		}
		// dhmiourgia client
		Client client = new Client(serverAddress, portNumber, userName);
		// sundesh me to server
		try {
			if(!client.start())
				return;
		} catch (InvalidKeyException | KeyStoreException
				| NoSuchAlgorithmException | CertificateException
				| NoSuchProviderException | SignatureException | IOException e) {			
			e.printStackTrace();
		}
		
		// wait for messages from user
		@SuppressWarnings("resource")
		Scanner scan = new Scanner(System.in);
		// loop forever for message from the user
		while(true) {
			System.out.print("> ");
			// read message from user
			String msg = scan.nextLine();
			// logout if message is LOGOUT
			if(msg.equalsIgnoreCase("LOGOUT")) {
				try {
					client.sendMessage(new ChatMessage(ChatMessage.LOGOUT, ""));
				} catch (InvalidKeyException | UnrecoverableKeyException
						| NoSuchAlgorithmException | NoSuchPaddingException
						| SignatureException | KeyStoreException
						| CertificateException | IllegalBlockSizeException
						| BadPaddingException | ClassNotFoundException
						| IOException e) {
					e.printStackTrace();
				}
				// break to do the disconnect
				break;
			}
			// message WhoIsIn
			else if(msg.equalsIgnoreCase("WHOISIN")) {
				try {
					client.sendMessage(new ChatMessage(ChatMessage.WHOISIN, ""));
				} catch (InvalidKeyException | UnrecoverableKeyException
						| NoSuchAlgorithmException | NoSuchPaddingException
						| SignatureException | KeyStoreException
						| CertificateException | IllegalBlockSizeException
						| BadPaddingException | ClassNotFoundException
						| IOException e) {
					e.printStackTrace();
				}				
			}
			else {				// default to ordinary message
				try {
					client.sendMessage(new ChatMessage(ChatMessage.MESSAGE, msg));
				} catch (InvalidKeyException | UnrecoverableKeyException
						| NoSuchAlgorithmException | NoSuchPaddingException
						| SignatureException | KeyStoreException
						| CertificateException | IllegalBlockSizeException
						| BadPaddingException | ClassNotFoundException
						| IOException e) {
					e.printStackTrace();
				}
			}
		}
		// done disconnect
		client.disconnect();	
	}

	/*
	 * a class that waits for the message from the server and append them to the JTextArea
	 * if we have a GUI or simply System.out.println() it in console mode
	 */
	class ListenFromServer extends Thread {

		int counter = 1;
		
		public void run() {
			while(true) {
				try {
					Message mo = (Message) sInput.readObject();
					
					//Elengxos ths psifiakhs  ypografhs				
					PublicKey serverPublicKey = session.getPeerCertificates()[0].getPublicKey();
					Signature serverVerifySign = Signature.getInstance("MD5withRSA");
					serverVerifySign.initVerify(serverPublicKey);
					serverVerifySign.update(mo.getSData().getBytes());
					
					System.out.println();
					System.out.println((counter ++)+"."+"(from: server)");
					boolean verifySign = serverVerifySign.verify(mo.getSignature());
					if (verifySign == false){
						System.out.println("Digital signature failed verification.");
					}
					else{
						System.out.println("Digital signature has been verified.");
					}
					
					//apokruptografhsh tou summetrikoy kleidioy me ton RSA
					KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
					char[] password = "access".toCharArray();
					FileInputStream fis = new FileInputStream(clientN+"KeyStore");
					ks.load(fis, password);
					fis.close();	
					
					PrivateKey clientPrivateKey = (PrivateKey) ks.getKey(clientN, password);
				    int index = mo.getSData().indexOf("|");
				    String AesKeyEncryptedRsa = mo.getSData().substring(0,index);
				    String MDChatMessage = mo.getSData().substring(index+1);
				    
				    //To summetriko kleidi
				    byte[] EncryptedRsa = new BASE64Decoder().decodeBuffer(AesKeyEncryptedRsa);
				    byte[] DecryptedRsa = encdec.decrypt(EncryptedRsa, clientPrivateKey, "RSA/ECB/PKCS1Padding");
				    
				    //apokruptografoume to mhnuma me to summetriko kleidi
				    SecretKeySpec secretKey = new SecretKeySpec(DecryptedRsa, "AES");
				    byte[] DecryptedAes = encdec.decrypt(mo.getEnChatMessage(), secretKey, "AES");
				    				    
				    //elengxos ths sunopshs toy mhnumatos
				    MessageDigest md = MessageDigest.getInstance("MD5");
				    md.update(DecryptedAes);
					byte HashSignedData[] = md.digest();
					String strHashData = new String();
						
					for (int i = 0; i < HashSignedData.length; i++){
						strHashData = strHashData + Integer.toHexString((int)HashSignedData[i] & 0xFF) ;
				    }
					
					if (!strHashData.equals(MDChatMessage))
					{
						System.out.println("The message has been changed or corrupted.");
						System.out.println(strHashData);
						System.out.println(MDChatMessage);
					}
					else{
						System.out.println("The message has not been changed or corrupted.");
					}
					System.out.println();
					
					String msg = new String(DecryptedAes);
					
					// if console mode print the message and add back the prompt
					if(cg == null) {
						System.out.println(msg);
						System.out.print("> ");
					}
					else {
						cg.append(msg);
					}
				}
				catch(IOException e) {
					display("Server has close the connection: " + e);
					if(cg != null) 
						cg.connectionFailed();
					break;
				}
				// can't happen with a String object but need the catch anyhow
				catch(ClassNotFoundException e2) {
				} catch (KeyStoreException e) {
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				} catch (CertificateException e) {
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					e.printStackTrace();
				} catch (UnrecoverableKeyException e) {
					e.printStackTrace();
				} catch (SignatureException e) {
					e.printStackTrace();
				}
			}
		}
	}
}

