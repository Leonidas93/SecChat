package secchat;

/*
 * Source code from http://www.dreamincode.net/forums/topic/259777-a-simple-chat-program-with-clientserver-gui-optional/
 */
import java.io.*;
import java.net.*;
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
import java.text.SimpleDateFormat;
import java.util.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/*
 * The server that can be run both as a console application or a GUI
 */
public class Server {
	// a unique ID for each connection
	private static int uniqueId;
	// an ArrayList to keep the list of the Client
	private ArrayList<ClientThread> al;
	// if I am in a GUI
	private ServerGUI sg;
	// to display time
	private SimpleDateFormat sdf;
	// the port number to listen for connection
	private int port;
	// the boolean that will be turned of to stop the server
	private boolean keepGoing;
	
	private EncryptDecrypt encdec;
	
	static SSLContext ssl_ctx;

	/*
	 *  server constructor that receive the port to listen to for connection as parameter
	 *  in console
	 */
	public Server(int port) {
		this(port, null);
	}
	
	public Server(int port, ServerGUI sg) {
		// GUI or not
		this.sg = sg;
		// the port
		this.port = port;
		// to display hh:mm:ss
		sdf = new SimpleDateFormat("HH:mm:ss");
		// ArrayList for the Client list
		al = new ArrayList<ClientThread>();
	}
	
	public void start() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException, NoSuchProviderException, UnrecoverableKeyException, KeyManagementException {
		
		encdec = new EncryptDecrypt();
		
		keepGoing = true;
		
		//truststore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        FileInputStream fis = new FileInputStream("serverTrustStore");
        trustStore.load(fis, "access".toCharArray());
        fis.close();
        trustManagerFactory.init(trustStore);
        
        //keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        fis = new FileInputStream("serverKeyStore");
        keyStore.load(fis, "access".toCharArray());
        fis.close();
        keyManagerFactory.init(keyStore, "access".toCharArray());
              

        // Setup the SSL context to use the truststore and keystore
        ssl_ctx = SSLContext.getInstance("TLS");
        ssl_ctx.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
		
		SSLServerSocketFactory ssf = (SSLServerSocketFactory) ssl_ctx.getServerSocketFactory();
		
		/* create socket server and wait for connection requests */
		try 
		{
			// the socket used by the server			
			SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);
			serverSocket.setNeedClientAuth(true);
			// infinite loop to wait for connections
			while(keepGoing) 
			{
				// format message saying we are waiting
				display("Server waiting for Clients on port " + port + ".");
				
				SSLSocket socket = (SSLSocket) serverSocket.accept();  	// accept connection
				
			
				// if I was asked to stop
				if(!keepGoing)
					break;
				ClientThread t = new ClientThread(socket);  // make a thread of it
				al.add(t);									// save it in the ArrayList
				t.start();
			}
			// I was asked to stop
			try {
				serverSocket.close();
				for(int i = 0; i < al.size(); ++i) {
					ClientThread tc = al.get(i);
					try {
					tc.sInput.close();
					tc.sOutput.close();
					tc.socket.close();
					}
					catch(IOException ioE) {
						// not much I can do
					}
				}
			}
			catch(Exception e) {
				display("Exception closing the server and clients: " + e);
			}
		}
		// something went bad
		catch (IOException e) {
            String msg = sdf.format(new Date()) + " Exception on new ServerSocket: " + e + "\n";
			display(msg);
		}
	}		
    /*
     * For the GUI to stop the server
     */
	protected void stop() {
		keepGoing = false;

		try {
			new Socket("localhost", port);
		}
		catch(Exception e) {
		}
	}
	/*
	 * Display an event (not a message) to the console or the GUI
	 */
	private void display(String msg) {
		String time = sdf.format(new Date()) + " " + msg;
		if(sg == null)
			System.out.println(time);
		else
			sg.appendEvent(time + "\n");
	}
	/*
	 *  to broadcast a message to all Clients
	 */
	private synchronized void broadcast(String message) {
		// add HH:mm:ss and \n to the message
		String time = sdf.format(new Date());
		String messageLf = time + " " + message + "\n";
		// display message on console or GUI
		if(sg == null)
			System.out.print(messageLf);
		else
			sg.appendRoom(messageLf);     // append in the room window
		
		// we loop in reverse order in case we would have to remove a Client
		// because it has disconnected
		for(int i = al.size(); --i >= 0;) {
			ClientThread ct = al.get(i);
			// try to write to the Client if it fails remove it from the list
			if(!ct.writeMsg(messageLf)) {
				al.remove(i);
				display("Disconnected Client " + ct.username + " removed from list.");
			}
		}
	}

	// for a client who logoff using the LOGOUT message
	synchronized void remove(int id) {
		// scan the array list until we found the Id
		for(int i = 0; i < al.size(); ++i) {
			ClientThread ct = al.get(i);
			// found it
			if(ct.id == id) {
				al.remove(i);
				return;
			}
		}
	}
	
	/*
	 *  To run as a console application just open a console window and: 
	 * > java Server
	 * > java Server portNumber
	 * If the port number is not specified 1500 is used
	 */ 
	public static void main(String[] args) {		
		// start server on port 1500 unless a PortNumber is specified 
		int portNumber = 1500;
		switch(args.length) {
			case 1:
				try {
					portNumber = Integer.parseInt(args[0]);
				}
				catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Server [portNumber]");
					return;
				}
			case 0:
				break;
			default:
				System.out.println("Usage is: > java Server [portNumber]");
				return;
				
		}
		// create a server object and start it
		Server server = new Server(portNumber);
		try {
			server.start();
		} catch (InvalidKeyException | KeyStoreException
				| NoSuchAlgorithmException | CertificateException
				| SignatureException | NoSuchProviderException | IOException | UnrecoverableKeyException | KeyManagementException e) {
			e.printStackTrace();
		}
	}

	/** One instance of this thread will run for each client */
	class ClientThread extends Thread {
		// the socket where to listen/talk
		SSLSocket socket;
		ObjectInputStream sInput;
		ObjectOutputStream sOutput;
		// my unique id (easier for deconnection)
		int id;
		// the Username of the Client
		String username;
		// the only type of message a will receive
		ChatMessage cm;
		// the date I connect
		String date;
		
		SSLSession session;
		
		int counter = 1;
		
		Message m;

		// Constructore
		ClientThread(SSLSocket socket) throws SSLPeerUnverifiedException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, SignatureException, InvalidKeyException, CertificateException, NoSuchProviderException {
			// a unique id
			id = ++uniqueId;
			this.socket = socket;
			
			session = socket.getSession();			
			
			//elegxos tis egkurothtas kai ths upografhs certificate
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
			
			
		    /* Creating both Data Stream */
			System.out.println("Thread trying to create Object Input/Output Streams");
			try
			{
				// create output first
				sOutput = new ObjectOutputStream(socket.getOutputStream());
				sInput  = new ObjectInputStream(socket.getInputStream());
				// read the username
				m = (Message) sInput.readObject();
				
				//ypografh											
				PublicKey clientPublicKey = ClientThread.this.session.getPeerCertificates()[0].getPublicKey();		
				Signature serverVerifySign = Signature.getInstance("MD5withRSA");
				serverVerifySign.initVerify(clientPublicKey);
				serverVerifySign.update(m.getSData().getBytes());
				
				System.out.println();
				System.out.println((counter ++)+"."+"(from: "+ClientThread.this.session.getPeerPrincipal().getName().split("=")[1].toLowerCase()+")");
				boolean verifySign = serverVerifySign.verify(m.getSignature());
				if (verifySign == false){
					System.out.println("Digital signature failed verification.");
				}
				else{
					System.out.println("Digital signature has been verified.");
				}
				
				//apokruptografhsh tou summetrikoy kleidiou me ton RSA
				KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
				char[] password = "access".toCharArray();
				FileInputStream fis = new FileInputStream("serverKeyStore");
				ks.load(fis, password);
				fis.close();
				
				PrivateKey serverPrivateKey = (PrivateKey) ks.getKey("server", password);
			    int index = m.getSData().indexOf("|");
			    String AesKeyEncryptedRsa = m.getSData().substring(0,index);
			    String MDChatMessage = m.getSData().substring(index+1);
			    
			    // summetriko kleidi
			    byte[] EncryptedRsa = new BASE64Decoder().decodeBuffer(AesKeyEncryptedRsa);
			    byte[] DecryptedRsa = encdec.decrypt(EncryptedRsa, serverPrivateKey, "RSA/ECB/PKCS1Padding");
			    
			    //apokruptografoume to mhnuma me to summetriko kleidi
			    SecretKeySpec secretKey = new SecretKeySpec(DecryptedRsa, "AES");
			    byte[] DecryptedAes = encdec.decrypt(m.getEnChatMessage(), secretKey, "AES");
			    				    
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
				
				username = new String(DecryptedAes);
				display(username + " just connected.");
			}
			catch (IOException e) {
				display("Exception creating new Input/output Streams: " + e);
				return;
			}
			// have to catch ClassNotFoundException
			// but I read a String, I am sure it will work
			catch (ClassNotFoundException e) {
			}
            date = new Date().toString() + "\n";
		}

		// what will run forever
		public void run() {
			// to loop until LOGOUT
			boolean keepGoing = true;
			while(keepGoing) {
				// read a String (which is an object)
				try {
					m = (Message) sInput.readObject();
					//Elegxos ths ypografhs						
					PublicKey clientPublicKey = ClientThread.this.session.getPeerCertificates()[0].getPublicKey();
					Signature serverVerifySign = Signature.getInstance("MD5withRSA");
					serverVerifySign.initVerify(clientPublicKey);
					serverVerifySign.update(m.getSData().getBytes());
					
					System.out.println();
					System.out.println((counter ++)+"."+"(from: "+ClientThread.this.session.getPeerPrincipal().getName().split("=")[1].toLowerCase()+")");
					boolean verifySign = serverVerifySign.verify(m.getSignature());
					if (verifySign == false){
						System.out.println("Digital signature failed verification.");
					}
					else{
						System.out.println("Digital signature has been verified.");
					}
					
					//apokryptografhsh tou kleidioy
					KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
					char[] password = "access".toCharArray();
					FileInputStream fis = new FileInputStream("serverKeyStore");
					ks.load(fis, password);
					fis.close();
					
					PrivateKey serverPrivateKey = (PrivateKey) ks.getKey("server", password);	
				    int index = m.getSData().indexOf("|");
				    String AesKeyEncryptedRsa = m.getSData().substring(0,index);
				    String MDChatMessage = m.getSData().substring(index+1);
				    byte[] EncryptedRsa = new BASE64Decoder().decodeBuffer(AesKeyEncryptedRsa);
				    byte[] DecryptedRsa = encdec.decrypt(EncryptedRsa, serverPrivateKey, "RSA/ECB/PKCS1Padding");
				    
				    //apokryptografhsh tou mhnymatos
				    SecretKeySpec secretKey = new SecretKeySpec(DecryptedRsa, "AES");
				    byte[] DecryptedAes = encdec.decrypt(m.getEnChatMessage(), secretKey, "AES");
				    				    
				    //elegxos ths sunopshs
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
					
					//Dhmiourgia mhnumatos
					ByteArrayInputStream bis = new ByteArrayInputStream(DecryptedAes);
					ObjectInput in = null;
					ChatMessage m;
					try {
					  in = new ObjectInputStream(bis);
					  m = (ChatMessage) in.readObject(); 
					} finally {
					  try {
					    bis.close();
					  } catch (IOException ex) {
					    // ignore close exception
					  }
					  try {
					    if (in != null) {
					      in.close();
					    }
					  } catch (IOException ex) {
					    // ignore close exception
					  }
					}
						
					cm = m;
										
				}
				catch (IOException | ClassNotFoundException | KeyStoreException | NoSuchAlgorithmException | CertificateException | InvalidKeyException | SignatureException | UnrecoverableKeyException e) {
					display(username + " Exception reading Streams: " + e);
					break;				
				}
				// the message part of the ChatMessage
				String message = cm.getMessage();

				// Switch on the type of message receive
				switch(cm.getType()) {

				case ChatMessage.MESSAGE:
					broadcast(username + ": " + message);
					break;
				case ChatMessage.LOGOUT:
					display(username + " disconnected with a LOGOUT message.");
					keepGoing = false;
					break;
				case ChatMessage.WHOISIN:
					writeMsg("List of the users connected at " + sdf.format(new Date()) + "\n");
					// scan al the users connected
					for(int i = 0; i < al.size(); ++i) {
						ClientThread ct = al.get(i);
						writeMsg((i+1) + ") " + ct.username + " since " + ct.date);
					}
					break;
				}
			}
			// remove myself from the arrayList containing the list of the
			// connected Clients
			remove(id);
			close();
		}
		
		// try to close everything
		private void close() {
			// try to close the connection
			try {
				if(sOutput != null) sOutput.close();
			}
			catch(Exception e) {}
			try {
				if(sInput != null) sInput.close();
			}
			catch(Exception e) {};
			try {
				if(socket != null) socket.close();
			}
			catch (Exception e) {}
		}

		/*
		 * Write a String to the Client output stream
		 */
		private boolean writeMsg(String msg) {
			// if Client is still connected send the message to it
			if(!socket.isConnected()) {
				close();
				return false;
			}
			// write the message to the stream
			try {
				SecretKey senderSecretKey = EncryptDecrypt.getSecretkey();
				
				//kryptografhsh toy mhnymatos
				byte[] EncryptedAes = encdec.encrypt(msg.getBytes(), senderSecretKey, "AES");
				
				//kruptografhsh toy summetrikoy kleidioy
				PublicKey clientPublicKey = ClientThread.this.session.getPeerCertificates()[0].getPublicKey();
				byte[] EncryptedRsa = encdec.encrypt(senderSecretKey.getEncoded(), clientPublicKey, "RSA/ECB/PKCS1Padding");
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
				FileInputStream fis = new FileInputStream("serverKeyStore");
				ks.load(fis, password);
				fis.close();			
		
				PrivateKey serverPrivateKey = (PrivateKey) ks.getKey("server", password);
				Signature clientSign = Signature.getInstance("MD5withRSA");
				clientSign.initSign(serverPrivateKey);
				clientSign.update(ChatMessageToSignature.getBytes());
				byte[] SignedChatMessage = clientSign.sign();
				
				//To mhnuma pros apostolh
				Message msgToSend = new Message(EncryptedAes, ChatMessageToSignature, SignedChatMessage);
				sOutput.writeObject(msgToSend);
			}
			// if an error occurs, do not abort just inform the user
			catch(IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | InvalidKeyException | SignatureException e) {
				display("Error sending message to " + username);
				display(e.toString());
			}
			return true;
		}
	}
}
