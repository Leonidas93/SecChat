package secchatroom;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class EncryptDecrypt{			
		static KeyGenerator keyGen;
		
		public static SecretKey getSecretkey(){
			//Dimiourgia kleidiou AES
			try
			{
				keyGen = KeyGenerator.getInstance("AES");
				keyGen.init(128);
			}					
			catch(Exception exp)
			{
				System.out.println(" Exception inside constructor " +exp);
			}
			
			SecretKey secretKey = keyGen.generateKey();
			return secretKey;
		}

		public byte[] encrypt(byte[] EncryptData, Key secretKey, String Alg) {
			byte[] byteCipherText = new byte[200];
			
			try 
			{
				//Dhmioourgia Cipher antikeimenou topo8etontas to epilegmeno algorithmo kriptographshs
				Cipher cipher = Cipher.getInstance(Alg);
			
				//Ciphers Initialization
				if(Alg.equals("AES")){
					cipher.init(Cipher.ENCRYPT_MODE,secretKey,cipher.getParameters());
				}
				else if(Alg.equals("RSA/ECB/PKCS1Padding")){
					cipher.init(Cipher.ENCRYPT_MODE,secretKey);
				} 
					
				//kruptografhsh toy pinaka byteCipherText
				byteCipherText = cipher.doFinal(EncryptData); 
			}			
			catch (NoSuchAlgorithmException noSuchAlgorithm)
			{
				System.out.println(" No Such Algorithm exists " + noSuchAlgorithm);
			}
			catch (NoSuchPaddingException noSuchPadding)
			{
				System.out.println(" No Such Padding exists " + noSuchPadding);
			}
		
			catch (InvalidKeyException invalidKey)
			{
				System.out.println(" Invalid Key " + invalidKey);
			}			
			catch (BadPaddingException badPadding)
			{
				System.out.println(" Bad Padding " + badPadding);
			}			
			catch (IllegalBlockSizeException illegalBlockSize)
			{
				System.out.println(" Illegal Block Size " + illegalBlockSize);
				illegalBlockSize.printStackTrace();
			}
			catch (Exception exp)
			{
				exp.printStackTrace();
			}
					
			return byteCipherText;
		}
		
		public byte[] decrypt(byte[] CipherText, Key secretKey, String Alg) {
			byte[] DecryptedText = new byte[200];
						
			try
			{	
				//Dhmioourgia Cipher antikeimenou topo8etontas to epilegmeno algorithmo kriptographshs
				Cipher cipher = Cipher.getInstance(Alg);
				 
				//Ciphers Initialization
				if(Alg.equals("AES")){
					cipher.init(Cipher.DECRYPT_MODE,secretKey,cipher.getParameters());
				}
				else if(Alg.equals("RSA/ECB/PKCS1Padding")){
					cipher.init(Cipher.DECRYPT_MODE,secretKey);
				} 
				
				//Apokruptografhsh toy pinaka byteCipherText
				DecryptedText = cipher.doFinal(CipherText);
			}			
			catch (NoSuchAlgorithmException noSuchAlgorithm)
			{
				System.out.println(" No Such Algorithm exists " + noSuchAlgorithm);
			}
			catch (NoSuchPaddingException noSuchPadding)
			{
				System.out.println(" No Such Padding exists " + noSuchPadding);
			}
			catch (InvalidKeyException invalidKey)
			{
				System.out.println(" Invalid Key " + invalidKey);
				invalidKey.printStackTrace();
			}	
			catch (BadPaddingException badPadding)
			{
				System.out.println(" Bad Padding " + badPadding);
				badPadding.printStackTrace();
			}			
			catch (IllegalBlockSizeException illegalBlockSize)
			{
				System.out.println(" Illegal Block Size " + illegalBlockSize);
				illegalBlockSize.printStackTrace();
			}			
			catch (InvalidAlgorithmParameterException invalidParameter)
			{
				System.out.println(" Invalid Parameter " + invalidParameter);
			}
	
			return DecryptedText;
		}
}
