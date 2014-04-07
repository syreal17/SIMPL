package protocol.payload;

import java.io.*;
import java.net.*;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import common.Constants;

public class ServerNegotiateRequestPayload implements Serializable {

	private static final long serialVersionUID = -7149274176512251578L;
	
	public String wantToUsername;
	public InetAddress wantToIP;
	public PublicKey clientA_DHContrib; 	//g^amodp
	public byte[] N;						//nonce
	
	public ServerNegotiateRequestPayload(String wantToUsername, InetAddress wantToIP, PublicKey clientA_DHContrib, byte[] N){
		this.wantToUsername = wantToUsername;
		this.wantToIP = wantToIP;
		this.clientA_DHContrib = clientA_DHContrib;
		this.N = N;
	}
	
	//COPY PASTA!!!!!!!!!!!!
	public byte[] getSerialization(){
		try{
			return common.Utils.serialize(this);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	//COPY PASTA!!!!!!!!!!!!
	//TODO: put in superclass
	public byte[] encrypt(byte[] seshKey){
		try{
			if (Constants.CRYPTO_OFF)
			{
				return this.getSerialization();
			}
			else
			{
				Cipher cipher = Cipher.getInstance(Constants.SYMMETRIC_CRYPTO_MODE);
				SecretKeySpec k = new SecretKeySpec(seshKey, Constants.SYMMETRIC_CRYPTO_MODE);
				cipher.init(Cipher.ENCRYPT_MODE, k);
				//return encrypted bytes
				return cipher.doFinal(this.getSerialization());
			}
		} catch (NoSuchAlgorithmException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (NoSuchPaddingException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (IllegalBlockSizeException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	//COPY PASTA!! Minor tweaks
	public ServerNegotiateRequestPayload decrypt(byte[] seshKey, byte[] encryptedData){
		try{
			if (Constants.CRYPTO_OFF)
			{
				Object o = common.Utils.deserialize(encryptedData);
				ServerNegotiateRequestPayload payload = (ServerNegotiateRequestPayload) o;
				return payload;
			}
			else
			{
				Cipher cipher = Cipher.getInstance(Constants.SYMMETRIC_CRYPTO_MODE);
				SecretKeySpec k = new SecretKeySpec(seshKey, Constants.SYMMETRIC_CRYPTO_MODE);
				cipher.init(Cipher.DECRYPT_MODE, k);
				//write encrypted bytes to encryptedData since it was passed by reference
				byte[] plaintext =  cipher.doFinal(encryptedData);
				//deserialize the plaintext into an object
				Object o = common.Utils.deserialize(plaintext);
				//cast the object as a DiscoverPayload
				ServerNegotiateRequestPayload payload = (ServerNegotiateRequestPayload) o;
				//create an array list for the client
				return payload;
			}
		} catch (NoSuchAlgorithmException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (NoSuchPaddingException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (IllegalBlockSizeException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (ClassNotFoundException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		}	
	}
}
