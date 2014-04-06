package protocol;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import common.Constants;
import common.Utils;

public class DiscoverPayload implements Serializable {
	
	private static final long serialVersionUID = 102688147909876831L;
	ArrayList<String> usernames;
	
	public DiscoverPayload(ArrayList<String> usernames){
		this.usernames = usernames;
	}
	
	public byte[] getSerialization(){
		try{
			return common.Utils.serialize(this);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Serializes then encrypts result and returns it. Only called by Client
	 * @author Jaffe
	 * @param pubk Public key of Server
	 * @return the encrypted object in byte array form
	 */
	public byte[] encrypt(byte[] seshKey){
		try{
			if (Constants.CRYPTO_OFF)
			{
				return this.getSerialization();
			}
			else
			{
				//instantiate signature with chosen algorithm
				Cipher cipher = Cipher.getInstance(Constants.SYMMETRIC_CRYPTO_MODE);
				Utils.printByteArr(seshKey);
				SecretKeySpec k = new SecretKeySpec(seshKey, Constants.SYMMETRIC_CRYPTO_MODE);
				//init signature with public key
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
	
	/**
	 * Decrypt encryptedData, then fill out fields of AuthenticationPayload object
	 * @param privk Private key of the Server
	 * @param encryptedData encrypted byte array of AuthenticationPayload
	 * @return 
	 * @return the decrypted serialized object
	 */
	public ArrayList<String> decrypt(byte[] seshKey, byte[] encryptedData){
		try{
			if (Constants.CRYPTO_OFF)
			{
				Object o = common.Utils.deserialize(encryptedData);
				//cast the object as a DiscoverPayload
				DiscoverPayload list = (DiscoverPayload) o;
				//create an array list for the client
				return list.usernames;
			}
			else
			{
				//instantiate signature with chosen algorithm
				Cipher cipher = Cipher.getInstance(Constants.SYMMETRIC_CRYPTO_MODE);
				SecretKeySpec k = new SecretKeySpec(seshKey, Constants.SYMMETRIC_CRYPTO_MODE);
				//init signature with private key
				cipher.init(Cipher.DECRYPT_MODE, k);
				//write encrypted bytes to encryptedData since it was passed by reference
				byte[] plaintext =  cipher.doFinal(encryptedData);
				//deserialize the plaintext into an object
				Object o = common.Utils.deserialize(plaintext);
				//cast the object as a DiscoverPayload
				DiscoverPayload list = (DiscoverPayload) o;
				//create an array list for the client
				return list.usernames;
			}
		//ltj: for all of these exceptions, return null if an Exception was raised so that return value is more defined
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
