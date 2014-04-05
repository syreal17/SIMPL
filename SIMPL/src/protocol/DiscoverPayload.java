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

import common.Constants;

public class DiscoverPayload implements Serializable {
	
	private static final long serialVersionUID = 102688147909876831L;
	Set<String> usernames;
	
	public DiscoverPayload(Set<String> usernames){
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
	public byte[] encrypt(SecretKey seshKey){
		try{
			if (Constants.CRYPTO_OFF)
			{
				return this.getSerialization();
			}
			else
			{
				//instantiate signature with chosen algorithm
				Cipher cipher = Cipher.getInstance(Constants.SYMMETRIC_CRYPTO_MODE);
				//init signature with public key
				cipher.init(Cipher.ENCRYPT_MODE, seshKey);
				//return encrypted bytes
				return cipher.doFinal(this.getSerialization());
			}
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
			return null;
		} catch (NoSuchPaddingException e){
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e){
			e.printStackTrace();
			return null;
		} catch (IllegalBlockSizeException e){
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e){
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
	public ArrayList<String> decrypt(SecretKey seshKey, byte[] encryptedData){
		try{
			if (Constants.CRYPTO_OFF)
			{
				ArrayList<String> strings = new ArrayList<String>();
				//populate the array list
				for( String s : usernames ) strings.add(s);
				return strings;
			}
			else
			{
				//instantiate signature with chosen algorithm
				Cipher cipher = Cipher.getInstance(Constants.SYMMETRIC_CRYPTO_MODE);
				//init signature with private key
				cipher.init(Cipher.DECRYPT_MODE, seshKey);
				//write encrypted bytes to encryptedData since it was passed by reference
				byte[] plaintext = cipher.doFinal(encryptedData);
				//deserialize the plaintext into an object
				Object o = common.Utils.deserialize(plaintext);
				//cast the object as a DiscoverPayload
				DiscoverPayload list = (DiscoverPayload) o;
				//create an array list for the client
				ArrayList<String> strings = new ArrayList<String>();
				//populate the array list
				for( String s : list.usernames ) strings.add(s);
				return strings;
			}
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
		} catch (NoSuchPaddingException e){
			e.printStackTrace();
		} catch (InvalidKeyException e){
			e.printStackTrace();
		} catch (IllegalBlockSizeException e){
			e.printStackTrace();
		} catch (BadPaddingException e){
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return (ArrayList<String>) usernames;	
	}

}
