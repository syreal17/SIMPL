package protocol;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
	public byte[] encrypt(PublicKey pubk){
		try{
			if (Constants.CRYPTO_OFF)
			{
				return this.getSerialization();
			}
			else
			{
				//instantiate signature with chosen algorithm
				Cipher cipher = Cipher.getInstance(Constants.ASYMMETRIC_CRYPTO_MODE);
				//init signature with public key
				cipher.init(Cipher.ENCRYPT_MODE, pubk);
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
	 * @return the decrypted serialized object
	 */
	public void decrypt(PrivateKey privk, byte[] encryptedData){
		try{
			if (Constants.CRYPTO_OFF)
			{
				
			}
			else
			{
				//instantiate signature with chosen algorithm
				Cipher cipher = Cipher.getInstance(Constants.ASYMMETRIC_CRYPTO_MODE);
				//init signature with private key
				cipher.init(Cipher.DECRYPT_MODE, privk);
				//write encrypted bytes to encryptedData since it was passed by reference
				encryptedData = cipher.doFinal(encryptedData);
			}
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
			return;
		} catch (NoSuchPaddingException e){
			e.printStackTrace();
			return;
		} catch (InvalidKeyException e){
			e.printStackTrace();
			return;
		} catch (IllegalBlockSizeException e){
			e.printStackTrace();
			return;
		} catch (BadPaddingException e){
			e.printStackTrace();
			return;
		}
	}

}
