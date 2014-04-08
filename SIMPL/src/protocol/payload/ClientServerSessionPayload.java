package protocol.payload;

import java.io.*;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import common.*;

public abstract class ClientServerSessionPayload extends Payload {

	private static final long serialVersionUID = 8682513019611048706L;
	
	/**
	 * Returns the encrypted byte array of this object's serialization
	 * @param seshKey the session key to encrypt with
	 * @return the encrypted byte array of this object's serialization
	 */
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
	
	/**
	 * In-place decrypt (viz, fills in its own fields) of the encryptedData
	 * @param seshKey session key to decrypt with
	 * @param encryptedData the encrypted, serialized form of this object
	 */
	public void decrypt(byte[] seshKey, byte[] encryptedData){
		try{
			if (Constants.CRYPTO_OFF)
			{
				Object o = common.Utils.deserialize(encryptedData);
				//cast the object as a DiscoverPayload
				Payload template = (Payload) o;
				//create an array list for the client
				this.copyFrom(template);
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
				//cast the object as a generic Payload
				Payload template = (Payload) o;
				//copy all the unencrypted object fields to "this" object
				this.copyFrom(template);
			}
		} catch (SimplException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (NoSuchAlgorithmException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (NoSuchPaddingException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (InvalidKeyException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (IllegalBlockSizeException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (BadPaddingException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (ClassNotFoundException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (IOException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
}
