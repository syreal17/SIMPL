package protocol;

import java.io.*;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import common.Constants;

public class AuthenticationPayload implements Serializable {

	/**
	 * auto-gen for Serializable
	 */
	private static final long serialVersionUID = 4377476943444101218L;

	public String username;
	public byte[] pwHash;			//hash of the user password
	public byte[] N;				//TODO: PRNG 64 bits? 128 bits?
	
	public AuthenticationPayload(String username, byte[] pwHash, byte[] N){
		this.username = username;
		this.pwHash = pwHash;
		this.N = N;
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
	 * @author syreal
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
