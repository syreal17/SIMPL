package protocol;

import java.io.*;
import java.security.*;

public class AuthenticationPayload implements Serializable {

	/**
	 * auto-gen for Serializable
	 */
	private static final long serialVersionUID = 4377476943444101218L;

	public String username;
	public byte[] pwHash;			//hash of the user password
	public long N;				//TODO: PRNG 64 bits? 128 bits?
	
	public AuthenticationPayload(String username, byte[] pwHash, long N){
		this.username = username;
		this.pwHash = pwHash;
		this.N = N;
	}
	
	public byte[] getSerialization() throws IOException{
		return common.Utils.serialize(this);
	}
	
	/**
	 * Serializes then encrypts result and returns it. Only called by Client
	 * @author syreal
	 * @param pubk Public key of Server
	 * @return the encrypted object in byte array form
	 */
	public byte[] encrypt(PublicKey pubk){
		//TODO: implement
		//getSerialization then crypto
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Decrypt encryptedData, then fill out fields of AuthenticationPayload object
	 * @param privk Private key of the Server
	 * @param encryptedData encrypted byte array of AuthenticationPayload
	 * @return the decrypted serialized object
	 */
	public void decrypt(PrivateKey privk, byte[] encryptedData){
		//TODO: implement
		//Client might actually handle this decryption...
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
}
