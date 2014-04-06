package protocol;

import java.io.*;
import java.net.*;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

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
	
	public byte[] getSerialization(){
		try{
			return common.Utils.serialize(this);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	//COPY PASTA!!!!!!!!!!!!
	public byte[] encrypt(SecretKey seshKey){
		try{
			if (Constants.CRYPTO_OFF)
			{
				return this.getSerialization();
			}
			else
			{
				Cipher cipher = Cipher.getInstance(Constants.SYMMETRIC_CRYPTO_MODE);
				cipher.init(Cipher.ENCRYPT_MODE, seshKey);
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
	
	//TODO: copy pasta
}
