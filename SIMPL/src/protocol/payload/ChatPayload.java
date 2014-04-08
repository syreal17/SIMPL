package protocol.payload;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import common.*;

//TODO: Might even extend ClientServerSession if DH key can be made into byte[]
public class ChatPayload extends Payload {

	private static final long serialVersionUID = -4032008079394447168L;
	
	public String message;
	
	public ChatPayload(String message){
		this.message = message;
	}

	@Override
	public void copyFrom(Payload template) throws SimplException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	public void encrypt(SecretKey seshKey)
	{
		/* Encrypt the message with the symmetric key */
		try {
			Cipher cipher = Cipher.getInstance(common.Constants.SYMMETRIC_CRYPTO_MODE);
			cipher.init(Cipher.ENCRYPT_MODE, seshKey);
			message = cipher.doFinal(message.getBytes()).toString();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public String decrypt(SecretKey seshKey)
	{
		/* Encrypt the message with the symmetric key */
		try {
			Cipher cipher = Cipher.getInstance(common.Constants.SYMMETRIC_CRYPTO_MODE);
			cipher.init(Cipher.DECRYPT_MODE, seshKey);
			return cipher.doFinal(message.getBytes()).toString();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return message;
	}

}
