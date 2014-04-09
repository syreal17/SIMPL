package protocol.payload;

import java.io.IOException;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import common.*;

//TODO: Might even extend ClientServerSession if DH key can be made into byte[]
public class ChatPayload extends Payload {

	private static final long serialVersionUID = -4032008079394447168L;
	
	public byte[] message;
	
	public ChatPayload(String message){
		if (message != null)
			this.message = message.getBytes();
		else
			this.message = null;
	}

	@Override
	public void copyFrom(Payload template) throws SimplException {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	public void encrypt(byte[] seshKey)
	{
		/* Encrypt the message with the symmetric key */
		try {
			Cipher cipher = Cipher.getInstance(common.Constants.SYMMETRIC_CRYPTO_MODE);
			SecretKeySpec k = new SecretKeySpec(seshKey, Constants.SYMMETRIC_CRYPTO_MODE);
			cipher.init(Cipher.ENCRYPT_MODE, k);
			this.message = cipher.doFinal(this.message);
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
	
	public String decrypt(byte[] seshKey)
	{
		/* Encrypt the message with the symmetric key */
		try {
			Cipher cipher = Cipher.getInstance(common.Constants.SYMMETRIC_CRYPTO_MODE);
			SecretKeySpec k = new SecretKeySpec(seshKey, Constants.SYMMETRIC_CRYPTO_MODE);
			cipher.init(Cipher.DECRYPT_MODE, k);
			byte[] plainBytes = cipher.doFinal(this.message);
			//make a string
			String msg = new String(plainBytes);
			//and finally we return dat shit as a string
			return msg;
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
		return null;
	}

}
