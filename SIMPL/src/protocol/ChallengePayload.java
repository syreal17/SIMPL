package protocol;

import java.io.*;
import java.security.*;

import common.Constants;

/**
 * The signable and verifiable challenge payload of a Login message
 * @author syreal
 *
 */
public class ChallengePayload implements Serializable {

	private static final long serialVersionUID = -128127638431769002L;
	
	public byte[] R_1;
	public byte[] challengeHash;
	
	public ChallengePayload(byte[] R_1, byte[] challengeHash){
		this.R_1 = R_1;
		this.challengeHash = challengeHash;
	}
	
	public byte[] getSerialization() throws IOException{
		return common.Utils.serialize(this);
	}

	
	/**
	 * Sign the challenge payload with the Server private key. Used by Server only
	 * @author JaffeTaffy
	 * @param privk Private key of the SIMPL Server
	 * @return the ChallengePayload as a signed byte array (will add length to array)
	 */
	public byte[] sign(PrivateKey privk){
		try{
			if (Constants.CRYPTO_OFF)
			{
				return this.getSerialization();
			}
			else
			{
				//instantiate signature with chosen algorithm
				Signature sig = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);
				//init signature with private key
				sig.initSign(privk);
				//update signature with bytes to be signed
				sig.update(this.getSerialization());
				//return the signature
				return sig.sign();
			}
		} catch (IOException e){
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e){
			e.printStackTrace();
			return null;
		} catch (SignatureException e){
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Verified that the signature on the ChallengePayload checks out with the public key of SIMPL Server
	 * @param pubk Public key of the SIMPL Server
	 * @param signature the signature bytes for the ChallengePayload
	 * @return true if signature is valid SIMPL Server signature, false otherwise 
	 */
	public boolean verify(PublicKey pubk, byte[] signature) {
		try{
			if (Constants.CRYPTO_OFF)
			{
				return true;
			}
			else
			{
				//instantiate signature with chosen algorithm
				Signature sig = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);
				//init signature with public key
				sig.initVerify(pubk);
				//update signature with bytes to be verified
				sig.update(this.getSerialization());
				//check to see if the signature is valid
				return sig.verify(signature);
			}
		} catch (IOException e){
			e.printStackTrace();
			return (Boolean) null;
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
			return (Boolean) null;
		} catch (InvalidKeyException e){
			e.printStackTrace();
			return (Boolean) null;
		} catch (SignatureException e){
			e.printStackTrace();
			return (Boolean) null;
		}
	}
}
