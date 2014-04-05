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
	/**
	 * auto-gen for Serializable
	 */
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
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public byte[] sign(PrivateKey privk) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		//instantiate signature with chosen algorithm
		Signature sig = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);
		//init signature with private key
		sig.initSign(privk);
		//update signature with bytes to be signed
		sig.update(this.getSerialization());
		//return the signature
		return sig.sign();
	}
	
	/**
	 * Verified that the signature on the ChallengePayload checks out with the public key of SIMPL Server
	 * @param pubk Public key of the SIMPL Server
	 * @return true if signature is valid SIMPL Server signature, false otherwise
	 * @throws InvalidKeyException 
	 * @throws IOException 
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 */
	public boolean verify(PublicKey pubk, byte[] signature) throws InvalidKeyException, SignatureException, IOException, NoSuchAlgorithmException{
		//instantiate signature with chosen algorithm
		Signature sig = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);
		//init signature with public key
		sig.initVerify(pubk);
		//update signature with bytes to be signed
		sig.update(this.getSerialization());
		//check to see if the signature is valid
		return sig.verify(signature);
	}
}
