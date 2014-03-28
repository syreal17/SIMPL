package protocol;

import java.io.*;
import java.security.*;

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
	
	public long R_1;
	public byte[] challengeHash;
	
	public ChallengePayload(long R_1, byte[] challengeHash){
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
		//TODO: implement
		//TODO: involves getSerialization()
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Verified that the signature on the ChallengePayload checks out with the public key of SIMPL Server
	 * @param pubk Public key of the SIMPL Server
	 * @return true if signature is valid SIMPL Server signature, false otherwise
	 */
	public boolean verify(PublicKey pubk){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
}
