package protocol;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class Packet implements Serializable {
	
	/**
	 * auto-gen for Serializable
	 */
	private static final long serialVersionUID = 1L;

	private static enum Flag{
		Acknowledgement, Negotiation, Chat, Finished, Encrypted, Signed
	}
	
	private byte[] encrypted_data;
	
	abstract public Packet sign(PrivateKey privk);
	abstract public boolean verify(PublicKey pubk);
	abstract public Packet decrypt(PrivateKey privk);
	abstract public Packet encrypt(PublicKey pubk);
}
