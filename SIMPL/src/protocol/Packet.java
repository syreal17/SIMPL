package protocol;

import java.io.Serializable;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.EnumSet;

public abstract class Packet implements Serializable {
	
	/**
	 * auto-gen for Serializable
	 */
	private static final long serialVersionUID = 1L;

	private static enum Flag{
		Acknowledgement, Negotiation, Chat, Finished, Encrypted, Signed
	}
	
	private byte[] encrypted_data;
	private EnumSet<Flag> flags;		//will be zeroed out if encrypted
	private Socket socket;				//shouldn't be a problem to send this in clear
	
	abstract public Packet sign(PrivateKey privk);
	abstract public boolean verify(PublicKey pubk);
	abstract public Packet decrypt(PrivateKey privk);
	abstract public Packet encrypt(PublicKey pubk);
}
