package protocol;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class might be useless since Login is the only descendent
 * @author syreal
 *
 */
public abstract class ClientServerPreSessionPacket extends Packet {

	private static final long serialVersionUID = -1352874766933099117L;

	@Override
	public Packet sign(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerPreSessionPacket sign");
		return null;
	}

	@Override
	/**
	 * @return the data minus the signature. Useful, cause can then be casted to ChallengePayload.
	 */
	public byte[] verify(PublicKey pubk) {
		if( common.Constants.CRYPTO_OFF ){
			System.out.println("TODO: ClientServerPreSessionPacket verify");
			//return unmodified crypto_data, which if CRYPTO_OFF path is correct, should be already plaintext
			return this.crypto_data;
		}
		//this is used in Client.do_login
		// TODO: PROBABLY JUST PUT JAFFE CODE HERE?
		// TODO: deserialize the crypto_data
		// TODO: figure out how to link this to ChallengePayload!
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] decrypt(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerPreSessionPacket decrypt");
		return null;
	}

	@Override
	public byte[] encrypt(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerPreSessionPacket encrypt");
		return null;
	}

}
