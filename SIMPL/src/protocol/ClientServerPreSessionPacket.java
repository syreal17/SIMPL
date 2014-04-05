package protocol;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * This class might be useless since Login is the only descendent
 * @author syreal
 *
 */
public abstract class ClientServerPreSessionPacket extends Packet {

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
		// TODO Auto-generated method stub
		System.out.println("TODO: ClientServerPreSessionPacket verify");
		//this is used in Client.do_login
		// TODO: deserialize the crypto_data
		// TODO: figure out how to link this to ChallengePayload!
		throw new UnsupportedOperationException();
	}

	@Override
	public Packet decrypt(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerPreSessionPacket decrypt");
		return null;
	}

	@Override
	public Packet encrypt(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerPreSessionPacket encrypt");
		return null;
	}

}
