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
	public boolean verify(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerPreSessionPacket verify");
		return false;
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
