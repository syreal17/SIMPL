package protocol;

import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class ClientServerPreSessionPacket extends Packet {

	@Override
	public Packet sign(PrivateKey privk) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean verify(PublicKey pubk) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Packet decrypt(PrivateKey privk) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Packet encrypt(PublicKey pubk) {
		// TODO Auto-generated method stub
		return null;
	}

}
