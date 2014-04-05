package protocol;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ClientClientSessionPacket extends Packet {

	private static final long serialVersionUID = -1952428858862006860L;

	@Override
	public Packet sign(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientClientSessionPacket sign");
		return null;
	}

	@Override
	public byte[] verify(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientClientSessionPacket verify");
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] decrypt(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientClientSessionPacket decrypt");
		return null;
	}

	@Override
	public byte[] encrypt(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientClientSessionPacket encrypt");
		return null;
	}

}
