package protocol;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ClientServerSessionPacket extends Packet {

	private static final long serialVersionUID = 2542476687780929164L;

	@Override
	public Packet sign(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerSessionPacket sign");
		return null;
	}

	@Override
	public byte[] verify(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerSessionPacket verify");
		throw new UnsupportedOperationException();
	}

	@Override
	public byte[] decrypt(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerSessionPacket decrypt");
		return null;
	}

	@Override
	public byte[] encrypt(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerSessionPacket encrypt");
		return null;
	}

}
