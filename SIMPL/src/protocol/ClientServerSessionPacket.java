package protocol;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ClientServerSessionPacket extends Packet {

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
	public Packet decrypt(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerSessionPacket decrypt");
		return null;
	}

	@Override
	public Packet encrypt(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientServerSessionPacket encrypt");
		return null;
	}

}
