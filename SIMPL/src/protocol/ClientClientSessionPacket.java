package protocol;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ClientClientSessionPacket extends Packet {

	@Override
	public Packet sign(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientClientSessionPacket sign");
		return null;
	}

	@Override
	public boolean verify(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientClientSessionPacket verify");
		return false;
	}

	@Override
	public Packet decrypt(PrivateKey privk) {
		// TODO Auto-generated method stub
		System.out.println("ClientClientSessionPacket decrypt");
		return null;
	}

	@Override
	public Packet encrypt(PublicKey pubk) {
		// TODO Auto-generated method stub
		System.out.println("ClientClientSessionPacket encrypt");
		return null;
	}

}
