package protocol.packet;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.EnumSet;

import protocol.packet.Packet.Flag;
import protocol.payload.*;

public class ChatPacket extends Packet {

	private static final long serialVersionUID = 8812780492017128972L;
	
	public ChatPayload payload;
	
	//prep the message by encrypting it and setting flags
	public void prepareMessage(String msg, PublicKey buddyKey)
	{
		this.payload.message = msg;
		payload.encrypt(buddyKey);
		this.setChatPacketFlags();
	}
	
	//decrypt the message and return it as a String
	public String retrieveMessage(PrivateKey myKey)
	{
		return payload.decrypt(myKey);
	}
	
	/**
	 * Chat packet flags
	 */
	private void setChatPacketFlags(){
		this.flags = ChatPacket.getChatPacketFlags();
	}
	
	public static EnumSet<Flag> getChatPacketFlags(){
		return EnumSet.of(Packet.Flag.Chat);
	}
}
