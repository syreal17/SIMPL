package protocol.packet;

import java.util.*;

import javax.crypto.*;

import protocol.payload.*;

public class ChatPacket extends Packet {

	private static final long serialVersionUID = 8812780492017128972L;
	
	public ChatPayload payload;
	
	public ChatPacket(){
		this.payload = new ChatPayload(null);
	}
	
	//prep the message by encrypting it and setting flags
	public void prepareMessage(String msg, SecretKey seshKey)
	{
		this.payload.message = msg;
		payload.encrypt(seshKey);
		this.setChatPacketFlags();
	}
	
	//decrypt the message and return it as a String
	public String retrieveMessage(SecretKey seshKey)
	{
		return payload.decrypt(seshKey);
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
