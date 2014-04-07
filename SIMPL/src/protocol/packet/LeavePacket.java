package protocol.packet;

import java.util.EnumSet;

/**
 * I think this is currently vulnerable to TCP hijacking to do a denial of service
 * To fix it, we would have to:
 * 		1. Encrypt and decrypt these packets
 * 		2. Ensure that encrypted LeavePackets look different every time they are encrypted
 *
 * Reference:
 * 		http://www.techrepublic.com/article/tcp-hijacking/
 * 
 */
public class LeavePacket extends Packet {

	private static final long serialVersionUID = 917649278682126231L;
	
	public void readyClientA_FIN(){
		this.clearAllFields();
		this.setClientA_FIN_Flags();
	}

	public void readyClientB_FINACK(){
		this.clearAllFields();
		this.setClientB_FINACK_Flags();
	}
	
	public void readyClientA_ACK(){
		this.clearAllFields();
		this.setClientA_ACK();
	}
	
	private void setClientA_FIN_Flags(){
		this.flags = LeavePacket.getClientA_FIN_Flags();
	}
	
	public static EnumSet<Flag> getClientA_FIN_Flags(){
		return EnumSet.of(Packet.Flag.Leave, Packet.Flag.Finished);
	}
	
	private void setClientB_FINACK_Flags(){
		this.flags = LeavePacket.getClientB_FINACK_Flags();
	}
	
	public static EnumSet<Flag> getClientB_FINACK_Flags(){
		return EnumSet.of(Packet.Flag.Leave, Packet.Flag.Finished, Packet.Flag.Acknowledgement);
	}
	
	private void setClientA_ACK(){
		this.flags = LeavePacket.getClientA_ACK();
	}
	
	public static EnumSet<Flag> getClientA_ACK(){
		return EnumSet.of(Packet.Flag.Leave, Packet.Flag.Acknowledgement);
	}
}
