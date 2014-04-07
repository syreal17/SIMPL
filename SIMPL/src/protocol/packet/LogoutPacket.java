package protocol.packet;

import java.util.EnumSet;


/**
 * I think this is currently vulnerable to TCP hijacking to do a denial of service
 * To fix it, we would have to:
 * 		1. Encrypt and decrypt these packets
 * 		2. Ensure that encrypted LogoutPackets look different every time they are encrypted
 *
 */
public class LogoutPacket extends Packet {

	private static final long serialVersionUID = -5843876932465216286L;

	/**
	 * Client requests logout
	 */
	public void readyClientLogoutFIN(){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Client Login request
		this.setClientLogoutFINFlags();
	}
	
	/**
	 * Server says ok to logout
	 */
	public void readyServerLogoutFINACK(){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Client Login request
		this.setServerLogoutFINACKFlags();
	}
	
	/**
	 * Client says logging out
	 */
	public void readyClientLogoutACK(){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Client Login request
		this.setClientLogoutACKFlags();
	}
	
	/**
	 * Client logout FIN flag set
	 */
	private void setClientLogoutFINFlags(){
		this.flags = LogoutPacket.getClientLogoutFINFlags();
	}
	
	public static EnumSet<Flag> getClientLogoutFINFlags(){
		return EnumSet.of(Packet.Flag.Logout, Packet.Flag.Finished);
	}
	
	/**
	 * Server logout FIN/ACK flag set
	 */
	private void setServerLogoutFINACKFlags(){
		this.flags = LogoutPacket.getServerLogoutFINACKFlags();
	}
	
	public static EnumSet<Flag> getServerLogoutFINACKFlags(){
		return EnumSet.of(Packet.Flag.Logout, Packet.Flag.Finished, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Client logout ACK flag set
	 */
	private void setClientLogoutACKFlags(){
		this.flags = LogoutPacket.getClientLogoutACKFlags();
	}
	
	public static EnumSet<Flag> getClientLogoutACKFlags(){
		return EnumSet.of(Packet.Flag.Logout, Packet.Flag.Acknowledgement);
	}
	
}
