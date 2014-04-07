package protocol.packet;

import java.util.EnumSet;



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
		this.flags = EnumSet.of(Packet.Flag.Logout, Packet.Flag.Finished);
	}
	
	/**
	 * Server logout FIN/ACK flag set
	 */
	private void setServerLogoutFINACKFlags(){
		this.flags = EnumSet.of(Packet.Flag.Logout, Packet.Flag.Finished, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Client logout ACK flag set
	 */
	private void setClientLogoutACKFlags(){
		this.flags = EnumSet.of(Packet.Flag.Logout, Packet.Flag.Acknowledgement);
	}
	
}
