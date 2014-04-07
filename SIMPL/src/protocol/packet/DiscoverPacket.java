package protocol.packet;

import java.util.*;

import protocol.payload.DiscoverPayload;


public class DiscoverPacket extends Packet {
	
	private static final long serialVersionUID = -393407001993431232L;
	public DiscoverPayload discoveryList;
	
	public DiscoverPacket(){
		this.discoveryList = new DiscoverPayload(null);
	}
	
	public void readyClientDiscoverRequest(){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Client Discovery request
		this.setClientDiscoverRequestFlags();
	}

	public void readyServerDiscoverResponse(Set<String> usernames, byte[] seshKey){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Server Discovery response
		this.setServerDiscoverResponseFlags();
		
		//initialize the discovery list
		ArrayList<String> strings = new ArrayList<String>();
		//populate the array list
		for( String s : usernames ) strings.add(s);
		this.discoveryList = new DiscoverPayload(strings);
		
		//encrypt the discovery list
		byte[] encrypted_data = this.discoveryList.encrypt(seshKey);
		this.crypto_data = Arrays.copyOf(encrypted_data, encrypted_data.length);
	}
	
	public ArrayList<String> decryptServerDiscoverReponse(byte[] usernames, byte[] seshKey){
		//decrypt puts "list" into this.discoveryList.list
		this.discoveryList.decrypt(seshKey, usernames);
		return this.discoveryList.usernames;
	}

	/**
	 * Set flags for the discovery message that the Client sends
	 */
	private void setClientDiscoverRequestFlags(){
		this.flags = DiscoverPacket.getClientDiscoverRequestFlags();
	}
	
	public static EnumSet<Flag> getClientDiscoverRequestFlags(){
		return EnumSet.of(Packet.Flag.Discover, Packet.Flag.Syncronization);
	}

	/**
	 * Set flags for the Server's discovery response to the Client
	 */
	private void setServerDiscoverResponseFlags(){
		this.flags = DiscoverPacket.getServerDiscoverResponseFlags();
	}
	
	public static EnumSet<Flag> getServerDiscoverResponseFlags(){
		return EnumSet.of(Packet.Flag.Discover, Packet.Flag.Syncronization, Packet.Flag.Acknowledgement);
	}
	
}

