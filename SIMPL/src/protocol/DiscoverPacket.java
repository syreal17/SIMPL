package protocol;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.EnumSet;
import java.util.Set;

import protocol.DiscoverPayload;


public class DiscoverPacket extends ClientServerSessionPacket {
	
	DiscoverPayload discoveryList;
	
	public DiscoverPacket(){
		this.discoveryList = new DiscoverPayload(null);
	}
	
	public void readyClientDiscoverRequest(){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Client Discovery request
		this.setClientDiscoverRequestFlags();
	}

	public byte[] readyServerDiscoverResponse(Set<String> usernames, PublicKey pubk){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Server Discovery response
		this.setServerDiscoverResponseFlags();
		
		//initialize the discovery list
		this.discoveryList = new DiscoverPayload(usernames);
		
		//encrypt the discovery list
		return this.discoveryList.encrypt(pubk);
	}
	
	public void decryptServerDiscoverReponse(byte[] usernames, PrivateKey privk){
		//
		this.discoveryList.decrypt(privk, usernames);
	}

	/**
	 * Set flags for the discovery message that the Client sends
	 */
	private void setClientDiscoverRequestFlags(){
		this.flags = EnumSet.of(Packet.Flag.Discover, Packet.Flag.Syncronization);
	}

	/**
	 * Set flags for the Server's discovery response to the Client
	 */
	private void setServerDiscoverResponseFlags(){
		this.flags = EnumSet.of(Packet.Flag.Discover, Packet.Flag.Syncronization, Packet.Flag.Acknowledgement);
	}
	
}

