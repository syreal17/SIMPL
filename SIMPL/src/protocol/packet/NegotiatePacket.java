package protocol.packet;

import java.net.*;
import java.security.*;
import java.util.*;

import protocol.payload.ClientANegotiateRequestPayload;
import protocol.payload.ClientBNegotiateResponsePayload;
import protocol.payload.ServerNegotiateRequestPayload;
import protocol.payload.ServerNegotiateResponsePayload;

public class NegotiatePacket extends Packet  {


	private static final long serialVersionUID = -2305135360829217137L;
	
	public ClientANegotiateRequestPayload clientNegReqPayload;
	public ServerNegotiateRequestPayload serverNegReqPayload;
	public ClientBNegotiateResponsePayload clientNegRespPayload;
	public ServerNegotiateResponsePayload serverNegRespPayload;
	
	public NegotiatePacket(){
		this.clientNegReqPayload = null;
		this.serverNegReqPayload = null;
		this.clientNegRespPayload = null;
		this.serverNegRespPayload = null;
	}
	
	public void readyClientANegotiateRequest(byte[] clientA_seshKey, String clientB_Username, PublicKey clientA_DHContrib, 
			byte[] N){
		ClientANegotiateRequestPayload payload = new ClientANegotiateRequestPayload(clientB_Username, clientA_DHContrib, N);
		this.clearAllFields();
		this.setNegotiateRequestFlags();
		this.crypto_data = payload.encrypt(clientA_seshKey);
	}
	
	public void readyServerNegotiateRequest(byte[] clientB_seshKey, String clientA_Username, InetAddress clientA_IP, 
			PublicKey clientA_DHContrib, byte[] N){
		ServerNegotiateRequestPayload payload = new ServerNegotiateRequestPayload(clientA_Username, clientA_IP, 
				clientA_DHContrib, N);
		this.clearAllFields();
		this.setNegotiateRequestFlags();
		this.crypto_data = payload.encrypt(clientB_seshKey); 
		
	}

	/**
	 * Set flags for the initial negotiate message that the Client1 sends to Server AND what Server passes on to
	 * Client2
	 */
	private void setNegotiateRequestFlags(){
		this.flags = NegotiatePacket.getNegotiateRequestFlags();
	}
	
	public static EnumSet<Flag> getNegotiateRequestFlags(){
		return EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Syncronization);
	}
	
	/**
	 * Set flags for the Client2's "ok" response to Server AND Server's passing on of response to Client1
	 */
	private void setNegotiateOkResponseFlags(){
		this.flags = NegotiatePacket.getNegotiateOkResponseFlags();
	}
	
	public static EnumSet<Flag> getNegotiateOkResponseFlags(){
		return EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Syncronization, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Set flags for Client2's "deny" response to Server AND Server's passing on of response to Client1
	 */
	private void setNegotiateDenyResponseFlags(){
		this.flags = NegotiatePacket.getNegotiateDenyResponseFlags();
	}
	
	public static EnumSet<Flag> getNegotiateDenyResponseFlags(){
		return EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Deny, Packet.Flag.Finished);
	}
	
	@Override
	public void clearAllFields(){
		super.clearAllFields();
		
		this.clientNegReqPayload = null;
		this.serverNegReqPayload = null;
		this.clientNegRespPayload = null;
		this.serverNegRespPayload = null;
	}
}