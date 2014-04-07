package protocol.packet;

import java.security.*;
import java.util.*;
import protocol.payload.*;

public class NegotiatePacket extends Packet  {


	private static final long serialVersionUID = -2305135360829217137L;
	
	private ClientANegotiateRequestPayload clientNegReqPayload;
	private ServerNegotiateRequestPayload serverNegReqPayload;
	private ClientBNegotiateResponsePayload clientNegRespPayload;
	private ServerNegotiateResponsePayload serverNegRespPayload;
	
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
	
	/**
	 * Flags are implicitly outside of any encryption, so no seshKey needed.
	 */
	public void readyServerNegotiateDenyResponse(){
		this.clearAllFields();
		this.setNegotiateDenyResponseFlags();
	}
	
	/**
	 * Flags are implicitly outside of any encryption, so no seshKey needed.
	 */
	public void readyServerNegotiateNonexistantResponse(){
		this.clearAllFields();
		this.setNegotiateNonexistantResponseFlags();
	}
	
	public void readyServerNegotiateRequest(byte[] clientB_seshKey, ServerNegotiateRequestPayload payload){
		this.clearAllFields();
		this.setNegotiateRequestFlags();
		this.crypto_data = payload.encrypt(clientB_seshKey); 
	}
	
	public void readyClientBNegotiateResponse(byte[] clientB_seshKey, PublicKey clientB_DHContrib, byte[] N){
		ClientBNegotiateResponsePayload payload = new ClientBNegotiateResponsePayload(clientB_DHContrib, N);
		this.clearAllFields();
		this.setNegotiateOkResponseFlags();
		this.crypto_data = payload.encrypt(clientB_seshKey);
	}
	
	public void readyServerNegotiateResponse(byte[] clientA_seshKey, ServerNegotiateResponsePayload payload){
		this.clearAllFields();
		this.setNegotiateOkResponseFlags();
		this.crypto_data = payload.encrypt(clientA_seshKey);
	}
	
	public ClientANegotiateRequestPayload getClientARequestPayload(byte[] clientA_seshKey){
		ClientANegotiateRequestPayload payload = new ClientANegotiateRequestPayload();
		payload.decrypt(clientA_seshKey, this.crypto_data);
		this.clientNegReqPayload = payload;
		return this.clientNegReqPayload;
	}
	
	public ServerNegotiateRequestPayload getServerRequestPayload(byte[] clientB_seshKey){
		ServerNegotiateRequestPayload payload = new ServerNegotiateRequestPayload();
		payload.decrypt(clientB_seshKey, this.crypto_data);
		this.serverNegReqPayload = payload;
		return this.serverNegReqPayload;
	}
	
	public ClientBNegotiateResponsePayload getClientBResponsePayload(byte[] clientB_seshKey){
		ClientBNegotiateResponsePayload payload = new ClientBNegotiateResponsePayload();
		payload.decrypt(clientB_seshKey, this.crypto_data);
		this.clientNegRespPayload = payload;
		return this.clientNegRespPayload;
	}
	
	public ServerNegotiateResponsePayload getServerResponsePayload(byte[] clientA_seshKey){
		ServerNegotiateResponsePayload payload = new ServerNegotiateResponsePayload();
		payload.decrypt(clientA_seshKey, this.crypto_data);
		this.serverNegRespPayload = payload;
		return this.serverNegRespPayload;
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
	
	/**
	 * Set flags for when Client1 requests a non-existant username
	 */
	private void setNegotiateNonexistantResponseFlags(){
		this.flags = NegotiatePacket.getNegotiateNonexistantResponseFlags();
	}
	
	public static EnumSet<Flag> getNegotiateNonexistantResponseFlags(){
		return EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Nonexistant, Packet.Flag.Finished);
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
