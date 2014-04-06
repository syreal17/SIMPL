package protocol;

import java.util.EnumSet;

public class NegotiatePacket extends ClientServerSessionPacket  {


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

	/**
	 * Set flags for the initial negotiate message that the Client1 sends to Server AND what Server passes on to
	 * Client2
	 */
	private void setNegotiateRequestFlags(){
		this.flags = EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Syncronization);
	}
	
	/**
	 * Set flags for the Client2's "ok" response to Server AND Server's passing on of response to Client1
	 */
	private void setNegotiateOkResponseFlags(){
		this.flags = EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Syncronization, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Set flags for Client2's "deny" response to Server AND Server's passing on of response to Client1
	 */
	private void setNegotiateDenyResponseFlags(){
		this.flags = EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Deny, Packet.Flag.Finished);
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
