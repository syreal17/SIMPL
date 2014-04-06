package protocol;

import java.util.EnumSet;

public class NegotiatePacket extends ClientServerSessionPacket  {


	private static final long serialVersionUID = -2305135360829217137L;

	/**
	 * Set flags for the initial negotiate message that the Client1 sends to Server AND what Server passes on to
	 * Client2
	 */
	private void setNegotiateRequestFlags(){
		this.flags = EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Syncronization);
	}
	
	/**
	 * Set flags for the Client2's response to Server AND Server's passing on of response to Client1
	 */
	private void setNegotiateResponseFlags(){
		this.flags = EnumSet.of(Packet.Flag.Negotiate, Packet.Flag.Syncronization, Packet.Flag.Acknowledgement);
	}
}
