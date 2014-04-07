package protocol.payload;

import java.net.*;
import java.security.*;

import common.SimplException;

public class ServerNegotiateResponsePayload extends ClientServerSessionPayload {

	private static final long serialVersionUID = 585566613856440056L;

	public InetAddress talkToIP;
	public PublicKey clientB_DHContrib;
	public byte[] N;
	
	public ServerNegotiateResponsePayload(InetAddress talkToIP, PublicKey clientB_DHContrib, byte[] N){
		this.talkToIP = talkToIP;
		this.clientB_DHContrib = clientB_DHContrib;
		this.N = N;
	}
	
	public ServerNegotiateResponsePayload(){}
	
	@Override
	public void copyFrom(Payload template) throws SimplException {
		if( template instanceof ServerNegotiateResponsePayload){
			ServerNegotiateResponsePayload nrTemplate = (ServerNegotiateResponsePayload) template;
			this.talkToIP = nrTemplate.talkToIP;
			this.clientB_DHContrib = nrTemplate.clientB_DHContrib;
			this.N = nrTemplate.N;
		} else {
			throw new SimplException("Payload template was not a ServerNegotiateResponsePayload!");
		}
	}
}
