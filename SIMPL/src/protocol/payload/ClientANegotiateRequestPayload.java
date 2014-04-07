package protocol.payload;

import java.security.*;
import common.SimplException;

public class ClientANegotiateRequestPayload extends ClientServerSessionPayload {

	private static final long serialVersionUID = 451135002987918260L;

	public String clientB_Username;
	public PublicKey clientA_DHContrib; 	//g^amodp
	public byte[] N;						//nonce
	
	public ClientANegotiateRequestPayload(String talkToUsername, PublicKey clientA_DHContrib, byte[] N){
		this.clientB_Username = talkToUsername;
		this.clientA_DHContrib = clientA_DHContrib;
		this.N = N;
	}
	
	@Override
	public void copyFrom(Payload template) throws SimplException {
		if( template instanceof ClientANegotiateRequestPayload){
			ClientANegotiateRequestPayload anrTemplate = (ClientANegotiateRequestPayload) template;
			this.clientB_Username = anrTemplate.clientB_Username;
			this.clientA_DHContrib = anrTemplate.clientA_DHContrib;
			this.N = anrTemplate.N;
		} else {
			throw new SimplException("Payload template was not a ClientANegotiateRequestPayload!");
		}
	}
}
