package protocol.payload;

import java.security.*;

import common.SimplException;

public class ClientBNegotiateResponsePayload extends ClientServerSessionPayload {

	private static final long serialVersionUID = -5286488250088205693L;

	public PublicKey clientB_DHContrib;
	public byte[] N;
	
	public ClientBNegotiateResponsePayload(PublicKey clientB_DHContrib, byte[] N){
		this.clientB_DHContrib = clientB_DHContrib;
		this.N = N;
	}
	
	public ClientBNegotiateResponsePayload(){}

	@Override
	public void copyFrom(Payload template) throws SimplException {
		if( template instanceof ClientBNegotiateResponsePayload){
			ClientBNegotiateResponsePayload bnrTemplate = (ClientBNegotiateResponsePayload) template;
			this.clientB_DHContrib = bnrTemplate.clientB_DHContrib;
			this.N = bnrTemplate.N;
		} else {
			throw new SimplException("Payload template was not a ClientBNegotiateResponsePayload!");
		}
	}
}
