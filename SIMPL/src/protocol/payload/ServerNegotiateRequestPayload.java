package protocol.payload;

import java.net.*;
import java.security.*;
import common.SimplException;

public class ServerNegotiateRequestPayload extends ClientServerSessionPayload {

	private static final long serialVersionUID = -7149274176512251578L;
	
	public String wantToUsername;
	public InetAddress wantToIP;
	public PublicKey clientA_DHContrib; 	//g^amodp
	public byte[] N;						//nonce
	
	public ServerNegotiateRequestPayload(String wantToUsername, InetAddress wantToIP, PublicKey clientA_DHContrib, byte[] N){
		this.wantToUsername = wantToUsername;
		this.wantToIP = wantToIP;
		this.clientA_DHContrib = clientA_DHContrib;
		this.N = N;
	}
	
	public ServerNegotiateRequestPayload(){}
	
	@Override
	public void copyFrom(Payload template) throws SimplException {
		if( template instanceof ServerNegotiateRequestPayload){
			ServerNegotiateRequestPayload nrTemplate = (ServerNegotiateRequestPayload) template;
			this.wantToUsername = nrTemplate.wantToUsername;
			this.wantToIP = nrTemplate.wantToIP;
			this.clientA_DHContrib = nrTemplate.clientA_DHContrib;
			this.N = nrTemplate.N;
		} else {
			throw new SimplException("Payload template was not a ServerNegotiateRequestPayload!");
		}
	}
}
