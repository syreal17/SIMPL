package protocol;

import java.io.Serializable;
import java.security.*;

public class ClientANegotiateRequestPayload implements Serializable {

	private static final long serialVersionUID = 451135002987918260L;

	public String talkToUsername;
	public PublicKey clientA_DHContrib; 	//g^amodp
	public byte[] N;						//nonce
	
	public ClientANegotiateRequestPayload(String talkToUsername, PublicKey clientA_DHContrib, byte[] N){
		this.talkToUsername = talkToUsername;
		this.clientA_DHContrib = clientA_DHContrib;
		this.N = N;
	}
}
