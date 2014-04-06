package protocol;

import java.io.*;
import java.security.*;

public class ClientBNegotiateResponsePayload implements Serializable {

	private static final long serialVersionUID = -5286488250088205693L;

	public PublicKey clientB_DHContrib;
	public byte[] N;
	
	public ClientBNegotiateResponsePayload(PublicKey clientB_DHContrib, byte[] N){
		this.clientB_DHContrib = clientB_DHContrib;
		this.N = N;
	}
}
