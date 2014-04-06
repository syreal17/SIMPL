package protocol;

import java.io.*;
import java.net.*;
import java.security.*;

public class ServerNegotiateRequestPayload implements Serializable {

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
}
