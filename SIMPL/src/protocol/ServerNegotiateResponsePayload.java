package protocol;

import java.io.*;
import java.net.*;
import java.security.*;

public class ServerNegotiateResponsePayload implements Serializable {

	private static final long serialVersionUID = 585566613856440056L;

	public InetAddress talkToIP;
	public PublicKey clientB_DHContrib;
	public byte[] N;
	
	public ServerNegotiateResponsePayload(InetAddress talkToIP, PublicKey clientB_DHContrib, byte[] N){
		this.talkToIP = talkToIP;
		this.clientB_DHContrib = clientB_DHContrib;
		this.N = N;
	}
}
