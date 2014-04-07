package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

import protocol.*;
import protocol.packet.DiscoverPacket;
import protocol.packet.LoginPacket;
import protocol.packet.Packet;
import protocol.payload.AuthenticationPayload;

/*
 * An actual FSM implementation, which might be interesting and extreme over-engineering:
 * 		http://stackoverflow.com/questions/13221168/how-to-implement-a-fsm-finite-state-machine-in-java
 */
public class ClientHandlerThread extends Thread {
	
	private Server server;
	private PrivateKey serverPrivK;
	private Socket clientSocket;
	private InetAddress clientIP;
	private InputStream clientStream;
	private byte[] R_2;
	private String clientUsername;
	private byte[] sessionKey;

	//these fields the Server will manipulate when a different ClientHandlerThread wants to talk to this one's Client
	public boolean wanted;
	public String usernameToTalkWith;
	public InetAddress ipToTalkWith;
	
	@Override
	public void run() {
		try{
			this.wanted = false;
			this.usernameToTalkWith = null;
			this.ipToTalkWith = null;
			
			//remember some variables for thread lifetime
			this.server = CmdLine.server;
			this.serverPrivK = this.server.serverPrivK;
			//query the Server's ClientHandler for the unhandled client socket
			this.clientSocket = this.server.getClientHandler().getUnhandledEntry().getClientSocket();
			this.clientSocket.setSoTimeout(common.Constants.SO_TIMEOUT);
			this.clientIP = this.clientSocket.getInetAddress();
			this.clientStream = this.clientSocket.getInputStream();
			this.R_2 = new byte[protocol.packet.LoginPacket.R_2_size];
			this.clientUsername = null;
			
			while(true){
				//
				this.checkForNegotiations();
				//the client handle loop is going to return because of SocketTimeoutExceptions fairly frequently.
				this.enterClientHandleLoop();
			}
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	private void checkForNegotiations(){
		//TODO: check my wanted variable
		//
	}
	
	//ltj: One way of more robustly doing this is setting an ArrayList<EnumSet<Flag>> Expected so the Server can report
	//		unexpected packets from the Client. That would be fairly hefty, so we will just be assuming that the Client
	//		sends the packets in the right order.
	/**
	 * This is the packet handling "DEMULTIPLEXER".
	 * What's not obvious is that the while(true) loop is often broken out of by a SocketTimeoutException
	 */
	private void enterClientHandleLoop(){
		Object o;
		
		while( true ){
			try{
				byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
				//wait for data from client for common.Constants.SO_TIMEOUT ms, then throw SocketTimeoutException
				int count = this.clientStream.read(recv);
				//once we have it, truncate down to smallest array
				byte[] clientPacketBytes = new byte[count];
				System.arraycopy(recv, 0, clientPacketBytes, 0, count);
				//make Packet out of bytes
				o = common.Utils.deserialize(clientPacketBytes);
				Packet clientPacket = (Packet) o;

				//Send packet to the real meat of the demultiplexer.
				this.handlePacket(clientPacket);
				
			} catch (SocketTimeoutException e){
				//do nothing if the socket times out. Just return to the run function body
				return;
			} catch (IOException e) {
				e.printStackTrace();
				return;
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
				return;
			}
		}
	}
	
	private void handlePacket(Packet clientPacket){
		//Login steps
		if( clientPacket.checkForFlags(LoginPacket.getClientLoginRequestFlags()) )
		{
			this.handle_login_request();
		} else if( clientPacket.checkForFlags(LoginPacket.getClientLoginChallengeResponseFlags())){
			this.handle_login_challenge_response(clientPacket);
		}
		
		//Discover step
		else if( clientPacket.flags.contains(Packet.Flag.Discover) )
		{
			this.handle_discover();
		} 
		
		//Negotiate steps
		else if( clientPacket.flags.contains(Packet.Flag.Negotiate) )
		{
			this.start_handle_negotiation();
		}
		
		//Logout steps
		else if( clientPacket.flags.contains(Packet.Flag.Logout) )
		{
			this.start_handle_logout();
			//break;
		}
		
		//weirdness ensued
		else
		{
			System.err.println(Server.UNEXPECTED_CLIENT_PACKET_MSG);
		}
	}
	
	public void handle_login_request(){
		//ready the challenge for the client and send
		LoginPacket serverChallenge = new LoginPacket();
		//remember R_2 so we can check the challengeResponse
		this.R_2 = serverChallenge.readyServerLoginChallenge(this.serverPrivK);
		serverChallenge.go(this.clientSocket);
	}
	
	public String handle_login_challenge_response(Packet clientPacket){
		try{
			Object o;
			
			LoginPacket challengeResponse = (LoginPacket) clientPacket;
			//ensure the right R_2 was found before doing crypto work
			if( !Arrays.equals(this.R_2, challengeResponse.R_2) ){
				//if they aren't the same, send deny message
				LoginPacket denyResponse = new LoginPacket();
				denyResponse.readyServerLoginDeny();
				denyResponse.go(clientSocket);
				return null;
			}
			//if they're the same get the auth payload, and check that
			byte[] authenticationPayloadBytes = challengeResponse.crypto_data;
			//decrypt it first if CRYPTO isn't OFF
			if( !common.Constants.CRYPTO_OFF ){
				System.out.println();
				authenticationPayloadBytes = challengeResponse.authPayload.decrypt(this.serverPrivK, 
						authenticationPayloadBytes);	
			}
			//deserialize to AuthenticationPayload
			o = common.Utils.deserialize(authenticationPayloadBytes);
			AuthenticationPayload ap = (AuthenticationPayload) o;
			//check the user supplied username and password hash
			if( this.server.verify_user(ap.username, ap.pwHash) ){
				LoginPacket okResponse = new LoginPacket();
				okResponse.readyServerLoginOk();
				okResponse.go(clientSocket);
				sessionKey = ap.keyMake();
				return ap.username;
			} else {
				LoginPacket denyResponse = new LoginPacket();
				denyResponse.readyServerLoginDeny();
				denyResponse.go(clientSocket);
				return null;
			}
		} catch (ClassNotFoundException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	public void handle_discover(){
		//Build the initial packet and send it
		DiscoverPacket discoverResponse = new DiscoverPacket();
		discoverResponse.readyServerDiscoverResponse(this.server.userDB.keySet(), sessionKey);
		//send the usernames to the client
		discoverResponse.go(clientSocket);
	}
	
	public void start_handle_negotiation(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);

	}
	
	public void start_handle_logout(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * 
	 * @return
	 */
	public boolean isClientUsernameInitialized(){
		if( this.clientUsername == null ){
			return false;
		} else {
			return true;
		}
	}
}
