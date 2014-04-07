package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

import common.*;

import protocol.packet.*;
import protocol.payload.*;

/*
 * An actual FSM implementation, which might be interesting and extreme over-engineering:
 * 		http://stackoverflow.com/questions/13221168/how-to-implement-a-fsm-finite-state-machine-in-java
 */
public class ClientHandlerThread extends Thread {
	
	private boolean chatting; 	//indicating whether this thread's client is already chatting
	private boolean running; 	//to control when thread should exit
	private Server server;
	private PrivateKey serverPrivK;
	private Socket clientSocket;
	public InetAddress clientIP;
	private InputStream clientStream;
	private byte[] R_2;
	public String clientUsername;
	private byte[] sessionKey;

	//these fields the Server will manipulate when a different ClientHandlerThread wants to talk to this one's Client
	public boolean wanted;
	public ServerNegotiateRequestPayload requestPayload;
	public ServerNegotiateResponsePayload responsePayload;
	public ClientHandlerThread requestor_CHT;
	
	@Override
	public void run() {
		try{
			this.chatting = false;
			this.wanted = false;
			this.running = true;
			
			//remember some variables for thread lifetime
			this.server = CmdLine.server;
			this.serverPrivK = this.server.serverPrivK;
			//query the Server's ClientHandler for the unhandled client socket
			this.clientSocket = this.server.getClientHandler().getUnhandledEntry().getClientSocket();
			this.clientSocket.setSoTimeout(common.Constants.SO_TIMEOUT);
			this.clientIP = this.clientSocket.getInetAddress();
			this.clientStream = this.clientSocket.getInputStream();
			this.R_2 = new byte[protocol.packet.LoginPacket.R_2_size];
			
			while( this.running ){
				//
				this.checkForAsyncNegotiationRequests();
				//the client handle loop is going to return because of SocketTimeoutExceptions fairly frequently.
				this.enterClientHandleLoop();
			}
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Checks to see if any other CHTs have requested this CHT for a chat. If they have, it passes on the
	 * negotiation request payload
	 */
	private void checkForAsyncNegotiationRequests(){
		if( this.wanted ){
			this.wanted = false;
			this.do_negotiation_request();
		}
	}
	
	/**
	 * 
	 * @param requestor_CHT the requesting thread
	 * @param payload the information that 
	 * @return true if client was free to chat, false if client was already chatting
	 */
	public boolean mark_as_wanted(ClientHandlerThread requestor_CHT, ServerNegotiateRequestPayload payload){
		
		if( !this.chatting ){
			this.chatting = true; 	//ltj: it might be jumping the gun a little bit to set chatting as true here
									//		but probably just semantically, not functionally
			this.wanted = true;
			this.requestor_CHT = requestor_CHT;
			this.requestPayload = payload;
			return true;
		} else {
			return false;
		}
		
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
		
		//ltj: 	on second thought, this maybe shouldn't be in a loop, because then we are relying on 
		// 		SocketTimeoutExceptions to go look for asynchronous negotiation request, although, on
		//		third thought, this could be perfect if the timeout value is just right so that other 
		//		communication exchanges aren't killed by a timeout and interrupted by a negotiation.
		while( this.running ){
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
				//do nothing if the socket times out. Just return to the run() function body
				//this is how we check for negotiation requests
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
		//Login handle steps
		if( clientPacket.checkForFlags(LoginPacket.getClientLoginRequestFlags()) )
		{
			this.handle_login_request();
		} else if( clientPacket.checkForFlags(LoginPacket.getClientLoginChallengeResponseFlags()))
		{
			this.handle_login_challenge_response(clientPacket);
		}
		
		//Discover handle step
		else if( clientPacket.checkForFlags(DiscoverPacket.getClientDiscoverRequestFlags()) )
		{
			this.handle_discover();
		} 
		
		//Negotiate handle steps
		else if( clientPacket.checkForFlags(NegotiatePacket.getNegotiateRequestFlags()) )
		{
			this.handle_negotiation_request(clientPacket);
		} else if( clientPacket.checkForFlags(NegotiatePacket.getNegotiateOkResponseFlags()) )
		{
			this.handle_negotiation_response(clientPacket);
		}
		
		//Leave handle step
		else if( clientPacket.checkForFlags(LeavePacket.))
		
		//Logout handle steps
		else if( clientPacket.checkForFlags(LogoutPacket.getClientLogoutFINFlags()) )
		{
			this.start_handle_logout();
		} else if( clientPacket.checkForFlags(LogoutPacket.getClientLogoutACKFlags()) )
		{
			this.do_logout();
		}
		
		//else, weirdness ensued
		else
		{
			System.err.println(Server.UNEXPECTED_CLIENT_PACKET_MSG);
		}
	}
	
	private void handle_login_request(){
		//ready the challenge for the client and send
		LoginPacket serverChallenge = new LoginPacket();
		//remember R_2 so we can check the challengeResponse
		this.R_2 = serverChallenge.readyServerLoginChallenge(this.serverPrivK);
		serverChallenge.go(this.clientSocket);
	}
	
	private String handle_login_challenge_response(Packet clientPacket){
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
	
	private void handle_discover(){
		//Build the initial packet and send it
		DiscoverPacket discoverResponse = new DiscoverPacket();
		discoverResponse.readyServerDiscoverResponse(this.server.userDB.keySet(), sessionKey);
		//send the usernames to the client
		discoverResponse.go(clientSocket);
	}
	
	/**
	 * Handles A->B request from A at Server:CHT_A
	 * 
	 * Alerts CHT_B to do_negotiation_request next time it gets a chance
	 */
	private void handle_negotiation_request(Packet clientPacket){
		try{
			NegotiatePacket clientANegotiatePacket = (NegotiatePacket) clientPacket;
			
			//get the payload from A's packet
			ClientANegotiateRequestPayload clientReqPayload = 
					clientANegotiatePacket.getClientARequestPayload(this.sessionKey);
			//create the payload for B
			ServerNegotiateRequestPayload serverReqPayload = new ServerNegotiateRequestPayload(this.clientUsername,
					this.clientIP, clientReqPayload.clientA_DHContrib, clientReqPayload.N);
			//try to request the buddy
			boolean clientWasFreeToChat = this.server.request_username_as_wanted(this, 
					clientReqPayload.clientB_Username, serverReqPayload);
			
			if( !clientWasFreeToChat ){
				this.do_negotiation_deny();
				return;
			}
			
			//if client was indeed free to chat, we now wait for B's ClientHandlerThread to forward the request to B.
			//CHT_B calls CHT_A's do_negotiation_response when it receives B's response
		} catch (SimplException e){
			this.do_negotiation_nonexistant();
			return;
		}
	}
	
	/**
	 * Does A->B request from Server:CHT_B on behalf of A, to B
	 */
	private void do_negotiation_request(){
		NegotiatePacket packet = new NegotiatePacket();
		packet.readyServerNegotiateRequest(sessionKey, this.requestPayload);
		packet.go(this.clientSocket);
	}
	
	/**
	 * Server:CHT_A tells A that B was busy
	 */
	private void do_negotiation_deny(){
		NegotiatePacket packet = new NegotiatePacket();
		packet.readyServerNegotiateDenyResponse();
		packet.go(this.clientSocket);
	}
	
	/**
	 * Server:CHT_A tells A that B didn't exist
	 */
	private void do_negotiation_nonexistant(){
		NegotiatePacket packet = new NegotiatePacket();
		packet.readyServerNegotiateNonexistantResponse();
		packet.go(this.clientSocket);
	}
	
	/**
	 * Handles B->A response from B to Server:CHT_B
	 */
	private void handle_negotiation_response(Packet clientPacket){
		NegotiatePacket clientBResponsePacket = (NegotiatePacket) clientPacket;
		
		//Get the payload from Client B's response
		ClientBNegotiateResponsePayload clientRespPayload = clientBResponsePacket.getClientBResponsePayload(
				this.sessionKey);
		
		//Create the server response payload for ClientA
		ServerNegotiateResponsePayload serverRespPayload = new ServerNegotiateResponsePayload(this.clientIP, 
				clientRespPayload.clientB_DHContrib, clientRespPayload.N);
		
		//stuff the server response into CHT_A's field
		this.requestor_CHT.responsePayload = serverRespPayload;
		
		//tell CHT_A to send the response (this is really weird since it's another thread's execution calling a
		//method on the other thread object)
		this.requestor_CHT.do_negotiation_response();
	}
	
	/**
	 * Does B->A response from Server:CHT_A on behalf of B to A
	 * Should be called by CHT_B once it has processed B's negotiation response.
	 * Will this work? Maybe. It's not threadsafe, it's threadscary.
	 */
	private void do_negotiation_response(){
		NegotiatePacket packet = new NegotiatePacket();
		packet.readyServerNegotiateResponse(sessionKey, this.responsePayload);
		packet.go(this.clientSocket);
	}
	
	/**
	 * in a perfect world, might also have a do_leave_ack or something, analog to do_logout for Logout
	 */
	private void handle_leave(){
		this.chatting = false;
	}
	
	private void start_handle_logout(){
		LogoutPacket packet = new LogoutPacket();
		packet.readyServerLogoutFINACK();
		packet.go(this.clientSocket);
	}
	
	private void do_logout(){
		//exit the thread on next loop
		this.running = false;
	}
	
	public boolean isClientUsernameInitialized(){
		if( this.clientUsername == null ){
			return false;
		} else {
			return true;
		}
	}
}
