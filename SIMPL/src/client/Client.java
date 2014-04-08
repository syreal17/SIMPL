/**
 * Consumes user input from CmdLine and constructs Packets
 */

package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.*;

import common.*;
import protocol.packet.*;
import protocol.payload.*;

/*Resources:
 * _SINGLETON DESIGN PATTERN_
 * A good example of a thread-safe singleton implementation:
 * 		http://www.javaworld.com/article/2073352/core-java/simply-singleton.html?page=2
 * 
 * _NETWORKING_
 * A simple TCP server and client:
 * 		http://docs.oracle.com/javase/tutorial/networking/sockets/clientServer.html
 * Getting a byte array from Socket
 * 		http://stackoverflow.com/questions/10475898/receive-byte-using-bytearrayinputstream-from-a-socket
 */

/**
 * This is the Client abstraction. It's job is to be a finite state machine (FSM)
 * which anticipates the correct types of packets, verifies that they are the
 * correct types of packets, prints diagnostic messages if they are the wrong
 * types of packets, and constructs correct response packets.
 * (Most computation is pushed to the packet classes)
 * @author syreal
 *
 */
public class Client extends Thread {
	public boolean running;								//continue listening or exit thread
	public Synchronizable<Boolean> logged_in;
	public boolean chatting;
	public String myUsername; 							//clients username stored here
	public String passHash;
	public String buddyUsername;						//buddy's username
	public InetAddress buddyIP;
	
	public Socket serverSocket; 						//socket used for communication to server
	public InputStream serverStream;
	public Socket buddySocket;
	public InputStream buddyStream;
	public Synchronizable<ArrayList<String>> clients; 	//contains result of discover
	private byte[] N; 									//the nonce that we've used and sent to the Server
	public PublicKey serverPubK;
	public byte[] serverSeshKey;
	private KeyPair clientAgreementKeyPair;				//the PrivateKey used in the KeyAgreement
	public Synchronizable<SecretKey> clientSeshKey;		//the result of the KeyAgreement, used as the session key 
														//between two chatting clients
	
	//TODO: put TCP socket construction here? Makes semantic sense
	public Client(PublicKey serverPubK){
		//set the size for N
		this.N = new byte[common.Constants.NONCE_SIZE_BYTES];
		//remember the Server public key
		this.serverPubK = serverPubK;
		
		//initilize Synchronizables - the first time they are set will be synchronized, so don't set them now.
		this.clients = new Synchronizable<ArrayList<String>>();
		this.clientSeshKey = new Synchronizable<SecretKey>();
	}
	
	@Override
	public void run(){
		this.startListenLoop();
	}
	
	/**
	 * analog to ClientHandlerThread.enterClientHandleLoop
	 */
	public void startListenLoop(){
		//Going to try and do this without SocketTimeouts
		//Might be possible since default Client thread does all the listening
		//And UserInputThread does all the sending
		//If I do decide to do timeouts, CmdLine must wrap a call to this method in a while loop
		//AND the TCP connection should be created outside of this function!
					
		this.running = true;
		this.logged_in = new Synchronizable<Boolean>(false);
		
		while( this.running ){
			Packet packet = this.waitForPacket();
			//Send packet to the real meat of the demultiplexer.
			this.handlePacket(packet);	
		}
	}
	
	/**
	 * analog to CLientHandlerThread.handlePacket
	 * @param buddyPacket
	 */
	private void handlePacket(Packet packet){
		//Login steps
		if( packet.checkForFlags(LoginPacket.getServerLoginChallengeFlags()) )
		{
			this.handle_server_login_challenge(packet);
		} else if( packet.checkForFlags(LoginPacket.getServerLoginOkFlags()) )
		{
			this.handle_server_login_ok();
		} else if( packet.checkForFlags(LoginPacket.getServerLoginDenyFlags()) )
		{
			this.handle_server_login_deny();
		}
		
		//Discover step
		else if( packet.checkForFlags(DiscoverPacket.getServerDiscoverResponseFlags()) ){
			this.handle_discover_response(packet);
		}
		
		//Negotiate steps
		else if( packet.checkForFlags(NegotiatePacket.getNegotiateRequestFlags()) )
		{
			this.handle_negotiate_request(packet);
		}else if( packet.checkForFlags(NegotiatePacket.getNegotiateOkResponseFlags()) )
		{
			this.handle_negotiate_ok_response(packet);
		} else if( packet.checkForFlags(NegotiatePacket.getNegotiateDenyResponseFlags()) )
		{
			this.handle_negotiate_deny_response();
		} else if( packet.checkForFlags(NegotiatePacket.getNegotiateNonexistantResponseFlags()) )
		{
			this.handle_negotiate_nonexistant_response();
		}
		
		//Chat step
		else if( packet.checkForFlags(ChatPacket.getChatPacketFlags()) )
		{
			this.handle_chat();
		}
		
		//Leave steps
		//NOTE: 3-way handshake currently ignored
		if( packet.checkForFlags(LeavePacket.getClientA_FIN_Flags()) )
		{
			this.handle_leave();
		}
		
		//Logout step
		//TODO: need to handle receiving the server fin/ack since Server counts on ack to actually logout the Client
	}
	
	/**
	 * Login to the SIMPL Server
	 * @param serverName the host name or ip string to connect to
	 * @param port the port number that the server is listening for SIMPL on
	 * @return message to print on CmdLine 
	 */
//	public void do_entire_login(){
//		try{
//			//Build the initial packet and send it
//			LoginPacket loginRequest = new LoginPacket();
//			loginRequest.readyClientLoginRequest();
//			loginRequest.go(this.serverSocket);
//			
//			//Get challenge packet
//			LoginPacket serverChallenge = (LoginPacket) this.waitForPacket();
//			//get all the challengePayloadBytes
//			byte[] signature = serverChallenge.signature;
//			ChallengePayload cp = serverChallenge.challengePayload;
//			
//			if( !common.Constants.CRYPTO_OFF ) {
//
//				if (cp.verify(this.serverPubK, signature))
//				{
//					System.out.println("Signature success!");
//				}
//				else
//				{
//					System.out.println("Signature failure...");
//				}
//			}
//			
//			//Start constructing the response packet.
//			LoginPacket challengeResponse = new LoginPacket();
//			challengeResponse.R_1 = serverChallenge.R_1;
//			challengeResponse.challengePayload = cp;
//			//generating the nonce
//			SecureRandom.getInstance(common.Constants.RNG_ALOGRITHM).nextBytes(this.N);
//			//ready the Response for transmission and create the session key
//			serverSeshKey = challengeResponse.readyClientLoginChallengeResponse(this.serverPubK, this.myUsername, this.passHash.getBytes(), this.N);
//			//transmit the response
//			challengeResponse.go(this.serverSocket);
//			
//			//Get the server response: ok or deny
//			Packet serverResponse = this.waitForPacket();
//			
//			//check the flags of the packet to see if we were accepted, or not, or worse
//			if( serverResponse.flags.contains(Packet.Flag.Ok) && 
//					!serverResponse.flags.contains(Packet.Flag.Deny))
//			{
//				System.out.println(Client.LOGIN_SUCCESS_MSG);
//			} else if( !serverResponse.flags.contains(Packet.Flag.Ok) &&
//					serverResponse.flags.contains(Packet.Flag.Deny))
//			{
//				System.out.println(Client.LOGIN_FAILURE_MSG);
//			} else {
//				System.out.println(Client.LOGIN_UNDEFINED_MSG);
//			}
//		} catch (NoSuchAlgorithmException e){
//			System.err.println(e.getMessage());
//			e.printStackTrace();
//			return;
//		}
//	}
	
	/**
	 * Starts the login process
	 */
	public void do_login(){
		//Build the initial packet and send it
		LoginPacket loginRequest = new LoginPacket();
		loginRequest.readyClientLoginRequest();
		loginRequest.go(this.serverSocket);
	}
	
	/**
	 * intermediate login step
	 * @param packet
	 */
	private void handle_server_login_challenge(Packet packet){
		try{
			//Cast to correct type of packet
			LoginPacket serverChallenge = (LoginPacket) packet;
			//get all the challengePayloadBytes
			byte[] signature = serverChallenge.signature;
			ChallengePayload cp = serverChallenge.challengePayload;
			
			if( !common.Constants.CRYPTO_OFF ){
				if (cp.verify(this.serverPubK, signature))
				{
					System.out.println("SIMPL Server identity authenticated");
				}
				else
				{
					System.out.println("SIMPL Server identity rejected! RUUUUN!!");
				}
			}
			
			//Start constructing the response packet.
			LoginPacket challengeResponse = new LoginPacket();
			challengeResponse.R_1 = serverChallenge.R_1;
			challengeResponse.challengePayload = cp;
			//generating the nonce
			SecureRandom.getInstance(common.Constants.RNG_ALOGRITHM).nextBytes(this.N);
			//ready the Response for transmission and create the session key
			serverSeshKey = challengeResponse.readyClientLoginChallengeResponse(this.serverPubK, this.myUsername, 
					this.passHash.getBytes(), this.N);
			//transmit the response
			challengeResponse.go(this.serverSocket);
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * touches this.logged_in, signaling UI loop
	 */
	private void handle_server_login_ok(){
		try{
			//signal the UI loop by waiting at the Synchronizable
			this.logged_in.set(true);
		} catch (InterruptedException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (BrokenBarrierException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * touches this.logged_in, signaling UI loop
	 */
	private void handle_server_login_deny(){
		try{
			//signal the UI loop by waiting at the Synchronizable
			this.logged_in.set(false);
		} catch (InterruptedException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (BrokenBarrierException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Ask SIMPL Server for Login'd SIMPL Clients. Instantiates the clients ArrayList
	 * @return success or failure
	 */
//	public void do_entire_discover(){
//		//Build the initial packet and send it
//		DiscoverPacket discoverRequest = new DiscoverPacket();
//		discoverRequest.readyClientDiscoverRequest();
//		discoverRequest.go(this.serverSocket);
//
//		System.out.println("Client: do_discover1");
//		//Get challenge packet
//		Packet serverResponse = this.waitForPacket();
//		byte[] usernames = serverResponse.crypto_data;
//		//get array list out of packet
//		clients = discoverRequest.decryptServerDiscoverReponse(usernames, serverSeshKey);
//		System.out.println("Client: do_discover2");
//	}
	
	/**
	 * Sends discover packet
	 */
	public void do_discover(){
		//Build the initial packet and send it
		DiscoverPacket discoverRequest = new DiscoverPacket();
		discoverRequest.readyClientDiscoverRequest();
		discoverRequest.go(this.serverSocket);
	}
	
	/**
	 * touches this.clients, signaling UI thread
	 * @param packet
	 */
	private void handle_discover_response(Packet packet){
		try{
			DiscoverPacket serverResponse = (DiscoverPacket) packet;
			byte[] usernames = serverResponse.crypto_data;
			//get array list out of packet
			this.clients.set(serverResponse.decryptServerDiscoverReponse(usernames, this.serverSeshKey));
		} catch (InterruptedException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (BrokenBarrierException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * This is the only public method of all Client.*negotiate* methods, because this is the only one
	 * called by CmdLine. Fortunately, the Server is transparent at this and all following Client.*negotiate* methods.
	 * Initiates A->B from A
	 */
	public void do_negotiate_request(String clientB_Username) throws SimplException {
		//generate the DH Public/PrivateKeyPair
		this.generateKeyPairForKeyAgreement();
		//ensure it was successful
		if( this.clientAgreementKeyPair == null ){
			throw new SimplException("Client KeyAgreement KeyPair failed");
		}
		
		//build the initial NegotiatePacket
		NegotiatePacket requestPacket = new NegotiatePacket();
		requestPacket.readyClientANegotiateRequest(this.serverSeshKey, clientB_Username, 
				this.clientAgreementKeyPair.getPublic(), this.N);
		requestPacket.go(this.serverSocket);
	}
	
	/**
	 * Handles A->B at B
	 */
	private void handle_negotiate_request(Packet packet){
		NegotiatePacket requestPacket = (NegotiatePacket) packet;
		
		ServerNegotiateRequestPayload serverRequestPayload = requestPacket.getServerRequestPayload(this.serverSeshKey);
		//take out 1 wants to talk, store username of 1
		this.buddyUsername = serverRequestPayload.wantToUsername;
		//store the ip addr of 1
		this.buddyIP = serverRequestPayload.wantToIP;
		
		//take out DH contribution of A and create shared key
		PublicKey clientA_DHContrib = serverRequestPayload.clientA_DHContrib;
		//take out N
		byte[] N = serverRequestPayload.N;
		
		//send back packet with DH contribution of B and N
		requestPacket.readyClientBNegotiateResponse(serverSeshKey,clientAgreementKeyPair.getPublic(),N);
		requestPacket.go(this.serverSocket);
		
		//manufacture the secret key
		this.findSecretKey(clientA_DHContrib);
	}
	
	/**
	 * Touches this.clientSeshKey, signaling the UI thread
	 * finishes negotiation by handling B->A at A
	 */
	private void handle_negotiate_ok_response(Packet packet){
		try {
			NegotiatePacket responsePacket = (NegotiatePacket) packet;
			
			ServerNegotiateResponsePayload serverResponsePayload = responsePacket.getServerResponsePayload(this.serverSeshKey);
			//store the ip addr of 2
			this.buddyIP = serverResponsePayload.talkToIP;
			
			//take out DH contribution of A and create shared key
			PublicKey clientB_DHContrib = serverResponsePayload.clientB_DHContrib;
			//take out N
			byte[] N = serverResponsePayload.N;
			//check N
			if( !Arrays.equals(this.N, N) ){
				throw new SimplException("Nonce check failed.");
			}
			
			//manufacture the secret key
			this.clientSeshKey.set(this.findSecretKey(clientB_DHContrib));
		} catch (SimplException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (InterruptedException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (BrokenBarrierException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * touches this.clientSeshKey to signal UI loop
	 */
	private void handle_negotiate_deny_response(){
		try {
			//since both deny and nonexistant set to null, we print a explanatory message here
			System.out.println("Requested buddy was busy");
			this.clientSeshKey.set(null);
		} catch (InterruptedException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (BrokenBarrierException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * touches this.clientSeshKey to signal UI loop
	 */
	private void handle_negotiate_nonexistant_response(){
		try {
			//since both deny and nonexistant set to null, we print a explanatory message here
			System.out.println("Requested buddy doesn't exist");
			this.clientSeshKey.set(null);
		} catch (InterruptedException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (BrokenBarrierException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * @param message message to send chat buddy
	 * @return success or failure
	 */
	public void do_chat(String message){
		//make a chat packet
		ChatPacket chatPacket = new ChatPacket();
		//prepare and encrypt the message
		chatPacket.prepareMessage(message, this.clientSeshKey.get_bypass());
		//send the message
		chatPacket.go(this.buddySocket);
	}
	
	/**
	 * Handle being the recipient of a Chat message, not the sender, as do_chat does.
	 */
	public void handle_chat(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Leave the chat conversation with Buddy
	 * @return
	 */
	public void do_leave(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Handle being the recipient of a Leave message, not the sender, as d0_leave does.
	 */
	public void handle_leave(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Logout to Server
	 * @return
	 */
	public void do_logout(){
		//TODO: implement
		//TODO: send LogoutPacket
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
//	private void handle_logout_ack(){
//		//TODO: implement
//		//TODO: send the logout ack
//		//TODO: set this.running to false
//		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
//	}
	
	public Packet waitForPacket(){
		try{
			Object o;
			byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
			//wait for data from Server or possible Buddy indefinitely
			int count = this.serverStream.read(recv);
			//once we have it, truncate down to smallest array
			byte[] packetBytes = new byte[count];
			System.arraycopy(recv, 0, packetBytes, 0, count);
			//make Packet out of bytes
			o = common.Utils.deserialize(packetBytes);
			Packet packet = (Packet) o;
			return packet;
		} catch (IOException e) {
			System.out.println("Server has unexpectedly disconnected...");
			System.exit(1);
			return null;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Generate the Private/PublicKey pair used in the KeyAgreement
	 */
	private void generateKeyPairForKeyAgreement(){
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(common.Constants.KEY_AGREEMENT_ALGORITHM);
			kpg.initialize(common.Constants.KEY_AGREEMENT_KEY_SIZE);
			this.clientAgreementKeyPair = kpg.genKeyPair();
		} catch (NoSuchAlgorithmException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	private SecretKey findSecretKey(PublicKey buddyPublicKey){
		try
		{
			KeyAgreement ka = KeyAgreement.getInstance(common.Constants.KEY_AGREEMENT_ALGORITHM);
			ka.init(clientAgreementKeyPair.getPrivate());
			ka.doPhase(buddyPublicKey, true);	
			//forget KeyPair here
			clientAgreementKeyPair = null;
			return ka.generateSecret(common.Constants.SYMMETRIC_CRYPTO_MODE);
		}
		catch (NoSuchAlgorithmException e)
		{
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
}
