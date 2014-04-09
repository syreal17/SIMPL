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
	public ServerSocket buddyListenSocket;
	public Socket buddySocket;
	public Synchronizable<InputStream> buddyStream;
	public Synchronizable<ArrayList<String>> clients; 	//contains result of discover
	private byte[] N; 									//the nonce that we've used and sent to the Server
	public PublicKey serverPubK;
	public byte[] serverSeshKey;
	private KeyPair clientAgreementKeyPair;				//the PrivateKey used in the KeyAgreement
	public Synchronizable<byte[]> clientSeshKey;		//the result of the KeyAgreement, used as the session key 
														//between two chatting clients
	
	//TODO: put TCP socket construction here? Makes semantic sense
	public Client(PublicKey serverPubK){
		//set the size for N
		this.N = new byte[common.Constants.NONCE_SIZE_BYTES];
		//remember the Server public key
		this.serverPubK = serverPubK;
		
		//initilize Synchronizables - the first time they are set will be synchronized, so don't set them now.
		this.clients = new Synchronizable<ArrayList<String>>();
		this.clientSeshKey = new Synchronizable<byte[]>();
		this.buddyStream = new Synchronizable<InputStream>();
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
			//this waitForPacket will not block indefinitely because Timeout is set for serverSocket
			Packet serverPacket = this.waitForPacket(this.serverStream);
			//if server had packet for us, let us handle it
			if( serverPacket != null ){
				//Send serverPacket to the real meat of the demultiplexer.
				this.handleServerPacket(serverPacket);
			} else {
				//using an else because if the Server is sending packets right now, might as well go check the socket
				//again before possibly indefinitely blocking on buddySocket
				//if we have a working buddy socket
				if( this.buddySocket != null ){
					//this waitForPacket does indefinitely block, because if we have a live buddySocket, then
					//Chat messages preempt server messages (and we won't be sending server messages, and it
					//won't be sending us messages)
					Packet buddyPacket = this.waitForPacket(this.buddyStream.get_bypass());
					this.handleBuddyPacket(buddyPacket);
				}
			}
		}
	}
	
	/**
	 * analog to CLientHandlerThread.handlePacket
	 * @param buddyPacket
	 */
	private void handleServerPacket(Packet packet){
		//Login steps
		if( packet.checkForExactFlags(LoginPacket.getServerLoginChallengeFlags()) )
		{
			this.handle_server_login_challenge(packet);
		} else if( packet.checkForExactFlags(LoginPacket.getServerLoginOkFlags()) )
		{
			this.handle_server_login_ok();
		} else if( packet.checkForExactFlags(LoginPacket.getServerLoginDenyFlags()) )
		{
			this.handle_server_login_deny();
		}
		
		//Discover step
		else if( packet.checkForExactFlags(DiscoverPacket.getServerDiscoverResponseFlags()) ){
			this.handle_discover_response(packet);
		}
		
		//Negotiate steps
		else if( packet.checkForExactFlags(NegotiatePacket.getNegotiateRequestFlags()) )
		{
			try {
				this.handle_negotiate_request(packet);
			} catch (SimplException e) {
				//This happens because generating a KeyPair for DH agreement failed
				System.err.println(e.getMessage());
				e.printStackTrace();
				return;
			}
		}else if( packet.checkForExactFlags(NegotiatePacket.getNegotiateOkResponseFlags()) )
		{
			this.handle_negotiate_ok_response(packet);
		} else if( packet.checkForExactFlags(NegotiatePacket.getNegotiateDenyResponseFlags()) )
		{
			this.handle_negotiate_deny_response();
		} else if( packet.checkForExactFlags(NegotiatePacket.getNegotiateNonexistantResponseFlags()) )
		{
			this.handle_negotiate_nonexistant_response();
		}
		
		//TODO: remove from server packet handling code. Server is never going to send a Chat message to client
		//Chat step
		else if( packet.checkForExactFlags(ChatPacket.getChatPacketFlags()) )
		{
			this.handle_chat(packet);
		}
		
		//Leave steps
		//NOTE: 3-way handshake currently ignored
		if( packet.checkForExactFlags(LeavePacket.getClientA_FIN_Flags()) )
		{
			this.handle_leave();
		}
		
		//Logout step
		//TODO: need to handle receiving the server fin/ack since Server counts on ack to actually logout the Client
	}
	
	private void handleBuddyPacket(Packet packet){
		//Chat step
		if( packet.checkForExactFlags(ChatPacket.getChatPacketFlags()) ){
			this.handle_chat(packet);
		}
		
		//Leave step
		else if( packet.checkForExactFlags(LeavePacket.getClientA_FIN_Flags()) ){
			this.handle_leave();
		}
	}
	
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
		common.Utils.print_debug_msg("Entering do_negotiate_request");
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
	 * @throws SimplException 
	 */
	private void handle_negotiate_request(Packet packet) throws SimplException {
		try{
			//generate the DH Public/PrivateKeyPair
			this.generateKeyPairForKeyAgreement();
			//ensure it was successful
			if( this.clientAgreementKeyPair == null ){
				throw new SimplException("Client KeyAgreement KeyPair failed");
			}
			
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
			
			//create new packet for response //turns out reusing the packet wasn't the issue, don't feel bad Jaffe
			NegotiatePacket responsePacket = new NegotiatePacket();
			//send new packet with DH contribution of B and N
			responsePacket.readyClientBNegotiateResponse(this.serverSeshKey, this.clientAgreementKeyPair.getPublic(), N);
			responsePacket.go(this.serverSocket);
			common.Utils.print_debug_msg("Sent Negotiate response!");
			
			//manufacture the secret key
			this.clientSeshKey.set(this.findSecretKey(clientA_DHContrib));
			
			//build the buddySocket
			//use the least significant byte of the nonce as an offset from the server port to be the chat port
			//perhaps not the safest solution, but workable, I think. Adding 256 because we don't want the offset
			//to ever be negative
			int chatPortOffset = N[0] + common.Constants.BUDDY_PORT_OFFSET_BASE;
			//Must build a ServerSocket first to accept the connection
			this.buddyListenSocket = new ServerSocket(this.serverSocket.getPort()+chatPortOffset);
			//blocking wait on the connection from the buddy
			//TODO: chat negotiations really should be deniable from the perspective buddy.
			//		it's kinda easy to DOS "perspective buddies" like this
			this.buddySocket = this.buddyListenSocket.accept();
			//bypass the Synchronizable, since that is for the chat initiator, since the buddy blocks on the above
			//accept
			this.buddyStream.set_bypass(this.buddySocket.getInputStream());
			this.chatting = true;
		} catch (IOException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BrokenBarrierException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Touches this.clientSeshKey, signaling the UI thread
	 * finishes negotiation by handling B->A at A
	 */
	private void handle_negotiate_ok_response(Packet packet){
	//TODO: there's maybe some way to avoid using TWO Synchronizables here, but hey, just hoping this works
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
			
			//signal at Synchronizable, manufacture the secret key
			//TODO: might change the Synchronizable to the socket that do_chat needs, or just add another
			this.clientSeshKey.set(this.findSecretKey(clientB_DHContrib));
			//use the least significant byte of the nonce as an offset from the server port to be the chat port
			//perhaps not the safest solution, but workable, I think. Adding 256 because we don't want the offset
			//to ever be negative
			int chatPortOffset = N[0] + common.Constants.BUDDY_PORT_OFFSET_BASE;
			//build the buddySocket, should connect since ClientB should be waiting on accept()
			this.buddySocket = new Socket(this.buddyIP, this.serverSocket.getPort()+chatPortOffset);
			//set the buddyStream Synchronizable, signaling UI thread it's safe to send messages
			this.buddyStream.set(this.buddySocket.getInputStream());
		} catch (SimplException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (IOException e){
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
	public void handle_chat(Packet packet){
		ChatPacket chatPacket = (ChatPacket) packet;
		System.out.println(chatPacket.payload.decrypt(this.clientSeshKey.get_bypass()));
	}
	
	/**
	 * Leave the chat conversation with Buddy
	 * @return
	 */
	public void do_leave(){
		//TODO: implement
		//TODO: this.chatting = false
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
	
	public Packet waitForPacket(InputStream stream){
		try{
			Object o;
			byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
			//wait for data from Server or possible Buddy indefinitely
			int count = stream.read(recv);
			//once we have it, truncate down to smallest array
			byte[] packetBytes = new byte[count];
			System.arraycopy(recv, 0, packetBytes, 0, count);
			//make Packet out of bytes
			o = common.Utils.deserialize(packetBytes);
			Packet packet = (Packet) o;
			return packet;
		} catch (SocketTimeoutException e){
			//this isn't unexpected, just return null and let them deal with it
			return null;
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
	
	private byte[] findSecretKey(PublicKey buddyPublicKey){
		try
		{
			KeyAgreement ka = KeyAgreement.getInstance(common.Constants.KEY_AGREEMENT_ALGORITHM);
			ka.init(clientAgreementKeyPair.getPrivate());
			ka.doPhase(buddyPublicKey, true);	
			//forget KeyPair here
			clientAgreementKeyPair = null;
			SecretKey fullKey = ka.generateSecret(common.Constants.SYMMETRIC_CRYPTO_MODE);
			return Arrays.copyOf(fullKey.getEncoded(), 16); 
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
