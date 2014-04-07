/**
 * Consumes user input from CmdLine and constructs Packets
 */

package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

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
public class Client {
//TODO: close streams?
	
	private static String LOGIN_SUCCESS_MSG = "Dat worked!";
	private static String LOGIN_FAILURE_MSG = "Server doesn't like you.";
	private static String LOGIN_UNDEFINED_MSG = "Server's drunk. You should go home. It should too.";
	private static String LOGIN_VERIFY_FAIL = "The \"server\" is evil! Punting!";
	private static String LOGIN_CATCHEMALL = "If you are seeing this, I am wrong: Gotta catch-em-all!";
	
	public String username; 							//clients username stored here
	
	private Socket serverSocket; 				//socket used for communication to server
	public Socket buddySocket;
	private InputStream simplStream;
	private ArrayList<String> clients; 			//contains result of discover
	private byte[] N; 							//the nonce that we've used and sent to the Server
	public PublicKey serverPubK;
	public byte[] serverSeshKey;
	private KeyPair clientAgreementKeyPair;		//the PrivateKey used in the KeyAgreement
	private SecretKey clientSeshKey;			//the result of the KeyAgreement, used as the session key between
												//two chatting clients
	
	//Constructor currently sets nothing up. Defers to other class methods
	public Client(PublicKey serverPubK){
		//set the size for N
		this.N = new byte[common.Constants.NONCE_SIZE_BYTES];
		//remember the Server public key
		this.serverPubK = serverPubK;
	}
	
	/**
	 * analog to ClientHandlerThread.enterClientHandleLoop
	 */
	private void enterClientChatLoop(){
		try 
		(
            BufferedReader in = new BufferedReader(new InputStreamReader(buddySocket.getInputStream()));
        ) 
		{
			String buffer1 = "tmp";
			String buffer2 = "tmp";
			while (true)
			{
				if ((buffer2 = in.readLine()) != buffer1)
				{
					System.out.println(buffer2);
					buffer1 = buffer2;
				}
			}
        } 
		catch (IOException e) 
		{
            e.printStackTrace();
        }
	}
	
	/**
	 * analog to CLientHandlerThread.handlePacket
	 * @param buddyPacket
	 */
	private void handlePacket(Packet buddyPacket){
		
	}
	
	//TODO: this should probably be made like the ClientHandlerThread
	/**
	 * Login to the SIMPL Server
	 * @param serverName the host name or ip string to connect to
	 * @param port the port number that the server is listening for SIMPL on
	 * @return message to print on CmdLine 
	 */
	public String do_login(String serverName, int port){
		try{
			Object o;
			
			//create TCP connection
			this.serverSocket = new Socket(serverName, port);
			this.simplStream = this.serverSocket.getInputStream();
			
			//Build the initial packet and send it
			LoginPacket loginRequest = new LoginPacket();
			loginRequest.readyClientLoginRequest();
			loginRequest.go(this.serverSocket);
			
			//Get challenge packet
			byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
			int count = this.simplStream.read(recv);
			//truncating the unused part of the recv buffer
			byte[] serverChallengeBytes = new byte[count];
			System.arraycopy(recv, 0, serverChallengeBytes, 0, count);
			//deserialize and cast to Packet
			o = common.Utils.deserialize(serverChallengeBytes);
			LoginPacket serverChallenge = (LoginPacket) o;
			//get all the challengePayloadBytes
			byte[] signature = serverChallenge.signature;
			ChallengePayload cp = serverChallenge.challengePayload;
			
			if( common.Constants.CRYPTO_OFF ){

			} else {
				
				if (cp.verify(this.serverPubK, signature))
				{
					System.out.println("Signature success!");
				}
				else
				{
					System.out.println("Signature failure...");
				}
			}
			
			//Start constructing the response packet.
			LoginPacket challengeResponse = new LoginPacket();
			challengeResponse.R_1 = serverChallenge.R_1;
			challengeResponse.challengePayload = cp;
			//TODO: actually get user input here
			this.username = "syreal";
			String password = "password";
			//Hashing the password
			MessageDigest md = MessageDigest.getInstance(common.Constants.PASSWORD_HASH_ALGORITHM);
			md.update(password.getBytes());
			byte[] pwHash = md.digest();
			//generating the nonce
			SecureRandom.getInstance(common.Constants.RNG_ALOGRITHM).nextBytes(this.N);
			//ready the Response for transmission and create the session key
			serverSeshKey = challengeResponse.readyClientLoginChallengeResponse(this.serverPubK, username, pwHash, this.N);
			//transmit the response
			challengeResponse.go(this.serverSocket);
			
			//Get the server response: ok or deny
			Arrays.fill(recv, (byte)0);
			count = this.simplStream.read(recv);
			byte[] serverResponseBytes = new byte[count];
			//truncating the unused part of the recv buffer
			System.arraycopy(recv, 0, serverResponseBytes, 0, count);
			//deserialization and casting to Packet
			o = common.Utils.deserialize(serverResponseBytes);
			Packet serverResponse = (Packet) o;
			
			//check the flags of the packet to see if we were accepted, or not, or worse
			if( serverResponse.flags.contains(Packet.Flag.Ok) && 
					!serverResponse.flags.contains(Packet.Flag.Deny)){
				return Client.LOGIN_SUCCESS_MSG;
			} else if( !serverResponse.flags.contains(Packet.Flag.Ok) &&
					serverResponse.flags.contains(Packet.Flag.Deny)){
				return Client.LOGIN_FAILURE_MSG;
			} else {
				return Client.LOGIN_UNDEFINED_MSG;
			}
		} catch (IOException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return e.getMessage();
		} catch (ClassNotFoundException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return e.getMessage();
		} catch (NoSuchAlgorithmException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return e.getMessage();
		}
	}
	
	/**
	 * Ask SIMPL Server for Login'd SIMPL Clients. Instantiates the clients ArrayList
	 * @return success or failure
	 */
	public void do_discover(){
		try{
		Object o;
		
		//Build the initial packet and send it
		DiscoverPacket discoverRequest = new DiscoverPacket();
		discoverRequest.readyClientDiscoverRequest();
		discoverRequest.go(this.serverSocket);

		System.out.println("Client: do_discover1");
		//TODO: check flags? or just rely on FSM?
		//Get challenge packet
		byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
		int count = this.simplStream.read(recv);
		//truncating the unused part of the recv buffer
		byte[] serverDiscoverBytes = new byte[count];
		System.arraycopy(recv, 0, serverDiscoverBytes, 0, count);
		o = common.Utils.deserialize(serverDiscoverBytes);
		Packet serverResponse = (Packet) o;
		byte[] usernames = serverResponse.crypto_data;
		//get array list out of packet
		clients = discoverRequest.decryptServerDiscoverReponse(usernames, serverSeshKey);
		System.out.println("Client: do_discover2");
		
		} catch (IOException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		} catch (ClassNotFoundException e) {
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
	private void handle_negotiate_request(){
		//TODO: Find out if the Client is ever waiting for this??
	}
	
	/**
	 * Continues with negotiation by responding B->A from B
	 */
	private void do_negotiate_response(){
		
	}
	
	/**
	 * finishes negotiation by handling B->A at A
	 */
	private void handle_negotiate_response(){
		
	}
	
	/**
	 * @param message message to send chat buddy
	 * @return success or failure
	 */
	public void do_chat(String message){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
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
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
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
	
	private void findSecretKey(PublicKey buddyPublicKey){
		//TODO: forget KeyPair here
	}
	
	/**
	 * to avoid null-pointer exceptions
	 * @return
	 */
	public boolean isClientsValid(){
		if( this.clients != null){
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * clients getter
	 * @return
	 */
	public ArrayList<String> getClients(){
		return this.clients;
	}
}
