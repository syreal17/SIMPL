/**
 * Consumes user input from CmdLine and constructs Packets
 */

package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

import common.*;

import protocol.*;

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
 * Note: Singleton design pattern might be appropriate, but trying implementation
 * 			without quirky software engineering tricks first.
 * @author syreal
 *
 */
public class Client {
	
	private static String LOGIN_SUCCESS_MSG = "Dat worked!";
	private static String LOGIN_VERIFY_FAIL = "We aren't talking to server! Punting!";
	private static String LOGIN_CATCHEMALL = "If you are seeing this, I am wrong: Gotta catch-em-all!";
	
	private Socket simplSocket; //socket used for communication to server
	private InputStream simplStream;
	private ArrayList<String> clients; //contains result of discover
	private byte[] N; //the nonce that we've used and sent to the Server
	public PublicKey serverPubK;
	
	private SecureRandom RNG;
	
	//Constructor currently sets nothing up. Defers to other class methods
	public Client(PublicKey serverPubK){
		//set the size for N
		this.N = new byte[common.Constants.NONCE_SIZE_BYTES];
		//remember the Server public key
		this.serverPubK = serverPubK;
		//create a RNG instance
		//TODO: is it not a factory method?
	}
	
	/**
	 * Login to the SIMPL Server
	 * @param serverName the host name or ip string to connect to
	 * @param port the port number that the server is listening for SIMPL on
	 * @return success or failure
	 * @throws IOException 
	 * @throws UnknownHostException 
	 */
	public String do_login(String serverName, int port) 
			throws NoSuchAlgorithmException, UnknownHostException, IOException,	ClassNotFoundException{
		try{
			//TODO: maybe return more helpful error codes, instead of punting to Exceptions
			
			//An object variable to use throughout
			Object o;
			
			//create TCP connection
			this.simplSocket = new Socket(serverName, port);
			this.simplStream = this.simplSocket.getInputStream();
			
			//__Build the initial packet
			LoginPacket loginRequest = new LoginPacket();
			loginRequest.readyClientLoginRequest();
			//send it
			loginRequest.go(this.simplSocket);
			
			//__Get challenge packet
			//TODO: check flags
			//having faith that Java will correctly give me the entire packet at once
			byte[] recv = new byte[common.Constants.MAX_EXPECT_PACKET_SIZE];
			//we will wait till server sends something
			int count = this.simplStream.read(recv);
			//that something should be a Packet
			byte[] packetBytes = new byte[count];
			//manual copy, truncating the unused part of the recv buffer
			for(int i = 0; i < count; i++){
				packetBytes[i] = recv[i];
			}
			//turn into an object first
			o = common.Utils.deserialize(packetBytes);
			//then cast to a Packet
			Packet serverChallenge = (Packet) o;
			//TODO: decide whether or not to use the verify embedded in readyClientChallengeResponse or the below
			//verify the server signature, returns byte array of the ChallengePayload if successful
			byte[] challengePayloadBytes = serverChallenge.verify(this.serverPubK); 	//this is the ClientServerPreSessionPacket call.
			//invalid signature is a null byte[]
			if( challengePayloadBytes == null ){
				return Client.LOGIN_VERIFY_FAIL;
			}
			//deserialize the ChallengePayload into an object
			o = common.Utils.deserialize(challengePayloadBytes);
			//cast it to a ChallengePayload
			ChallengePayload cp = (ChallengePayload) o;
			
			//__Start constructing the response packet.
			LoginPacket challengeResponse = new LoginPacket();
			//stuff the ChallengePayload into challengeResponse so calculations can be done on it
			challengeResponse.challengePayload = cp;
			//TODO: actually get user input here
			String username = "syreal";
			String password = "password";
			//Hashing the password
			MessageDigest md = MessageDigest.getInstance(common.Constants.HASH_ALGORITHM);
			md.update(password.getBytes());
			byte[] pwHash = md.digest();
			challengeResponse.readyClientLoginChallengeResponse(this.serverPubK, username, pwHash, challengePayloadBytes);
			
			return Client.LOGIN_CATCHEMALL;
		} catch (Exception e){
			e.printStackTrace();
			return Client.LOGIN_CATCHEMALL;
		}
	}
	
	/**
	 * Ask SIMPL Server for Login'd SIMPL Clients. Instantiates the clients ArrayList
	 * @return success or failure
	 */
	public void do_discover(){
		//TODO: implement
		//TODO: build this.clients from this message
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * If, Client has no Buddy, negotiate Buddy (peer SIMPL client) with Server and then,
	 * or otherwise, just send chat message to Buddy
	 * @param message message to send chat buddy
	 * @return success or failure
	 */
	public void do_chat(String message){
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
	 * Logout to Server
	 * @return
	 */
	public void do_logout(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
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
