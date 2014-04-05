/**
 * Consumes user input from CmdLine and constructs Packets
 */

package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

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
	private static String LOGIN_FAILURE_MSG = "Server doesn't like you.";
	private static String LOGIN_UNDEFINED_MSG = "Server's drunk. You should go home. It should too.";
	@SuppressWarnings("unused")
	private static String LOGIN_VERIFY_FAIL = "The \"server\" is evil! Punting!";
	private static String LOGIN_CATCHEMALL = "If you are seeing this, I am wrong: Gotta catch-em-all!";
	
	private Socket simplSocket; 		//socket used for communication to server
	private InputStream simplStream;
	private ArrayList<String> clients; 	//contains result of discover
	private byte[] N; 					//the nonce that we've used and sent to the Server
	public PublicKey serverPubK;
	
	//Constructor currently sets nothing up. Defers to other class methods
	public Client(PublicKey serverPubK){
		//set the size for N
		this.N = new byte[common.Constants.NONCE_SIZE_BYTES];
		//remember the Server public key
		this.serverPubK = serverPubK;
	}
	
	/**
	 * Login to the SIMPL Server
	 * @param serverName the host name or ip string to connect to
	 * @param port the port number that the server is listening for SIMPL on
	 * @return success or failure
	 * @throws IOException 
	 * @throws UnknownHostException 
	 */
	public String do_login(String serverName, int port){
		try{
			//TODO: maybe return more helpful error codes, instead of punting to Exceptions
			
			Object o;
			
			//create TCP connection
			this.simplSocket = new Socket(serverName, port);
			this.simplStream = this.simplSocket.getInputStream();
			
			//__Build the initial packet
			LoginPacket loginRequest = new LoginPacket();
			loginRequest.readyClientLoginRequest();
			//send it!
			loginRequest.go(this.simplSocket);
			
			//__Get challenge packet
			//TODO: check flags?
			//having faith that Java will correctly give me the entire packet at once
			byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
			//we will wait till server sends something
			int count = this.simplStream.read(recv);
			//that something should be a Packet
			byte[] serverChallengeBytes = new byte[count];
			//truncating the unused part of the recv buffer
			System.arraycopy(recv, 0, serverChallengeBytes, 0, count);
			//TODO: verify viability
			o = common.Utils.deserialize(serverChallengeBytes);
			//TODO: verify viability
			Packet serverChallenge = (Packet) o;
			/*I want to avoid using weird ClientServerPreSessionPacket class for now
			//verify the server signature, returns byte array of the ChallengePayload if successful, sans sig
			//TODO: is calling "abstract" method even ok here?
			byte[] challengePayloadBytes = serverChallenge.verify(this.serverPubK); 	//this is the ClientServerPreSessionPacket call.
			*/
			byte[] challengePayloadBytes;
			if( common.Constants.CRYPTO_OFF ){
				challengePayloadBytes = serverChallenge.crypto_data;
			} else {
				//TODO: grab challengePayloadBytes sans signature bytes
				//TODO: construct ChallengePayload from deserialization
				//TODO: pass in signature bytes to ChallengePayload verify
				throw new UnsupportedOperationException();
			}
			/*//invalid signature is a null byte[]
			if( challengePayloadBytes == null ){
				return Client.LOGIN_VERIFY_FAIL;
			}*/
			//TODO: verify viability, correct order once fleshed out
			o = common.Utils.deserialize(challengePayloadBytes);
			//TODO: verify viability, correct order once fleshed out
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
			//generating the nonce
			SecureRandom.getInstance(common.Constants.RNG_ALOGRITHM).nextBytes(this.N);
			//ready the Response for transmission
			challengeResponse.readyClientLoginChallengeResponse(this.serverPubK, username, pwHash, this.N);
			challengeResponse.go(this.simplSocket);
			
			//__Get the server response: ok or deny
			//reset the recv buffer. Byte cast actually necessary ;P
			Arrays.fill(recv, (byte)0);
			count = this.simplStream.read(recv);
			byte[] serverResponseBytes = new byte[count];
			//manual copy, truncating the unused part of the recv buffer
			for(int i = 0; i < count; i++){
				serverResponseBytes[i] = recv[i];
			}
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
