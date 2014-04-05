/**
 * Consumes user input from CmdLine and constructs Packets
 */

package client;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

import javax.crypto.SecretKey;

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
//TODO: close streams?
	
	private static String LOGIN_SUCCESS_MSG = "Dat worked!";
	private static String LOGIN_FAILURE_MSG = "Server doesn't like you.";
	private static String LOGIN_UNDEFINED_MSG = "Server's drunk. You should go home. It should too.";
	private static String LOGIN_VERIFY_FAIL = "The \"server\" is evil! Punting!";
	private static String LOGIN_CATCHEMALL = "If you are seeing this, I am wrong: Gotta catch-em-all!";
	
	private Socket simplSocket; 		//socket used for communication to server
	private InputStream simplStream;
	private ArrayList<String> clients; 	//contains result of discover
	private byte[] N; 					//the nonce that we've used and sent to the Server
	public PublicKey serverPubK;
	public SecretKey sessionKey;
	
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
	 * @return message to print on CmdLine 
	 */
	public String do_login(String serverName, int port){
		try{
			Object o;
			
			//create TCP connection
			this.simplSocket = new Socket(serverName, port);
			this.simplStream = this.simplSocket.getInputStream();
			
			//Build the initial packet and send it
			LoginPacket loginRequest = new LoginPacket();
			loginRequest.readyClientLoginRequest();
			loginRequest.go(this.simplSocket);
			
			//TODO: check flags? or just rely on FSM?
			//Get challenge packet
			byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
			int count = this.simplStream.read(recv);
			//truncating the unused part of the recv buffer
			byte[] serverChallengeBytes = new byte[count];
			System.arraycopy(recv, 0, serverChallengeBytes, 0, count);
			//deserialize and cast to Packet
			o = common.Utils.deserialize(serverChallengeBytes);
			Packet serverChallenge = (Packet) o;
			//get all the challengePayloadBytes
			byte[] challengePayloadBytes = serverChallenge.crypto_data;
			ChallengePayload cp;
			if( common.Constants.CRYPTO_OFF ){
				//if there is no crypto, then we can deal simply with the challengePayloadBytes
				o = common.Utils.deserialize(challengePayloadBytes);
				cp = (ChallengePayload) o;
			} else {
				//TODO: grab challengePayloadBytes sans signature bytes
				//TODO: construct ChallengePayload from deserialization
				//TODO: pass in signature bytes to ChallengePayload verify
				//----------------------
				throw new UnsupportedOperationException();
			}
			
			//Start constructing the response packet.
			LoginPacket challengeResponse = new LoginPacket();
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
			e.printStackTrace();
			return e.getMessage();
		} catch (ClassNotFoundException e){
			e.printStackTrace();
			return e.getMessage();
		} catch (NoSuchAlgorithmException e){
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
		discoverRequest.go(this.simplSocket);
		
		//TODO: check flags? or just rely on FSM?
		//Get challenge packet
		byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
		int count = this.simplStream.read(recv);
		//truncating the unused part of the recv buffer
		byte[] serverDiscoverBytes = new byte[count];
		System.arraycopy(recv, 0, serverDiscoverBytes, 0, count);
		//get array list out of packet
		clients = discoverRequest.decryptServerDiscoverReponse(serverDiscoverBytes, sessionKey);
		
		
		} catch (IOException e){
			e.printStackTrace();
		}
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
