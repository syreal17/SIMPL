package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

import protocol.*;

/*
 * _NETWORKING_
 * A simple TCP server and client:
 * 		http://docs.oracle.com/javase/tutorial/networking/sockets/clientServer.html
 * 
 * _THREADING
 * A good discussion of the two main different syntax and semantics for starting a thread:
 * 		http://docs.oracle.com/javase/tutorial/essential/concurrency/runthread.html
 */

/**
 * ltj: I've mostly just included functions names here. There's plenty of missing pieces I think
 * @author JaffeTaffy
 *
 */
public class Server {
	
	public static final String UNEXPECTED_CLIENT_PACKET_MSG = "Client's drunk! Got unexpected packet.";
	
	private ServerSocket listenerSocket;
	private PrivateKey serverPrivK;
	//the username->pwHash map that the server retains TODO: include N(once) too?
	private Map<String, byte[]> userDB;
	//used for a new thread knowing which socket to use
	private ClientHandler clientHandler;
	//remember Threads, just because it seems like a good idea
	private ArrayList<Thread> threads;
	//should the start_listener_loop continue? I've made a useless mutator to change this to false.
	//Would need a separate thread to call the function. The main thread is spinning on listener loop
	private boolean running;
	
	public Server(int port, String userDBPath, PrivateKey serverPrivK){
		try {
			this.listenerSocket = new ServerSocket(port);
			this.load_users(userDBPath);
			this.serverPrivK = serverPrivK;
			this.clientHandler = new ClientHandler();
			this.threads = new ArrayList<Thread>();
			
			this.running = true;
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Start the loop for the Server to accept multiple Client connections, and spin off threads
	 */
	public void start_listener_loop(){
		try {
			while(this.running){
				//Listen for new client connections... (blocking)
				Socket clientSocket = this.listenerSocket.accept();
				this.clientHandler.addEntry(new ClientHandlerEntry(clientSocket, false) );
				//create thread
				Thread thread = (new Thread( new ClientHandlerThread() ));
				thread.start();
				//remember it for good measure
				this.threads.add(thread);
			}
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	//slide 5
	public void handle_login(Packet clientPacket, Socket clientSocket, InputStream clientStream){
		Object o;
		
		byte[] R_2 = new byte[protocol.LoginPacket.R_2_size];
		//ready the challenge for the client and send
		LoginPacket serverChallenge = new LoginPacket();
		//remember R_2 so we can check the challengeResponse
		R_2 = serverChallenge.readyServerLoginChallenge(this.serverPrivK);
		serverChallenge.go(clientSocket);
		
		try {
			//receive back the Client's challenge response
			byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
			int count = clientStream.read(recv);
			//truncate the buffer
			byte[] challengeResponseBytes = new byte[count];
			System.arraycopy(recv, 0, challengeResponseBytes, 0, count);
			//deserialize and cast to LoginPacket (all the way to LoginPacket so we can get R_2)
			o = common.Utils.deserialize(challengeResponseBytes);
			LoginPacket challengeResponse = (LoginPacket) o;
			//ensure the right R_2 was found before doing crypto work
			if( !Arrays.equals(R_2, challengeResponse.R_2) ){
				//if they aren't the same, send deny message
				LoginPacket denyResponse = new LoginPacket();
				denyResponse.readyServerLoginDeny();
				denyResponse.go(clientSocket);
				return;
			}
			//if they're the same get the auth payload, and check that
			byte[] authenticationPayloadBytes = challengeResponse.crypto_data;
			//decrypt it first if CRYPTO isn't OFF
			if( !common.Constants.CRYPTO_OFF ){
				//TODO: Jaffe AuthenticationPayload decrypt, etc.
				//TODO: then deserialize
			}
			//deserialize to AuthenticationPayload
			o = common.Utils.deserialize(authenticationPayloadBytes);
			AuthenticationPayload ap = (AuthenticationPayload) o;
			//check the user supplied username and password hash
			if( this.verify_user(ap.username, ap.pwHash) ){
				LoginPacket okResponse = new LoginPacket();
				okResponse.readyServerLoginOk();
				okResponse.go(clientSocket);
				return;
			} else {
				LoginPacket denyResponse = new LoginPacket();
				denyResponse.readyServerLoginDeny();
				denyResponse.go(clientSocket);
				return;
			}
		} catch (IOException e) {
			e.printStackTrace();
			return;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return;
		}
	}
	
	//slide 6
	public void handle_discover(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	//slide 7
	public void handle_chat_negotiation(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	//slide 9
	public void handle_logout(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Load all the users that the server remembers
	 * @param filepath points to the CSV file that contains all user records
	 * @return success or not
	 */
	private void load_users(String filepath){
		if( common.Constants.CRYPTO_OFF ){
			return;
		}
		//TODO: implement
		//TODO: create file if one doesn't exist or error, print warning message if this is the case
		//TODO: load file to this.userDB
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Save all the in-memory users to disk to be able to load next start-up
	 * @param filepath points to the location on disk to save all user records
	 * @return
	 */
	private void save_users(String filepath){
		if( common.Constants.CRYPTO_OFF ){
			return;
		}
		//TODO: implement
		//TODO: save this.userDB to disk
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Check that the user either has the right password, or is a new user, then add key->value to map
	 * @param username the username to check
	 * @param suppliedPwHash the pwhash that was supplied by the user
	 * @return is user verified or not
	 */
	private boolean verify_user(String username, byte[] suppliedPwHash){
		if( common.Constants.CRYPTO_OFF ){
			return true;
		} else {
			//TODO: add check of this.userDB
			//TODO: if username not in DB, add it to DB with the supplied hash
			throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
		}
	}
	
	public ClientHandler getClientHandler(){
		return this.clientHandler;
	}
	
	/**
	 * This is really, quite non-functional now since the main thread spins in start_listener_loop without
	 * possibility of this method getting called.
	 */
	public void stop(){
		this.running = false;
	}
}
