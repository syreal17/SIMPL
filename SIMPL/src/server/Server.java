package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

import javax.crypto.SecretKey;

import common.Keymake;

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
//TODO:close streams?
	
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
	
	public Server(int port, String userDBPath, String privKPath){
		try {
			this.listenerSocket = new ServerSocket(port);
			this.userDB = new HashMap<String, byte[]>();
			this.load_users(userDBPath);
			this.clientHandler = new ClientHandler();
			this.threads = new ArrayList<Thread>();
			this.running = true;
			
			//call to either load the PrivateKey at privKPath or create it there
			this.get_private_key(privKPath);
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
	public void handle_discover(Socket clientSocket,InputStream clientStream, SecretKey sessionKey){
		try{
			Object o;
			
			//Build the initial packet and send it
			DiscoverPacket discoverRequest = new DiscoverPacket();
			System.out.println("Server: handle_discover1");
			//TODO: check flags? or just rely on FSM?
			//Get challenge packet
			byte[] recv = new byte[common.Constants.MAX_EXPECTED_PACKET_SIZE];
			int count = clientStream.read(recv);
			//truncating the unused part of the recv buffer
			byte[] serverDiscoverBytes = new byte[count];
			System.arraycopy(recv, 0, serverDiscoverBytes, 0, count);
			//prepare the username list
			discoverRequest.readyServerDiscoverResponse(userDB.keySet(), sessionKey);
			//send the usernames to the client
			discoverRequest.go(clientSocket);
			System.out.println("Server: handle_discover2");
			
			} catch (IOException e){
				e.printStackTrace();
			}
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
	
	//TODO: test
	/**
	 * Either load the private key from a file, or create it, either way update the serverPrivK field
	 * @param filepath filepath to either load or save to
	 * @throws Exception Might be irregular file, too big, or unreadable&unwritable file
	 */
	private void get_private_key(String filepath) throws IOException, UnsupportedOperationException {
		try{
			File privateKeyFile = new File(filepath);
			if( privateKeyFile.isFile() ){
				if( privateKeyFile.canRead() ){
					long lKeyFileLength = privateKeyFile.length();
					if( lKeyFileLength > Integer.MAX_VALUE ){
						throw new UnsupportedOperationException(common.Constants.FILE_TOO_LARGE_MSG);
					} else {
						//read key file bytes from file
						int iKeyFileLength = (int) lKeyFileLength;
						byte[] privateKeyBytes = new byte[iKeyFileLength];
						FileInputStream fis = new FileInputStream(privateKeyFile);
						fis.read(privateKeyBytes);
						fis.close();
						
						//convert to PrivateKey
						KeyFactory kf = KeyFactory.getInstance(common.Constants.ASYMMETRIC_CRYPTO_MODE);
						PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
						this.serverPrivK = kf.generatePrivate(privateKeySpec);
					}
				} else if( privateKeyFile.canWrite() ){
					//if we can't read (presumably because it doesn't exist, but we can write,
					//create a key and write it.
					Keymake.writePrivateKey(filepath);
				} else {
					this.serverPrivK = null;
					throw new IOException(common.Constants.FILE_UNREADABLE_UNWRITABLE_MSG);
				}
			} else {
				this.serverPrivK = null;
				throw new IOException(common.Constants.NOT_A_FILE_MSG);
			}
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
			this.serverPrivK = null;
			return;
		} catch (InvalidKeySpecException e){
			e.printStackTrace();
			this.serverPrivK = null;
			return;
		}
	}
	
	/**
	 * Load all the users that the server remembers
	 * @param filepath points to the CSV file that contains all user records
	 * @return success or not
	 */
	private void load_users(String filepath){
		String entry1 = "goliath";
		String entry2 = "agamemnon";
		String entry3 = "charbydis";
		String entry4 = "enchilada";
		String entry5 = "kimjongun";
		userDB.put(entry1, entry1.getBytes());
		userDB.put(entry2, entry2.getBytes());
		userDB.put(entry3, entry3.getBytes());
		userDB.put(entry4, entry4.getBytes());
		userDB.put(entry5, entry5.getBytes());		
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
	 * @return is user verified or not, if user was added to DB, also true
	 */
	private boolean verify_user(String username, byte[] suppliedPwHash){
		if( common.Constants.CRYPTO_OFF ){
			return true;
		} else {
			if( this.userDB.containsKey(username) ){
				//if the userDB already has the username, we want to check to make sure hashes match
				byte[] storedHash = this.userDB.get(username);
				return Arrays.equals(suppliedPwHash, storedHash);
			} else {
				//if username doesn't exist, add it to the DB
				this.userDB.put(username, suppliedPwHash);
				return true;
			}
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
