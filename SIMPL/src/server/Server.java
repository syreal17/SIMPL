package server;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

import protocol.payload.ClientANegotiateRequestPayload;
import protocol.payload.ServerNegotiateRequestPayload;

import common.*;

/*
 * _NETWORKING_
 * A simple TCP server and client:
 * 		http://docs.oracle.com/javase/tutorial/networking/sockets/clientServer.html
 * 
 * _THREADING
 * A good discussion of the two main different syntax and semantics for starting a thread:
 * 		http://docs.oracle.com/javase/tutorial/essential/concurrency/runthread.html
 */

public class Server {
	
	public static final String UNEXPECTED_CLIENT_PACKET_MSG = "Client's drunk! Got unexpected packet.";
	
	public PrivateKey serverPrivK;
	//the username->pwHash map that the server retains
	public Map<String, byte[]> userDB;
	
	private ServerSocket listenerSocket;
	private String userDBPath;
	//used for a new thread knowing which socket to use
	private ClientHandler clientHandler;
	//remember Threads, just because it seems like a good idea
	private ArrayList<ClientHandlerThread> threads;
	//should the start_listener_loop continue? I've made a useless mutator to change this to false.
	//Would need a separate thread to call the function. The main thread is spinning on listener loop
	private boolean running;
	
	public Server(int port, String userDBPath, String privKPath){
		try {
			this.listenerSocket = new ServerSocket(port);
			
			this.userDB = new HashMap<String, byte[]>();
			this.userDBPath = userDBPath;
			this.load_users();
			
			this.clientHandler = new ClientHandler();
			this.threads = new ArrayList<ClientHandlerThread>();
			this.running = true;
			
			//call to either load the PrivateKey at privKPath or create it there
			this.get_private_key(privKPath);
			
		} catch (IOException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Should be called by a CHT wanting to negotiate
	 * @param clientA_CHT the CHT of the requester.
	 * @param username the username to request a chat with
	 * @return true if username can chat, false if username is already chatting
	 * @throws SimplException if username was not found
	 */
//	public boolean request_username_as_wanted(ClientHandlerThread clientA_CHT, ServerNegotiateRequestPayload payload)
//			throws SimplException{
//		
//		//try and find the requested CHT
//		ClientHandlerThread clientB_CHT = this.findClientThread(payload.wantToUsername);
//		//check that it was found
//		if( clientB_CHT == null ){
//			//if it wasn't, inform callee
//			throw new SimplException(common.Constants.USERNAME_NOT_FOUND_MSG);
//		}
//	}
	
	/**
	 * Find the server's thread that is talking to the client with username
	 * @param username the username to search for in the ClientHandlerThreads
	 * @return the thread if found, otherwise, null
	 */
	private ClientHandlerThread findClientThread(String username){
		//search all threads for the thread that is talking to "username"
		for( ClientHandlerThread cht : this.threads ){
			if( cht.clientUsername.equals(username)){
				return cht;
			}
		}
		
		return null;
	}
	
	/**
	 * Start the loop for the Server to accept multiple Client connections, and spin off ClientHandlerThreads
	 */
	public void start_listener_loop(){
		try {
			while(this.running){
				//Listen for new client connections... (blocking)
				Socket clientSocket = this.listenerSocket.accept();
				this.clientHandler.addEntry(new ClientHandlerEntry(clientSocket, false) );
				//create thread
				ClientHandlerThread cht = new ClientHandlerThread();
				cht.start();
				//remember thread
				this.threads.add(cht);
			}
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * This is really, quite non-functional now since the main thread spins in start_listener_loop without
	 * possibility of this method getting called.
	 */
	public void stop(){
		try{
			//TODO: good idea to save users here, but may want to do it somewhere that actually gets called
			this.save_users();
			this.running = false;
		} catch (SimplException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	//TODO: debug why it doesn't write a key when it creates a new file
	/**
	 * Either load the private key from a file, or create it, either way update the serverPrivK field
	 * @param filepath filepath to either load or save to
	 * @throws Exception Might be irregular file, too big, or unreadable&unwritable file
	 */
	private void get_private_key(String filepath) throws IOException, UnsupportedOperationException {
		try{
			File privateKeyFile = new File(filepath);
			if( !privateKeyFile.isDirectory() ){
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
				} else if( privateKeyFile.canWrite() || privateKeyFile.createNewFile() ){
					//if we can't read but we can write it; create a key and write it.
					Keymake.writePrivateKey(privateKeyFile);
					this.serverPrivK = Keymake.getPrivateKey();
				} else {
					//else it's a bad path to use
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
	private void load_users(){
		if( common.Constants.TESTING ){
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
		} else {
			//TODO: implement
			//punting on this right now because it's not critical
			throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
		}
	}
	
	/**
	 * Save all the in-memory users to disk to be able to load next start-up
	 * @param filepath points to the location on disk to save all user records
	 */
	private void save_users() throws SimplException {
		try{
			File userDBFile = new File(this.userDBPath);
			if( userDBFile.canWrite() ){
				ArrayList<UserDBEntry> serializableDB = new ArrayList<UserDBEntry>();
				byte[] dbBytes = common.Utils.serialize(serializableDB);
				FileOutputStream fos = new FileOutputStream(userDBFile);
				fos.write(dbBytes);
				fos.close();
			} else {
				throw new SimplException(common.Constants.FILE_UNWRITABLE_MSG);
			}
		} catch (IOException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	/**
	 * Check that the user either has the right password, or is a new user, then add key->value to map
	 * @param username the username to check
	 * @param suppliedPwHash the pwhash that was supplied by the user
	 * @return is user verified or not, if user was added to DB, also true
	 */
	public boolean verify_user(String username, byte[] suppliedPwHash){
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
}
