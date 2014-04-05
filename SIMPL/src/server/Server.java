package server;

import java.io.IOException;
import java.net.*;
import java.security.*;
import java.util.*;

/*
 * _NETWORKING_
 * A simple TCP server and client:
 * 		http://docs.oracle.com/javase/tutorial/networking/sockets/clientServer.html
 */

/**
 * ltj: I've mostly just included functions names here. There's plenty of missing pieces I think
 * @author JaffeTaffy
 *
 */
public class Server {
	
	private ServerSocket listenerSocket;
	private PrivateKey serverPrivK;
	//the username->pwHash map that the server retains
	private Map<String, byte[]> userDB;
	
	public Server(int port, String userDBPath, PrivateKey serverPrivK){
		try {
			this.listenerSocket = new ServerSocket(port);
			this.load_users(userDBPath);
			this.serverPrivK = serverPrivK;
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void start(){
		try {
			//TODO: put in a thread to make it able to server multiple clients at once?
			Socket clientSocket = this.listenerSocket.accept();
			
			//
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	//slide 5
	public void handle_login(){
		//TODO: implement
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
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
}
