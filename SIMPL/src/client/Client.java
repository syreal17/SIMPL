/**
 * Consumes user input from CmdLine and constructs Packets
 */

package client;

import java.net.Socket;
import java.util.ArrayList;

/*Resources:
 * _SINGLETON DESIGN PATTERN_
 * A good example of a thread-safe singleton implementation:
 * 		http://www.javaworld.com/article/2073352/core-java/simply-singleton.html?page=2
 * 
 * _NETWORKING_
 * A simple TCP server and client:
 * 		http://docs.oracle.com/javase/tutorial/networking/sockets/clientServer.html
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
	
	private Socket simplSocket; //socket used for communication to server
	private ArrayList<String> clients; //contains result of discover
	
	//Constructor currently sets nothing up. Defers to other class methods
	public Client(){}
	
	/**
	 * Login to the SIMPL Server
	 * @param serverName the host name or ip string to connect to
	 * @param port the port number that the server is listening for SIMPL on
	 * @return success or failure
	 */
	public int do_login(String serverName, int port){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	/**
	 * Ask SIMPL Server for Login'd SIMPL Clients. Instantiates the clients ArrayList
	 * @return success or failure
	 */
	public int do_discover(){
		//TODO: implement
		//TODO: build this.clients from this message
		return common.Constants.GENERIC_FAILURE;
	}
	
	/**
	 * If, Client has no Buddy, negotiate Buddy (peer SIMPL client) with Server and then,
	 * or otherwise, just send chat message to Buddy
	 * @param message message to send chat buddy
	 * @return success or failure
	 */
	public int do_chat(String message){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	/**
	 * Leave the chat conversation with Buddy
	 * @return
	 */
	public int do_leave(){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	/**
	 * Logout to Server
	 * @return
	 */
	public int do_logout(){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
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
