package server;

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
	
	//slide 5
	public int handle_login(){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	//slide 6
	public int handle_discover(){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	//slide 7
	public int handle_chat_negotiation(){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	//slide 9
	public int handle_logout(){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	/**
	 * Load all the users that the server remembers
	 * @param filepath points to the CSV file that contains all user records
	 * @return success or not
	 */
	private int load_users(String filepath){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	/**
	 * Save all the in-memory users to disk to be able to load next start-up
	 * @param filepath points to the location on disk to save all user records
	 * @return
	 */
	private int save_users(String filepath){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
}
