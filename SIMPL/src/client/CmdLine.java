/**
 * Handles command line user input to include starting up the Client object.
 */

package client;

import java.net.InetAddress;

/**
 * @author syreal
 *
 */
public class CmdLine {
	
	private static final String INVALID_SERVERNAME = "Not a valid server name!";
	private static final String INVALID_PORTNUM = "Not a valid port number!";
	private static final String WHO_PRELUDE = "Available usernames to chat with are:";
	private static final String LOGIN_FAIL = "SIMPL Client failed to login! Quitting.";
	private static final String DISCOVER_FAIL = "SIMPL Client failed to discover! Quitting.";
	private static final String HELP_MSG = 	"/who\t\t\t: Print list of available usernames to chat with\n" +
											"/chat <username> [message]\t: Start a chat with <username>\n" +
											"/leave\t\t\t: Leave the current chat\n" +
											"/quit\t\t\t: Logout from SIMPL Server and close Client\n" +
											"/help\t\t\t: Print this dialog\n";
	private static final String USAGE_MSG = "Usage: java client.CmdLine <server name> <port>";
	private static final int ARG_SERVERNAME_POS = 0;
	private static final int ARG_PORTNUM_POS = 1;
	
	private static Client client;	//the abstraction that this CmdLine interacts with. Should only be created once.
	
	private static boolean isClientValid(){
		if( CmdLine.client != null ){
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Command Line call to connect to a SIMPL server. Done at start-up.
	 * The Client should always be connected to Server
	 * @param serverName the host name or ip string to connect to
	 * @param port the port number that the server is listening for SIMPL on
	 * @return success or failure
	 */
	private static int client_connect(String serverName, int port){
		//TODO: implement
		return common.Constants.GENERIC_FAILURE;
	}
	
	/**
	 * Fetches data structure from Client and prints in a readable way
	 */
	private static void who_command(){
		
		if( CmdLine.isClientValid() ){
			if( CmdLine.client.isClientsValid() ){
				//print introductory message
				System.out.println(CmdLine.WHO_PRELUDE);
				
				//print each client name in an implicit iterator foreach loop
				for( String client : CmdLine.client.getClients() ){
					System.out.println(client);
				}
			}
		}
		
		return;
	}
	
	/**
	 * Prints SIMPL Client recognized commands to the terminal
	 */
	private static void help_command(){
		System.out.println(CmdLine.HELP_MSG);
		return;
	}
	
	/**
	 * The function which loops, accepting user commands (as seen in HELP_MSG) and devoid of any command,
	 * sends the text as a message to it's connected chat buddy
	 */
	private static void user_input_loop(){
		//TODO: implement
		//TODO: parse out first word of user input string, 
		//		if a command, do command, if not, try to send as message
		return;
	}
	
	public static void main(String[] Args){
		
		//parse server name and do validity check
		String serverName = Args[CmdLine.ARG_SERVERNAME_POS];
		if( !common.Utils.isValidIPAddr(serverName) ){
			System.out.println(CmdLine.INVALID_SERVERNAME);
			System.out.println(CmdLine.USAGE_MSG);
			System.exit(common.Constants.GENERIC_FAILURE);
		}
		
		//parse port number and do validity check
		int portNum = Integer.valueOf(Args[CmdLine.ARG_PORTNUM_POS]);
		if( !common.Utils.isValidPort(Args[CmdLine.ARG_PORTNUM_POS])){
			System.out.println(CmdLine.INVALID_PORTNUM);
			System.out.println(CmdLine.USAGE_MSG);
			System.exit(common.Constants.GENERIC_FAILURE);
		}
		
		//create Client instance
		CmdLine.client = new Client();
		
		//try connecting
		//ltj: these lines are very C-like. Java style is more exception oriented
		if( CmdLine.client.do_login(serverName, portNum) == common.Constants.GENERIC_FAILURE ){
			System.out.println(CmdLine.LOGIN_FAIL);
			System.exit(common.Constants.GENERIC_FAILURE);
		}
		
		//try discover
		if( CmdLine.client.do_discover() == common.Constants.GENERIC_FAILURE ){
			System.out.println(CmdLine.DISCOVER_FAIL);
			System.exit(common.Constants.GENERIC_FAILURE);
		}
		
		//ensure that discovery list is valid
		if( !CmdLine.client.isClientsValid() ){
			System.out.println(CmdLine.DISCOVER_FAIL);
			System.exit(common.Constants.GENERIC_FAILURE);
		}
		
		//print available commands
		CmdLine.help_command();
		
		//print clients list
		CmdLine.who_command();
		
		//enter ui loop
		//TODO: ui thread stuff needs to go here
		CmdLine.user_input_loop();
		
		//only reason to exit ui loop is quitting SIMPL Client
		System.exit(common.Constants.GENERIC_SUCCESS);
	}
}
