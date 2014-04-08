/**
 * Handles command line user input to include starting up the Client object.
 */

package client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * @author syreal
 *
 */
public class CmdLine {
	
	private static final String USAGE_MSG = "Usage: java client.CmdLine <server name> <port> <path to server public key>\n" +
			"'path to server public key': point to valid '"+common.Constants.SERVER_PUBK_NAME+"' otherwise, one will be created";
	private static final int ARG_NUM = 3;
	private static final int ARG_SERVERNAME_POS = 0;
	private static final int ARG_PORTNUM_POS = 1;
	private static final int ARG_SERVERPUBK_POS = 2;
	
	private static final String WHO_PRELUDE = "Available usernames to chat with are:";
	private static final String LOGIN_FAIL = "SIMPL Client failed to login! Quitting.";
	private static final String DISCOVER_FAIL = "SIMPL Client failed to discover! Quitting.";
	private static final String HELP_MSG = 	"/who\t\t\t: Print list of available usernames to chat with\n" +
											"/chat <username> [message]\t: Start a chat with <username>\n" +
											"/leave\t\t\t: Leave the current chat\n" +
											"/quit\t\t\t: Logout from SIMPL Server and close Client\n" +
											"/help\t\t\t: Print this dialog\n";
	
	public static final String COMMAND_TOKEN_WHO = "who";
	public static final String COMMAND_TOKEN_GREET= "chat";
	public static final String COMMAND_TOKEN_LEAVE = "leave";
	public static final String COMMAND_TOKEN_QUIT = "quit";
	public static final String COMMAND_TOKEN_HELP = "help";
	private static Client client;	//the abstraction that this CmdLine interacts with. Should only be created once.
	
	/**
	 * Reports on whether client has been initialized
	 * @return
	 */
	private static boolean isClientValid(){
		if( CmdLine.client != null ){
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * Get PublicKey object from filename provided by user
	 * @param filename the path to the Server public key
	 * @return PublicKey object
	 */
	private static PublicKey getPublicKeyFromFile(String filename){
		if( common.Constants.CRYPTO_OFF ){
			return null;
		} else {
			try{
				File publicKeyFile = new File(filename);
				if( !publicKeyFile.isDirectory() ){
					if( publicKeyFile.canRead() ){
						long lKeyFileLength = publicKeyFile.length();
						if( lKeyFileLength > Integer.MAX_VALUE ){
							throw new UnsupportedOperationException(common.Constants.FILE_TOO_LARGE_MSG);
						} else {
							//read key file bytes from file
							int iKeyFileLength = (int) lKeyFileLength;
							byte[] publicKeyBytes = new byte[iKeyFileLength];
							FileInputStream fis = new FileInputStream(publicKeyFile);
							fis.read(publicKeyBytes);
							fis.close();
							
							//convert to PrivateKey
							KeyFactory kf = KeyFactory.getInstance(common.Constants.ASYMMETRIC_CRYPTO_MODE);
							X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
							return kf.generatePublic(publicKeySpec);
						}
					}
				} 
			} catch (NoSuchAlgorithmException e){
				e.printStackTrace();
				return null;
			} catch (InvalidKeySpecException e){
				e.printStackTrace();
				return null;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}
	
	/**
	 * Fetches data structure from Client and prints in a readable way
	 */
	public static void who_command(){
	//TODO: make this do another Discover
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
	 * Starts a chat with another SIMPL client
	 */
	public static void greet_command(String msg){
		System.out.println("Greeting this mafaka...");
		return;
	}
	
	/**
	 * Sends chat message to the connected client
	 */
	public static void chat_command(String msg){
		System.out.println("Chat this mafaka...");
		return;
	}
	
	/**
	 * Leaves the current SIMPL chat, doesn't log the client out
	 */
	public static void leave_command(){
		System.out.println("Leaving chat with buddy...");
		return;
	}
	
	/**
	 * Quits SIMPL, logs the client out
	 */
	public static void quit_command(){
		System.out.println("Quitting SIMPL, goodbye!");
		return;
	}
	
	/**
	 * Prints SIMPL Client recognized commands to the terminal
	 */
	public static void help_command(){
		System.out.println(CmdLine.HELP_MSG);
		return;
	}
	
	/**
	 * The function which loops, accepting user commands (as seen in HELP_MSG) and devoid of any command,
	 * sends the text as a message to it's connected chat buddy
	 */
	private static void user_input_loop(){
		try 
		(
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))
		)
		{
			String userInput;
			/* Here we listen for user input, then take an appropriate action */
			while ((userInput = stdIn.readLine()) != null) 
			{
				String[] words = userInput.split(" ");
				switch (words[0])
				{ 
					case CmdLine.COMMAND_TOKEN_WHO:
						CmdLine.who_command();
						break;
					case CmdLine.COMMAND_TOKEN_GREET:
						if (words.length < 2) 
						{
							System.out.println("Please specify a username.");
							break;
						}
						//check to see if the second token is a valid username
						if (CmdLine.check_user(words[1]))
						{
							System.out.println("Connecting to client: " + words[1]);
						}
						else //otherwise indicate this it is not
						{
							System.out.println("User [" + words[1] + "] is not currently online.");
							break;
						}
						String message;
						if (words.length > 2) //if the client has an additional message to send
						{
							message = Arrays.copyOfRange(words, 2, words.length).toString();
						}
						else //otherwise send a default message
						{
							//TODO: check that CmdLine.client.buddyUsername actually initialized by here
							message = "You have connected to client: " + CmdLine.client.buddyUsername;
						}
						//send the first message to the chat_command, who will ship it off
						CmdLine.greet_command(message);
						CmdLine.client.chatting = true;
						break;
					case CmdLine.COMMAND_TOKEN_LEAVE:
						CmdLine.leave_command();
						break;
					case CmdLine.COMMAND_TOKEN_QUIT:
						CmdLine.quit_command();
						break;
					case CmdLine.COMMAND_TOKEN_HELP:
						CmdLine.help_command();
						break;
					//send message to other client
					default:
						//if currently chatting with another user
						if (CmdLine.client.chatting)
						{
							CmdLine.chat_command(userInput);
						}
						break;
				}	
			}
		} catch (IOException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
	
	public static boolean check_user(String username)
	{
		for( String client : CmdLine.client.getClients() ){
			if (client == username) return true;
		}
		return false;
	}
	
	public static void main(String[] Args){
		try{
			common.Utils.reportCrypto();
			
			if( Args.length != CmdLine.ARG_NUM ){
				System.out.println(common.Constants.INVALID_ARG_NUM);
				System.out.println(CmdLine.USAGE_MSG);
				System.exit(common.Constants.GENERIC_FAILURE);
			}
			
			//parse server name and do validity check
			String serverName = Args[CmdLine.ARG_SERVERNAME_POS];
			if( !common.Utils.isValidIPAddr(serverName) ){
				System.out.println(common.Constants.INVALID_SERVERNAME);
				System.out.println(CmdLine.USAGE_MSG);
				System.exit(common.Constants.GENERIC_FAILURE);
			}
			
			//parse port number and do validity check
			int portNum = Integer.valueOf(Args[CmdLine.ARG_PORTNUM_POS]);
			if( !common.Utils.isValidPort(Args[CmdLine.ARG_PORTNUM_POS])){
				System.out.println(common.Constants.INVALID_PORTNUM);
				System.out.println(CmdLine.USAGE_MSG);
				System.exit(common.Constants.GENERIC_FAILURE);
			}
			
			//parse the path to server public key argument
			PublicKey serverPubK = CmdLine.getPublicKeyFromFile(Args[CmdLine.ARG_SERVERPUBK_POS]);
			
			//create Client instance
			CmdLine.client = new Client(serverPubK);
			
			//create TCP connection (probably shouldn't make the connection here)
			CmdLine.client.serverSocket = new Socket(serverName, portNum);
			CmdLine.client.serverStream = CmdLine.client.serverSocket.getInputStream();
			
			//try connecting
			try{
				CmdLine.client.do_login();
			} catch (Exception e){
				System.err.println(e.getMessage());
				e.printStackTrace();
				System.out.println(CmdLine.LOGIN_FAIL);
				System.exit(common.Constants.GENERIC_FAILURE);
			}
			
			//try discover
			try{
				CmdLine.client.do_discover();
			} catch (Exception e){
				System.err.println(e.getMessage());
				e.printStackTrace();
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
			
			//enter Client listen loop. This should be an indefinite loop
			CmdLine.client.startListenLoop();
			
			//only reason to exit ui loop is quitting SIMPL Client
			System.exit(common.Constants.GENERIC_SUCCESS);
		} catch (IOException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
			return;
		}
	}
}
