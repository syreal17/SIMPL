package server;

import java.security.*;

public class CmdLine {
	
	public static final String USAGE_MSG = "Usage: java server.CmdLine <port> <path to user db> " +
			"<path to private key>\n" +
			"'path to user db': point to valid '"+common.Constants.USER_DB_NAME+"' otherwise, one will be created\n" +
			"'path to private key': point to valid '"+common.Constants.SERVER_PRIVK_NAME+"' otherwise, one will be created";
	public static final int ARG_NUM = 3;
	public static final int ARG_PORTNUM_POS = 0;
	public static final int ARG_USERDB_POS = 1;
	public static final int ARG_SERVERPRIVK_POS = 2;
	
	public static Server server;
	
	private static PrivateKey getPrivateKeyFromFile(String filename){
		if( common.Constants.CRYPTO_OFF ){
			return null;
		} else { 
			throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
		}
	}
	
	public static void main(String[] Args){

		if( Args.length != CmdLine.ARG_NUM ){
			System.out.println(common.Constants.INVALID_ARG_NUM);
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
		
		//TODO: check validity of path
		String userDBFilename = Args[CmdLine.ARG_USERDB_POS];
		
		//parse the private key
		PrivateKey serverPrivK = CmdLine.getPrivateKeyFromFile(Args[CmdLine.ARG_SERVERPRIVK_POS]);
		
		//create Server instance and start it
		CmdLine.server = new Server(portNum, userDBFilename, serverPrivK);
		CmdLine.server.start_listener_loop();
	}
}
