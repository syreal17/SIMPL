package common;

import java.net.InetAddress;

public class Utils {
	
	/**
	 * Check is argument is a valid domain name or ip address string
	 * @param arg string to check
	 * @return true or false
	 */
	public static boolean isValidIPAddr(String arg){
		try{
			InetAddress.getByName(arg);
			return true;
		} catch (Exception e){
			return false;
		}
	}
	
	/**
	 * Check if argument is a valid port number
	 * @param arg argument to check
	 * @return true or false
	 */
	public static boolean isValidPort(String arg){
		try{
			int port = Integer.parseInt(arg);
			if ( port >= Constants.MIN_PORT && port <= Constants.MAX_PORT){
				return true;
			} else {
				return false;
			}
		} catch (Exception e){
			return false;
		}
	}
}
