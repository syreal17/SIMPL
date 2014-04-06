package common;

import java.io.*;
import java.net.*;

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
	
	/**
	 * Convert a generic object to a byte array
	 * @param obj object to serialize to a byte array
	 * @return array of bytes representing object
	 * @throws IOException
	 */
	public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(obj);
        return b.toByteArray();
    }
	
	/**
	 * Convert a byte array to an Object
	 * @param bytes to convert
	 * @return Object
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	public static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream b = new ByteArrayInputStream(bytes);
        ObjectInputStream o = new ObjectInputStream(b);
        return o.readObject();
    }
	
	public static void print_debug_msg(String msg){
		if( common.Constants.TESTING ){
			System.out.println(msg);
		}
	}
	
	public static void incrementByteArray(Byte[] byteArr){
		for( int i = 0; i < byteArr.length; i++){
			if( byteArr[i] < Byte.MAX_VALUE ){
				Byte oldByte = byteArr[i];
				Byte newByte = (byte) (oldByte+1);
				byteArr[i] = newByte;
				return;
			}
		}
	}
	
	public static void printByteArr(byte[] byteArr){
		for( int i = 0; i < byteArr.length; i++){
			System.out.print(byteArr[i] + " ");
		}
		System.out.println();
	}
	
	public static void reportCrypto(){
		if( Constants.CRYPTO_OFF ){
			System.out.println("Crypto is off!");
		} else {
			System.out.println("Crypto is on!");
		}
	}
}
