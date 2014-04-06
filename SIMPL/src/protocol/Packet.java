package protocol;

import java.io.IOException;
import java.io.Serializable;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.EnumSet;

/* Resources:
 * _ENUMSET_
 * How to set EnumSet flags:
 * 		http://stackoverflow.com/questions/6073347/best-practice-of-using-flags-in-java-method
 */

/**
 * Momma class of all packets. Mandates that packets should implement crypto-interpretation
 * methods, but doesn't define them, since it's different for the session type.
 * @author syreal
 *
 */
public abstract class Packet implements Serializable {

	/**
	 * auto-gen field for Serializable
	 */
	private static final long serialVersionUID = 6380983796997084358L;

	public static enum Flag{
		Login, Discover, Negotiate, Chat, Leave, Logout,	//SIMPL types 	
		Syncronization, Acknowledgement, Finished,			//more typical flags
		Encrypted, Signed,									//cryptography flags
		Ok, Deny											//Login Response
	}
	
	public byte[] crypto_data;
	public EnumSet<Flag> flags;			//will be zeroed out if encrypted
	//private Socket socket;				//shouldn't be a problem to send this in clear
	
	/**
	 * Setting fields to null manually might be redundant in Java
	 */
	public Packet(){
		this.crypto_data = null;
		this.flags = null;
	}
	
	//would like to make ctor from byte[]...
	
	//Prototypes to require child classes to implement crypto-interpretation.
	//Though serializing for encryption/decryption and then socket transportation
	//is an interesting problem. Might just end up decrypting/encrypting in FSM
	abstract public Packet sign(PrivateKey privk);
	abstract public byte[] verify(PublicKey pubk);
	abstract public byte[] decrypt(PrivateKey privk);
	abstract public byte[] encrypt(PublicKey pubk);
	
	/**
	 * Send thineself out to the Server or Buddy
	 * @param sendingSocket which packet should go through
	 */
	public void go(Socket sendingSocket){
		try {
			sendingSocket.getOutputStream().write(this.getSerialization());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public boolean checkForFlags(EnumSet<Flag> flagsToCheckFor){
		return this.flags.contains(flagsToCheckFor);
	}
	
	/**
	 * Simple wrapper to call the common serialization function
	 * @return byte array representation of object
	 * @throws IOException
	 */
	public byte[] getSerialization() throws IOException{
		return common.Utils.serialize(this);
	}
	
	/**
	 * Clear all the fields of the Packet object.
	 * (crypto_data, flags)
	 * @return
	 */
	public void clearAllFields(){
		this.crypto_data = null;
		this.flags = null;
	}
}
