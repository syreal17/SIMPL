package common;

public class Constants {
	//erm..PROGRAMMING
	public final static int GENERIC_SUCCESS = 0;
	public final static int GENERIC_FAILURE = -1;
	
	//NETWORKING
	public final static int MIN_PORT = 1;
	public final static int MAX_PORT = 65535;
	
	//EXCEPTIONS
	public final static String USO_EXCPT_MSG = "We have not implemented that yet!";
	
	//CONSTANTS OF FAITH
	public final static int MAX_EXPECTED_PACKET_SIZE = 65536;
	public final static int NONCE_SIZE_BYTES = 16;
	
	//CRYPTO
	public final static boolean CRYPTO_OFF = true;
	public final static String RNG_ALOGRITHM = "SHA1PRNG";
	public final static String HASH_ALGORITHM = "SHA-256";
	public final static String SIGNATURE_ALGORITHM = "SHA512withRSA";
	public final static int SIGNATURE_SIZE_BYTES = 64; 	//I think the above algo must produce 512 bit sig, but I'm not 
														//positive. I'm not sure how RSA after SHA512 modifies the result!
	public final static String ASYMMETRIC_CRYPTO_MODE = "RSA";
	public final static String SYMMETRIC_CRYPTO_MODE = "AES/CBC/PKCS5Padding";
}
