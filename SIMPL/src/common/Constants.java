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
	public final static int MAX_EXPECT_PACKET_SIZE = 65536;
	public final static int NONCE_SIZE_BYTES = 16;
	
	//CRYPTO
	public final static String HASH_ALGORITHM = "SHA-256";
	public final static String SIGNATURE_ALGORITHM = "SHA512withRSA";
	public final static String ASYMMETRIC_CRYPTO_MODE = "RSA";
	public final static String SYMMETRIC_CRYPTO_MODE = "AES/CBC/PKCS5Padding";
}
