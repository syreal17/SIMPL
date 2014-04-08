package common;

public class Constants {
	//UI
	public final static int UI_FEEDBACK_FREQ = 8; //higher number is less frequent
	
	//FILESYSTEM
	public final static String USER_DB_NAME = "simpl.user.db";
	public final static String SERVER_PRIVK_NAME = "simpl.server.priv";
	public final static String SERVER_PUBK_NAME = "simpl.server.pub";
	
	//erm..PROGRAMMING
	public final static int GENERIC_SUCCESS = 0;
	public final static int GENERIC_FAILURE = -1;
	public final static int BYTE_MIN = -128;
	public final static int BYTE_MAX_PLUS_1 = 128;
	
	//NETWORKING
	public final static int MIN_PORT = 1;
	public final static int MAX_PORT = 65535;
	//amount of time the Server Socket.read will block until trying again.
	//This is to facilitate the ClientHandlerThreads checking if they have been requested
	public final static int SO_SERVER_TIMEOUT = 200; //ms
	//amount of time the Client Socket.read will wait on Server until processing outgoing packets ??
	public final static int SO_CLIENT_TIMEOUT = 100; //ms (More responsive than the Server)
	public final static int BUDDY_PORT_OFFSET_BASE = 256;
	
	
	//EXCEPTIONS, ERRORS
	public static final String KEY_PAIR_IMBALANCE_MSG = "Only one key in pair exists!";
	public static final String FILE_TOO_LARGE_MSG = "File is too large";
	public static final String NOT_A_FILE_MSG = "Path points to non-regular file (directory, device, etc.)";
	public static final String FILE_UNREADABLE_UNWRITABLE_MSG = "File cannot be read or written!";
	public static final String FILE_UNREADABLE_MSG = "File cannot be Read!";
	public static final String FILE_UNWRITABLE_MSG = "File cannot be written!";
	public final static String USO_EXCPT_MSG = "We have not implemented that yet!";
	public static final String INVALID_CHALLENGE_SIG = "Invalid Server signature on challenge!";
	public static final String INVALID_ARG_NUM = "Invalid number of arguments!";
	public static final String INVALID_SERVERNAME = "Not a valid server name!";
	public static final String INVALID_PORTNUM = "Not a valid port number!";
	public static final String USERNAME_NOT_FOUND_MSG = "That username was not found!";
	
	//CONSTANTS OF FAITH
	public final static int MAX_EXPECTED_PACKET_SIZE = 65536;
	
	//TESTING
	public final static boolean TESTING = true;
	
	//CRYPTO
	public final static boolean CRYPTO_OFF = false;
	public final static String KEY_AGREEMENT_ALGORITHM = "DH";
	public final static int KEY_AGREEMENT_KEY_SIZE = 1024;
	public final static String RNG_ALOGRITHM = "SHA1PRNG";
	public final static String CHALLENGE_HASH_ALGORITHM = "MD5";
	public final static String PASSWORD_HASH_ALGORITHM = "SHA-256";
	public final static String KEY_HASH_ALGORITHM = "SHA-256";
	public final static String SIGNATURE_ALGORITHM = "SHA512withRSA";
	public final static int SIGNATURE_SIZE_BYTES = 64;
	public final static String ASYMMETRIC_CRYPTO_MODE = "RSA";
	public final static int RSA_BITS = 4096;
	public final static String SYMMETRIC_CRYPTO_MODE = "AES";///ECB/PKCS5Padding
	public final static int NONCE_SIZE_BYTES = 16;
}
