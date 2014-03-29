package crypto;

import java.util.Arrays;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

//This class will do all of our hashing-related activities... does that make sense?
//I gave it some extra power! It has a lot of knowledge...
public class Hash {
	//We can change this to a different algo
	private final String HASH_ALGO = "SHA-256";
	MessageDigest md;
	//Also, we can do different hash algorithms for different parts
	//if we need to... in which case we would update in functions
	//instead of in the constructor
	public Hash() throws NoSuchAlgorithmException
	{
		try
		{
			this.md = MessageDigest.getInstance(HASH_ALGO);
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * Take R1, R2 -> make the hash
	 * @author JaffeTaffy
	 * @return challenge in byte array form
	 */
	public byte[] makeChallenge(long R1, short R2) {
		byte[] puzzle = new byte[10];
		//get the byte array form of the numbers
		byte[] B1 = ByteBuffer.allocate(8).putLong(R1).array();
		byte[] B2 = ByteBuffer.allocate(2).putShort(R2).array();
		//concatenate the byte arrays
		System.arraycopy(B1,0,puzzle,0,B1.length);
		System.arraycopy(B2,0,puzzle,B1.length,B2.length);
		//update message digest with byte array
		md.update(puzzle);
		//make the hash and return it
        return md.digest();
	}

	/**
	 * Take the puzzle and R1, find R2
	 * @author JaffeTaffy
	 * @return R2
	 */
	public short solveChallenge(byte[] puzzle, long R1) {
		//byte array contains hash attempt
		byte[] attempt = new byte[10];
		//loop through all possible values of R2
		for (short R2 = 0; R2 < (1 << 16); R2++){
			//get the byte array form of the numbers
			byte[] B1 = ByteBuffer.allocate(8).putLong(R1).array();
			byte[] B2 = ByteBuffer.allocate(2).putShort(R2).array();
			//concatenate the byte arrays
			System.arraycopy(B1,0,attempt,0,B1.length);
			System.arraycopy(B2,0,attempt,B1.length,B2.length);
			//update message digest with byte array
			md.update(attempt);
			//make the hash, check if it matches the puzzle
	        if (Arrays.equals(md.digest(), puzzle))
	        {
	        	return R2;
	        }
		}
		//Failure! Didn't find R2...
		return 0;
	}

}


