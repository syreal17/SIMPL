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
	public byte[] makeChallenge(byte[] R1, byte[] R2) {
		byte[] puzzle = new byte[11];
		//concatenate the byte arrays
		System.arraycopy(R1,0,puzzle,0,R1.length);
		System.arraycopy(R2,0,puzzle,R1.length,R2.length);
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
	public byte[] solveChallenge(byte[] puzzle, byte[] R1) {
		//byte array contains hash attempt
		byte[] attempt = new byte[11];
		//loop through all possible values of R2
		for (int R2 = 0; R2 < (1 << 24); R2++){
			//get the byte array form of the numbers
			byte[] B2 = ByteBuffer.allocate(3).putInt(R2).array();
			//concatenate the byte arrays
			System.arraycopy(R1,0,attempt,0,R1.length);
			System.arraycopy(B2,0,attempt,R1.length,B2.length);
			//update message digest with byte array
			md.update(attempt);
			//make the hash, check if it matches the puzzle
	        if (Arrays.equals(md.digest(), puzzle))
	        {
	        	return B2;
	        }
		}
		//Failure! Didn't find R2...
		return null;
	}

}


