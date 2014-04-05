package protocol;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import common.Constants;

public class LoginPacket extends ClientServerPreSessionPacket {
	public static final int R_1_size = 8; //bytes
	public static final int R_2_size = 3; //bytes
	
	//R_1 is in ChallengePayload object
	public byte[] R_1;
	public byte[] R_2;
	
	public ChallengePayload challengePayload;
	public AuthenticationPayload authPayload;					//{username,W_1,N}_Ks

	//Server side, this is the challenge we generate and send
	//Client side, this is where we store the challenge prior to solving it
	public byte[] challenge;
	
	// Cryptographically secure PRNG
	private SecureRandom RNG;
	//Hashing object
	MessageDigest md;

	public LoginPacket() throws NoSuchAlgorithmException{
		this.challengePayload = new ChallengePayload( null, null);
		this.R_1 = new byte[R_1_size];
		this.R_2 = new byte[R_2_size];
		this.authPayload = new AuthenticationPayload((String) null, null, null);
		RNG = new SecureRandom();
		this.md = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
	}
	
	/**
	 * Generate R_1 and R_2 and store in LoginPacket instance. Should be called Server-side, not Client
	 * @author JaffeTaffy
	 * @return success or failure
	 */
	public void generateRs(){
		//generate PRN R1 using R_1_size bits
		RNG.nextBytes(R_1);	//ltj: find the API that provides this behind the scenes
		//generate PRN R2 using R_2_size bits
		RNG.nextBytes(R_2); //ltj: this is somewhat problematic. Converting from int to short might
									//lose precision
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Create MessageDigest from R_1 and R_2 and store in LoginPacket instance. Should be called Server-side, 
	 * not Client
	 * @author JaffeTaffy
	 * @return success or failure
	 */
	public void generateChallengeHash(){
		if (Constants.CRYPTO_OFF)
		{
			byte[] concat = new byte[R_1_size + R_2_size];
			System.arraycopy(R_1,0,concat,0,R_1.length);
			System.arraycopy(R_2,0,concat,R_1.length,R_2.length);
			challenge = concat;
		}
		else
		{
			byte[] puzzle = new byte[R_1_size + R_2_size];
			//concatenate the byte arrays
			System.arraycopy(R_1,0,puzzle,0,R_1.length);
			System.arraycopy(R_2,0,puzzle,R_1.length,R_2.length);
			//update message digest with byte array
			md.update(puzzle);
			//make the hash and return it
	        challenge = md.digest();
			//TODO: think about specifying the MessageDigest type string in common package somewhere
			throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
		}
	}
	
	/**
	 * Brute force R_2 to answer the challenge. Should be called Client-side
	 * @author syreal
	 * @return success or failure
	 */
	public void findR_2(){
		if (Constants.CRYPTO_OFF)
		{
			R_2 = null;
		}
		else
		{
			//use the hash class to solve the challenge 
			//by feeding it the challenge and R1
			byte[] attempt = new byte[R_1_size + R_2_size];
			//loop through all possible values of R2
			for (int R2 = 0; R2 < (1 << 24); R2++){
				//get the byte array form of the numbers
				byte[] B2 = ByteBuffer.allocate(3).putInt(R2).array();
				//concatenate the byte arrays
				System.arraycopy(R_1,0,attempt,0,R_1.length);
				System.arraycopy(B2,0,attempt,R_1.length,B2.length);
				//update message digest with byte array
				md.update(attempt);
				//make the hash, check if it matches the puzzle
		        if (Arrays.equals(md.digest(), challenge))
		        {
		        	R_2 = B2;
		        }
			}
		}
	}
	
	/**
	 * Set flags for the initial Login message that the Client sends
	 */
	private void setClientLoginRequestFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Syncronization);
	}
	
	/**
	 * Set flags for the Server's challenge request to the Client
	 */
	private void setServerLoginChallengeFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Syncronization, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Set flags for the Client's challenge response to the Server
	 */
	private void setClientLoginChallengeResponseFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Set flags for Server to accept Client login
	 */
	private void setServerLoginOkFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Ok);
	}
	
	/**
	 * Set flags for Server to deny Client login
	 */
	private void setServerLoginDenyFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Deny);
	}
	
	/**
	 * Resets and makes the packet ready to be used as a Client Login request.
	 * @return success
	 */
	public void readyClientLoginRequest(){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Client Login request
		this.setClientLoginRequestFlags();
	}
	
	/**
	 * Readies the Login packet to be a Server Login challenge packet
	 * @param privk private key of the Server
	 * @throws IOException 
	 * @throws SignatureException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public byte[] readyServerLoginChallenge(PrivateKey privk) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException{
		//generate the R's
		this.generateRs();
		
		//remember R_2 for the future. Fields are cleared later
		byte[] R_2 = this.R_2;
		
		//generate the challenge hash
		this.generateChallengeHash();
		
		//calculate main payload: sign the ChallengePayload
		byte[] signed_data = this.challengePayload.sign(privk);
		
		//reset the packet (we don't want to send object with all filled out fields, just the ChallengePayload
		this.clearAllFields();
		
		//set the flags appropriately
		this.setServerLoginChallengeFlags();
		
		//copy the signed data into a packet field
		this.crypto_data = Arrays.copyOf(signed_data, signed_data.length);
		
		//return the value for R_2 that the server should remember
		return R_2;
	}
	
	/**
	 * Readies the Login packet to be a Client response to a Server challenge
	 * @param pubk public key of the Server
	 * ASSUMPTIONS: LoginPacket has ChallengeResponse, but no R_2.
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 */
	public void readyClientLoginChallengeResponse(PublicKey pubk, String username, byte[] pwHash, byte[] N) throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		//verify that ChallengePayload exists
		try {
			if( this.challengePayload == null ){
				throw new UnsupportedOperationException("Challenge Payload must exist before preparing Client response");
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//verify the ChallengePayload
		if( !this.challengePayload.verify(pubk, this.crypto_data) ){
			System.out.println(client.CmdLine.INVALID_CHALLENGE_SIG);
			return;
		}
		
		//find R_2, given a ChallengePayload
		this.findR_2();
		
		//remember R_2, so we can zero out fields later, and refill out R_2
		byte[] R_2 = this.R_2;
		
		//build authPayload so it can be encrypted
		this.authPayload = new AuthenticationPayload(username, pwHash, N);
		
		//encrypt it
		byte[] encrypted_data = this.authPayload.encrypt(pubk);
		
		//reset the packet (we don't want to send object with all filled out fields)
		this.clearAllFields();
		
		//set flags
		this.setClientLoginChallengeResponseFlags();
		
		//stuff encrypted data into crypto data packet field
		this.crypto_data = Arrays.copyOf(encrypted_data, encrypted_data.length);
		
		//set R_2 to what the Client found it to be
		this.R_2 = R_2;
	}
	
	/**
	 * Readies the LoginPacket to be a Server Login OK response to Client
	 */
	public void readyServerLoginOk(){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Client Login request
		this.setServerLoginOkFlags();
	}
	
	/**
	 * Readies the LoginPacket to be a Server Login Deny response to Client
	 */
	public void readyServerLoginDeny(){
		//reset the packet
		this.clearAllFields();
		
		//prepare it as a Client Login request
		this.setServerLoginDenyFlags();
	}
	
	/**
	 * Clear all fields of LoginPacket object, calls super method also
	 * (R_1, R_2, challengeHash, authPayload, challengePayload)
	 * @return success
	 */
	@Override
	public void clearAllFields(){
		super.clearAllFields();
		
		this.challengePayload.R_1 = null;
		this.challengePayload.challengeHash = (byte[]) null;
		
		this.R_2 = (byte[]) null;
		
		this.authPayload.username = (String) null;
		this.authPayload.pwHash = null;
		this.authPayload.N = null;
	}
}
