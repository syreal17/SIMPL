package protocol;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;

import common.Constants;

public class LoginPacket extends ClientServerPreSessionPacket {
	/**
	 * auto-gen
	 */
	private static final long serialVersionUID = -6680306190616418814L;
	
	public static final int R_1_size = 8; //bytes
	public static final int R_2_size = 3; //bytes
	
	//R_1 is in ChallengePayload object
	public byte[] R_1;
	public byte[] R_2;
	
	public ChallengePayload challengePayload;
	public AuthenticationPayload authPayload;					//{username,W_1,N}_Ks

	//Server side, this is the challenge we generate and send
	//Client side, this is where we store the challenge prior to solving it
	//ltj: possibly redundant to this.challengePayload.challengeHash; not an issue to be concerned about, just a note
	public byte[] challenge;
	
	// Cryptographically secure PRNG
	private SecureRandom RNG;
	//Hashing object
	private MessageDigest md;

	public LoginPacket() throws NoSuchAlgorithmException{
		this.challengePayload = new ChallengePayload( null, null );
		this.R_1 = new byte[R_1_size];
		this.R_2 = new byte[R_2_size];
		this.authPayload = new AuthenticationPayload( null, null, null );
		RNG = SecureRandom.getInstance(common.Constants.RNG_ALOGRITHM);
		this.md = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
	}
	
	/**
	 * Generate R_1 and R_2 and store in LoginPacket instance. Should be called Server-side, not Client
	 * @author JaffeTaffy
	 * @return success or failure
	 */
	public void generateRs(){
		//generate PRN R1 using R_1_size bits
		RNG.nextBytes(R_1);
		//generate PRN R2 using R_2_size bits
		RNG.nextBytes(R_2);
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
		}
	}
	
	/**
	 * Brute force R_2 to answer the challenge. Should be called Client-side
	 * @author Jaffe
	 * @return 
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
	 */
	public byte[] readyServerLoginChallenge(PrivateKey privk){
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
	 */
	public void readyClientLoginChallengeResponse(PublicKey pubk, String username, byte[] pwHash, byte[] N){
		//verify that ChallengePayload exists
		if( this.challengePayload == null ){
			throw new UnsupportedOperationException("Challenge Payload must exist before preparing Client response");
		}
		
		/* Punting this to Client.java do_login. Easier to uncrypto and construct ChallengePayload there
		//verify the ChallengePayload
		if( !this.challengePayload.verify(pubk, this.crypto_data) ){
			System.out.println(client.CmdLine.INVALID_CHALLENGE_SIG);
			return;
		}*/
		
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
	 * Clear all fields of LoginPacket object, calls super method also. This should be checked at least once per day
	 * of coding so that unintentional fields aren't being leaked.
	 * (R_1, challengeHash, R_2, challengePayload, authPayload, challenge, RNG, md)
	 * @return success
	 */
	@Override
	public void clearAllFields(){
		super.clearAllFields();
		
		this.challengePayload.R_1 = null;
		this.challengePayload.challengeHash = null;
		
		this.R_2 = null;
		
		this.authPayload.username = null;
		this.authPayload.pwHash = null;
		this.authPayload.N = null;
		
		this.challenge = null;
		this.RNG = null;
		this.md = null;
	}
}
