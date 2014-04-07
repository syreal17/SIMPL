package protocol.packet;

import java.security.*;
import java.util.*;

import protocol.payload.AuthenticationPayload;
import protocol.payload.ChallengePayload;

import common.Constants;

public class LoginPacket extends Packet {

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
	public byte[] signature;
	
	// Cryptographically secure PRNG
	private SecureRandom RNG;
	//Hashing object
	private MessageDigest md;

	//TODO: null inits necessary?
	public LoginPacket() {
		try{
			this.challengePayload = new ChallengePayload( null, null );
			this.R_1 = new byte[R_1_size];
			this.R_2 = new byte[R_2_size];
			this.authPayload = new AuthenticationPayload( null, null, null );
			RNG = SecureRandom.getInstance(common.Constants.RNG_ALOGRITHM);
			this.md = MessageDigest.getInstance(Constants.CHALLENGE_HASH_ALGORITHM);
		} catch (NoSuchAlgorithmException e){
			e.printStackTrace();
		}
	}
	
	/**
	 * Generate R_1 and R_2 and store in LoginPacket instance. Should be called Server-side, not Client
	 * @author JaffeTaffy
	 * @return success or failure
	 */
	public void generateRs(){
		//generate PRN R1 using R_1_size bits
		RNG.nextBytes(R_1);
		//common.Utils.printByteArr(R_1);
		//generate PRN R2 using R_2_size bits
		RNG.nextBytes(R_2);
		//common.Utils.printByteArr(R_2);
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
			//challenge = concat; //ltj:seeing if using ChallengePayload is easiest way for me vvv
			this.challengePayload.challengeHash = concat;
		}
		else
		{
			//update message digest with R_1 and R_2
			md.reset();
			md.update(R_1);
			md.update(R_2);
	        //challenge = md.digest(); //ltj:seeing if using ChallengePayload is easiest way for me vvv
			this.challengePayload.challengeHash = md.digest();
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
			//if crypto is off, simply copy out R_1 and R_2
			System.arraycopy(this.challengePayload.challengeHash, 0, this.R_1, 0, LoginPacket.R_1_size);
			System.arraycopy(this.challengePayload.challengeHash, LoginPacket.R_1_size, this.R_2, 0, LoginPacket.R_2_size);
		}
		else
		{
			//common.Utils.printByteArr(R_1);
			System.out.println("Finding R");

			//use the hash class to solve the challenge 
			//by feeding it the challenge and R1
			//loop through all possible values of R2
			for (int i = Byte.MIN_VALUE; i <= Byte.MAX_VALUE; i++){
				if( i % common.Constants.UI_FEEDBACK_FREQ == 0){
					System.out.print(".");
				}
				for (int j = Byte.MIN_VALUE; j <= Byte.MAX_VALUE; j++){
					for (int k = Byte.MIN_VALUE; k <= Byte.MAX_VALUE; k++){
						//get the byte array form of the numbers
						byte[] B2 = new byte[3];
						B2[0] = (byte) i;
						B2[1] = (byte) j;
						B2[2] = (byte) k;
						//update message digest with byte array
						md.reset();
						md.update(R_1);
						md.update(B2);
						//System.out.println(i);
						//make the hash, check if it matches the puzzle
				        if (Arrays.equals(md.digest(), this.challengePayload.challengeHash))
				        {
				        	R_2 = B2;
				    		//common.Utils.printByteArr(R_2);
				    		break;
				        }
					}
				}
			}
			System.out.println();
		}
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
		
		//reset the packet (we don't want to send object with all filled out fields, just the ChallengePayload
		this.challengePayload.R_1 = null;
		
		this.R_2 = null;
		
		this.authPayload.username = null;
		this.authPayload.pwHash = null;
		this.authPayload.N = null;
		
		this.RNG = null;
		this.md = null;
		
		//set the flags appropriately
		this.setServerLoginChallengeFlags();
		
		//calculate the signature
		this.signature = this.challengePayload.sign(privk);
		
		//return the value for R_2 that the server should remember
		return R_2;
	}
	
	/**
	 * Readies the Login packet to be a Client response to a Server challenge
	 * @param pubk public key of the Server
	 * ASSUMPTIONS: LoginPacket has ChallengeResponse, but no R_2. 
	 */
	public byte[] readyClientLoginChallengeResponse(PublicKey pubk, String username, byte[] pwHash, byte[] N){
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
		byte[] sessionKey = this.authPayload.keyMake();
		//common.Utils.printByteArr(this.authPayload.getSerialization());
		System.out.println();
		//encrypt it
		byte[] encrypted_data = this.authPayload.encrypt(pubk);
		//common.Utils.printByteArr(encrypted_data);
		System.out.println();
		//reset the packet (we don't want to send object with all filled out fields)
		this.clearAllFields();
		
		//set flags
		this.setClientLoginChallengeResponseFlags();
		
		//stuff encrypted data into crypto data packet field
		this.crypto_data = encrypted_data;
		
		//set R_2 to what the Client found it to be
		this.R_2 = R_2;
		
		//return the sessionKey to the client
		return sessionKey;
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
		
		this.RNG = null;
		this.md = null;
	}
	
	/**
	 * Set flags for the initial Login message that the Client sends
	 */
	private void setClientLoginRequestFlags(){
		this.flags = LoginPacket.getClientLoginRequestFlags();
	}
	
	public static EnumSet<Flag> getClientLoginRequestFlags(){
		return EnumSet.of(Packet.Flag.Login, Packet.Flag.Syncronization);
	}
	
	/**
	 * Set flags for the Server's challenge request to the Client
	 */
	private void setServerLoginChallengeFlags(){
		this.flags = LoginPacket.getServerLoginChallengeFlags();
	}
	
	public static EnumSet<Flag> getServerLoginChallengeFlags(){
		return EnumSet.of(Packet.Flag.Login, Packet.Flag.Syncronization, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Set flags for the Client's challenge response to the Server
	 */
	private void setClientLoginChallengeResponseFlags(){
		this.flags = LoginPacket.getClientLoginChallengeResponseFlags();
	}
	
	public static EnumSet<Flag> getClientLoginChallengeResponseFlags(){
		return EnumSet.of(Packet.Flag.Login, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Set flags for Server to accept Client login
	 */
	private void setServerLoginOkFlags(){
		this.flags = LoginPacket.getServerLoginOkFlags();
	}
	
	public static EnumSet<Flag> getServerLoginOkFlags(){
		return EnumSet.of(Packet.Flag.Login, Packet.Flag.Ok);
	}
	
	/**
	 * Set flags for Server to deny Client login
	 */
	private void setServerLoginDenyFlags(){
		this.flags = LoginPacket.getServerLoginDenyFlags();
	}
	
	public static EnumSet<Flag> getServerLoginDenyFlags(){
		return EnumSet.of(Packet.Flag.Login, Packet.Flag.Deny);
	}
}
