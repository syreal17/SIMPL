package protocol;

import java.security.*;
import java.util.*;
//This is the package that I made... I don't know how to import it!
//I also don't know if it should exist at all
import crypto.Hash;


public class LoginPacket extends ClientServerPreSessionPacket {
	public static final int R_1_size = 64; //bits
	public static final int R_2_size = 16; //bits (too short! but makes it easy)
	
	//ltj: these almost certainly won't be longs by the end of the project
	//maybe BigInt of 64 bits and 20 bits or something
	//R_1 is in ChallengePayload object
	private long R_1; //the big tricksy number		
	private short R_2;  //the smaller, crackable number	
	
	private ChallengePayload challengePayload;
	private AuthenticationPayload authPayload;					//{username,W_1,N}_Ks

	//Server side, this is the challenge we generate and send
	//Client side, this is where we store the challenge prior to solving it
	byte[] challenge;
	
	//our hashing machine
	private Hash hash;
	private SecureRandom RNG;

	public LoginPacket() throws NoSuchAlgorithmException{
		this.challengePayload = new ChallengePayload((Long) null, (byte[]) null);
		this.R_2 = (Short) null;
		this.authPayload = new AuthenticationPayload((String) null, (byte[]) null, (Long) null);
		this.hash = new Hash();
		RNG = new SecureRandom();
	}
	
	/**
	 * Generate R_1 and R_2 and store in LoginPacket instance. Should be called Server-side, not Client
	 * @author JaffeTaffy
	 * @return success or failure
	 */
	public void generateRs(){
		//generate PRN R1 using R_1_size bits
		R_1 = RNG.next(R_1_size);	//ltj: find the API that provides this behind the scenes
		//generate PRN R2 using R_2_size bits
		R_2 = RNG.next(R_2_size); //ltj: this is somewhat problematic. Converting from int to short might
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
		challenge = hash.makeChallenge(R_1, R_2);
		//TODO: think about specifying the MessageDigest type string in common package somewhere
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Brute force R_2 to answer the challenge. Should be called Client-side
	 * @author syreal
	 * @return success or failure
	 */
	public void findR_2(){
		//use the hash class to solve the challenge 
		//by feeding it the challenge and R1
		R_2 = hash.solveChallenge(challenge, R_1);
		throw new UnsupportedOperationException(common.Constants.USO_EXCPT_MSG);
	}
	
	/**
	 * Set flags for the initial Login message that the Client sends
	 */
	public void setClientLoginRequestFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Syncronization);
	}
	
	/**
	 * Set flags for the Server's challenge request to the Client
	 */
	public void setServerLoginChallengeFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Syncronization, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Set flags for the Client's challenge response to the Server
	 */
	public void setClientLoginChallengeResponseFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Acknowledgement);
	}
	
	/**
	 * Set flags for Server to accept Client login
	 */
	public void setServerLoginOkFlags(){
		this.flags = EnumSet.of(Packet.Flag.Login, Packet.Flag.Ok);
	}
	
	/**
	 * Set flags for Server to deny Client login
	 */
	public void setServerLoginDenyFlags(){
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
	public long readyServerLoginChallenge(PrivateKey privk){
		//generate the R's
		this.generateRs();
		
		//remember R_2 for the future. Fields are cleared later
		long R_2 = this.R_2;
		
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
	public void readyClientLoginChallengeResponse(PublicKey pubk, String username, byte[] pwHash, long N){
		//verify that ChallengePayload exists
		if( this.challengePayload == null ){
			throw new UnsupportedOperationException("Challenge Payload must exist before preparing Client response");
		}
		
		//verify the ChallengePayload
		if( !this.challengePayload.verify(pubk) ){
			System.out.println(client.CmdLine.INVALID_CHALLENGE_SIG);
			return;
		}
		
		//find R_2, given a ChallengePayload
		this.findR_2();
		
		//remember R_2, so we can zero out fields later, and refill out R_2
		short R_2 = this.R_2;
		
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
		
		this.challengePayload.R_1 = (Long) null;
		this.challengePayload.challengeHash = (byte[]) null;
		
		this.R_2 = (Short) null;
		
		this.authPayload.username = (String) null;
		this.authPayload.pwHash = (byte[]) null;
		this.authPayload.N = (Long) null;
	}
}
