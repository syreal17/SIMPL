package common;

import java.io.*;
import java.security.*;

public class Keymake
{
	private static boolean generated = false;
	private static PrivateKey privateKey = null;
	private static PublicKey publicKey = null;
	
    private static void generatePair() throws UnsupportedOperationException {
		try
		{
			if( !Keymake.generated ){
				KeyPairGenerator kg = KeyPairGenerator.getInstance(Constants.ASYMMETRIC_CRYPTO_MODE);
				kg.initialize(Constants.RSA_BITS);
				KeyPair pair = kg.generateKeyPair();
				Keymake.privateKey = pair.getPrivate();
				Keymake.publicKey = pair.getPublic();
				
				Keymake.generated = true;
			} else {
				throw new UnsupportedOperationException();
			}
		}
		catch(NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
	}
    
    public static void writePublicKey(File publicKeyFile){
    	try{
    		Keymake.ensureGeneration();
			FileOutputStream fos = new FileOutputStream(publicKeyFile);
			byte[] publicKeyBytes = Keymake.publicKey.getEncoded();
			fos.write(publicKeyBytes);
			fos.close();
    	} catch (FileNotFoundException e){
    		System.err.println(e.getMessage());
    		e.printStackTrace();
    		return;
    	} catch (IOException e){
    		System.err.println(e.getMessage());
    		e.printStackTrace();
    		return;
    	}
    }
    
    public static void writePrivateKey(File privateKeyFile){
    	try{
    		Keymake.ensureGeneration();
			FileOutputStream fos = new FileOutputStream(privateKeyFile);
			byte[] privateKeyBytes = Keymake.privateKey.getEncoded();
			fos.write(privateKeyBytes);
			fos.close();
    	} catch (FileNotFoundException e){
    		System.err.println(e.getMessage());
    		e.printStackTrace();
    		return;
    	} catch (IOException e){
    		System.err.println(e.getMessage());
    		e.printStackTrace();
    		return;
    	}
    }
    
    public static PublicKey getPublicKey(){
    	Keymake.ensureGeneration();
    	return Keymake.publicKey;
    }
    
    public static PrivateKey getPrivateKey(){
    	Keymake.ensureGeneration();
    	return Keymake.privateKey;
    }
    
    /**
     * uses isGenerated and checkSanity to generate pair if it has not already been generated.
     */
    private static void ensureGeneration(){
    	if( Keymake.isGenerated() ){
    		return;
    	} else {
    		Keymake.generatePair();
    	}
    }
    
    /**
     * are the keys generated already?
     * @return
     */
    private static boolean isGenerated(){
    	if( checkSanity() ){
    		return Keymake.generated;
    	} else {
    		return false;
    	}
    }
    
    /**
     * Ensures that nothing crazy happens like only one key existing and the other not
     */
    private static boolean checkSanity(){
    	if( (Keymake.privateKey == null && Keymake.publicKey != null) ||
    			Keymake.privateKey != null && Keymake.publicKey == null){
    		throw new UnsupportedOperationException(Constants.KEY_PAIR_IMBALANCE_MSG);
    	}
    	
    	return true;
    }
}