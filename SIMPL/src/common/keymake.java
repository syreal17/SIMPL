package common;

import java.io.*;
import java.security.*;

public class keymake
{
	private static boolean generated = false;
	private static PrivateKey privateKey = null;
	private static PublicKey publicKey = null;
	
    private static void generatePair() throws UnsupportedOperationException {
		try
		{
			if( !keymake.generated ){
				KeyPairGenerator kg = KeyPairGenerator.getInstance(Constants.ASYMMETRIC_CRYPTO_MODE);
				kg.initialize(Constants.RSA_BITS);
				KeyPair pair = kg.generateKeyPair();
				keymake.privateKey = pair.getPrivate();
				keymake.publicKey = pair.getPublic();
				
				keymake.generated = true;
				
				/*Not writing the keys out in generateMethod
				String fl = args[0];
				FileOutputStream out1 = new FileOutputStream(fl);
				byte[] ky1 = priKey.getEncoded();
				out1.write(ky1);
				out1.close();
				*/
			} else {
				throw new UnsupportedOperationException();
			}
		}
		catch(NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
	}
    
    public static void writePublicKey(String path){
    	try{
			FileOutputStream fos = new FileOutputStream(path);
			byte[] publicKeyBytes = keymake.publicKey.getEncoded();
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
    
    public static void writePrivateKey(String path){
    	
    }
    
    public static PublicKey getPublicKey(){
    	keymake.ensureGeneration();
    	return keymake.publicKey;
    }
    
    public static PrivateKey getPrivateKey(){
    	keymake.ensureGeneration();
    	return keymake.privateKey;
    }
    
    /**
     * uses isGenerated and checkSanity to generate pair if it has not already been generated.
     */
    private static void ensureGeneration(){
    	if( keymake.isGenerated() ){
    		return;
    	} else {
    		keymake.generatePair();
    	}
    }
    
    /**
     * are the keys generated already?
     * @return
     */
    private static boolean isGenerated(){
    	if( checkSanity() ){
    		return keymake.generated;
    	} else {
    		return false;
    	}
    }
    
    /**
     * Ensures that nothing crazy happens like only one key existing and the other not
     */
    private static boolean checkSanity(){
    	if( (keymake.privateKey == null && keymake.publicKey != null) ||
    			keymake.privateKey != null && keymake.publicKey == null){
    		throw new UnsupportedOperationException(Constants.KEY_PAIR_IMBALANCE_MSG);
    	}
    	
    	return true;
    }
}