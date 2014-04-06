package server;

import java.io.Serializable;

public class UserDBEntry implements Serializable {

	private static final long serialVersionUID = 3345995632362053636L;
	
	private String username;
	private byte[] pwHash;
	
	public UserDBEntry(String username, byte[] pwHash){
		this.username = username;
		this.pwHash = pwHash;
	}
	
	public String getUsername(){
		return this.username;
	}
	
	public byte[] getPwHash(){
		return this.pwHash;
	}
}
