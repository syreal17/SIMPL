package protocol.payload;

import java.io.*;

import common.SimplException;

public abstract class Payload implements Serializable {

	private static final long serialVersionUID = 3468462487434824713L;
	
	/**
	 * Simple error-checked call to common.Utils.serialize
	 * @return
	 */
	public byte[] getSerialization(){
		try{
			return common.Utils.serialize(this);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
	
	public abstract void copyFrom(Payload template) throws SimplException;
}
