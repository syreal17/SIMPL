/**
 * The listener for user input
 */

package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

public class UserInputThread implements Runnable {

	Socket buddySocket;
	
	UserInputThread(Socket buddySocket)
	{
		this.buddySocket = buddySocket;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		try 
		(
            BufferedReader in = new BufferedReader(new InputStreamReader(buddySocket.getInputStream()));
        ) 
		{
			String buffer1 = "tmp";
			String buffer2 = "tmp";
			while (true)
			{
				if ((buffer2 = in.readLine()) != buffer1)
				{
					System.out.println(buffer2);
					buffer1 = buffer2;
				}
			}
        } 
		catch (IOException e) 
		{
            e.printStackTrace();
        }
	}

}
