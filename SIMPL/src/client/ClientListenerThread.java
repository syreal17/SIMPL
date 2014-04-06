/**
 * Listens on the socket for packets
 */

package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientListenerThread implements Runnable {

	Socket buddySocket;
	
	ClientListenerThread(Socket buddySocket)
	{
		this.buddySocket = buddySocket;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		try 
		(
            PrintWriter out = new PrintWriter(this.buddySocket.getOutputStream(), true);
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))
		)
		{
			String userInput;
			/* Here we listen for user input, then take an appropriate action */
			while ((userInput = stdIn.readLine()) != null) 
			{
				switch (userInput)
				{
					case client.CmdLine.COMMAND_TOKEN_WHO:
						CmdLine.who_command();
						break;
					case client.CmdLine.COMMAND_TOKEN_CHAT:
						CmdLine.chat_command();
						break;
					case client.CmdLine.COMMAND_TOKEN_LEAVE:
						CmdLine.leave_command();
						break;
					case client.CmdLine.COMMAND_TOKEN_QUIT:
						CmdLine.quit_command();
						break;
					case client.CmdLine.COMMAND_TOKEN_HELP:
						CmdLine.help_command();
						break;
					//send message to other client
					default:
						out.println(userInput);
						break;
				}	
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
