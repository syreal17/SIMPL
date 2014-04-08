///**
// * Listens on the socket for packets
// */
//
//package client;
//
//import java.io.BufferedReader;
//import java.io.IOException;
//import java.io.InputStreamReader;
//import java.net.Socket;
//import java.util.Arrays;
//
//public class UserInputThread implements Runnable {
//
//	Socket buddySocket;
//	String username;
//	boolean chatting;
//	
//	UserInputThread(String username)
//	{
//		this.username = username;
//		this.chatting = false;
//	}
//	
//	@Override
//	public void run() {
//		try 
//		(
//            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))
//		)
//		{
//			String userInput;
//			/* Here we listen for user input, then take an appropriate action */
//			while ((userInput = stdIn.readLine()) != null) 
//			{
//				String[] words = userInput.split(" ");
//				switch (words[0])
//				{ 
//					case client.CmdLine.COMMAND_TOKEN_WHO:
//						CmdLine.who_command();
//						break;
//					case client.CmdLine.COMMAND_TOKEN_GREET:
//						if (words.length < 2) 
//						{
//							System.out.println("Please specify a username.");
//							break;
//						}
//						//check to see if the second token is a valid username
//						if (CmdLine.check_user(words[1]))
//						{
//							System.out.println("Connecting to client: " + words[1]);
//						}
//						else //otherwise indicate this it is not
//						{
//							System.out.println("User [" + words[1] + "] is not currently online.");
//							break;
//						}
//						String message;
//						if (words.length > 2) //if the client has an additional message to send
//						{
//							message = Arrays.copyOfRange(words, 2, words.length).toString();
//						}
//						else //otherwise send a default message
//						{
//							message = "You have connected to client: " + this.username;
//						}
//						//send the first message to the chat_command, who will ship it off
//						CmdLine.greet_command(message);
//						this.chatting = true;
//						break;
//					case client.CmdLine.COMMAND_TOKEN_LEAVE:
//						CmdLine.leave_command();
//						break;
//					case client.CmdLine.COMMAND_TOKEN_QUIT:
//						CmdLine.quit_command();
//						break;
//					case client.CmdLine.COMMAND_TOKEN_HELP:
//						CmdLine.help_command();
//						break;
//					//send message to other client
//					default:
//						//if currently chatting with another user
//						if (this.chatting)
//						{
//							CmdLine.chat_command(userInput);
//						}
//						break;
//				}	
//			}
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//	}
//
//}
