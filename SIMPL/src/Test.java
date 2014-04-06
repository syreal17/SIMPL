import java.util.Arrays;


public class Test {
	public static void main(String[] Args){
		Byte[] iByteArr = { 0x00, 0x00, 0x00 };
		Byte[] maxByteArr = { Byte.MAX_VALUE, Byte.MAX_VALUE, Byte.MAX_VALUE };
		
		while(!Arrays.equals(iByteArr, maxByteArr)){
			printByteArr(iByteArr);
			incrementByteArray(iByteArr);
		}
	}
	
	public static void incrementByteArray(Byte[] byteArr){
		for( int i = 0; i < byteArr.length; i++){
			if( byteArr[i] < Byte.MAX_VALUE ){
				Byte oldByte = byteArr[i];
				Byte newByte = (byte) (oldByte+1);
				byteArr[i] = newByte;
				return;
			}
		}
	}
	
	public static void printByteArr(Byte[] byteArr){
		for( int i = 0; i < byteArr.length; i++){
			System.out.print(byteArr[i] + " ");
		}
		System.out.println();
	}
}
