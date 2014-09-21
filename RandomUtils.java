import javax.crypto.spec.*;
import javax.crypto.*;
import java.security.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class RandomUtils {
	// Uses PBKDF2 to derive a longer key of length desiredLength from the master key shortKey
	// Note: desiredLength must be divisible by the master key's length.
	public static byte[] keyDerivation(byte[] shortKey, int iterations, byte[] salt, int desiredLength)
		throws GeneralSecurityException, IllegalArgumentException {
		
		if( (desiredLength % shortKey.length) != 0)
			throw new IllegalArgumentException("Desired key length is not divisible by the master key length.");
			
		int numPartials = desiredLength/shortKey.length;
		int currentEndPos = 0;
		byte[] key = new byte[desiredLength];
		byte[][] u = new byte[numPartials][];
		Mac mac = Mac.getInstance("HmacSHA256");
		
		for( int i = 0; i < numPartials; i++ ) {
			for( int j = 0; j < iterations-1; j++ ) {
				mac.init(new SecretKeySpec(shortKey,"HMACSHA256"));
				if( j == 0 ) {
					ByteBuffer bb = ByteBuffer.wrap(ByteBuffer.allocate(4).putInt(i).array());
					bb.order(ByteOrder.BIG_ENDIAN);
					u[j] = mac.doFinal(combineArrays(salt,bb.array()));

				} else
					u[j] = mac.doFinal(u[j-1]);
			}
			byte[] t = xorPartials(u);
			
			System.arraycopy(t,0,key,i * shortKey.length,(i+1) * shortKey.length);
			
			u = new byte[numPartials][];
		}
		return key;
	}
	
	// XOR's all the arrays together.
	public static byte[] xorPartials(byte[][] array) {
		byte[] xoredArray = array[0];
		for( int i = 1; i < array.length; i++ ) {
			for( int j = 0; j < array[0].length; j++ ) {
				xoredArray[j] = (byte)(xoredArray[j] ^ array[i][j]);
			}
		}
		return xoredArray;
	}	
	
	// Concatenates byte arrays together, in order of arguments listed.
	public static byte[] combineArrays(byte[]... arrays) {
		int currentEndPos = arrays[0].length;
		int totalLength = 0;
		for( byte[] partial : arrays )
			totalLength += partial.length;
			
		byte[] result = new byte[totalLength];
		for( int i = 0; i < arrays.length; i++ ) {
			if(i == 0)
				System.arraycopy(arrays[i],0,result,0,currentEndPos);
			else
				System.arraycopy(arrays[i],0,result,currentEndPos,arrays[i].length);	
			
			currentEndPos = arrays[i].length;
		}
		return result;
	}
}