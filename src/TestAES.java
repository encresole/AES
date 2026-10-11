public class TestAES {
	public static void main(String[] args) throws Exception {
		AES aes = new AES(128);
		int[] tab = {1,1,1,1,1,1,1,1};
		System.out.println(aes.ByteOfBitsToInt(tab));
	}
}

