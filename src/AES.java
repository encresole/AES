public class AES {

	public int masterkey;
	private int[] masterKeyBits;
	
	public AES(int masterkey) throws Exception {
		if (masterkey != 128) {
			throw new Exception("masterkey n'est pas égal à 128");
		}
		this.masterkey = masterkey;
		this.masterKeyBits = generateMasterKey();
	}
	
	public int[] stringToBits(String message) {
		if (message == null) {
			return new int[0];
		}
		
		int[] bits = new int[message.length() * 8];
		for (int i = 0; i < message.length(); i++) {
			int value = message.charAt(i);
			for (int j = 7; j >= 0; j--) {
				bits[i * 8 + (7 - j)] = (value >> j) & 1;
			}
		}
		return bits;
	}
	
	public String bitsToString(int[] bits) {
		if (bits == null || bits.length % 8 != 0) {
			return "";
		}
		
		StringBuilder message = new StringBuilder();
		for (int i = 0; i < bits.length; i += 8) {
			int value = 0;
			for (int j = 0; j < 8; j++) {
				value = (value << 1) | bits[i + j];
			}
			if (value == 0 && i + 8 >= bits.length) {
				break;
			}
			message.append((char) value);
		}
		return message.toString();
	}

	public int[] generateMasterKey() {
		int[] masterKeyBits = new int[masterkey];
		for (int i = 0; i < masterkey; i++) {
			masterKeyBits[i] = (i * 17 + 7) % 2;
		}
		return masterKeyBits;
	}

	public int[] createKey(int[] masterKeyBits) {
		if (masterKeyBits == null || masterKeyBits.length != masterkey) {
			return new int[0];
		}
		
		int[] keyBits = new int[masterkey];
		for (int i = 0; i < masterkey; i++) {
			keyBits[i] = masterKeyBits[i];
		}
		return keyBits;
	}

	public int[] bourrage(int[] keyBits) {
		if (keyBits == null || keyBits.length != masterkey) {
			return new int[0];
		}
		
		int[] bourrageBits = new int[masterkey];
		for (int i = 0; i < masterkey; i++) {
			bourrageBits[i] = keyBits[i] ^ 1;
		}
		return bourrageBits;
	}

	public int[] debourrage(int[] bourrageBits) {
		if (bourrageBits == null || bourrageBits.length != masterkey) {
			return new int[0];
		}
		
		int[] keyBits = new int[masterkey];
		for (int i = 0; i < masterkey; i++) {
			keyBits[i] = bourrageBits[i] ^ 1;
		}
		return keyBits;
	}

	public int[][] decoupe_en_blocs(int[] bits) {
		if (bits == null || bits.length % 128 != 0) {
			return new int[0][0];
		}
		
		int numBlocks = bits.length / 128;
		int[][] blocks = new int[numBlocks][128];
		for (int i = 0; i < numBlocks; i++) {
			for (int j = 0; j < 128; j++) {
				blocks[i][j] = bits[i * 128 + j];
			}
		}
		return blocks;
	}

	public int[] recollage_des_bloc(int[][] blocks) {
		if (blocks == null || blocks.length == 0 || blocks[0].length != 128) {
			return new int[0];
		}
		
		int[] bits = new int[blocks.length * 128];
		for (int i = 0; i < blocks.length; i++) {
			for (int j = 0; j < 128; j++) {
				bits[i * 128 + j] = blocks[i][j];
			}
		}
		return bits;
	}

	public int[] xor(int[] bits1, int[] bits2) {
		if (bits1 == null || bits2 == null || bits1.length != bits2.length) {
			return new int[0];
		}
		
		int[] result = new int[bits1.length];
		for (int i = 0; i < bits1.length; i++) {
			result[i] = bits1[i] ^ bits2[i];
		}
		return result;
	}

	public int[] addRoundKey(int[] state, int[] roundKey) {
		if (state == null || roundKey == null || state.length != roundKey.length) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i] ^ roundKey[i];
		}
		return result;
	}

	public int[] subBytes(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	}

	public int[] subByteInv(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	}

	public int[] shiftRows(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	}

	public int[] shiftRowsInv(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	} 

	public int[] mixColumns(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	}

	public int[] crypte(int[] plaintext) {
		if (plaintext == null) {
			return new int[0];
		}
		
		int[] state = new int[128];
		for (int i = 0; i < 128; i++) {
			state[i] = (i < plaintext.length) ? plaintext[i] : 0;
		}
		
		state = addRoundKey(state, masterKeyBits);
		state = subBytes(state);
		state = shiftRows(state);
		state = mixColumns(state);
		
		return state;
	}

	public int[] decrypte(int[] ciphertext) {
		if (ciphertext == null) {
			return new int[0];
		}
		
		int[] state = new int[128];
		for (int i = 0; i < 128; i++) {
			state[i] = (i < ciphertext.length) ? ciphertext[i] : 0;
		}
		
		state = mixColumns(state);
		state = shiftRowsInv(state);
		state = subByteInv(state);
		state = addRoundKey(state, masterKeyBits);
		
		return state;
	}

	public static void main(String[] args) throws Exception {
		AES aes = new AES(128);
		int[] plaintext = aes.stringToBits("Hello, World!");
		int[] ciphertext = aes.crypte(plaintext);
		int[] decrypted = aes.decrypte(ciphertext);
		String decryptedMessage = aes.bitsToString(decrypted);
		System.out.println("Decrypted message: " + decryptedMessage);
	}
}
