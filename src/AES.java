import java.util.Random;

public class AES {
	
	private final int tailleBloc = 128;
	
	private final int[] rcon = {
		    1, 2, 4, 8,
		    16, 32, 64, 128,
		    27, 54
		};

	private final int[][] sBox = {
	    { 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118 },
	    {202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192 },
	    {183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21 },
	    {  4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117 },
	    {  9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  65, 227,  47, 132 },
	    { 83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207 },
	    {208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168 },
	    { 81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210 },
	    {205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115 },
	    { 96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219 },
	    {224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121 },
	    {231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8 },
	    {186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138 },
	    {112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158 },
	    {225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223 },
	    {140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22 }
	};

	private final int[][] sBoxInv = {
	    { 82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251 },
	    {124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203 },
	    { 84, 143, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78 },
	    {  8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37 },
	    {114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146 },
	    {108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132 },
	    {144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6 },
	    {208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107 },
	    { 58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115 },
	    {150, 116,  59, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,  71 },
	    {241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27, 252 },
	    { 86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,  31 },
	    {221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,  96 },
	    { 81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239,  60 },
	    {224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,  23 },
	    { 43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125,  19 }
	};
	
	private int tailleCleMaitre;
	private int nbRonde;
	private int[] masterkey;
	private int[] keys;
	
	public AES(int tailleCle) throws Exception {
		if (tailleCle != 128 || tailleCle != 192 || tailleCle != 256) {
			throw new Exception("la clé n'est pas de la bonne taille");
		}
		tailleCleMaitre = tailleCle;
		switch (tailleCleMaitre) {
		case 128: 
			nbRonde = 10;
		case 192: 
			nbRonde = 12;
		case 256:
			nbRonde = 14;
		}
		this.masterkey = generateMasterKey();
		this.keys=createKey(masterkey);
	}
	
	private int[] stringToBits(String message) {
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
	
	private String bitsToString(int[] bits) {
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

	private int[] generateMasterKey() {
	    Random random = new Random();
	    int[] masterKeyBits = new int[tailleCleMaitre];
	    for (int i = 0; i < tailleCleMaitre; i++) {
	        masterKeyBits[i] = random.nextInt(2);
	    }
	    return masterKeyBits;
	}

	private int[] createKey(int[] masterKeyBits) {
		if (masterKeyBits == null || masterKeyBits.length != masterkey) {
			return new int[0];
		}
		
		int[] keyBits = new int[masterkey];
		for (int i = 0; i < masterkey; i++) {
			keyBits[i] = masterKeyBits[i];
		}
		return keyBits;
	}

	private int[] bourrage(int[] keyBits) {
		if (keyBits == null || keyBits.length != masterkey) {
			return new int[0];
		}
		
		int[] bourrageBits = new int[masterkey];
		for (int i = 0; i < masterkey; i++) {
			bourrageBits[i] = keyBits[i] ^ 1;
		}
		return bourrageBits;
	}

	private int[] debourrage(int[] bourrageBits) {
		if (bourrageBits == null || bourrageBits.length != masterkey) {
			return new int[0];
		}
		
		int[] keyBits = new int[masterkey];
		for (int i = 0; i < masterkey; i++) {
			keyBits[i] = bourrageBits[i] ^ 1;
		}
		return keyBits;
	}

	private int[][] decoupe_en_blocs(int[] bits) {
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

	private int[] recollage_des_bloc(int[][] blocks) {
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

	private int[] xor(int[] bits1, int[] bits2) {
		if (bits1 == null || bits2 == null || bits1.length != bits2.length) {
			return new int[0];
		}
		
		int[] result = new int[bits1.length];
		for (int i = 0; i < bits1.length; i++) {
			result[i] = bits1[i] ^ bits2[i];
		}
		return result;
	}

	private int[] addRoundKey(int[] state, int[] roundKey) {
		if (state == null || roundKey == null || state.length != roundKey.length) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i] ^ roundKey[i];
		}
		return result;
	}

	private int[] subBytes(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	}

	private int[] subByteInv(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	}

	private int[] shiftRows(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	}

	private int[] shiftRowsInv(int[] state) {
		if (state == null || state.length != 128) {
			return new int[0];
		}
		
		int[] result = new int[state.length];
		for (int i = 0; i < state.length; i++) {
			result[i] = state[i];
		}
		return result;
	} 

	private int[] mixColumns(int[] state) {
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
