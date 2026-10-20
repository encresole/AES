import java.util.Random;

/**
 * Implémentation de l'algorithme de chiffrement AES (clés de 128, 192 ou 256 bits).
 * Les messages, blocs, états et clés sont représentés par des tableaux de bits (int[] de 0 et de 1).
 * Seuls le constructeur, crypte et decrypte sont publics.
 */
public class AES {

	private final int tailleBloc = 128;

	private final int[] rcon = { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };

	private final int[][] sBox = {
		{ 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118 },
		{202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192 },
		{183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21 },
		{  4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117 },
		{  9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132 },
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
		{ 84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78 },
		{  8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37 },
		{114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146 },
		{108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132 },
		{144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6 },
		{208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107 },
		{ 58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115 },
		{150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110 },
		{ 71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27 },
		{252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244 },
		{ 31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95 },
		{ 96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239 },
		{160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97 },
		{ 23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125 }
	};

	private int tailleCleMaitre;
	private int nbRonde;
	private int[] masterkey;
	private int[] keys;

	/**
	 * Crée un objet AES avec une clé maître générée au hasard.
	 *
	 * @param tailleCle taille de la clé maître en bits (128, 192 ou 256)
	 * @throws IllegalArgumentException si la taille n'est pas 128, 192 ou 256
	 */
	public AES(int tailleCle) {
		if (tailleCle != 128 && tailleCle != 192 && tailleCle != 256) {
			throw new IllegalArgumentException("la clé n'est pas de la bonne taille");
		}
		tailleCleMaitre = tailleCle;
		if (tailleCle == 128) {
			nbRonde = 10;
		} else if (tailleCle == 192) {
			nbRonde = 12;
		} else {
			nbRonde = 14;
		}
		masterkey = genereMasterKey();
		keys = createKeys();
	}

	/**
	 * Transforme un texte en tableau de bits : chaque caractère donne 8 bits.
	 *
	 * @param message le texte à convertir
	 * @return un tableau de 0 et de 1 de taille 8 fois la longueur du texte
	 */
	private int[] stringToBits(String message) {
		int[] bits = new int[message.length() * 8];
		for (int i = 0; i < message.length(); i++) {
			ecrireOctet(bits, i, message.charAt(i));
		}
		return bits;
	}

	/**
	 * Transforme un tableau de bits en texte : chaque groupe de 8 bits donne un caractère.
	 *
	 * @param bits tableau de 0 et de 1 (taille multiple de 8)
	 * @return le texte correspondant
	 */
	private String bitsToString(int[] bits) {
		String message = "";
		for (int i = 0; i < bits.length / 8; i++) {
			message = message + (char) lireOctet(bits, i);
		}
		return message;
	}

	/**
	 * Lit un octet dans un tableau de bits.
	 *
	 * @param bits tableau de 0 et de 1
	 * @param i numéro de l'octet (l'octet i utilise les bits 8i à 8i+7)
	 * @return la valeur de l'octet, entre 0 et 255
	 */
	private int lireOctet(int[] bits, int i) {
		int valeur = 0;
		for (int b = 0; b < 8; b++) {
			valeur = valeur * 2 + bits[i * 8 + b];
		}
		return valeur;
	}

	/**
	 * Écrit un octet dans un tableau de bits.
	 *
	 * @param bits tableau de 0 et de 1 modifié par la méthode
	 * @param i numéro de l'octet à écrire
	 * @param valeur valeur de l'octet, entre 0 et 255
	 */
	private void ecrireOctet(int[] bits, int i, int valeur) {
		for (int b = 0; b < 8; b++) {
			bits[i * 8 + b] = (valeur >> (7 - b)) & 1;
		}
	}

	/**
	 * Génère une clé maître aléatoire.
	 *
	 * @return un tableau de tailleCleMaitre bits (0 ou 1) tirés au hasard
	 */
	private int[] genereMasterKey() {
		Random random = new Random();
		int[] cle = new int[tailleCleMaitre];
		for (int i = 0; i < cle.length; i++) {
			cle[i] = random.nextInt(2);
		}
		return cle;
	}

	/**
	 * Key Expansion : calcule les nbRonde + 1 clés de ronde à partir de la clé maître.
	 * Les clés de ronde font toujours 128 bits et sont mises bout à bout dans l'attribut keys.
	 *
	 * @return le tableau de bits contenant toutes les clés de ronde K0 à Knr
	 */
	private int[] createKeys() {
		int nk = tailleCleMaitre / 32;
		int nbMots = 4 * (nbRonde + 1);
		int[][] w = new int[nbMots][4];

		for (int i = 0; i < nk; i++) {
			for (int j = 0; j < 4; j++) {
				w[i][j] = lireOctet(masterkey, 4 * i + j);
			}
		}
		for (int i = nk; i < nbMots; i++) {
			int[] temp = new int[4];
			for (int j = 0; j < 4; j++) {
				temp[j] = w[i - 1][j];
			}
			if (i % nk == 0) {
				temp = subWord(rotWord(temp));
				temp[0] = temp[0] ^ rcon[i / nk - 1];
			} else if (nk > 6 && i % nk == 4) {
				temp = subWord(temp);
			}
			for (int j = 0; j < 4; j++) {
				w[i][j] = w[i - nk][j] ^ temp[j];
			}
		}
		int[] resultat = new int[nbMots * 32];
		for (int i = 0; i < nbMots; i++) {
			for (int j = 0; j < 4; j++) {
				ecrireOctet(resultat, 4 * i + j, w[i][j]);
			}
		}
		keys = resultat;
		return resultat;
	}

	/**
	 * RotWord : rotation d'un mot de 4 octets, (a,b,c,d) devient (b,c,d,a).
	 *
	 * @param mot tableau de 4 octets
	 * @return le mot après rotation
	 */
	private int[] rotWord(int[] mot) {
		return new int[] { mot[1], mot[2], mot[3], mot[0] };
	}

	/**
	 * SubWord : remplace chacun des 4 octets d'un mot par sa valeur dans la S-box.
	 *
	 * @param mot tableau de 4 octets
	 * @return le mot après substitution
	 */
	private int[] subWord(int[] mot) {
		int[] r = new int[4];
		for (int i = 0; i < 4; i++) {
			r[i] = sBox[mot[i] / 16][mot[i] % 16];
		}
		return r;
	}

	/**
	 * Extrait une clé de ronde de l'attribut keys.
	 *
	 * @param r numéro de la ronde (0 à nbRonde)
	 * @return la clé de ronde Kr, soit 128 bits
	 */
	private int[] cleDeRonde(int r) {
		int[] cle = new int[128];
		for (int i = 0; i < 128; i++) {
			cle[i] = keys[r * 128 + i];
		}
		return cle;
	}

	/**
	 * Bourrage PKCS7 : ajoute n octets valant tous n (n entre 1 et 16) pour que la taille
	 * devienne un multiple de 16 octets. Si la taille est déjà un multiple de 16 octets,
	 * un bloc entier de 16 octets valant 16 est ajouté.
	 *
	 * @param messageBits le message en bits
	 * @return le message en bits avec le bourrage ajouté
	 */
	private int[] bourrage(int[] messageBits) {
		int tailleOctets = messageBits.length / 8;
		int nbPadding = 16 - (tailleOctets % 16);
		int[] resultat = new int[messageBits.length + nbPadding * 8];
		for (int i = 0; i < messageBits.length; i++) {
			resultat[i] = messageBits[i];
		}
		for (int i = tailleOctets; i < tailleOctets + nbPadding; i++) {
			ecrireOctet(resultat, i, nbPadding);
		}
		return resultat;
	}

	/**
	 * Retire le bourrage ajouté par bourrage : lit le dernier octet n, vérifie que les n derniers
	 * octets valent tous n, puis les supprime.
	 *
	 * @param messageBits le message en bits avec son bourrage
	 * @return le message en bits sans le bourrage
	 * @throws IllegalArgumentException si le bourrage est invalide (par exemple avec une mauvaise clé)
	 */
	private int[] debourrage(int[] messageBits) {
		int tailleOctets = messageBits.length / 8;
		int nbPadding = lireOctet(messageBits, tailleOctets - 1);
		if (nbPadding < 1 || nbPadding > 16) {
			throw new IllegalArgumentException("Bourrage invalide");
		}
		for (int i = tailleOctets - nbPadding; i < tailleOctets; i++) {
			if (lireOctet(messageBits, i) != nbPadding) {
				throw new IllegalArgumentException("Bourrage invalide");
			}
		}
		int[] resultat = new int[messageBits.length - nbPadding * 8];
		for (int i = 0; i < resultat.length; i++) {
			resultat[i] = messageBits[i];
		}
		return resultat;
	}

	/**
	 * Découpe un message en blocs de 128 bits.
	 *
	 * @param bits message en bits (taille multiple de 128)
	 * @return un tableau de blocs, chaque bloc contenant 128 bits
	 */
	private int[][] decoupageEnBlocs(int[] bits) {
		int[][] blocs = new int[bits.length / 128][128];
		for (int i = 0; i < blocs.length; i++) {
			for (int j = 0; j < 128; j++) {
				blocs[i][j] = bits[i * 128 + j];
			}
		}
		return blocs;
	}

	/**
	 * Recolle des blocs de 128 bits en un seul tableau de bits (opération inverse de decoupageEnBlocs).
	 *
	 * @param blocks les blocs de 128 bits
	 * @return le tableau de bits obtenu en mettant les blocs bout à bout
	 */
	private int[] recollageDesBlocs(int[][] blocks) {
		int[] bits = new int[blocks.length * 128];
		for (int i = 0; i < blocks.length; i++) {
			for (int j = 0; j < 128; j++) {
				bits[i * 128 + j] = blocks[i][j];
			}
		}
		return bits;
	}

	/**
	 * XOR bit à bit entre deux tableaux de même taille.
	 *
	 * @param bits1 premier tableau de bits
	 * @param bits2 deuxième tableau de bits
	 * @return un tableau où chaque case vaut bits1[i] XOR bits2[i]
	 */
	private int[] xor(int[] bits1, int[] bits2) {
		int[] result = new int[bits1.length];
		for (int i = 0; i < bits1.length; i++) {
			result[i] = bits1[i] ^ bits2[i];
		}
		return result;
	}

	/**
	 * AddRoundKey : XOR de l'état avec la clé de ronde. Cette opération est sa propre inverse.
	 *
	 * @param state l'état de 128 bits
	 * @param roundKey la clé de ronde de 128 bits
	 * @return le nouvel état
	 */
	private int[] addRoundKey(int[] state, int[] roundKey) {
		return xor(state, roundKey);
	}

	/**
	 * SubBytes : remplace chaque octet de l'état par sa valeur dans la S-box
	 * (ligne = valeur / 16, colonne = valeur % 16).
	 *
	 * @param state l'état de 128 bits
	 * @return le nouvel état
	 */
	private int[] subBytes(int[] state) {
		int[] result = new int[128];
		for (int i = 0; i < 16; i++) {
			int v = lireOctet(state, i);
			ecrireOctet(result, i, sBox[v / 16][v % 16]);
		}
		return result;
	}

	/**
	 * Inverse de SubBytes : même principe avec la S-box inverse.
	 *
	 * @param state l'état de 128 bits
	 * @return le nouvel état
	 */
	private int[] subByteInv(int[] state) {
		int[] result = new int[128];
		for (int i = 0; i < 16; i++) {
			int v = lireOctet(state, i);
			ecrireOctet(result, i, sBoxInv[v / 16][v % 16]);
		}
		return result;
	}

	/**
	 * ShiftRows : la ligne l de l'état est décalée de l positions vers la gauche
	 * (la ligne 0 ne bouge pas). L'état est lu colonne par colonne : l'octet i est à la
	 * colonne i/4 et à la ligne i%4.
	 *
	 * @param state l'état de 128 bits
	 * @return le nouvel état
	 */
	private int[] shiftRows(int[] state) {
		int[] result = new int[128];
		for (int c = 0; c < 4; c++) {
			for (int l = 0; l < 4; l++) {
				ecrireOctet(result, 4 * c + l, lireOctet(state, 4 * ((c + l) % 4) + l));
			}
		}
		return result;
	}

	/**
	 * Inverse de ShiftRows : les lignes sont décalées vers la droite.
	 *
	 * @param state l'état de 128 bits
	 * @return le nouvel état
	 */
	private int[] shiftRowsInv(int[] state) {
		int[] result = new int[128];
		for (int c = 0; c < 4; c++) {
			for (int l = 0; l < 4; l++) {
				ecrireOctet(result, 4 * ((c + l) % 4) + l, lireOctet(state, 4 * c + l));
			}
		}
		return result;
	}

	/**
	 * Multiplication d'un octet par 2 dans GF(2^8) : on double la valeur, et si elle dépasse
	 * 255 (bit de poids fort à 1) on fait un XOR avec 27 (0x1B) pour réduire modulo le
	 * polynôme irréductible x^8 + x^4 + x^3 + x + 1.
	 *
	 * @param a un octet (0 à 255)
	 * @return 2 x a dans GF(2^8)
	 */
	private int deux_a(int a) {
		int r = (a * 2) % 256;
		if (a >= 128) {
			r = r ^ 27;
		}
		return r;
	}

	/**
	 * Multiplication par 3 : 3a = 2a XOR a.
	 *
	 * @param a un octet (0 à 255)
	 * @return 3 x a dans GF(2^8)
	 */
	private int trois_a(int a) {
		return deux_a(a) ^ a;
	}

	/**
	 * Multiplication par 9 : 9a = 8a XOR a.
	 *
	 * @param a un octet (0 à 255)
	 * @return 9 x a dans GF(2^8)
	 */
	private int neuf_a(int a) {
		return deux_a(deux_a(deux_a(a))) ^ a;
	}

	/**
	 * Multiplication par 11 : 11a = 8a XOR 2a XOR a.
	 *
	 * @param a un octet (0 à 255)
	 * @return 11 x a dans GF(2^8)
	 */
	private int onze_a(int a) {
		return deux_a(deux_a(deux_a(a))) ^ deux_a(a) ^ a;
	}

	/**
	 * Multiplication par 13 : 13a = 8a XOR 4a XOR a.
	 *
	 * @param a un octet (0 à 255)
	 * @return 13 x a dans GF(2^8)
	 */
	private int treize_a(int a) {
		return deux_a(deux_a(deux_a(a))) ^ deux_a(deux_a(a)) ^ a;
	}

	/**
	 * Multiplication par 14 : 14a = 8a XOR 4a XOR 2a.
	 *
	 * @param a un octet (0 à 255)
	 * @return 14 x a dans GF(2^8)
	 */
	private int quatorze_a(int a) {
		return deux_a(deux_a(deux_a(a))) ^ deux_a(deux_a(a)) ^ deux_a(a);
	}

	/**
	 * Multiplie une colonne de 4 octets par la matrice de MixColumns
	 * (lignes : 2 3 1 1 / 1 2 3 1 / 1 1 2 3 / 3 1 1 2).
	 *
	 * @param a la colonne (4 octets)
	 * @return la nouvelle colonne (4 octets)
	 */
	private int[] prodAu(int[] a) {
		int[] b = new int[4];
		b[0] = deux_a(a[0]) ^ trois_a(a[1]) ^ a[2] ^ a[3];
		b[1] = a[0] ^ deux_a(a[1]) ^ trois_a(a[2]) ^ a[3];
		b[2] = a[0] ^ a[1] ^ deux_a(a[2]) ^ trois_a(a[3]);
		b[3] = trois_a(a[0]) ^ a[1] ^ a[2] ^ deux_a(a[3]);
		return b;
	}

	/**
	 * Multiplie une colonne de 4 octets par la matrice inverse de MixColumns
	 * (lignes : 14 11 13 9 / 9 14 11 13 / 13 9 14 11 / 11 13 9 14).
	 *
	 * @param a la colonne (4 octets)
	 * @return la nouvelle colonne (4 octets)
	 */
	private int[] prodAuInv(int[] a) {
		int[] b = new int[4];
		b[0] = quatorze_a(a[0]) ^ onze_a(a[1]) ^ treize_a(a[2]) ^ neuf_a(a[3]);
		b[1] = neuf_a(a[0]) ^ quatorze_a(a[1]) ^ onze_a(a[2]) ^ treize_a(a[3]);
		b[2] = treize_a(a[0]) ^ neuf_a(a[1]) ^ quatorze_a(a[2]) ^ onze_a(a[3]);
		b[3] = onze_a(a[0]) ^ treize_a(a[1]) ^ neuf_a(a[2]) ^ quatorze_a(a[3]);
		return b;
	}

	/**
	 * MixColumns : applique prodAu à chacune des 4 colonnes de l'état.
	 *
	 * @param state l'état de 128 bits
	 * @return le nouvel état
	 */
	private int[] mixColumns(int[] state) {
		int[] result = new int[128];
		for (int c = 0; c < 4; c++) {
			int[] colonne = new int[4];
			for (int l = 0; l < 4; l++) {
				colonne[l] = lireOctet(state, 4 * c + l);
			}
			int[] nouvelle = prodAu(colonne);
			for (int l = 0; l < 4; l++) {
				ecrireOctet(result, 4 * c + l, nouvelle[l]);
			}
		}
		return result;
	}

	/**
	 * Inverse de MixColumns : applique prodAuInv à chacune des 4 colonnes de l'état.
	 *
	 * @param state l'état de 128 bits
	 * @return le nouvel état
	 */
	private int[] mixColumnsInv(int[] state) {
		int[] result = new int[128];
		for (int c = 0; c < 4; c++) {
			int[] colonne = new int[4];
			for (int l = 0; l < 4; l++) {
				colonne[l] = lireOctet(state, 4 * c + l);
			}
			int[] nouvelle = prodAuInv(colonne);
			for (int l = 0; l < 4; l++) {
				ecrireOctet(result, 4 * c + l, nouvelle[l]);
			}
		}
		return result;
	}

	/**
	 * Chiffre un bloc de 128 bits : AddRoundKey avec K0, puis les rondes 1 à nbRonde - 1
	 * (SubBytes, ShiftRows, MixColumns, AddRoundKey), puis la dernière ronde sans MixColumns.
	 *
	 * @param bloc un bloc de 128 bits
	 * @return le bloc chiffré (128 bits)
	 */
	private int[] crypteBloc(int[] bloc) {
		int[] state = addRoundKey(bloc, cleDeRonde(0));
		for (int r = 1; r < nbRonde; r++) {
			state = subBytes(state);
			state = shiftRows(state);
			state = mixColumns(state);
			state = addRoundKey(state, cleDeRonde(r));
		}
		state = subBytes(state);
		state = shiftRows(state);
		return addRoundKey(state, cleDeRonde(nbRonde));
	}

	/**
	 * Déchiffre un bloc de 128 bits en refaisant les opérations inverses dans l'ordre inverse,
	 * avec les clés de ronde de Knr vers K0.
	 *
	 * @param bloc un bloc chiffré de 128 bits
	 * @return le bloc déchiffré (128 bits)
	 */
	private int[] decrypteBloc(int[] bloc) {
		int[] state = addRoundKey(bloc, cleDeRonde(nbRonde));
		state = shiftRowsInv(state);
		state = subByteInv(state);
		for (int r = nbRonde - 1; r >= 1; r--) {
			state = addRoundKey(state, cleDeRonde(r));
			state = mixColumnsInv(state);
			state = shiftRowsInv(state);
			state = subByteInv(state);
		}
		return addRoundKey(state, cleDeRonde(0));
	}

	/**
	 * Chiffre un message : conversion en bits, bourrage, découpage en blocs, chiffrement
	 * de chaque bloc, puis recollage des blocs.
	 *
	 * @param message le texte à chiffrer
	 * @return le message chiffré en bits (taille multiple de 128)
	 */
	public int[] crypte(String message) {
		int[] bits = bourrage(stringToBits(message));
		int[][] blocs = decoupageEnBlocs(bits);
		for (int i = 0; i < blocs.length; i++) {
			blocs[i] = crypteBloc(blocs[i]);
		}
		return recollageDesBlocs(blocs);
	}

	/**
	 * Déchiffre un message : découpage en blocs, déchiffrement de chaque bloc, recollage,
	 * suppression du bourrage, puis conversion en texte.
	 *
	 * @param messCode le message chiffré en bits (taille multiple de 128)
	 * @return le texte d'origine
	 * @throws IllegalArgumentException si le bourrage est invalide (par exemple avec une mauvaise clé)
	 */
	public String decrypte(int[] messCode) {
		int[][] blocs = decoupageEnBlocs(messCode);
		for (int i = 0; i < blocs.length; i++) {
			blocs[i] = decrypteBloc(blocs[i]);
		}
		return bitsToString(debourrage(recollageDesBlocs(blocs)));
	}

	/**
	 * Petit exemple : chiffre puis déchiffre un message et l'affiche.
	 *
	 * @param args non utilisé
	 */
	public static void main(String[] args) {
		AES aes = new AES(128);
		int[] chiffre = aes.crypte("Hello, World!");
		System.out.println(aes.decrypte(chiffre));
	}
}