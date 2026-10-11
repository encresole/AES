import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Classe de test pour la classe AES du TP (à placer dans le même dossier que AES.java).
 * Lance simplement le main : chaque test affiche [OK], [ECHEC] ou [SKIP].
 *
 * Cette classe ne dépend de AES que par réflexion : elle COMPILE même si ton AES est incomplet,
 * et un test dont la méthode n'existe pas encore est simplement [SKIP]. Tu peux donc la lancer
 * "au fur et à mesure", dans l'ordre de l'énoncé.
 *
 * Ce que le test attend (énoncé du TP) :
 *  - constructeur AES(int taille_cle_maitre) ;
 *  - public int[] crypte(String message) et public String decrypte(int[] messCode) ;
 *  - attributs taille_bloc, taille_cle_maitre, nb_ronde, master_Key, keys (les noms sont reconnus
 *    sans tenir compte des majuscules ni des "_" : master_Key, masterKey, masterkey...) ;
 *  - méthodes privées nommées comme dans l'énoncé (genereMasterKey, createKeys, bourrage, debourrage,
 *    decoupage_en_blocs, recollage_des_bloc(s), xor, addRoundKey, subByte, subByteInv, shiftRows,
 *    shiftRowsInv, deux_a ... quatorze_a, mixColumns, stringToBits, bitsToString).
 *
 * Hypothèses sur TES choix de représentation (tu peux les désactiver ci-dessous) :
 *  - section "méthodes privées" : un état AES est un int[128] de 0/1 (comme dans ton AES.java) ;
 *  - master_Key peut être un int[] ou un int[][] contenant des bits, des octets ou des mots de 32 bits :
 *    le test s'adapte, pour imposer une clé connue et comparer avec l'AES officiel du JDK ;
 *  - le bourrage est celui de ton bourrage() (PKCS7 : on ajoute n octets valant n).
 */
public class TestAES {

	// ------------------------------------------------------------------
	// CONFIGURATION
	// ------------------------------------------------------------------

	/** true : teste aussi AES-192 et AES-256 (deuxième version du TP). false : AES-128 seulement. */
	static final boolean VERSION_2 = true;

	/** true : teste les méthodes privées en supposant un état = int[128] de bits. false : saute cette section. */
	static final boolean ETAT_EN_BITS = true;

	// Noms reconnus (insensible à la casse et aux "_")
	static final String[] MASTER_KEY = { "master_Key", "masterKey", "cle_maitre", "cleMaitre" };
	static final String[] KEYS = { "keys", "cles", "roundKeys" };
	static final String[] NB_RONDE = { "nb_ronde", "nbRonde", "nb_rondes", "nbRondes" };
	static final String[] TAILLE_CLE = { "taille_cle_maitre", "tailleCleMaitre" };
	static final String[] TAILLE_BLOC = { "taille_bloc", "tailleBloc" };
	static final String[] GENERE = { "genereMasterKey", "generateMasterKey" };
	static final String[] CREATE_KEYS = { "createKeys", "create_Keys" };
	static final String[] STRING_TO_BITS = { "stringToBits" };
	static final String[] BITS_TO_STRING = { "bitsToString" };
	static final String[] BOURRAGE = { "bourrage" };
	static final String[] DEBOURRAGE = { "debourrage" };
	static final String[] DECOUPAGE = { "decoupage_en_blocs", "decoupageEnBlocs", "decoupage_en_bloc" };
	static final String[] RECOLLAGE = { "recollage_des_bloc", "recollage_des_blocs", "recollageDesBlocs" };
	static final String[] XOR = { "xor" };
	static final String[] ADD_ROUND_KEY = { "addRoundKey" };
	static final String[] SUB_BYTE = { "subByte", "subBytes" };
	static final String[] SUB_BYTE_INV = { "subByteInv", "subBytesInv" };
	static final String[] SHIFT_ROWS = { "shiftRows" };
	static final String[] SHIFT_ROWS_INV = { "shiftRowsInv" };
	static final String[] MIX_COLUMNS = { "mixColumns" };
	static final String[] MIX_COLUMNS_INV = { "mixColumnsInv", "invMixColumns" };
	static final String[] DEUX_A = { "deux_a" };
	static final String[] TROIS_A = { "trois_a" };
	static final String[] NEUF_A = { "neuf_a" };
	static final String[] ONZE_A = { "onze_a" };
	static final String[] TREIZE_A = { "treize_a" };
	static final String[] QUATORZE_A = { "quatorze_a" };

	// ------------------------------------------------------------------
	// Petit moteur de test
	// ------------------------------------------------------------------

	interface Test { void run() throws Throwable; }

	static class Echec extends RuntimeException { Echec(String m) { super(m); } }
	static class Ignore extends RuntimeException { Ignore(String m) { super(m); } }

	static int reussis = 0, echecs = 0, ignores = 0, bonusOk = 0, bonusNon = 0;
	static Class<?> classeAES;

	static void groupe(String titre) {
		System.out.println();
		System.out.println("--- " + titre + " ---");
	}

	static Throwable racine(Throwable e) {
		Throwable c = e;
		while (c.getCause() != null && !(c instanceof Echec) && !(c instanceof Ignore)) {
			c = c.getCause();
		}
		return c;
	}

	static void test(String nom, Test t) {
		try {
			t.run();
			reussis++;
			System.out.println("  [OK]     " + nom);
		} catch (Throwable e) {
			Throwable c = racine(e);
			if (c instanceof Ignore) {
				ignores++;
				System.out.println("  [SKIP]   " + nom + " -> " + c.getMessage());
			} else {
				echecs++;
				System.out.println("  [ECHEC]  " + nom + " -> " + (c instanceof Echec ? c.getMessage() : c.toString()));
			}
		}
	}

	/** Test "bonus" : indicatif, ne compte pas dans les échecs. */
	static void bonus(String nom, Test t) {
		try {
			t.run();
			bonusOk++;
			System.out.println("  [bonus OK]   " + nom);
		} catch (Throwable e) {
			bonusNon++;
			Throwable c = racine(e);
			System.out.println("  [bonus non]  " + nom + " -> "
					+ ((c instanceof Echec || c instanceof Ignore) ? c.getMessage() : c.toString()));
		}
	}

	static void verifier(boolean condition, String message) {
		if (!condition) {
			throw new Echec(message);
		}
	}

	static void egal(String contexte, String attendu, String obtenu) {
		if (!attendu.equals(obtenu)) {
			throw new Echec(contexte + " : attendu " + attendu + " mais obtenu " + obtenu);
		}
	}

	static void egalBits(String contexte, int[] attendu, int[] obtenu) {
		if (obtenu == null) {
			throw new Echec(contexte + " : résultat null");
		}
		if (!Arrays.equals(attendu, obtenu)) {
			throw new Echec(contexte + " : attendu " + bitsVersHex(attendu) + " (" + attendu.length
					+ " valeurs) mais obtenu " + bitsVersHex(obtenu) + " (" + obtenu.length + " valeurs)");
		}
	}

	static void doitLever(Test t) {
		boolean leve = false;
		try {
			t.run();
		} catch (Ignore i) {
			throw i;
		} catch (Throwable e) {
			leve = true;
		}
		if (!leve) {
			throw new Echec("une exception était attendue");
		}
	}

	// ------------------------------------------------------------------
	// Outils bits / hexadécimal
	// ------------------------------------------------------------------

	static int[] hexVersBits(String hex) {
		int[] bits = new int[hex.length() * 4];
		for (int i = 0; i < hex.length(); i++) {
			int v = Character.digit(hex.charAt(i), 16);
			for (int b = 0; b < 4; b++) {
				bits[i * 4 + b] = (v >> (3 - b)) & 1;
			}
		}
		return bits;
	}

	static String bitsVersHex(int[] bits) {
		if (bits == null) {
			return "null";
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i + 3 < bits.length; i += 4) {
			sb.append(Character.forDigit(bits[i] * 8 + bits[i + 1] * 4 + bits[i + 2] * 2 + bits[i + 3], 16));
		}
		return sb.toString();
	}

	static byte[] hexVersOctets(String hex) {
		byte[] o = new byte[hex.length() / 2];
		for (int i = 0; i < o.length; i++) {
			o[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
		}
		return o;
	}

	static String hex(byte[] o) {
		StringBuilder sb = new StringBuilder();
		for (byte b : o) {
			sb.append(String.format("%02x", b & 0xFF));
		}
		return sb.toString();
	}

	static int[] bitsDe(byte[] octets) {
		int[] bits = new int[octets.length * 8];
		for (int i = 0; i < octets.length; i++) {
			for (int b = 0; b < 8; b++) {
				bits[i * 8 + b] = (octets[i] >> (7 - b)) & 1;
			}
		}
		return bits;
	}

	static byte[] octetsDe(int[] bits) {
		byte[] o = new byte[bits.length / 8];
		for (int i = 0; i < o.length; i++) {
			int v = 0;
			for (int b = 0; b < 8; b++) {
				v = (v << 1) | bits[i * 8 + b];
			}
			o[i] = (byte) v;
		}
		return o;
	}

	static int[] bitsAleatoires(Random rnd, int nbOctets) {
		int[] bits = new int[nbOctets * 8];
		for (int i = 0; i < bits.length; i++) {
			bits[i] = rnd.nextInt(2);
		}
		return bits;
	}

	static String texteAleatoire(Random rnd, int n) {
		String alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ";
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < n; i++) {
			sb.append(alpha.charAt(rnd.nextInt(alpha.length())));
		}
		return sb.toString();
	}

	/** Oracle GF(2^8) pour vérifier deux_a, trois_a, ... (polynôme x^8+x^4+x^3+x+1). */
	static int gmul(int a, int b) {
		int r = 0;
		for (int i = 0; i < 8; i++) {
			if ((b & 1) != 0) {
				r ^= a;
			}
			a <<= 1;
			if ((a & 0x100) != 0) {
				a ^= 0x11B;
			}
			b >>= 1;
		}
		return r;
	}

	// ------------------------------------------------------------------
	// Réflexion : tout passe par là, donc le test compile avec n'importe quel AES.java
	// ------------------------------------------------------------------

	static String norm(String s) {
		return s.toLowerCase().replace("_", "");
	}

	static boolean nomEn(String nom, String[] liste) {
		for (String l : liste) {
			if (norm(nom).equals(norm(l))) {
				return true;
			}
		}
		return false;
	}

	static Field champOuNull(String[] noms) {
		for (Field f : classeAES.getDeclaredFields()) {
			if (nomEn(f.getName(), noms)) {
				f.setAccessible(true);
				return f;
			}
		}
		return null;
	}

	static Field champ(String[] noms) {
		Field f = champOuNull(noms);
		if (f == null) {
			throw new Ignore("attribut " + noms[0] + " introuvable");
		}
		return f;
	}

	static Method methodeOuNull(String[] noms, int nbParams) {
		for (Method m : classeAES.getDeclaredMethods()) {
			if (!m.isSynthetic() && m.getParameterCount() == nbParams && nomEn(m.getName(), noms)) {
				m.setAccessible(true);
				return m;
			}
		}
		return null;
	}

	static Method methode(String[] noms, int nbParams) {
		Method m = methodeOuNull(noms, nbParams);
		if (m == null) {
			throw new Ignore("méthode " + noms[0] + " (" + nbParams + " paramètre(s)) introuvable");
		}
		return m;
	}

	static Object invoquer(Method m, Object cible, Object[] args) throws Throwable {
		try {
			return m.invoke(cible, args);
		} catch (InvocationTargetException e) {
			throw e.getCause();
		} catch (IllegalArgumentException e) {
			throw new Ignore("paramètres incompatibles avec " + m.getName() + " (représentation différente ?)");
		}
	}

	static Object appeler(Object aes, String[] noms, Object[] args) throws Throwable {
		return invoquer(methode(noms, args.length), aes, args);
	}

	static Object un(Object aes, String[] noms, Object arg) throws Throwable {
		return appeler(aes, noms, new Object[] { arg });
	}

	/** Appelle une méthode qui prend et renvoie des int[] (attention : pas pour un int[][] en argument). */
	static int[] ints(Object aes, String[] noms, Object... args) throws Throwable {
		Object r = appeler(aes, noms, args);
		if (!(r instanceof int[])) {
			throw new Echec(noms[0] + " doit renvoyer un int[]");
		}
		return (int[]) r;
	}

	static Object nouveau(int taille) throws Throwable {
		Constructor<?> c;
		try {
			c = classeAES.getDeclaredConstructor(int.class);
		} catch (NoSuchMethodException e) {
			throw new Echec("constructeur AES(int taille_cle_maitre) introuvable");
		}
		c.setAccessible(true);
		try {
			return c.newInstance(taille);
		} catch (InvocationTargetException e) {
			throw e.getCause();
		}
	}

	static int[] crypte(Object aes, String message) throws Throwable {
		for (Method m : classeAES.getDeclaredMethods()) {
			if (m.getName().equals("crypte") && m.getParameterCount() == 1 && m.getParameterTypes()[0] == String.class) {
				m.setAccessible(true);
				Object r = invoquer(m, aes, new Object[] { message });
				if (!(r instanceof int[])) {
					throw new Echec("crypte doit renvoyer un int[]");
				}
				return (int[]) r;
			}
		}
		throw new Echec("crypte(String message) : int[] introuvable (voir l'énoncé)");
	}

	static String decrypte(Object aes, int[] messCode) throws Throwable {
		for (Method m : classeAES.getDeclaredMethods()) {
			if (m.getName().equals("decrypte") && m.getParameterCount() == 1 && m.getParameterTypes()[0] == int[].class) {
				m.setAccessible(true);
				Object r = invoquer(m, aes, new Object[] { messCode });
				if (!(r instanceof String)) {
					throw new Echec("decrypte doit renvoyer un String");
				}
				return (String) r;
			}
		}
		throw new Echec("decrypte(int[] messCode) : String introuvable (voir l'énoncé)");
	}

	static int lireEntier(Object aes, String[] noms) throws Throwable {
		Object v = champ(noms).get(aes);
		if (!(v instanceof Number)) {
			throw new Echec("l'attribut " + noms[0] + " doit être un entier");
		}
		return ((Number) v).intValue();
	}

	static void aplatir(Object o, List<Integer> out) {
		if (o instanceof int[]) {
			for (int x : (int[]) o) {
				out.add(x);
			}
		} else if (o instanceof Object[]) {
			for (Object e : (Object[]) o) {
				aplatir(e, out);
			}
		} else {
			throw new Ignore("format non reconnu (int[] ou int[][]... attendu)");
		}
	}

	static int[] choisir(int n, int[] bits, int[] octets, int[] mots) {
		if (n == bits.length) {
			return bits;
		}
		if (n == octets.length) {
			return octets;
		}
		if (n == mots.length) {
			return mots;
		}
		throw new Ignore("taille de master_Key (" + n + " valeurs) non reconnue : attendu " + bits.length
				+ " bits, " + octets.length + " octets ou " + mots.length + " mots");
	}

	/**
	 * Impose une clé maître connue dans l'objet puis recalcule les clés de ronde avec createKeys().
	 * Renvoie true si master_Key est un tableau à deux dimensions (le remplissage peut alors se faire
	 * par lignes ou par colonnes : le paramètre colonne choisit).
	 */
	static boolean imposerCle(Object aes, byte[] cle, boolean colonne) throws Throwable {
		Field f = champ(MASTER_KEY);
		Object actuel = f.get(aes);
		if (actuel == null) {
			throw new Ignore("master_Key n'est pas initialisée par le constructeur");
		}
		int[] bits = bitsDe(cle);
		int[] octets = new int[cle.length];
		for (int i = 0; i < cle.length; i++) {
			octets[i] = cle[i] & 0xFF;
		}
		int[] mots = new int[cle.length / 4];
		for (int i = 0; i < mots.length; i++) {
			mots[i] = ((cle[4 * i] & 0xFF) << 24) | ((cle[4 * i + 1] & 0xFF) << 16)
					| ((cle[4 * i + 2] & 0xFF) << 8) | (cle[4 * i + 3] & 0xFF);
		}
		boolean deuxD;
		if (actuel instanceof int[]) {
			f.set(aes, choisir(((int[]) actuel).length, bits, octets, mots));
			deuxD = false;
		} else if (actuel instanceof int[][]) {
			int[][] a = (int[][]) actuel;
			int lignes = a.length, cols = a[0].length;
			int[] source = choisir(lignes * cols, bits, octets, mots);
			int[][] nouv = new int[lignes][cols];
			for (int i = 0; i < source.length; i++) {
				if (colonne) {
					nouv[i % lignes][i / lignes] = source[i];
				} else {
					nouv[i / cols][i % cols] = source[i];
				}
			}
			f.set(aes, nouv);
			deuxD = true;
		} else {
			throw new Ignore("format de master_Key non géré (int[] ou int[][] attendu)");
		}
		Method m = methodeOuNull(CREATE_KEYS, 0);
		if (m == null) {
			throw new Ignore("createKeys() introuvable");
		}
		Object r = invoquer(m, aes, new Object[0]);
		if (r != null) {
			Field k = champOuNull(KEYS);
			if (k != null && k.getType().isInstance(r)) {
				k.set(aes, r);
			}
		}
		return deuxD;
	}

	// ------------------------------------------------------------------
	// AES officiel du JDK = référence indépendante
	// ------------------------------------------------------------------

	static byte[] jdk(String mode, byte[] cle, byte[] data, boolean chiffrer) throws Exception {
		Cipher c = Cipher.getInstance(mode);
		c.init(chiffrer ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(cle, "AES"));
		return c.doFinal(data);
	}

	/** Compare crypte() avec le JDK. complet = false : seul le 1er bloc de 16 octets est comparé. */
	static void verifierContreJDK(int taille, String message, boolean complet, long graine) throws Throwable {
		Random rnd = new Random(graine);
		byte[] cle = new byte[taille / 8];
		rnd.nextBytes(cle);
		byte[] msg = message.getBytes(StandardCharsets.ISO_8859_1);
		byte[] attendu = complet ? jdk("AES/ECB/PKCS5Padding", cle, msg, true) : jdk("AES/ECB/NoPadding", cle, msg, true);
		String premier = null;
		for (boolean colonne : new boolean[] { false, true }) {
			Object aes = nouveau(taille);
			boolean deuxD = imposerCle(aes, cle, colonne);
			byte[] obtenu = octetsDe(crypte(aes, message));
			int n = complet ? attendu.length : 16;
			if (obtenu.length >= n && Arrays.equals(Arrays.copyOf(obtenu, n), attendu)) {
				return;
			}
			if (premier == null) {
				premier = "clé " + hex(cle) + " : attendu " + hex(attendu) + " mais obtenu " + hex(obtenu);
			}
			if (!deuxD) {
				break;
			}
		}
		throw new Echec(premier);
	}

	static void verifierDecrypteJDK(int taille, String message, long graine) throws Throwable {
		Random rnd = new Random(graine);
		byte[] cle = new byte[taille / 8];
		rnd.nextBytes(cle);
		byte[] ct = jdk("AES/ECB/PKCS5Padding", cle, message.getBytes(StandardCharsets.ISO_8859_1), true);
		String premier = null;
		for (boolean colonne : new boolean[] { false, true }) {
			Object aes = nouveau(taille);
			boolean deuxD = imposerCle(aes, cle, colonne);
			try {
				String r = decrypte(aes, bitsDe(ct));
				if (message.equals(r)) {
					return;
				}
				if (premier == null) {
					premier = "attendu \"" + message + "\" mais obtenu \"" + r + "\"";
				}
			} catch (Ignore i) {
				throw i;
			} catch (Throwable t) {
				if (premier == null) {
					Throwable c = racine(t);
					premier = (c instanceof Echec) ? c.getMessage() : "exception : " + c;
				}
			}
			if (!deuxD) {
				break;
			}
		}
		throw new Echec(premier);
	}

	// ------------------------------------------------------------------
	// A. Constructeur et attributs
	// ------------------------------------------------------------------

	static int[] tailles() {
		return VERSION_2 ? new int[] { 128, 192, 256 } : new int[] { 128 };
	}

	static void testConstructeur() {
		groupe("A. Constructeur et attributs");

		test("le constructeur accepte 128" + (VERSION_2 ? ", 192 et 256" : ""), () -> {
			for (int t : tailles()) {
				nouveau(t);
			}
		});

		test("le constructeur refuse une taille invalide (100)", () -> {
			nouveau(128); // le constructeur doit exister (sinon Echec ici, pas un faux "refus")
			doitLever(() -> nouveau(100));
		});

		test("taille_bloc = 128", () -> {
			egal("taille_bloc", "128", "" + lireEntier(nouveau(128), TAILLE_BLOC));
		});

		int[][] attendus = { { 128, 10 }, { 192, 12 }, { 256, 14 } };
		for (int[] a : attendus) {
			if (a[0] != 128 && !VERSION_2) {
				continue;
			}
			test("AES-" + a[0] + " : taille_cle_maitre = " + a[0] + " et nb_ronde = " + a[1], () -> {
				Object aes = nouveau(a[0]);
				egal("taille_cle_maitre", "" + a[0], "" + lireEntier(aes, TAILLE_CLE));
				egal("nb_ronde", "" + a[1], "" + lireEntier(aes, NB_RONDE));
			});
		}
	}

	// ------------------------------------------------------------------
	// B. API publique : crypte(String) / decrypte(int[])
	// ------------------------------------------------------------------

	static void testApiPublique() {
		groupe("B. API de l'énoncé : crypte(String) -> int[] et decrypte(int[]) -> String");

		String[] messages = { "", "A", "bonjour", "Hello World", "0123456789abcdef", "0123456789abcdef0123456789abcdef",
				"Voici un message assez long pour faire plusieurs blocs de 128 bits sans aucun accent" };

		for (int taille : tailles()) {
			for (String m : messages) {
				test("AES-" + taille + " : aller-retour d'un message de " + m.length() + " caractères", () -> {
					Object aes = nouveau(taille);
					int[] c = crypte(aes, m);
					verifier(c.length > 0 && c.length % 128 == 0,
							"le chiffré doit contenir un nombre non nul de blocs de 128 bits (" + c.length + " bits reçus)");
					for (int b : c) {
						verifier(b == 0 || b == 1, "le chiffré ne doit contenir que des 0 et des 1");
					}
					egal("message", m, decrypte(aes, c));
				});
			}
			test("AES-" + taille + " : 71 textes aléatoires (lettres et espaces) de 0 à 70 caractères", () -> {
				Random rnd = new Random(taille);
				Object aes = nouveau(taille);
				for (int n = 0; n <= 70; n++) {
					String m = texteAleatoire(rnd, n);
					int[] c = crypte(aes, m);
					verifier(c.length % 128 == 0, n + " caractères : chiffré pas multiple de 128 bits");
					egal(n + " caractères", m, decrypte(aes, c));
				}
			});
		}

		test("deux objets AES (clés aléatoires) donnent des chiffrés différents", () -> {
			int[] c1 = crypte(nouveau(128), "message de test");
			int[] c2 = crypte(nouveau(128), "message de test");
			verifier(!Arrays.equals(c1, c2), "chiffrés identiques avec deux clés aléatoires");
		});

		test("même objet, même message = même chiffré", () -> {
			Object aes = nouveau(128);
			egalBits("déterminisme", crypte(aes, "message de test"), crypte(aes, "message de test"));
		});

		test("déchiffrer avec une autre clé ne redonne pas le message", () -> {
			String m = "message secret de test";
			int[] c = crypte(nouveau(128), m);
			boolean bon;
			try {
				bon = !m.equals(decrypte(nouveau(128), c));
			} catch (Ignore i) {
				throw i;
			} catch (Throwable e) {
				bon = true; // bourrage invalide : résultat correct aussi
			}
			verifier(bon, "le message a été déchiffré avec une mauvaise clé !");
		});

		test("avalanche : changer 1 bit du message change environ la moitié du 1er bloc chiffré", () -> {
			Object aes = nouveau(128);
			int[] c1 = crypte(aes, "abcdefghijklmnop");
			int[] c2 = crypte(aes, "abcdefghijklmnoq"); // 'p' et 'q' ne diffèrent que d'un bit
			int diff = 0;
			for (int i = 0; i < 128; i++) {
				if (c1[i] != c2[i]) {
					diff++;
				}
			}
			verifier(diff >= 40 && diff <= 88, "seulement " + diff + " bits sur 128 diffèrent (attendu environ 64)");
		});
	}

	// ------------------------------------------------------------------
	// C. Comparaison avec l'AES officiel du JDK (clé imposée par réflexion)
	// ------------------------------------------------------------------

	static void testContreJDK() {
		groupe("C. Comparaison avec l'AES officiel du JDK (javax.crypto)");

		for (int taille : tailles()) {
			test("AES-" + taille + " : 1er bloc chiffré = AES officiel (ne dépend pas du bourrage)", () -> {
				verifierContreJDK(taille, "0123456789abcdef", false, taille);
			});

			for (String m : new String[] { "", "Bonjour",
					"Bonjour tout le monde, voici un message plus long que seize caracteres" }) {
				test("AES-" + taille + " : message de " + m.length() + " caractères = AES/ECB/PKCS5 du JDK (bourrage PKCS7)", () -> {
					verifierContreJDK(taille, m, true, 100 + m.length());
				});
			}

			test("AES-" + taille + " : 20 textes aléatoires = AES/ECB/PKCS5 du JDK (clés différentes)", () -> {
				Random rnd = new Random(7 * taille);
				for (int i = 0; i < 20; i++) {
					verifierContreJDK(taille, texteAleatoire(rnd, rnd.nextInt(60)), true, 1000 + i);
				}
			});

			test("AES-" + taille + " : decrypte() déchiffre un chiffré produit par le JDK", () -> {
				verifierDecrypteJDK(taille, "Message chiffre par le JDK, a dechiffrer par mon AES", 42);
			});
		}
	}

	// ------------------------------------------------------------------
	// D. Méthodes privées (par réflexion), état = int[128] de bits
	// ------------------------------------------------------------------

	static final String H0F = "000102030405060708090a0b0c0d0e0f";

	static void testMethodesPrivees() {
		groupe("D. Méthodes privées, une par une (état = int[128] de bits)");
		if (!ETAT_EN_BITS) {
			System.out.println("  (section sautée : ETAT_EN_BITS = false)");
			return;
		}

		test("stringToBits(\"A\") = 01000001", () -> {
			Object aes = nouveau(128);
			egalBits("A", new int[] { 0, 1, 0, 0, 0, 0, 0, 1 }, ints(aes, STRING_TO_BITS, "A"));
		});

		test("bitsToString(stringToBits(t)) = t", () -> {
			Object aes = nouveau(128);
			for (String t : new String[] { "Hello World", "abcXYZ et un espace", "" }) {
				Object r = un(aes, BITS_TO_STRING, ints(aes, STRING_TO_BITS, t));
				egal("aller-retour", t, "" + r);
			}
		});

		test("genereMasterKey : clé de 128 bits, différente à chaque appel", () -> {
			Object aes = nouveau(128);
			Method m = methode(GENERE, 0);
			Object r1 = invoquer(m, aes, new Object[0]);
			List<Integer> a = new ArrayList<>();
			aplatir(m.getReturnType() == void.class ? champ(MASTER_KEY).get(aes) : r1, a);
			Object r2 = invoquer(m, aes, new Object[0]);
			List<Integer> b = new ArrayList<>();
			aplatir(m.getReturnType() == void.class ? champ(MASTER_KEY).get(aes) : r2, b);
			boolean bits = true;
			for (int x : a) {
				if (x != 0 && x != 1) {
					bits = false;
				}
			}
			verifier(!bits || a.size() == 128, "clé de " + a.size() + " bits au lieu de 128");
			verifier(!a.equals(b), "deux clés générées identiques");
		});

		test("bourrage : 13 octets -> 16 octets, les 3 derniers valent 03", () -> {
			Object aes = nouveau(128);
			int[] msg = bitsAleatoires(new Random(1), 13);
			int[] r = ints(aes, BOURRAGE, msg);
			verifier(r.length == 128, "longueur " + r.length + " au lieu de 128");
			egalBits("début conservé", msg, Arrays.copyOfRange(r, 0, msg.length));
			egal("fin", "030303", bitsVersHex(Arrays.copyOfRange(r, 104, 128)));
		});

		test("bourrage : 16 octets -> un bloc entier de 10 (16) est ajouté", () -> {
			Object aes = nouveau(128);
			int[] r = ints(aes, BOURRAGE, bitsAleatoires(new Random(2), 16));
			verifier(r.length == 256, "longueur " + r.length + " au lieu de 256");
			egal("fin", "10".repeat(16), bitsVersHex(Arrays.copyOfRange(r, 128, 256)));
		});

		test("debourrage(bourrage(x)) = x pour 0 à 40 octets", () -> {
			Object aes = nouveau(128);
			Random rnd = new Random(3);
			for (int n = 0; n <= 40; n++) {
				int[] x = bitsAleatoires(rnd, n);
				egalBits(n + " octets", x, ints(aes, DEBOURRAGE, ints(aes, BOURRAGE, x)));
			}
		});

		test("debourrage refuse un bourrage invalide", () -> {
			Object aes = nouveau(128);
			int[] r = ints(aes, BOURRAGE, bitsAleatoires(new Random(4), 5)).clone();
			for (int i = r.length - 8; i < r.length; i++) {
				r[i] = 0;
			}
			doitLever(() -> un(aes, DEBOURRAGE, r));
		});

		test("decoupage_en_blocs : 3 blocs, et recollage_des_blocs les recolle", () -> {
			Object aes = nouveau(128);
			int[] bits = bitsAleatoires(new Random(5), 48);
			Object blocs = un(aes, DECOUPAGE, bits);
			verifier(blocs instanceof int[][], "decoupage_en_blocs doit renvoyer un int[][]");
			verifier(((int[][]) blocs).length == 3, ((int[][]) blocs).length + " blocs au lieu de 3");
			Object recolle = un(aes, RECOLLAGE, blocs);
			verifier(recolle instanceof int[], "recollage_des_blocs doit renvoyer un int[]");
			egalBits("recollage", bits, (int[]) recolle);
		});

		test("xor : f0f0 xor 0ff0 = ff00", () -> {
			Object aes = nouveau(128);
			egal("xor", "ff00", bitsVersHex(ints(aes, XOR, hexVersBits("f0f0"), hexVersBits("0ff0"))));
		});

		test("addRoundKey : 53 xor CA = 99, et c'est son propre inverse", () -> {
			Object aes = nouveau(128);
			int[] etat = hexVersBits("53" + "00".repeat(15));
			int[] cle = hexVersBits("ca" + "00".repeat(15));
			int[] r = ints(aes, ADD_ROUND_KEY, etat, cle);
			egal("53 xor ca", "99" + "00".repeat(15), bitsVersHex(r));
			egalBits("A xor K xor K", etat, ints(aes, ADD_ROUND_KEY, r, cle));
		});

		test("subByte(00..0f) = 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76", () -> {
			Object aes = nouveau(128);
			egal("subByte", "637c777bf26b6fc53001672bfed7ab76", bitsVersHex(ints(aes, SUB_BYTE, hexVersBits(H0F))));
		});

		test("subByte : S(53) = ed et S(95) = 2a (exemple du cours)", () -> {
			Object aes = nouveau(128);
			egal("subByte", "ed2a" + "63".repeat(14), bitsVersHex(ints(aes, SUB_BYTE, hexVersBits("5395" + "00".repeat(14)))));
		});

		test("subByteInv(637c...76) = 00..0f", () -> {
			Object aes = nouveau(128);
			egal("subByteInv", H0F, bitsVersHex(ints(aes, SUB_BYTE_INV, hexVersBits("637c777bf26b6fc53001672bfed7ab76"))));
		});

		test("S-box : 256 valeurs distinctes et subByteInv est l'inverse (teste toute la table)", () -> {
			Object aes = nouveau(128);
			boolean[] vu = new boolean[256];
			for (int bloc = 0; bloc < 16; bloc++) {
				int[] etat = new int[128];
				for (int j = 0; j < 16; j++) {
					int v = bloc * 16 + j;
					for (int b = 0; b < 8; b++) {
						etat[j * 8 + b] = (v >> (7 - b)) & 1;
					}
				}
				int[] s = ints(aes, SUB_BYTE, etat);
				verifier(s.length == 128, "subByte doit renvoyer 128 bits");
				for (int j = 0; j < 16; j++) {
					int v = 0;
					for (int b = 0; b < 8; b++) {
						v = (v << 1) | s[j * 8 + b];
					}
					verifier(!vu[v], "la valeur " + v + " est produite deux fois par la S-box");
					vu[v] = true;
				}
				egalBits("subByteInv(subByte(x))", etat, ints(aes, SUB_BYTE_INV, s));
			}
		});

		test("shiftRows(00..0f) = 00 05 0a 0f 04 09 0e 03 08 0d 02 07 0c 01 06 0b", () -> {
			Object aes = nouveau(128);
			egal("shiftRows", "00050a0f04090e03080d02070c01060b", bitsVersHex(ints(aes, SHIFT_ROWS, hexVersBits(H0F))));
		});

		test("shiftRowsInv est l'inverse de shiftRows", () -> {
			Object aes = nouveau(128);
			egal("shiftRowsInv", H0F, bitsVersHex(ints(aes, SHIFT_ROWS_INV, hexVersBits("00050a0f04090e03080d02070c01060b"))));
			Random rnd = new Random(6);
			for (int i = 0; i < 20; i++) {
				int[] x = bitsAleatoires(rnd, 16);
				egalBits("shiftRowsInv(shiftRows(x))", x, ints(aes, SHIFT_ROWS_INV, ints(aes, SHIFT_ROWS, x)));
			}
		});

		int[] valeurs = { 0x00, 0x01, 0x02, 0x53, 0x57, 0x80, 0xAE, 0xCA, 0xFF };
		String[][] noms = { DEUX_A, TROIS_A, NEUF_A, ONZE_A, TREIZE_A, QUATORZE_A };
		int[] facteurs = { 2, 3, 9, 11, 13, 14 };
		for (int i = 0; i < noms.length; i++) {
			final String[] nom = noms[i];
			final int f = facteurs[i];
			test(nom[0] + "(a) = a x " + f + " dans GF(2^8)", () -> {
				Object aes = nouveau(128);
				for (int v : valeurs) {
					int obtenu = appelOctet(aes, nom, v);
					verifier(obtenu == gmul(v, f), nom[0] + "(0x" + Integer.toHexString(v) + ") : attendu 0x"
							+ Integer.toHexString(gmul(v, f)) + " mais obtenu 0x" + Integer.toHexString(obtenu));
				}
			});
		}

		test("mixColumns : db135345 -> 8e4da1bc, f20a225c -> 9fdc589d, 01010101 et c6c6c6c6 inchangés", () -> {
			Object aes = nouveau(128);
			String entree = "db135345" + "f20a225c" + "01010101" + "c6c6c6c6";
			String sortie = "8e4da1bc" + "9fdc589d" + "01010101" + "c6c6c6c6";
			egal("mixColumns", sortie, bitsVersHex(ints(aes, MIX_COLUMNS, hexVersBits(entree))));
		});

		test("inverse de mixColumns (mixColumnsInv, si tu en écris une) redonne l'entrée", () -> {
			Object aes = nouveau(128);
			String entree = "db135345" + "f20a225c" + "01010101" + "c6c6c6c6";
			String sortie = "8e4da1bc" + "9fdc589d" + "01010101" + "c6c6c6c6";
			egal("mixColumnsInv", entree, bitsVersHex(ints(aes, MIX_COLUMNS_INV, hexVersBits(sortie))));
		});
	}

	/** Appelle deux_a, trois_a... que l'octet soit un int, un byte ou un int[8] de bits. */
	static int appelOctet(Object aes, String[] noms, int a) throws Throwable {
		Method m = methode(noms, 1);
		Class<?> p = m.getParameterTypes()[0];
		Object r;
		if (p == int.class || p == Integer.class) {
			r = invoquer(m, aes, new Object[] { a });
		} else if (p == byte.class) {
			r = invoquer(m, aes, new Object[] { (byte) a });
		} else if (p == int[].class) {
			int[] bits = new int[8];
			for (int b = 0; b < 8; b++) {
				bits[b] = (a >> (7 - b)) & 1;
			}
			r = invoquer(m, aes, new Object[] { bits });
		} else {
			throw new Ignore("type de paramètre non géré pour " + noms[0] + " : " + p.getSimpleName());
		}
		if (r instanceof Number) {
			return ((Number) r).intValue() & 0xFF;
		}
		if (r instanceof int[] && ((int[]) r).length == 8) {
			int v = 0;
			for (int b : (int[]) r) {
				v = (v << 1) | b;
			}
			return v;
		}
		throw new Echec(noms[0] + " doit renvoyer un entier (ou un int[8])");
	}

	// ------------------------------------------------------------------
	// E. Bonus indicatifs (ne comptent pas dans les échecs)
	// ------------------------------------------------------------------

	static void verifierCleDeTour(String cleHex, int ronde, String attenduHex) throws Throwable {
		byte[] cle = hexVersOctets(cleHex);
		Object aes = nouveau(cle.length * 8);
		imposerCle(aes, cle, false);
		List<Integer> v = new ArrayList<>();
		aplatir(champ(KEYS).get(aes), v);
		boolean mots = false, bits = true;
		for (int x : v) {
			if (x < 0 || x > 255) {
				mots = true;
			}
			if (x != 0 && x != 1) {
				bits = false;
			}
		}
		int parRonde = mots ? 4 : (bits ? 128 : 16);
		String unite = mots ? "mots de 32 bits" : (bits ? "bits" : "octets");
		verifier(v.size() >= (ronde + 1) * parRonde, "keys aplati = " + v.size() + " valeurs (lues comme " + unite + ")");
		StringBuilder sb = new StringBuilder();
		StringBuilder transpose = new StringBuilder();
		List<Integer> tranche = v.subList(ronde * parRonde, (ronde + 1) * parRonde);
		if (bits) {
			for (int i = 0; i + 3 < tranche.size(); i += 4) {
				sb.append(Character.forDigit(tranche.get(i) * 8 + tranche.get(i + 1) * 4 + tranche.get(i + 2) * 2 + tranche.get(i + 3), 16));
			}
		} else if (mots) {
			for (int x : tranche) {
				sb.append(String.format("%08x", x));
			}
		} else {
			for (int x : tranche) {
				sb.append(String.format("%02x", x));
			}
			for (int a = 0; a < 4; a++) {
				for (int b = 0; b < 4; b++) {
					transpose.append(String.format("%02x", tranche.get(4 * b + a)));
				}
			}
		}
		verifier(sb.toString().equals(attenduHex) || transpose.toString().equals(attenduHex),
				"clé de ronde " + ronde + " : attendu " + attenduHex + " mais obtenu " + sb + " (keys lu comme " + unite + ")");
	}

	static void testBonus() {
		groupe("E. Bonus indicatifs (ne comptent pas dans le résultat)");

		String cle128 = "2b7e151628aed2a6abf7158809cf4f3c";
		bonus("createKeys AES-128 : K0 (FIPS-197, annexe A.1)", () -> verifierCleDeTour(cle128, 0, cle128));
		bonus("createKeys AES-128 : K1", () -> verifierCleDeTour(cle128, 1, "a0fafe1788542cb123a339392a6c7605"));
		bonus("createKeys AES-128 : K10", () -> verifierCleDeTour(cle128, 10, "d014f9a8c9ee2589e13f0cc8b6630ca6"));
		if (VERSION_2) {
			bonus("createKeys AES-192 : K12", () -> verifierCleDeTour(
					"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 12, "e98ba06f448c773c8ecc720401002202"));
			bonus("createKeys AES-256 : K14", () -> verifierCleDeTour(
					"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 14, "fe4890d1e6188d0b046df344706c631e"));
		}

		bonus("textes avec accents : aller-retour (é à ç ù, pour aller plus loin que l'énoncé)", () -> {
			Object aes = nouveau(128);
			String m = "Été à Albi : ça marche, où ça ? Voilà !";
			egal("message", m, decrypte(aes, crypte(aes, m)));
		});

		bonus("seuls le constructeur, crypte et decrypte sont publics (reste private)", () -> {
			List<String> pub = new ArrayList<>();
			for (Method m : classeAES.getDeclaredMethods()) {
				String n = m.getName();
				if (Modifier.isPublic(m.getModifiers()) && !m.isSynthetic() && !n.equals("main")
						&& !n.equals("crypte") && !n.equals("decrypte")) {
					pub.add(n + "()");
				}
			}
			for (Field f : classeAES.getDeclaredFields()) {
				if (Modifier.isPublic(f.getModifiers())) {
					pub.add(f.getName());
				}
			}
			verifier(pub.isEmpty(), "encore publics : " + pub);
		});
	}

	public static void main(String[] args) {
		System.out.println("=== Tests AES (version 2 : " + VERSION_2 + ", état en bits : " + ETAT_EN_BITS + ") ===");
		try {
			classeAES = Class.forName("AES");
		} catch (ClassNotFoundException e) {
			System.out.println("Classe AES introuvable : compile AES.java dans le même dossier.");
			System.exit(1);
		}
		testConstructeur();
		testApiPublique();
		testContreJDK();
		testMethodesPrivees();
		testBonus();

		System.out.println();
		System.out.println("Résultat : " + reussis + " réussis, " + echecs + " échecs, " + ignores + " ignorés"
				+ "  (bonus : " + bonusOk + " OK, " + bonusNon + " non)");
		if (echecs == 0 && ignores == 0) {
			System.out.println("Tout marche !");
		}
		System.exit(echecs == 0 ? 0 : 1);
	}
}