import java.awt.*;
import javax.swing.*;

public class View extends JFrame {

	private static final long serialVersionUID = 1L;
	private JTextArea inputArea;
	private JTextArea outputArea;
	private AES aes = new AES(128);

	public View() {
		super("AES - View");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setLayout(new BorderLayout(10, 10));

		JLabel title = new JLabel("Cryptage AES 128 bits");
		title.setHorizontalAlignment(JLabel.CENTER);
		add(title, BorderLayout.NORTH);

		inputArea = new JTextArea(6, 40);
		inputArea.setLineWrap(true);
		outputArea = new JTextArea(6, 40);
		outputArea.setLineWrap(true);
		outputArea.setEditable(false);

		JPanel center = new JPanel(new GridLayout(4, 1));
		center.add(new JLabel("Message (ou texte hexadécimal à déchiffrer) :"));
		center.add(new JScrollPane(inputArea));
		center.add(new JLabel("Résultat :"));
		center.add(new JScrollPane(outputArea));
		add(center, BorderLayout.CENTER);

		JPanel buttons = new JPanel();
		JButton encryptButton = new JButton("Chiffrer");
		JButton decryptButton = new JButton("Déchiffrer");
		encryptButton.addActionListener(e -> chiffrer());
		decryptButton.addActionListener(e -> dechiffrer());
		buttons.add(encryptButton);
		buttons.add(decryptButton);
		add(buttons, BorderLayout.SOUTH);

		setSize(520, 450);
		setLocationRelativeTo(null);
		setVisible(true);
	}

	private void chiffrer() {
		String message = inputArea.getText();
		int[] bits = aes.crypte(message);
		outputArea.setText(bitsVersHex(bits));
	}

	private void dechiffrer() {
		String hex = inputArea.getText();
		int[] bits = hexVersBits(hex);
		outputArea.setText(aes.decrypte(bits));
	}

	private String bitsVersHex(int[] bits) {
		String hex = "";
		for (int i = 0; i < bits.length; i += 4) {
			int valeur = bits[i] * 8 + bits[i + 1] * 4 + bits[i + 2] * 2 + bits[i + 3];
			hex = hex + Integer.toHexString(valeur);
		}
		return hex;
	}

	private int[] hexVersBits(String hex) {
		int[] bits = new int[hex.length() * 4];
		for (int i = 0; i < hex.length(); i++) {
			int valeur = Character.digit(hex.charAt(i), 16);
			for (int b = 0; b < 4; b++) {
				bits[i * 4 + b] = (valeur >> (3 - b)) & 1;
			}
		}
		return bits;
	}

	public static void main(String[] args) {
		new View();
	}
}